// Real Reverse/Ghidra providers + bundled Unicorn, using generated temporary
// PE bytes only. No Windows debuggee is started and no user database is opened.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
import { runtimeConfiguration, terminateTree } from '../engine_runtime.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-permissions-'));
const generated = buildPE64Fixture();
const bytes = Buffer.alloc(0x2000); generated.image.copy(bytes);
const optional = 0x98;
bytes.writeUInt16LE(4, 0x86);
bytes.writeUInt32LE(0x1200, optional + 0xf0 + 2 * 40 + 8); // .data includes a BSS tail.
bytes.writeUInt32LE(0x6000, optional + 56);
const deny = optional + 0xf0 + 3 * 40;
bytes.write('.deny', deny, 'ascii');
for (const [offset, value] of [[8, 0x200], [12, 0x5000], [16, 0x200], [20, 0x1e00], [36, 0x40]]) bytes.writeUInt32LE(value, deny + offset);
bytes[0x1e00] = 0xc3;
// An exported indirect tail call exercises NX without executing native code.
bytes.set(Buffer.from('ffe1', 'hex'), 0x500);
bytes[0x1d00] = 0xc3;
const addresses = { ...generated.addresses, rw: '0x140003f00', bss: '0x140004000', deny: '0x140005000', ro: '0x140002500' };
const evidence = { scope: 'generated PE64; real static providers and bundled Unicorn, no native debuggee', results: [] };

function reverseDirectory() {
  if (process.env.IG5_IDA_DIR) return process.env.IG5_IDA_DIR;
  for (const parent of [path.join(os.homedir(), 'Desktop'), 'C:\\Program Files', 'C:\\Program Files (x86)']) {
    if (!fs.existsSync(parent)) continue;
    for (const name of fs.readdirSync(parent).filter(value => /^IDA\b/i.test(value))) {
      const directory = path.join(parent, name);
      if (fs.existsSync(path.join(directory, 'idalib', 'python'))) return directory;
    }
  }
  throw new Error('Configure an available licensed Reverse installation with IG5_IDA_DIR');
}

async function verify(engine) {
  const target = path.join(scratch, engine + '.exe'); fs.writeFileSync(target, bytes);
  let executable, args, extra = {};
  if (engine === 'reverse') {
    const directory = reverseDirectory();
    executable = process.env.IG5_PYTHON || path.join(directory, 'python311', 'python.exe');
    args = ['-X', 'utf8', '-B', path.join(root, 'worker', 'ig5_worker.py'), '--ida-dir', directory];
  } else {
    const runtime = runtimeConfiguration().ghidra; assert(runtime.available, runtime.reason);
    executable = runtime.pythonExe;
    args = ['-I', '-B', path.join(root, 'adapters', 'ghidra', 'worker.py')];
    extra = { IG5_GHIDRA_HOME: runtime.ghidraHome, IG5_JAVA_HOME: runtime.javaHome, IG5_GHIDRA_PROJECT_ROOT: path.join(scratch, 'projects') };
  }
  const child = spawn(executable, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, ...extra, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' } });
  let sequence = 0, stderr = '', readyResolve, readyReject;
  const pending = new Map();
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const timer = setTimeout(() => readyReject(new Error(engine + ' worker readiness timeout')), 120000);
  const exited = new Promise(resolve => child.once('exit', resolve));
  child.once('error', readyReject);
  child.once('exit', code => { readyReject(new Error(engine + ' worker exited ' + code)); for (const slot of pending.values()) slot.reject(new Error(engine + ' worker exited ' + code)); });
  child.stderr.on('data', value => { stderr = (stderr + value.toString()).slice(-30000); });
  readline.createInterface({ input: child.stdout }).on('line', line => {
    let value; try { value = JSON.parse(line); } catch { return; }
    if (value.ig5 === 'ready') { clearTimeout(timer); readyResolve(); return; }
    if (value.ig5 === 'progress') return;
    const slot = pending.get(value.id); if (!slot) return;
    clearTimeout(slot.timer); pending.delete(value.id);
    if (value.error) slot.reject(new Error(typeof value.error === 'string' ? value.error : value.error.message)); else slot.resolve(value.result);
  });
  function rpc(method, params = {}) {
    const id = ++sequence;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => { pending.delete(id); reject(new Error(engine + ' ' + method + ' timeout')); }, 120000);
      pending.set(id, { resolve, reject, timer: timeout });
      child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    });
  }
  function record(name, result) {
    evidence.results.push({ engine, name, result });
    console.log('PASS', engine, name, JSON.stringify(result.reason ?
      { reason: result.reason, protectionMode: result.protectionMode, fault: result.fault,
        unknownPermissionRegions: result.unknownPermissionRegions, unknownPermissionPages: result.unknownPermissionPages } : result));
  }
  const emulate = (name, params) => rpc('emulate', { ea: addresses[name], ...params });
  function protection(result, access, permissions) {
    assert.equal(result.ok, false); assert.equal(result.reason, 'memory-protection');
    assert.equal(result.fault.kind, 'protection'); assert.equal(result.fault.accessType, access); assert.equal(result.fault.permissions, permissions);
  }
  try {
    await ready;
    await rpc('open', { path: target, fresh: true, auto: true, analysis_profile: 'interactive' });
    const add = await emulate('add', { args: [19, 23] });
    assert.equal(add.ok, true); assert.equal(add.return_value, '0x2a'); assert.equal(add.sourceEngine, engine);
    assert.equal(add.pageSize, 4096);
    assert.equal(add.protectionMode, engine === 'reverse' ? 'engine-page-permissions-with-unknown-rwx' : 'engine-page-permissions');
    record('RX function and protected synthetic stack return', add);
    const read = await emulate('fault', { args: [addresses.ro] }); assert.equal(read.ok, true); record('R page readable', read);
    const written = await emulate('buffer', { args: [addresses.rw], capture: [{ ea: addresses.rw, size: 1 }] });
    assert.equal(written.ok, true); assert.equal(written.memory[0].hex, '5a'); record('RW page write', written);
    const readOnly = await emulate('buffer', { args: [addresses.ro] }); protection(readOnly, 'write', 1); record('R page write protection', readOnly);
    const codeWrite = await emulate('buffer', { args: [addresses.add], memory: [{ ea: addresses.add, hex: '48' }] }); protection(codeWrite, 'write', 5); record('RX page buffer does not upgrade protection', codeWrite);
    const nx = await emulate('constant', { args: [addresses.rw] }); protection(nx, 'execute', 3); record('RW page NX', nx);
    const missing = await emulate('fault', { args: ['0x55550000'] });
    assert.equal(missing.reason, 'unmapped-memory'); assert.equal(missing.fault.kind, 'unmapped'); assert.equal(missing.fault.accessType, 'read'); record('unmapped remains distinct', missing);
    const denied = await emulate('constant', { args: [addresses.deny] });
    if (engine === 'ghidra') { protection(denied, 'execute', 0); const deniedRead = await emulate('fault', { args: [addresses.deny] }); protection(deniedRead, 'read', 0); record('explicit no-access read', deniedRead); }
    else { assert.equal(denied.ok, true); assert(denied.unknownPermissionRegions >= 1); assert(denied.unknownPermissionPages >= 1); assert(denied.limitations.some(value => value.includes('Unknown engine permissions'))); }
    record(engine === 'ghidra' ? 'explicit no-access execute' : 'native zero mask explicitly unknown with RWX compatibility', denied);
    for (const [name, params, expected] of [
      ['ea-only compatibility', { ea: addresses.add }, { size: 1, contiguous: true, fileOffset: 0x400 }],
      ['contiguous complete range', { ea: addresses.add, size: 5 }, { size: 5, contiguous: true, fileOffset: 0x400 }],
      ['last mapped byte', { ea: '0x140003fff', size: 1 }, { size: 1, contiguous: true, fileOffset: 0x1dff }],
      ['raw/BSS boundary rejected', { ea: '0x140003fff', size: 2 }, { size: 2, contiguous: false, fileOffset: -1 }],
      ['BSS has no file offset', { ea: addresses.bss, size: 8 }, { size: 8, contiguous: false, fileOffset: -1 }],
    ]) {
      const mapping = await rpc('fileoffset', params);
      for (const [key, value] of Object.entries(expected)) assert.equal(mapping[key], value, engine + ' ' + name + ' ' + key);
      record('file mapping ' + name, mapping);
    }
    await assert.rejects(rpc('fileoffset', { ea: addresses.add, size: 4097 }), /1\.\.4096/);
    await rpc('close'); assert.deepEqual(fs.readFileSync(target), bytes);
  } catch (error) {
    error.message += '\n' + stderr; throw error;
  } finally {
    clearTimeout(timer); for (const slot of pending.values()) clearTimeout(slot.timer);
    child.stdin.end();
    const graceful = await Promise.race([exited.then(() => true), new Promise(resolve => setTimeout(() => resolve(false), 5000))]);
    if (!graceful) terminateTree(child);
  }
}

try {
  const selected = process.argv.slice(2); const engines = selected.length ? selected : ['reverse', 'ghidra'];
  assert(engines.every(value => ['reverse', 'ghidra'].includes(value)));
  for (const engine of engines) await verify(engine);
  evidence.ok = true;
} catch (error) { evidence.ok = false; evidence.error = error.stack; console.error(error.stack); process.exitCode = 1; }
finally { fs.writeFileSync(path.join(scratch, 'acceptance.json'), JSON.stringify(evidence, null, 2)); console.log('Evidence:', path.join(scratch, 'acceptance.json')); }
