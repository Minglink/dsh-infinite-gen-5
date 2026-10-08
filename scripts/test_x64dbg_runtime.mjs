// Explicit live opt-in: only executes a generated PE in a new temporary folder.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
import { runtimeConfiguration } from '../engine_runtime.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const runtime = runtimeConfiguration().x64dbg;
assert.equal(runtime.available, true, runtime.reason);
const configPath = runtime.manifest;
const config = JSON.parse(fs.readFileSync(configPath, 'utf8').replace(/^\uFEFF/, ''));
const python = path.resolve(path.dirname(configPath), config.pythonExe);
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-x64dbg-'));
const bits = process.argv.includes('--x86') ? 32 : 64;
function pe32() {
  const b = Buffer.alloc(0x400); b.write('MZ'); b.writeUInt32LE(0x80, 0x3c); b.write('PE\0\0', 0x80);
  const c = 0x84, o = c + 20, s = o + 0xe0;
  b.writeUInt16LE(0x14c, c); b.writeUInt16LE(1, c + 2); b.writeUInt16LE(0xe0, c + 16); b.writeUInt16LE(0x102, c + 18);
  b.writeUInt16LE(0x10b, o); b.writeUInt32LE(0x200, o + 4); b.writeUInt32LE(0x1000, o + 16); b.writeUInt32LE(0x1000, o + 20);
  b.writeUInt32LE(0x400000, o + 28); b.writeUInt32LE(0x1000, o + 32); b.writeUInt32LE(0x200, o + 36); b.writeUInt16LE(6, o + 40);
  b.writeUInt16LE(6, o + 48); b.writeUInt32LE(0x2000, o + 56); b.writeUInt32LE(0x200, o + 60); b.writeUInt16LE(3, o + 68);
  b.writeUInt16LE(0x100, o + 70); b.writeUInt32LE(0x100000, o + 72); b.writeUInt32LE(0x1000, o + 76);
  b.writeUInt32LE(0x100000, o + 80); b.writeUInt32LE(0x1000, o + 84); b.writeUInt32LE(16, o + 92);
  b.write('.text', s); b.writeUInt32LE(0x200, s + 8); b.writeUInt32LE(0x1000, s + 12); b.writeUInt32LE(0x200, s + 16);
  b.writeUInt32LE(0x200, s + 20); b.writeUInt32LE(0x60000020, s + 36);
  Buffer.from('b8010000009090ebfe', 'hex').copy(b, 0x200); return b;
}
const fixture = bits === 32 ? pe32() : buildPE64Fixture();
const target = path.join(scratch, '隔离样本.exe');
fs.writeFileSync(target, Buffer.isBuffer(fixture) ? fixture : fixture.image || fixture.bytes || fixture.buffer);
const worker = spawn(python, ['-I', '-B', path.join(root, 'adapters', 'x64dbg', 'adapter.py')], {
  windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, IG5_X64DBG_RUNTIME: configPath, IG5_X64DBG_STATE_ROOT: path.join(scratch, 'state') },
});
let sequence = 0, buffer = '', debuggerPid;
const pending = new Map();
let readyResolve, readyReject;
const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
worker.stdout.on('data', data => {
  buffer += data.toString('utf8');
  for (;;) {
    const index = buffer.indexOf('\n');
    if (index < 0) break;
    const line = buffer.slice(0, index).trim(); buffer = buffer.slice(index + 1);
    if (!line) continue;
    let message;
    try { message = JSON.parse(line); } catch { readyReject(new Error('non JSON stdout: ' + line)); throw new Error('non JSON stdout: ' + line); }
    if (message.ig5 === 'ready') { readyResolve(message); continue; }
    const request = pending.get(message.id);
    if (!request) continue;
    clearTimeout(request.timer); pending.delete(message.id);
    message.error ? request.reject(Object.assign(new Error(message.error.message), message.error)) : request.resolve(message.result);
  }
});
worker.stderr.on('data', data => process.stderr.write(data));
worker.on('exit', code => { for (const req of pending.values()) req.reject(new Error('adapter exited: ' + code)); pending.clear(); });
function rpc(method, params = {}) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('JSONL RPC timeout: ' + method)); }, 25000);
    pending.set(id, { resolve, reject, timer });
    worker.stdin.write(JSON.stringify({ id, method, params }) + '\n');
  });
}
const dbg = async (op, params = {}) => {
  const value = await rpc('dbg', { op, timeout: 10, ...params });
  console.log(`[${op}] ${JSON.stringify(value)}`);
  assert.equal(value.ok, true, op + ' must succeed');
  return value;
};
try {
  assert.equal((await ready).engine, 'x64dbg');
  assert.equal((await rpc('doctor')).ok, true);
  const opened = await rpc('open', { path: target });
  assert.equal(opened.targetExecuted, false);
  assert.equal((await dbg('load')).targetExecuted, false);
  const started = await dbg('start');
  assert.equal(started.mode, 'headless');
  assert.equal(started.state, 'suspended');
  assert.ok(started.runId); assert.ok(started.stopSeq > 0);
  assert.equal(started.context.module?.toLowerCase(), 'ntdll.dll', 'system breakpoint must name its actual containing module');
  assert.notEqual(started.context.moduleBase, started.context.mainModuleBase);
  debuggerPid = started.debuggerPid;
  const base = BigInt(started.context.mainModuleBase);
  assert.equal(started.context.bits, bits);
  const ip = bits === 32 ? 'eip' : 'rip', ax = bits === 32 ? 'eax' : 'rax';
  const entry = '0x' + (base + 0x1000n).toString(16);
  await dbg('bpt', { rva: '0x1000' });
  let regs = await dbg('regs');
  if (regs.regs[ip] !== entry) { await dbg('cont'); regs = await dbg('regs'); }
  assert.equal(regs.regs[ip], entry);
  const read = await dbg('readmem', { rva: '0x1000', size: 5 });
  assert.equal(read.hex, bits === 32 ? 'b801000000' : '488d0411c3');
  for (const request of [{ rva: '-0x1', size: 1 }, { rva: '0x' + (started.context.mainModuleSize - 1).toString(16), size: 2 }]) {
    await assert.rejects(rpc('dbg', { op: 'readmem', ...request }), error => error.code === 'EINVAL');
  }
  const moduleList = await dbg('modules');
  assert.equal(moduleList.modules.find(m => m.isMain).base, started.context.mainModuleBase);
  const stepped = await dbg('step');
  assert.ok(stepped.stopSeq > started.stopSeq);
  const after = await dbg('regs');
  assert.notEqual(after.regs[ip], regs.regs[ip]);
  await dbg('setreg', { reg: ax, value: '0x1234', expected: after.regs[ax] });
  assert.equal((await dbg('regs')).regs[ax], '0x1234');
  // A reversible code-memory write proves readback and expected-value rejection.
  const bytes = await dbg('readmem', { rva: '0x1010', size: 2 });
  await dbg('writemem', { rva: '0x1010', hex: '9090', expected: bytes.hex });
  const refused = await rpc('dbg', { op: 'writemem', rva: '0x1010', hex: 'cccc', expected: 'abab' });
  assert.equal(refused.ok, false); assert.equal((await dbg('readmem', { rva: '0x1010', size: 2 })).hex, '9090');
  await dbg('writemem', { rva: '0x1010', hex: bytes.hex, expected: '9090' });
  await dbg('stepover');
  await dbg('suspend');
  await dbg('setreg', { reg: ip, value: '0x' + (base + (bits === 32 ? 0x1007n : 0x1080n)).toString(16) });
  const trace = await dbg('trace', { count: 5 });
  assert.equal(trace.maxSteps, 5); assert.equal(trace.state, 'suspended');
  await dbg('setreg', { reg: ip, value: '0x0' });
  const fault = await dbg('step');
  assert.equal(fault.eventName, 'exception');
  assert.equal(fault.event.data.ExceptionCode, '0xc0000005');
  assert.equal(fault.state, 'suspended');
  assert.equal(fault.context.module, null); assert.equal(fault.context.moduleBase, null);
  await dbg('regs');
  await dbg('setreg', { reg: ip, value: after.regs[ip] });
  await dbg('bpt', { rva: '0x1010' });
  await dbg('unbpt', { rva: '0x1010' });
  assert.equal((await dbg('state')).state, 'suspended');
  assert.ok((await dbg('event')).events.length > 0);
  assert.equal((await dbg('stop')).state, 'no-task');
  assert.equal((await rpc('close')).closed, true);
  console.log(`=== X64DBG ${bits}-BIT HEADLESS LIVE ASSERTIONS PASSED ===`);
} finally {
  try { await rpc('close'); } catch {}
  worker.stdin.end();
  await new Promise(resolve => { if (worker.exitCode !== null) resolve(); else { worker.once('exit', resolve); setTimeout(() => { worker.kill(); resolve(); }, 4000).unref(); } });
  fs.rmSync(scratch, { recursive: true, force: true });
}
