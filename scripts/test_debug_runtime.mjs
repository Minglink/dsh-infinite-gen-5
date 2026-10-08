// Opt-in live debug smoke test. Executes only the bundled notepad fixture copy.
// Default: native Windows debugger; IG5_DEBUG_BACKEND=bochs explicitly tests Bochs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixture = path.join(pluginRoot, '..', '_research', 'fixtures', 'notepad.exe');
const tempRoot = fs.realpathSync(os.tmpdir());
const scratch = fs.mkdtempSync(path.join(tempRoot, 'ig5-debug-runtime-'));
const target = path.join(scratch, 'notepad.exe');
const effects = [];
const tools = new Map();
const backend = process.env.IG5_DEBUG_BACKEND || 'win32';
let launched = false;

try {
  fs.copyFileSync(fixture, target);
  const pe = fs.readFileSync(target);
  const optional = pe.readUInt32LE(0x3c) + 24;
  const is64 = pe.readUInt16LE(optional) === 0x20b;
  const imageBase = is64 ? pe.readBigUInt64LE(optional + 24) : BigInt(pe.readUInt32LE(optional + 28));
  const entry = `0x${(imageBase + BigInt(pe.readUInt32LE(optional + 16))).toString(16)}`;
  const entryRva = BigInt(pe.readUInt32LE(optional + 16));
  const mod = await import(pathToFileURL(path.join(pluginRoot, 'index.js')).href);
  mod.apply({
    tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
    on() {},
    get() {},
    inject() { return { dispose() {} }; },
    effect(fn) { const dispose = fn(); if (typeof dispose === 'function') effects.push(dispose); },
  }, {
    artifactDir: path.join(scratch, 'artifacts'),
    requestTimeoutMs: 15_000,
    openTimeoutMs: 15_000,
    toolset: 'full',
  });
  await tools.get('ig5_open').execute({ path: target, background: false });
  const dbg = async (op, args = {}) => {
    const result = await tools.get('ig5_dbg').execute({ target, op, timeout: 2, ...args });
    console.log(`[${op}] ${JSON.stringify(result)}`);
    return result;
  };
  const loaded = await dbg('load', { backend });
  assert.equal(loaded.ok, true, 'debugger must load');
  assert.equal(loaded.debugger.toLowerCase(), backend, 'live test requires the explicit backend');
  assert.equal((await dbg('bpt', { ea: entry })).ok, true);
  launched = true;
  const started = await dbg('start', { path: target });
  assert.equal(started.ok, true, 'start must reach a suspended event');
  const runtimeEntry = started.context?.module?.base
    ? '0x' + (BigInt(started.context.module.base) + entryRva).toString(16) : entry;
  let regs = await dbg('regs');
  assert.equal(regs.ok, true);
  const ip = is64 ? 'rip' : 'eip';
  for (let attempt = 0; regs.regs[ip] !== runtimeEntry && attempt < 3; attempt++) {
    assert.equal((await dbg('cont')).ok, true);
    regs = await dbg('regs');
    assert.equal(regs.ok, true);
  }
  assert.equal(regs.regs[ip], runtimeEntry, 'entry breakpoint must be reached, accounting for ASLR');
  const saved = regs.regs[is64 ? 'rax' : 'eax'];
  assert.equal((await dbg('setreg', { reg: is64 ? 'rax' : 'eax', value: '0x1234' })).ok, true);
  assert.equal((await dbg('regs')).regs[is64 ? 'rax' : 'eax'], '0x1234');
  assert.equal((await dbg('setreg', { reg: is64 ? 'rax' : 'eax', value: saved })).ok, true);
  const memory = await dbg('readmem', { ea: regs.regs[ip], size: 16 });
  assert.equal(memory.ok, true);
  assert.equal(memory.size, 16);
  assert.match(memory.hex, /^[0-9a-f]{32}$/i);
  const databaseEntry = '0x' + (BigInt(regs.databaseBase || '0x' + imageBase.toString(16)) + entryRva).toString(16);
  const comment = await tools.get('ig5_comment').execute({ target, ea: databaseEntry,
    text: `IG5 live breakpoint: ${ip}=${regs.regs[ip]}` });
  assert.equal(comment.ok, true, 'breakpoint context can be recorded through the journaled comment operation');
  const checked = await tools.get('ig5_run_idapython').execute({ target,
    code: `import ida_bytes\nprint(ida_bytes.get_cmt(${databaseEntry}, False))` });
  assert.match(checked.output, /IG5 live breakpoint/);
  assert.equal((await tools.get('ig5_undo').execute({ target })).kind, 'comment');
  assert.equal((await dbg('step')).ok, true);
  const stepped = await dbg('regs');
  assert.equal(stepped.ok, true);
  assert.notEqual(stepped.regs[ip], regs.regs[ip], 'single step must advance the instruction pointer');
  assert.equal((await dbg('setreg', { reg: ip, value: '0x0' })).ok, true);
  const fault = await dbg('step');
  assert.equal(fault.eventName, 'exception', 'invalid instruction pointer must produce a structured exception event');
  assert.equal(fault.context.exception.code, '0xc0000005');
  assert.equal(fault.state, 'suspended', 'exception must keep the worker responsive and process paused');
  assert.equal((await dbg('regs')).ok, true, 'RPC must remain usable after the exception');
  assert.equal((await dbg('setreg', { reg: ip, value: stepped.regs[ip] })).ok, true);
  const stopped = await dbg('stop');
  assert.equal(stopped.ok, true, 'stop must reach no-task state');
  launched = false;
  console.log('=== LIVE DEBUG RUNTIME ASSERTIONS PASSED ===');
} finally {
  if (launched) {
    try {
      await tools.get('ig5_dbg').execute({ target, op: 'stop', timeout: 2 });
    } catch { /* A timed-out worker may already have been reclaimed. */ }
  }
  for (const dispose of effects.reverse()) dispose();
  const relative = path.relative(tempRoot, path.resolve(scratch));
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
  await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
