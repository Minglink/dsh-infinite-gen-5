// Explicit runtime integration: executes only a generated, temporary PE fixture.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { apply } from '../index.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-debug-integration-'));
const target = path.join(scratch, '调试样本.exe'), fixture = buildPE64Fixture(1);
fs.writeFileSync(target, fixture.image);
const tools = new Map(), effects = [], hooks = new Map(), routes = new Map();
const webServer = { register(spec) { routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } };
const ctx = { tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
  get: (name) => name === 'webServer' ? webServer : undefined, on(name, fn) { hooks.set(name, fn); },
  inject(names, fn) { if (names.includes('webServer')) fn({ webServer }); return { dispose() {} }; },
  effect(body) { const remove = body(); if (typeof remove === 'function') effects.push(remove); } };
const call = (name, args = {}, agent = 'owner-one') => tools.get(name).execute({ target, engine: 'ghidra', ...args }, { agent: { id: agent } });
const dbg = (op, args = {}, owner) => call('ig5_dbg', { backend: 'x64dbg', op, timeout: 10, ...args }, owner);
try {
  apply(ctx, { reverse: false, toolset: 'full', artifactDir: path.join(scratch, 'artifacts'), requestTimeoutMs: 120000 });
  await call('ig5_open', { path: target, background: false });
  assert.equal((await call('ig5_doctor', { engine: 'x64dbg' })).ok, true);
  let approvalDispatch = false;
  const unapproved = await hooks.get('tools/pre-execute')({ name: 'ig5_dbg', arguments: { target, op: 'start', backend: 'x64dbg' } }, () => { approvalDispatch = true; return { kind: 'allow' }; });
  assert.equal(unapproved.kind, 'deny', 'Missing agent/approval service must deny debugger execution');
  assert.equal(approvalDispatch, false);
  assert.equal((await dbg('load')).targetExecuted, false);
  const started = await dbg('start');
  assert.equal(started.ok, true); assert.equal(started.mode, 'headless'); assert.equal(started.state, 'suspended');
  await dbg('bpt', { rva: '0x1000' });
  const entry = '0x' + (BigInt(started.context.mainModuleBase || started.context.moduleBase) + 0x1000n).toString(16);
  let regs = await dbg('regs');
  for (let attempt = 0; regs.regs.rip !== entry && attempt < 4; attempt++) { await dbg('cont'); regs = await dbg('regs'); }
  assert.equal(regs.regs.rip, entry);
  assert.equal((await dbg('readmem', { rva: '0x1000', size: 5 })).hex, '488d0411c3');
  await assert.rejects(dbg('step', {}, 'owner-two'), /controlled by another/);
  await assert.rejects(dbg('step', { expected_stop_seq: regs.stopSeq + 1 }), /pause changed/);
  const stepped = await dbg('step', { control: 'takeover', expected_stop_seq: regs.stopSeq, expected_run_id: regs.runId }, 'owner-two');
  assert.equal(stepped.ok, true); assert.ok(stepped.stopSeq > regs.stopSeq);
  const next = await dbg('regs', {}, 'owner-two');
  await dbg('setreg', { reg: 'rax', value: '0x1234', expected: next.regs.rax }, 'owner-two');
  assert.equal((await dbg('regs', {}, 'owner-two')).regs.rax, '0x1234');
  await dbg('setreg', { reg: 'rip', value: '0' }, 'owner-two');
  const fault = await dbg('step', {}, 'owner-two');
  assert.equal(fault.eventName, 'exception'); assert.equal(fault.context.exception.code, '0xc0000005');
  assert.equal((await dbg('regs', {}, 'owner-two')).ok, true);
  const cached = await new Promise((resolve) => routes.get('/ig5-data')({ method: 'GET', url: '/ig5-data?' + new URLSearchParams({ type: 'debug_state', engine: 'x64dbg', target }) }, {
    writeHead(code) { assert.equal(code, 200); }, end(body) { resolve(JSON.parse(body)); },
  }));
  assert.equal(cached.engine, 'x64dbg'); assert.equal(cached.data.runId, started.runId);
  assert.equal(cached.data.state, 'suspended'); assert.equal(cached.data.regs.rip, '0x0');
  assert.equal((await dbg('stop', {}, 'owner-two')).state, 'no-task');
  const status = await call('ig5_status'); assert.ok(status.sessions.some((session) => session.engine === 'x64dbg'));
  assert.deepEqual(fs.readFileSync(target), fixture.image);
  console.log('Public x64dbg tools: Ghidra-only host, approval hook, true headless run, ASLR/RVA, register/memory, ownership takeover, stale pause rejection, step, structured AV, cached UI state and stop passed.');
} finally {
  for (const remove of effects.reverse()) await remove();
  assert.equal(path.dirname(path.resolve(scratch)), path.resolve(os.tmpdir()));
  assert.ok(path.basename(scratch).startsWith('ig5-debug-integration-'));
  await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 30, retryDelay: 100 });
}
