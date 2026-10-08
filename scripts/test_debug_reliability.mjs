// Actual public multi-engine control, on a generated temporary sample only.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { apply } from '../index.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-debug-reliability-'));
const target = path.join(scratch, '双引擎调试.exe'), fixture = buildPE64Fixture(1);
fs.writeFileSync(target, fixture.image);
const tools = new Map(), effects = [], routes = new Map();
const webServer = { register(spec) { routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } };
const ctx = { tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
  get: (name) => name === 'webServer' ? webServer : undefined, on() {},
  inject(names, fn) { if (names.includes('webServer')) fn({ webServer }); return { dispose() {} }; },
  effect(body) { const remove = body(); if (typeof remove === 'function') effects.push(remove); } };
const call = (name, args = {}, engine = 'reverse', agent = 'owner', signal) => tools.get(name).execute({ target, engine, ...args }, { agent: { id: agent }, signal });
const dbg = (op, args = {}, engine, agent, signal) => call('ig5_dbg', { backend: 'x64dbg', timeout: 10, op, ...args }, engine, agent, signal);
const state = () => new Promise((resolve, reject) => routes.get('/ig5-data')({ method: 'GET', url: '/ig5-data?' + new URLSearchParams({ target, engine: 'x64dbg', type: 'debug_state' }) }, {
  writeHead(status) { assert.equal(status, 200); }, end(body) { const r = JSON.parse(body); r.error ? reject(new Error(r.error)) : resolve(r.data); },
}));
async function spin() {
  const started = await dbg('start');
  await dbg('bpt', { rva: '0x1000' });
  const base = BigInt(started.context.mainModuleBase), entry = '0x' + (base + 0x1000n).toString(16);
  let regs = await dbg('regs');
  for (let i = 0; regs.regs.rip !== entry && i < 5; i++) { await dbg('cont'); regs = await dbg('regs'); }
  assert.equal(regs.regs.rip, entry);
  await dbg('setreg', { reg: 'rip', value: '0x' + (base + 0x1080n).toString(16) });
  return dbg('regs');
}
try {
  apply(ctx, { toolset: 'full', artifactDir: path.join(scratch, 'artifacts'), requestTimeoutMs: 120000 });
  for (const engine of ['reverse', 'ghidra']) await call('ig5_open', { path: target, background: false }, engine);
  await dbg('load');
  let before = await spin();
  const running = dbg('cont', { expected_stop_seq: before.stopSeq });
  await delay(150);
  await assert.rejects(dbg('suspend', {}, 'ghidra', 'intruder'), /controlled by another/);
  const stale = assert.rejects(dbg('step', { control: 'takeover', expected_stop_seq: before.stopSeq }, 'ghidra', 'intruder'), /pause changed/);
  const abort = new AbortController();
  const cancelledQueued = assert.rejects(dbg('setreg', { reg: 'rax', value: '0x5555' }, 'ghidra', 'owner', abort.signal), /cancelled/);
  abort.abort();
  const paused = await dbg('suspend', {}, 'ghidra');
  const continued = await running;
  await Promise.all([stale, cancelledQueued]);
  assert.equal(paused.state, 'suspended'); assert.equal(continued.state, 'suspended');
  assert.equal(paused.runId, continued.runId); assert.equal(paused.stopSeq, continued.stopSeq);
  assert.equal(paused.stopSeq, before.stopSeq + 1, 'one physical pause must increment once across two response paths');
  await assert.rejects(call('ig5_close', {}, 'ghidra', 'intruder'), /controlled by another/);
  const stoppedRun = dbg('cont'); await delay(150);
  const stopped = await dbg('stop', {}, 'ghidra');
  assert.equal(stopped.state, 'no-task'); assert.equal((await stoppedRun).state, 'no-task');
  assert.equal((await state()).state, 'no-task');
  await dbg('load'); before = await spin();
  const activeAbort = new AbortController();
  const cancelledRun = assert.rejects(dbg('cont', {}, 'reverse', 'owner', activeAbort.signal), (error) => {
    assert.equal(error.cleanedUp, true); assert.equal(error.state, 'no-task'); return true;
  });
  await delay(150); activeAbort.abort(); await cancelledRun;
  const clean = await state(); assert.equal(clean.state, 'no-task'); assert.equal(clean.regs, undefined);
  // Cleanup released the previous owner, allowing a new approved controller.
  await dbg('load', {}, 'ghidra', 'replacement');
  await dbg('stop', {}, 'ghidra', 'replacement');
  assert.deepEqual(fs.readFileSync(target), fixture.image);
  console.log('Public debug reliability: shared Reverse/Ghidra queue, priority pause/stop, exact stop sequence, queued/running cancellation, owner-safe close and cache cleanup passed. Evidence:', scratch);
} finally {
  for (const remove of effects.reverse()) await remove();
}
