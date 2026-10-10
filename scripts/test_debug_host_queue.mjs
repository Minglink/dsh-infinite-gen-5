// Deterministic regressions over the actual WorkerManager implementation.
// Only the engine transport/project persistence is stubbed: no process or PE runs.
import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
import { engineId } from '../engine_runtime.js';
import { attachWorker, doctorWorker } from '../source/worker_transport.js';

const source = fs.readFileSync(new URL('../index.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const classSource = source.match(/class WorkerManager \{[\s\S]*?\n\}\n/)?.[0];
assert.ok(classSource, 'actual WorkerManager source must be present');
const errorStart = source.indexOf('function publicEngineError(');
const errorEnd = source.indexOf('// ── Worker 池', errorStart);
const publicEngineError = vm.runInNewContext(source.slice(errorStart, errorEnd) + '\npublicEngineError;');

class MemoryProjects {
  constructor() { this.closed = []; this.counter = 0; }
  recoverAttachments() { return { recovered: [], retained: [] }; }
  listAttachments() { return []; }
  open() { return { projectId: 'project-fixture', artifactId: 'artifact-fixture', sha256: 'fixture-hash' }; }
  attachEngine() { return { attachmentId: 'attachment-' + ++this.counter, dbRevision: 0 }; }
  closeAttachment(id) { this.closed.push(id); }
}
const terminated = [];
const WorkerManager = vm.runInNewContext(classSource + '\nWorkerManager;', {
  path, fs, createHash, AsyncLocalStorage, attachWorker, doctorWorker, ProjectStore: MemoryProjects, engineId,
  process, setTimeout, clearTimeout, Buffer, publicEngineError,
  terminateTree: proc => { terminated.push(proc); proc.exitCode = -1; }, diagAppend() {},
});
const cfg = { defaultEngine: 'reverse', defaultDebugger: 'x64dbg', maxSessions: 5,
  requestTimeoutMs: 2000, openTimeoutMs: 2000, projectRoot: 'C:/unused-memory-projects' };
const target = path.resolve('readonly-host-queue-fixture.exe');
const targetKey = target.toLowerCase();
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function until(predicate) {
  for (let i = 0; i < 50 && !predicate(); i++) await turn();
  assert.ok(predicate(), 'stub engine operation should be reached without waiting for a timer');
}
const paused = (stopSeq = 2) => ({ ok: true, state: 'suspended', stateCode: 0,
  runId: 'run-fixture', stopSeq, context: { runId: 'run-fixture', stopSeq } });

function harness(owner = 'agent-one') {
  const mgr = new WorkerManager(cfg);
  let pid = 100;
  function session(engine) {
    const key = mgr.sessionKey(target, engine);
    const value = { key, target, engine, proc: { exitCode: null, pid: ++pid }, ready: true,
      pending: new Map(), cache: new Map(), info: {}, dbRevision: 0,
      projectId: 'project-fixture', artifactId: 'artifact-fixture' };
    mgr.sessions.set(key, value); return value;
  }
  const reverse = session('reverse'), ghidra = session('ghidra'), debug = session('x64dbg');
  debug.controlOwner = owner; debug.runtime = paused(1);
  mgr.debugOwners.set(targetKey, 'x64dbg');
  const calls = [];
  mgr.rpc = async (selected, method, params) => { calls.push({ selected, method, params }); return paused(); };
  const run = (selected, params, agent = 'agent-one', signal) => mgr.scope.run({ agentId: agent, signal },
    () => mgr.debug(selected, { backend: 'x64dbg', ...params }, 2000));
  return { mgr, reverse, ghidra, debug, calls, run };
}

// Reverse and Ghidra have different static queues but share one debugger target.
{
  const h = harness(), firstNative = deferred();
  h.mgr.rpc = async (selected, method, params) => {
    h.calls.push({ selected, method, params }); return firstNative.promise;
  };
  const args = { op: 'step', expected_stop_seq: 1, expected_run_id: 'run-fixture' };
  const first = h.run(h.reverse, args), second = h.run(h.ghidra, args);
  const stale = assert.rejects(second, /pause changed/);
  await until(() => h.calls.length === 1);
  assert.equal(h.calls[0].selected, h.debug);
  await turn(); assert.equal(h.calls.length, 1, 'second engine must not enter native RPC concurrently');
  firstNative.resolve(paused(2)); await first; await stale;
  assert.equal(h.calls.length, 1); assert.equal(h.debug.runtime.stopSeq, 2);
  assert.equal(h.mgr.debugQueues.size, 0);
  console.log('PASS shared-target queue: one same-stop step executes; the other is rejected as stale');
}

{
  const h = harness(null), firstNative = deferred();
  h.mgr.rpc = async (selected, method, params) => {
    h.calls.push({ selected, method, params });
    assert.equal(selected.controlOwner, 'agent-one', 'owner must be reserved before entering native RPC');
    return firstNative.promise;
  };
  const first = h.run(h.reverse, { op: 'step' });
  await until(() => h.calls.length === 1);
  const second = h.run(h.ghidra, { op: 'step' }, 'agent-two');
  let secondSettled = false;
  second.then(() => { secondSettled = true; }, () => { secondSettled = true; });
  const denied = assert.rejects(second, /controlled by another agent/);
  await turn(); await turn();
  assert.equal(secondSettled, false, 'owner validation must run after the predecessor completes');
  assert.equal(h.debug.controlOwner, 'agent-one');
  firstNative.resolve(paused(2)); await first; await denied;
  assert.equal(h.calls.length, 1); assert.equal(h.debug.controlOwner, 'agent-one');
  console.log('PASS owner reservation: acquired before RPC and checked inside the shared queue');
}

{
  const h = harness(), priorTerminations = terminated.length;
  await assert.rejects(h.mgr.scope.run({ agentId: 'agent-two' }, () => h.mgr.close(target, false, 'reverse')), /controlled by another agent/);
  assert.equal(h.calls.length, 0); assert.equal(terminated.length, priorTerminations);
  assert.equal(h.mgr.sessions.size, 3); assert.equal(h.reverse.closing, undefined);
  console.log('PASS close guard: another owner cannot close the static target and kill its debugger');
}

// Execute actual open() to install its real worker exit handler on a stub process.
{
  const mgr = new WorkerManager(cfg), child = new EventEmitter();
  child.pid = 123456; child.exitCode = null;
  child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = new EventEmitter();
  child.stdin.write = () => true;
  mgr.spawnWorker = () => { setImmediate(() => child.stdout.emit('data', Buffer.from('{"ig5":"ready","capabilities":["open","dbg","close"]}\n'))); return child; };
  mgr.rpc = async (_session, method) => { assert.equal(method, 'open'); return { ok: true }; };
  await mgr.open(target, false, { engine: 'x64dbg', internal: true });
  const session = mgr.get(target, 'x64dbg');
  session.runtime = paused(); session.controlOwner = 'agent-one'; mgr.debugOwners.set(targetKey, 'x64dbg');
  child.exitCode = 7; child.emit('exit', 7);
  assert.equal(mgr.get(target, 'x64dbg'), undefined); assert.equal(mgr.debugOwners.has(targetKey), false);
  assert.equal(session.runtime, null); assert.equal(session.controlOwner, null);
  assert.equal(mgr.projects.closed.includes(session.attachmentId), true);
  console.log('PASS worker exit: the actual exit handler clears debugger lease, owner and runtime');
}

{
  const h = harness(), runningNative = deferred();
  h.mgr.rpc = async (selected, method, params) => {
    h.calls.push({ selected, method, params });
    if (params.op === 'cont') return runningNative.promise;
    assert.equal(params.op, 'suspend', 'cancelled queued register write must never reach native RPC');
    setImmediate(() => runningNative.resolve(paused(2)));
    return { ...paused(2), op: 'suspend' };
  };
  const running = h.run(h.reverse, { op: 'cont' });
  await until(() => h.calls.length === 1);
  assert.equal(h.debug.runtime.state, 'running');
  const controller = new AbortController();
  const queued = h.run(h.ghidra, { op: 'setreg', reg: 'rax', value: '0x99' }, 'agent-one', controller.signal);
  const skipped = assert.rejects(queued, /cancelled before execution/);
  controller.abort();
  const suspend = await h.run(h.ghidra, { op: 'suspend' });
  assert.equal(suspend.state, 'suspended');
  await running; await skipped;
  assert.deepEqual(h.calls.map(c => c.params.op), ['cont', 'suspend']);
  assert.equal(h.debug.runtime.stopSeq, 2); assert.equal(h.mgr.debugQueues.size, 0);
  console.log('PASS priority control: suspend bypasses pending cont; an aborted normal write never executes');
}

{
  const h = harness(); h.debug.runtime.previousRegisters = { rax: 'stale' };
  h.mgr.rpc = async () => ({ ...paused(3), ok: false, event: null, eventName: 'history-gap',
    historyGap: { droppedCount: 10 }, cacheInvalidated: true, registers: { rax: 'fresh' } });
  const result = await h.run(h.reverse, { op: 'regs' });
  assert.equal(result.ok, false); assert.equal(h.debug.runtime.previousRegisters, undefined);
  assert.equal(h.debug.runtime.registers.rax, 'fresh'); assert.equal(h.debug.runtime.stopSeq, 3);
  assert.equal(terminated.includes(h.debug.proc), false);
  console.log('PASS history gap: stale context is removed, fresh stop evidence retained, owner process preserved');
}

console.log('=== DEBUG HOST QUEUE REGRESSIONS PASSED (6 scenarios, no native process) ===');
