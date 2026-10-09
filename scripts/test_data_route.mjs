// Exercise the actual route with a mocked Cordis context and worker manager.
// No engine process, database, or user artifact is opened or changed.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { spawn as nativeSpawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { defineAdvancedTools } from '../advanced_tools.js';
import { defineIntegrationTools } from '../integration_tools.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { engineId } from '../engine_runtime.js';
import { spawnWorker, attachWorker, doctorWorker } from '../source/worker_transport.js';
import { fileURLToPath } from 'node:url';

const source = fs.readFileSync(new URL('../index.js', import.meta.url), 'utf8');
const cfg = {
  idaDir: 'C:\\engine\\IDA Professional 9.2',
  pythonExe: 'C:\\engine\\IDA Professional 9.2\\python311\\python.exe',
  artifactDir: 'C:\\unused-test-artifacts',
  maxSessions: 3,
  requestTimeoutMs: 240_000,
  openTimeoutMs: 1_800_000,
  reverseAvailable: true,
  defaultEngine: 'reverse',
  projectRoot: 'C:\\unused-test-projects',
};
const errorStart = source.indexOf('function publicEngineError(');
const errorEnd = source.indexOf('// ── Worker 池', errorStart);
assert.ok(errorStart >= 0 && errorEnd > errorStart, 'error redaction must be present');
const publicEngineError = vm.runInNewContext(source.slice(errorStart, errorEnd) + '\npublicEngineError;');
const diagnostic = `license unavailable: ${cfg.pythonExe}; ${cfg.idaDir}; IDA Professional 9.2; idalib 9.2; Hex-Rays decompiler v9.2`;
function assertRedacted(message) {
  assert.match(message, /license unavailable/);
  assert.doesNotMatch(message, /\bIDA\b|idalib|Hex-Rays|9\.2|C:[\\/]+engine/i);
  return true;
}
assertRedacted(publicEngineError(diagnostic, cfg));
assertRedacted(publicEngineError(diagnostic.replace(/\\/g, '/').toUpperCase().replace('LICENSE UNAVAILABLE', 'license unavailable'), cfg));
assertRedacted(publicEngineError(JSON.stringify(diagnostic), cfg));
assert.equal(publicEngineError('Python exception: missing pythoncom', { pythonExe: 'python' }), 'Python exception: missing pythoncom');
const start = source.indexOf('function installDataRoute(');
const end = source.indexOf('function formatProgress(', start);
assert.ok(start >= 0 && end > start, 'data route implementation must be present');
const installDataRoute = vm.runInNewContext(
  source.slice(start, end) + '\ninstallDataRoute;',
  { URL, path, fs: { existsSync: () => false }, publicEngineError, diagAppend() {} },
);

function makeRoute(active = true) {
  const target = 'C:\\fixtures\\sample.exe';
  const session = { target, alive: true };
  const calls = [];
  let spawns = 0;
  let handler;
  const mgr = {
    sessions: new Map(active ? [[target.toLowerCase(), session]] : []),
    sessionKey: (value) => value.toLowerCase(),
    alive: (value) => value?.alive === true,
    spawnWorker() { spawns++; throw new Error('data route must never spawn a worker'); },
    async rpc(value, method, params, timeout) {
      calls.push({ target: value.target, method, params, timeout });
      return { method };
    },
  };
  const ctx = {
    inject(_services, callback) {
      callback({ webServer: { register(spec) {
        assert.equal(spec.path, '/ig5-data');
        handler = spec.handler;
        return () => {};
      } } });
    },
  };
  installDataRoute(ctx, mgr, cfg);
  assert.equal(typeof handler, 'function');
  async function request(query = '', method = 'GET') {
    return new Promise((resolve, reject) => {
      let status;
      try {
        handler({ method, url: '/ig5-data' + query }, {
          writeHead(code) { status = code; },
          end(body) { resolve({ status, body: JSON.parse(body) }); },
        });
      } catch (error) { reject(error); }
    });
  }
  return { target, session, calls, request, mgr, spawnCount: () => spawns };
}

const route = makeRoute();
for (const type of [
  'undo', 'dbg', 'open', 'rename', 'patch', 'comment', 'analyze', 'set_type',
  'idapython', 'doctor', 'ping', 'fileoffset', 'unknown', '__proto__', 'constructor',
  'switch_repair', 'emulate', 'semantics', 'bindiff',
]) {
  const result = await route.request('?type=' + encodeURIComponent(type));
  assert.equal(result.status, 400, type + ' must be rejected');
  assert.match(result.body.error, /read-only/);
}
for (const action of ['define', 'apply', 'unknown']) {
  const result = await route.request('?type=struct&action=' + action + '&decl=struct+X%7Bint+x%3B%7D%3B&ea=0x1000');
  assert.equal(result.status, 400, 'struct ' + action + ' must be rejected');
}
assert.equal((await route.request('?type=funcs', 'POST')).status, 405);
assert.equal(route.calls.length, 0, 'rejected requests must not enter any worker');

for (const type of [
  'funcs', 'decompile', 'xrefs', 'strings', 'listing', 'calls', 'bytes',
  'search', 'scan', 'cfg', 'slice', 'fingerprint', 'disasm', 'stack', 'switches', 'vtables', 'microcode',
]) {
  const result = await route.request('?type=' + type + '&target=' + encodeURIComponent(route.target) + '&ea=0x1000');
  assert.equal(result.status, 200);
  assert.equal(result.body.target, route.target);
  assert.equal(result.body.data.method, type);
  assert.equal(route.calls.at(-1).method, type);
  assert.equal(route.calls.at(-1).timeout, 60_000);
}
await route.request('?type=funcs&offset=5&limit=12&filter=main');
assert.deepEqual(JSON.parse(JSON.stringify(route.calls.at(-1).params)), { offset: 5, limit: 12, filter: 'main', user_only: false });
for (const [query, expected] of [['&user_only=true', true], ['&user_only=false', false], ['', false]]) {
  await route.request('?type=funcs' + query);
  assert.equal(route.calls.at(-1).params.user_only, expected);
}
await route.request('?type=struct');
assert.equal(route.calls.at(-1).params.action, 'list');
await route.request('?type=microcode&action=optimize&rules=xor-self&maturity=generated');
assert.equal(route.calls.at(-1).params.action, 'inspect', 'HTTP view cannot install optimization filters');
assert.equal('rules' in route.calls.at(-1).params, false);
await route.request('?type=struct&action=get&name=Packet&decl=ignored&ea=0x1000');
assert.equal(route.calls.at(-1).params.action, 'get');
assert.equal(route.calls.at(-1).params.name, 'Packet');
assert.equal('decl' in route.calls.at(-1).params, false);
assert.equal('ea' in route.calls.at(-1).params, false);
await route.request();
assert.equal(route.calls.at(-1).method, 'funcs', 'default route remains funcs');
const beforeApprovals = route.calls.length;
assert.deepEqual((await route.request('?type=approvals')).body.data, { rows: [], total: 0, offset: 0, limit: 30 });
assert.equal(route.calls.length, beforeApprovals, 'approvals are read locally');

const inactive = makeRoute(false);
assert.equal((await inactive.request('?type=funcs')).body.error, 'no open target');
assert.equal((await inactive.request('?type=struct&action=define')).status, 400);
assert.equal(inactive.calls.length, 0);
assert.equal(inactive.spawnCount(), 0);
const before = route.calls.length;
assert.equal((await route.request('?type=funcs&target=C%3A%5Cmissing.exe')).body.error, 'no open target');
route.session.alive = false;
assert.equal((await route.request('?type=funcs')).body.error, 'no open target');
assert.equal(route.calls.length, before, 'missing/dead sessions must not enter a worker');
assert.equal(route.spawnCount(), 0);
for (const synchronous of [false, true]) {
  const failing = makeRoute();
  failing.mgr.rpc = synchronous
    ? () => { throw new Error(diagnostic); }
    : async () => { throw new Error(diagnostic); };
  const result = await failing.request('?type=funcs');
  assert.equal(result.status, 200);
  assertRedacted(result.body.error);
}

// Evaluate the actual tool definitions with a fake child process; doctor must
// filter the worker result before both execute() and output.render() expose it.
const toolsStart = source.indexOf('function textRender(');
const toolsEnd = source.indexOf('// ── ig5dash', toolsStart);
assert.ok(toolsStart >= 0 && toolsEnd > toolsStart, 'tool definitions must be present');
const defineIg5Tools = vm.runInNewContext(
  source.slice(toolsStart, toolsEnd) + '\ndefineIg5Tools;',
  { path, fs, publicEngineError, defineAdvancedTools, defineIntegrationTools, doctorWorker,
    IG5_WRITE_TOOLS: vm.runInNewContext(source.slice(source.indexOf('const IG5_WRITE_TOOLS'), source.indexOf('function installApprovalGate')) + '\nIG5_WRITE_TOOLS;'),
    PLUGIN_ID: 'dsh-infinite-gen-5', PLUGIN_VERSION: '1.0.0', setTimeout, clearTimeout },
);
let killed = false;
let doctorMode = 'success';
const mockManager = {
  status: () => [],
  spawnWorker() {
    if (doctorMode === 'spawnThrow') throw new Error(diagnostic);
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stdin = { write(line) {
      assert.equal(JSON.parse(line).method, 'doctor');
      if (doctorMode === 'workerError') {
        queueMicrotask(() => child.stdout.emit('data', JSON.stringify({ id: 0, error: diagnostic }) + '\n'));
        return;
      }
      if (doctorMode === 'spawnError') {
        queueMicrotask(() => child.emit('error', new Error(diagnostic)));
        return;
      }
      queueMicrotask(() => child.stdout.emit('data', JSON.stringify({ id: 0, result: {
        python: '3.11.9',
        idaDir: cfg.idaDir,
        pythonExe: cfg.pythonExe,
        idaVersion: [9, 2, 0],
        idalib: 'loaded',
        extra: 'IDA Professional 9.2',
        caps: { 'ida_auto.plan_and_wait': true, 'ida_auto.auto_wait': true, 'ida_auto.auto_make_code': false },
      } }) + '\n'));
    } };
    child.kill = () => { killed = true; };
    return child;
  },
};
const definitions = defineIg5Tools({}, mockManager, cfg);
assert.equal(definitions.length, 36);
for (const definition of definitions) {
  assert.doesNotMatch(definition.description, /\bIDA\b|IDAPython|idalib|Hex-Rays|ida_[a-z]/i);
}
for (const name of ['ig5_profile', 'ig5_status', 'ig5_doctor']) {
  const definition = definitions.find((value) => value.name === name);
  const value = await definition.execute({});
  const serialized = JSON.stringify(value);
  assert.doesNotMatch(serialized, /\bIDA\b|idaVersion|idalib|9\.2|pythonExe|idaDir/);
  assert.doesNotMatch(JSON.stringify(definition.output.render({}, value)), /\bIDA\b|idaVersion|idalib|9\.2|pythonExe|idaDir/);
  if (name === 'ig5_profile') {
    assert.equal(value.engineConfigured, true);
    assert.equal(value.pythonConfigured, true);
  }
  if (name === 'ig5_doctor') {
    assert.equal(value.runtimeReady, true);
    assert.deepEqual(JSON.parse(JSON.stringify(value.caps)), { planAndWait: true, wait: true, makeCode: false });
  }
}
assert.equal(killed, true, 'doctor must recycle its temporary worker');
for (const mode of ['workerError', 'spawnThrow', 'spawnError']) {
  doctorMode = mode;
  await assert.rejects(definitions.find((value) => value.name === 'ig5_doctor').execute({}), (error) => assertRedacted(error.message));
}
const workerStart = source.indexOf('class WorkerManager');
const workerEnd = source.indexOf('// ── 诊断回路', workerStart);
let workerMode = 'success';
let releaseOpening, openingArrived, writesDuringOpening = 0;
const workerContext = {
  AsyncLocalStorage, engineId, attachWorker, doctorWorker,
  HERE: fileURLToPath(new URL('..', import.meta.url)),
  spawnWorker: (cfg, engine, root, options) => spawnWorker(cfg, engine, root, { ...options, spawnProcess: (...args) => workerContext.spawn(...args) }),
  terminateTree: (proc) => proc?.kill(),
  ProjectStore: class {
    open() { return { projectId: 'p', artifactId: 'a', sha256: 'h' }; }
    attachEngine() { return { attachmentId: 'at', dbRevision: 0 }; }
    closeAttachment() {}
  },
  path, process, publicEngineError, WORKER: 'mock-worker.py', setTimeout, clearTimeout,
  spawn() {
    if (workerMode === 'spawnThrow') throw new Error(diagnostic);
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.exitCode = null;
    child.kill = () => { child.exitCode = 1; };
    child.stdin = { write(line) {
      const request = JSON.parse(line);
      if (workerMode === 'delayedOpen') {
        if (request.method === 'open') {
          releaseOpening = () => child.stdout.emit('data', JSON.stringify({ id: request.id, result: { n_funcs: 1, bits: 64 } }) + '\n');
          openingArrived?.();
        } else {
          writesDuringOpening++;
          queueMicrotask(() => child.stdout.emit('data', JSON.stringify({ id: request.id, result: { ok: true } }) + '\n'));
        }
        return;
      }
      if (workerMode === 'runtimeExit' && request.method !== 'open') {
        queueMicrotask(() => {
          child.stderr.emit('data', diagnostic);
          child.exitCode = 3;
          child.emit('exit', 3);
        });
        return;
      }
      queueMicrotask(() => child.stdout.emit('data', JSON.stringify(request.method === 'open'
        ? { id: request.id, result: { target: 'C:\\fixtures\\sample.exe', n_funcs: 1, bits: 64 } }
        : workerMode === 'partialCommit'
          ? { id: request.id, error: { message: 'Persistence failed after database save', code: 'partial_commit', committed: true, saved: true,
            recoveryRequired: true, journalId: 'journal-test', revision: 1, durableRevision: 1, stage: 'journal' } }
        : workerMode === 'metadataFailure'
          ? { id: request.id, result: { ok: true } }
          : { id: request.id, error: 'Traceback\n' + diagnostic }) + '\n'));
    } };
    setImmediate(() => {
      if (workerMode === 'startupError') child.emit('error', new Error(diagnostic));
      else if (workerMode === 'startupExit' || workerMode === 'startupTimeout') {
        child.stderr.emit('data', diagnostic);
        if (workerMode === 'startupExit') { child.exitCode = 1; child.emit('exit', 1); }
      } else child.stdout.emit('data', '{"ig5":"ready"}\n');
    });
    return child;
  },
};
const WorkerManager = vm.runInNewContext(source.slice(workerStart, workerEnd) + '\nWorkerManager;', workerContext);
assert.doesNotMatch(JSON.stringify(new WorkerManager(cfg).snapshot()), /\bIDA\b|9\.2|pythonExe|idaDir/);
const manager = new WorkerManager(cfg);
await manager.open('C:\\fixtures\\sample.exe');
await assert.rejects(manager.rpc(manager.get('C:\\fixtures\\sample.exe'), 'decompile', {}), (error) => assertRedacted(error.message));
workerMode = 'runtimeExit';
await assert.rejects(manager.rpc(manager.get('C:\\fixtures\\sample.exe'), 'microcode', {}), (error) => {
  assert.match(error.message, /exited code=3/);
  return assertRedacted(error.message);
});
assert.equal(manager.sessions.size, 0, 'native worker crash must reject pending requests and remove the dead session');
manager.killSession(manager.sessionKey('C:\\fixtures\\sample.exe'));
workerMode = 'success';
const metadataFailure = new WorkerManager(cfg);
await metadataFailure.open('C:\\fixtures\\sample.exe');
metadataFailure.projects.bumpRevision = () => { throw new Error('STORE_BUSY'); };
workerMode = 'metadataFailure';
await assert.rejects(metadataFailure.rpc(metadataFailure.get('C:\\fixtures\\sample.exe'), 'comment', {}), /completed but revision metadata could not be committed/);
assert.equal(metadataFailure.sessions.size, 0, 'committed mutation plus metadata failure must reject and recycle instead of crashing the host or reusing a stale revision');
for (const mode of ['spawnThrow', 'startupError', 'startupExit', 'startupTimeout']) {
  workerMode = mode;
  if (mode === 'startupTimeout') workerContext.setTimeout = (callback) => { setImmediate(callback); return 1; };
  const failing = new WorkerManager(cfg);
  await assert.rejects(failing.open('C:\\fixtures\\sample.exe'), (error) => assertRedacted(error.message));
  for (const key of failing.sessions.keys()) failing.killSession(key);
}
workerContext.setTimeout = setTimeout;
workerMode = 'success';
const partialCommit = new WorkerManager(cfg);
await partialCommit.open('C:\\fixtures\\sample.exe');
partialCommit.projects.bumpRevision = () => ({ dbRevision: 1 });
const partialSession = partialCommit.get('C:\\fixtures\\sample.exe');
partialSession.cache.set('previous', 'stale');
workerMode = 'partialCommit';
await assert.rejects(partialCommit.rpc(partialSession, 'rename', {}), (error) => {
  assert.equal(error.code, 'partial_commit'); assert.equal(error.committed, true); assert.equal(error.saved, true);
  assert.equal(error.recoveryRequired, true); assert.equal(error.journalId, 'journal-test');
  assert.equal(error.durableRevision, 1); assert.equal(error.stage, 'journal'); return true;
});
assert.equal(partialSession.dbRevision, 1); assert.equal(partialSession.cache.size, 0);
partialCommit.killSession(partialSession.key);
workerMode = 'delayedOpen';
const openingManager = new WorkerManager(cfg);
openingManager.projects.attachEngine = () => ({ attachmentId: 'historical', dbRevision: 7 });
openingManager.projects.bumpRevision = () => ({ dbRevision: 8 });
const openArrived = new Promise((resolve) => { openingArrived = resolve; });
const opening = openingManager.open('C:\\fixtures\\sample.exe');
await openArrived;
assert.equal(typeof releaseOpening, 'function');
const openingSession = openingManager.get('C:\\fixtures\\sample.exe');
const earlyWrite = openingManager.rpc(openingSession, 'comment', {});
await new Promise(setImmediate);
assert.equal(writesDuringOpening, 0, 'no operation may run between transport readiness and database attachment');
releaseOpening(); await opening; await earlyWrite;
assert.equal(openingSession.dbRevision, 8, 'the first write must increment the attached historical revision');
openingManager.killSession(openingSession.key);
workerContext.spawn = nativeSpawn;
const missingRuntime = new WorkerManager({ ...cfg, pythonExe: path.join(process.env.TEMP, 'ig5-deliberately-missing-runtime.exe') });
await assert.rejects(missingRuntime.open('C:\\fixtures\\sample.exe'), /ENOENT/);
assert.equal(missingRuntime.sessions.size, 0, 'early spawn failure must be caught rather than become an uncaught error');

console.log('IG5 data route and metadata: approval isolation, user_only, inactive sessions, and success/failure Reverse redaction passed.');
