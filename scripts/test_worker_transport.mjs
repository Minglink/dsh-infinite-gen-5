import assert from 'node:assert/strict';
import { EventEmitter, getEventListeners } from 'node:events';
import { spawn } from 'node:child_process';
import { WorkerClient, attachWorker, doctorWorker, workerLaunch, spawnWorker } from '../source/worker_transport.js';
import { terminateTree } from '../engine_runtime.js';

const pass = label => console.log('PASS', label);
function fake() {
  const child = new EventEmitter();
  child.pid = 12345; child.exitCode = null;
  child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = new EventEmitter();
  child.sent = []; child.stdin.write = line => { child.sent.push(JSON.parse(line)); return true; };
  return child;
}
function harness(engine = 'ghidra') {
  const child = fake(), session = { engine, pending: new Map(), seq: 0 };
  const client = attachWorker(child, { session, onMessage(message) {
    if (message.ig5 === 'ready') { session.ready = true; session.capabilities = message.capabilities; return; }
    const pending = session.pending.get(message.id);
    if (!pending) return;
    if (message.ig5 === 'progress') { pending.onProgress?.(message.payload); return; }
    session.pending.delete(message.id); clearTimeout(pending.timer); pending.removeAbort?.();
    if (message.error) pending.reject(Object.assign(new Error(message.error.message), message.error));
    else pending.resolve({ ...message.result, ...(pending.cancelled ? { cancellationRequested: true } : {}) });
  } });
  const response = (id, result) => child.stdout.emit('data', Buffer.from(JSON.stringify({ id, result }) + '\n'));
  return { child, session, client, response };
}

{
  const child = fake(); const client = new WorkerClient(child); const seen = [];
  child.stdout.emit('data', Buffer.from('engine startup noise\nnull\n[]\n{"ig5":"ready","capabilities":["open"]}\n'));
  const line = Buffer.from('{"id":7,"result":{"name":"中文🧪"}}\n');
  for (const byte of line) child.stdout.emit('data', Buffer.of(byte));
  client.configure({ onMessage: message => seen.push(message) });
  await client.waitReady(100);
  assert.equal(seen.length, 2); assert.equal(seen[0].ig5, 'ready'); assert.equal(seen[1].result.name, '中文🧪');
  client.dispose(); pass('early ready frames are retained and split UTF-8 JSONL is decoded without corruption');
}
{
  const child = spawnWorker({ reverseAvailable: true, pythonExe: 'missing', idaDir: 'licensed' }, 'reverse', '/plugin', {
    spawnProcess() { const child = fake(); queueMicrotask(() => child.emit('error', Object.assign(new Error('missing runtime'), { code: 'ENOENT' }))); return child; },
  });
  await new Promise(resolve => queueMicrotask(resolve));
  const client = attachWorker(child);
  await assert.rejects(client.waitReady(100), /missing runtime/);
  client.dispose(); pass('spawn errors before admission are caught and fail readiness');
}
{
  const h = harness(); const signal = new AbortController(); signal.abort();
  await assert.rejects(h.client.request(h.session, 'comment', {}, { signal: signal.signal, timeoutMs: 100 }), { code: 'ABORT_ERR' });
  assert.equal(h.child.sent.length, 0); assert.equal(h.session.pending.size, 0);
  h.client.dispose(); pass('already-cancelled requests never enter the subprocess');
}
{
  const h = harness(); const signal = new AbortController();
  const progress = [];
  const result = h.client.request(h.session, 'decompile', {}, { timeoutMs: 1000, signal: signal.signal, onProgress: value => progress.push(value) });
  h.child.stdout.emit('data', '{"ig5":"progress","id":1,"payload":{"stage":"working"}}\n');
  signal.abort(); await assert.rejects(result, { code: 'ABORT_ERR' });
  assert.equal(h.session.pending.size, 1, 'in-flight read must drain its response rather than discard protocol state');
  h.response(1, { code: 'discarded' });
  assert.equal(h.session.pending.size, 0); assert.equal(getEventListeners(signal.signal, 'abort').length, 0);
  assert.deepEqual(progress, [{ stage: 'working' }]); h.client.dispose();
  pass('static read cancellation discards the result and cleans listeners after response');
}
{
  const h = harness(); const signal = new AbortController();
  const result = h.client.request(h.session, 'patch', {}, { timeoutMs: 1000, signal: signal.signal, mutation: true });
  signal.abort(); assert.equal(h.session.pending.get(1).cancelled, true);
  h.response(1, { ok: false, committed: true, saved: true });
  assert.deepEqual(await result, { ok: false, committed: true, saved: true, cancellationRequested: true });
  assert.equal(getEventListeners(signal.signal, 'abort').length, 0); h.client.dispose();
  pass('running static mutations retain commit evidence when cancellation is requested');
}
{
  const h = harness('x64dbg'); const signal = new AbortController();
  const result = h.client.request(h.session, 'dbg', { op: 'cont' }, { timeoutMs: 1000, signal: signal.signal });
  signal.abort(); assert.deepEqual(h.child.sent[1], { id: 2, method: 'cancel', params: { requestId: 1 } });
  h.child.stdout.emit('data', '{"id":1,"error":{"message":"cancelled","code":"cancelled","cleanedUp":true}}\n');
  await assert.rejects(result, { code: 'cancelled', cleanedUp: true });
  assert.equal(h.session.pending.size, 0); h.client.dispose();
  pass('debug cancellation targets the exact running request and preserves adapter error metadata');
}
{
  const h = harness(); const signal = new AbortController(); let recycled = 0;
  const result = h.client.request(h.session, 'open', {}, { timeoutMs: 5, signal: signal.signal, onTimeout: () => recycled++ });
  await assert.rejects(result, /worker rpc 超时/);
  assert.equal(recycled, 1); assert.equal(h.session.pending.size, 0); assert.equal(getEventListeners(signal.signal, 'abort').length, 0);
  h.client.dispose(); pass('RPC timeout recycles only its worker and removes pending cancellation hooks');
}
for (const failure of ['exit', 'stdin']) {
  const h = harness(); const readiness = h.client.waitReady(1000);
  const result = h.client.request(h.session, 'open', {}, { timeoutMs: 1000 });
  const readyReject = assert.rejects(readiness, failure === 'exit' ? /exited code=3/ : /broken stdin/);
  const requestReject = assert.rejects(result, failure === 'exit' ? /exited code=3/ : /broken stdin/);
  if (failure === 'exit') { h.child.exitCode = 3; h.child.emit('exit', 3); }
  else h.child.stdin.emit('error', new Error('broken stdin'));
  await Promise.all([readyReject, requestReject]); assert.equal(h.session.pending.size, 0);
  h.client.dispose(); pass(failure + ' failure settles readiness and every pending request');
}
{
  const child = fake(); child.stdin.write = line => {
    const request = JSON.parse(line);
    queueMicrotask(() => child.stdout.emit('data', JSON.stringify({ id: request.id, result: { ok: true, capabilities: ['open'] } }) + '\n'));
  };
  const result = await doctorWorker(child, { timeoutMs: 1000 }); assert.equal(result.ok, true);
  assert.equal(child.__ig5Client.disposed, true); pass('doctor shares JSONL/request cleanup without opening a target');
}
{
  const cfg = { host: { platform: 'linux' }, projectRoot: '/data/projects', home: '/data',
    ghidra: { available: true, pythonExe: '/plugin/runtimes/linux-arm64/ghidra/python/bin/python3',
      ghidraHome: '/plugin/ghidra', javaHome: '/plugin/jdk' } };
  const launch = workerLaunch(cfg, 'ghidra', '/plugin');
  assert.equal(launch.options.detached, true); assert.deepEqual(launch.args.slice(0, 2), ['-I', '-B']);
  assert.equal(launch.options.env.IG5_GHIDRA_PROJECT_ROOT, '/data/projects/ghidra-databases');
  assert.equal(launch.executable, cfg.ghidra.pythonExe); assert.equal(launch.options.env.PYTHONIOENCODING, 'utf-8');
  const groups = []; const proc = { pid: 12345, exitCode: null, __ig5ProcessGroup: true, kill() { assert.fail('only the owned group should be signalled'); } };
  terminateTree(proc, { platform: 'linux', kill: (...args) => groups.push(args) });
  assert.deepEqual(groups, [[-12345, 'SIGKILL']]);
  const windows = fake(); let args;
  terminateTree(windows, { platform: 'win32', spawnProcess(file, argv) { assert.equal(file, 'taskkill.exe'); args = argv; return new EventEmitter(); } });
  assert.deepEqual(args, ['/PID', '12345', '/T', '/F']);
  pass('Linux workers use an owned process group; Windows tree cleanup retains its original contract');
}
{
  // A real local child confirms the transport is not only mocked. It runs no sample/native engine.
  const code = `const r=require('node:readline').createInterface({input:process.stdin});
    console.log(JSON.stringify({ig5:'ready',capabilities:['echo']}));
    r.on('line',line=>{const v=JSON.parse(line);console.log(JSON.stringify({id:v.id,result:v.params}));r.close();});`;
  const child = spawn(process.execPath, ['-e', code], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  const session = { engine: 'fixture', seq: 0, pending: new Map() };
  const client = attachWorker(child, { session, onMessage(message) {
    const pending = session.pending.get(message.id); if (!pending) return;
    session.pending.delete(message.id); clearTimeout(pending.timer); pending.resolve(message.result);
  } });
  await client.waitReady(5000);
  const result = await client.request(session, 'echo', { text: '中文🧪' }, { timeoutMs: 5000 });
  assert.deepEqual(result, { text: '中文🧪' }); child.stdin.end();
  if (child.exitCode === null) await new Promise(resolve => child.once('exit', resolve));
  client.dispose(); pass('actual local subprocess roundtrip preserves JSONL/Unicode and exits cleanly');
}
console.log('Worker transport regression tests passed.');
