import assert from 'node:assert/strict';
import { EventEmitter, getEventListeners } from 'node:events';
import { spawn } from 'node:child_process';
import { WorkerClient, WORKER_RECEIVE_LIMITS } from '../source/worker_transport.js';

let count = 0;
const pass = label => { count++; console.log('PASS', label); };
function fixture(limits) {
  const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = new EventEmitter(); child.stdin.write = () => true;
  child.exitCode = null; child.pid = 12345;
  const session = { seq: 0, engine: 'fixture', pending: new Map() }; let terminated = 0, notified = 0;
  const client = new WorkerClient(child, { limits, terminate() { terminated++; child.emit('exit', 1); } });
  client.configure({ session, onMessage() {}, onExit() { notified++; } });
  return { child, client, session, counts: () => ({ terminated, notified }) };
}
{
  const bytes = Buffer.from(JSON.stringify({ id: 1, result: { text: '中文🧪' } }) + '\n');
  const h = fixture({ lineBytes: bytes.length - 1 }); const received = [];
  h.client.configure({ onMessage: message => received.push(message) });
  for (const byte of bytes) h.child.stdout.emit('data', Buffer.of(byte));
  assert.equal(received[0].result.text, '中文🧪'); assert.equal(h.client.failure, null); assert.equal(h.client.buffer.length, 0);
  assert.deepEqual(h.counts(), { terminated: 0, notified: 0 }); h.client.dispose(); pass('split UTF-8 accepts the exact byte boundary without character-count errors');
}
{
  const h = fixture({ lineBytes: 32 }), controller = new AbortController();
  const readiness = assert.rejects(h.client.waitReady(5000), { code: 'WORKER_PROTOCOL_LIMIT' });
  const pending = assert.rejects(h.client.request(h.session, 'echo', {}, { timeoutMs: 5000, signal: controller.signal }), { code: 'WORKER_PROTOCOL_LIMIT' });
  h.child.stdout.emit('data', Buffer.alloc(33, 0x78)); await Promise.all([readiness, pending]);
  assert.equal(h.client.failure.limit, 'lineBytes'); assert.equal(h.client.buffer.length, 0); assert.equal(h.client.backlog.length, 0); assert.equal(h.session.pending.size, 0);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  h.child.stdout.emit('data', Buffer.alloc(500)); h.child.emit('exit', 2); h.client.configure({ onExit() { assert.fail('failure must be delivered only once'); } });
  assert.deepEqual(h.counts(), { terminated: 1, notified: 1 }); h.client.dispose(); pass('oversized unterminated lines fail once, reject every promise and release buffers/listeners');
}
{
  const h = fixture({ lineBytes: 64, bufferBytes: 32 }); h.child.stdout.emit('data', Buffer.alloc(20, 0x78)); h.child.stdout.emit('data', Buffer.alloc(13, 0x78));
  assert.equal(h.client.failure.limit, 'bufferBytes'); assert.equal(h.client.buffer.length, 0); assert.deepEqual(h.counts(), { terminated: 1, notified: 1 }); h.client.dispose(); pass('cumulative raw UTF-8 buffering has a separate hard limit');
}
for (const kind of ['backlogMessages', 'backlogBytes']) {
  const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = new EventEmitter(); let stopped = 0, notified = 0;
  const line = Buffer.from('{"ig5":"progress","payload":{"text":"中文"}}\n');
  const limits = kind === 'backlogMessages' ? { backlogMessages: 2 } : { backlogBytes: line.length * 2 };
  const client = new WorkerClient(child, { limits, terminate() { stopped++; } });
  child.stdout.emit('data', Buffer.concat([line, line, line]));
  assert.equal(client.failure.code, 'WORKER_PROTOCOL_LIMIT'); assert.equal(client.failure.limit, kind); assert.equal(client.backlogBytes, 0); assert.equal(client.backlog.length, 0); assert.equal(client.buffer.length, 0);
  client.configure({ onExit() { notified++; } }); client.configure({ onExit() { notified++; } });
  assert.equal(stopped, 1); assert.equal(notified, 1); await assert.rejects(client.waitReady(100), { code: 'WORKER_PROTOCOL_LIMIT' }); client.dispose(); pass(kind + ' before configure is bounded and cleans up without replaying messages');
}
{
  const h = fixture(); h.child.stdout.emit('data', Buffer.from([0xff, 0x0a]));
  assert.equal(h.client.failure.limit, 'invalidUtf8'); assert.equal(h.client.buffer.length, 0); h.client.dispose(); pass('invalid UTF-8 fails closed without exposing the raw line');
}
{
  const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = new EventEmitter(); let killed = 0;
  const client = new WorkerClient(child, { limits: { lineBytes: 1 }, terminate() { killed++; }, formatError() { throw new Error('formatter fixture'); } });
  client.configure({ onExit() { throw new Error('cleanup fixture'); } }); child.stdout.emit('data', 'xx');
  assert.equal(client.failure.code, 'WORKER_PROTOCOL_LIMIT'); assert.match(client.failure.cleanupError.message, /cleanup fixture/); assert.equal(killed, 1); client.dispose(); pass('formatter and exit callback failures retain evidence without crashing stdout handling');
}
function childProcess(code) { return spawn(process.execPath, ['-e', code], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }); }
async function exited(child) {
  if (child.exitCode !== null || child.signalCode) return;
  await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('Owned fixture child did not exit')), 10000); child.once('exit', () => { clearTimeout(timer); resolve(); }); child.once('error', error => { clearTimeout(timer); reject(error); }); });
}
{
  const companion = childProcess('setInterval(()=>{},1000)');
  const child = childProcess('setTimeout(()=>process.stdout.write("x".repeat(100)),100);setInterval(()=>{},1000)');
  const client = new WorkerClient(child, { limits: { lineBytes: 64 } });
  try {
    await exited(child); assert.equal(client.failure.code, 'WORKER_PROTOCOL_LIMIT'); assert.equal(client.buffer.length, 0); assert.equal(companion.exitCode, null);
  } finally { client.dispose(); if (child.exitCode === null && !child.signalCode) child.kill(); companion.kill(); await Promise.all([exited(child), exited(companion)]); }
  pass('real overflowing subprocess is recycled while an independent companion remains alive');
}
{
  const child = childProcess('setTimeout(()=>{for(let i=0;i<3;i++)console.log(JSON.stringify({ig5:"progress",payload:{i}}))},100);setInterval(()=>{},1000)');
  const client = new WorkerClient(child, { limits: { backlogMessages: 2 } });
  try { await exited(child); assert.equal(client.failure.limit, 'backlogMessages'); assert.equal(client.backlog.length, 0); assert.equal(client.backlogBytes, 0); }
  finally { client.dispose(); if (child.exitCode === null && !child.signalCode) child.kill(); await exited(child); }
  pass('real preconfigure output flood is recycled with no retained backlog');
}
assert.equal(WORKER_RECEIVE_LIMITS.lineBytes, 16 * 1024 * 1024);
console.log(`Worker receive-budget regression: ${count} groups passed.`);
