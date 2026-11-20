import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { once } from 'node:events';
import { test } from 'node:test';
import { CaptureService } from '../source/capture_service.js';
import { createAnalysisService } from '../analysis_tools.js';
import { defineCaptureTools } from '../capture_tools.js';

class FakeProxy {
  static created = 0;
  constructor(options) { this.options = options; this.running = false; FakeProxy.created++; }
  async start(options) { this.running = true; this.current = options; return this.status(); }
  status() { return { running: this.running, port: this.current?.port || 23456, tlsInterceptEnabled: this.current?.tls === true }; }
  async stop() { this.running = false; }
  emit(exchange) { return this.options.onExchange(exchange); }
}
async function fixture(options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-capture-service-'));
  const cfg = { artifactDir: root, capture: options };
  const mgr = { checkCancelled() {} };
  mgr.analysis = createAnalysisService(mgr, cfg);
  const service = new CaptureService(mgr, cfg, { CaptureProxy: FakeProxy });
  return { root, cfg, mgr, service, async dispose() { await service.dispose(); await mgr.analysis.dispose(); fs.rmSync(root, { recursive: true, force: true }); } };
}
const exchange = (url, additions = {}) => ({ method: 'POST', url, startedAt: new Date().toISOString(), endedAt: new Date().toISOString(), protocol: 'http', encrypted: false, complete: true,
  request: { headers: { authorization: 'Bearer secret-credential', cookie: 'sid=secret-cookie', 'content-type': 'application/octet-stream' }, body: Buffer.from([0, 255, 1, 128]), bodyBytes: 4, truncated: false },
  response: { statusCode: 200, headers: { 'content-type': 'text/html', 'set-cookie': ['session=private; HttpOnly'] }, body: Buffer.from('hello'), bodyBytes: 5, truncated: false }, ...additions });
async function seed(f, url = 'http://127.0.0.1:3000/api?token=secret-query', additions) {
  if (!f.service.status().running) await f.service.control({ action: 'start', scope: [new URL(url).origin] });
  const id = await f.service.proxy.emit(exchange(url, additions)); await f.service.queue; return id;
}

test('capture status/list are dormant reads; tool shapes isolate read and control', async () => {
  const f = await fixture(); const before = FakeProxy.created;
  try {
    assert.equal(f.service.status().running, false); assert.equal(f.service.list().total, 0); assert.equal(FakeProxy.created, before);
    f.mgr.capture = f.service;
    const tools = defineCaptureTools({}, f.mgr, f.cfg);
    assert.deepEqual(tools.map(t => t.name), ['ig5_capture', 'ig5_capture_control', 'ig5_app_observe']);
    assert.equal(tools[0].execute({ action: 'status' }).running, false);
    assert.throws(() => tools[0].execute({ action: 'start', scope: ['http://localhost'] }), /Capture action/);
    assert.equal(FakeProxy.created, before);
    for (const tool of tools) assert.deepEqual(tool.parameters.required, ['action']);
  } finally { await f.dispose(); }
});

test('start validates exact origins, limits and cancellation before proxy creation', async () => {
  const f = await fixture(); const before = FakeProxy.created;
  try {
    for (const scope of [[], ['http://a.test/path'], ['https://u:p@a.test'], ['file:///tmp'], ['http://a.test?token=1']]) await assert.rejects(f.service.control({ action: 'start', scope }), /scope|origin/);
    await assert.rejects(f.service.control({ action: 'start', scope: ['http://localhost'], port: -1 }), /port/);
    const cancel = new AbortController(); cancel.abort();
    await assert.rejects(f.service.control({ action: 'start', scope: ['http://localhost'] }, { signal: cancel.signal }), /cancelled/);
    assert.equal(FakeProxy.created, before);
  } finally { await f.dispose(); }
});

test('exact binary body refs, redacted default headers and query, producer chain and passive review', async () => {
  const f = await fixture();
  try {
    const id = await seed(f), detail = f.service.get(id), view = JSON.stringify(detail);
    assert.equal(detail.request.body.previewHex, '00ff0180');
    for (const secret of ['secret-credential', 'secret-cookie', 'secret-query', 'session=private']) assert(!view.includes(secret));
    assert.equal(detail.headersRedacted, true); assert.equal(detail.response.body.previewText, 'hello');
    const out = f.service.export({ id, body: 'request' });
    assert.equal(out.exactCapturedBytes, true); assert.equal(out.complete, true);
    assert.deepEqual(f.mgr.analysis.artifacts.read(out.input.ref).data, Buffer.from([0, 255, 1, 128]));
    const analysis = await f.mgr.analysis.execute('protocol', { action: 'inspect', input: out.input });
    assert.equal(analysis.input.origin.derivedFrom.resultId, id); assert.equal(analysis.input.origin.derivedFrom.kind, 'capture');
    const review = f.service.review({ id }); assert.equal(review.networkRequests, 0);
    assert(review.observations.some(row => row.code === 'COOKIE_ATTRIBUTE_NOT_OBSERVED'));
    assert(!JSON.stringify(review).includes('private'));
  } finally { await f.dispose(); }
});

test('capture records survive stop/reopen and validate producer body hashes', async () => {
  const f = await fixture(); let reopened;
  try {
    const id = await seed(f); await f.service.control({ action: 'stop' });
    reopened = new CaptureService(f.mgr, f.cfg, { CaptureProxy: FakeProxy });
    assert.equal(reopened.list().items[0].id, id); assert.equal(reopened.get(id).response.body.previewText, 'hello');
    const ref = reopened.export({ id }).body.ref;
    fs.writeFileSync(path.join(f.mgr.analysis.artifacts.root, 'blobs', `${ref.slice(7)}.bin`), 'modified');
    assert.throws(() => reopened.export({ id }), /hash/);
  } finally { await reopened?.dispose(); await f.dispose(); }
});

test('long URL summary has a byte budget and history can always reopen', async () => {
  const f = await fixture(); let reopened;
  try {
    const id = await seed(f, 'http://127.0.0.1:3000/' + 'x'.repeat(12000));
    assert.equal(f.service.list().items[0].urlTruncated, true);
    assert(fs.statSync(path.join(f.service.directory, id + '.json')).size < 8192);
    reopened = new CaptureService(f.mgr, f.cfg, { CaptureProxy: FakeProxy });
    assert.equal(reopened.list().items[0].id, id);
    assert.equal(reopened.get(id).url.length, 12022);
  } finally { await reopened?.dispose(); await f.dispose(); }
});

test('lower new-capture budgets do not invalidate historical records', async () => {
  const f = await fixture(); let reopened;
  try {
    const first = await seed(f); await seed(f);
    reopened = new CaptureService(f.mgr, { ...f.cfg, capture: { maxBodyBytes: 1, maxEntries: 1, maxStoredBytes: 1 } }, { CaptureProxy: FakeProxy });
    assert.equal(reopened.status().storageFull, true); assert.equal(reopened.list().total, 2);
    assert.equal(reopened.get(first).response.body.previewText, 'hello');
    assert.deepEqual(f.mgr.analysis.artifacts.read(reopened.export({ id: first }).input.ref).data, Buffer.from('hello'));
  } finally { await reopened?.dispose(); await f.dispose(); }
});

test('WebSocket frame metadata and binary direction survive persistence, export and replay guards', async () => {
  const f = await fixture();
  try {
    const id = await seed(f, undefined, { method: 'WEBSOCKET', protocol: 'websocket', websocket: { direction: 'client_to_server', opcode: 2, fin: false, masked: true, compressed: true, payloadEncoding: 'compressed-undecoded', reassembled: false } });
    const detail = f.service.get(id); assert.equal(detail.websocket.compressed, true); assert.equal(detail.websocket.fin, false);
    const exported = f.service.export({ id }); assert.equal(exported.direction, 'request');
    assert.deepEqual(f.mgr.analysis.artifacts.read(exported.input.ref).data, Buffer.from([0, 255, 1, 128]));
    assert.match(exported.representation, /not a reassembled/);
    await assert.rejects(f.service.control({ action: 'replay', id, session_id: f.service.status().session_id }), /plaintext HTTP/);
  } finally { await f.dispose(); }
});

test('truncated captured bytes export honestly and cannot be replayed as complete requests', async () => {
  const f = await fixture();
  try {
    const id = await seed(f, undefined, { request: { headers: {}, body: Buffer.from('part'), bodyBytes: 20, truncated: true } });
    const out = f.service.export({ id, body: 'request' });
    assert.equal(out.capturedBytes, 4); assert.equal(out.observedBytes, 20); assert.equal(out.complete, false); assert.equal(out.truncated, true);
    await assert.rejects(f.service.control({ action: 'replay', id, session_id: f.service.status().session_id }), /complete captured/);
  } finally { await f.dispose(); }
});

test('encrypted CONNECT never presents an HTTP plaintext export', async () => {
  const f = await fixture();
  try {
    const id = await seed(f, 'https://127.0.0.1:444/', { method: 'CONNECT', encrypted: true, tunnel: true, protocol: 'connect' });
    assert.throws(() => f.service.export({ id }), /encrypted CONNECT/);
    assert.throws(() => f.service.review({ id }), /encrypted tunnel/);
  } finally { await f.dispose(); }
});

test('sessions isolate reads and stale replay/stop, no implicit old capture attachment', async () => {
  const f = await fixture();
  try {
    const id = await seed(f), old = f.service.status().session_id;
    await f.service.control({ action: 'stop', session_id: old });
    await f.service.control({ action: 'start', scope: ['http://127.0.0.1:3001'] });
    assert.equal(f.service.list().total, 0); assert.equal(f.service.list({ session_id: old }).total, 1);
    assert.throws(() => f.service.get(id, { session_id: f.service.status().session_id }), /another session/);
    await assert.rejects(f.service.control({ action: 'stop', session_id: old }), /changed/);
    await assert.rejects(f.service.control({ action: 'replay', id, session_id: old }), /active capture/);
  } finally { await f.dispose(); }
});

test('storage and pagination are bounded, dropped records are explicit', async () => {
  const f = await fixture({ maxEntries: 2, maxStoredBytes: 9 });
  try {
    await seed(f); const dropped = await f.service.proxy.emit(exchange('http://127.0.0.1:3000/other')); await f.service.queue;
    assert.equal(dropped, null); assert.equal(f.service.status().storedBytes, 9); assert.equal(f.service.status().dropped, 1); assert.equal(f.service.status().storageFull, true);
    assert.throws(() => f.service.list({ limit: 101 }), /limit/); assert.throws(() => f.service.list({ offset: -1 }), /offset/);
    assert.equal(f.service.list({ limit: 1 }).hasMore, false);
  } finally { await f.dispose(); }
});

test('replay sends exact binary body once, allows bounded edits on same origin and never follows redirect', async () => {
  const seen = [];
  const server = http.createServer((req, res) => { const chunks = []; req.on('data', b => chunks.push(b)); req.on('end', () => { seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) }); res.writeHead(302, { location: 'http://127.0.0.1:1/must-not-follow' }); res.end('redirect'); }); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const f = await fixture();
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const id = await seed(f, `${origin}/request`), session_id = f.service.status().session_id;
    const result = await f.service.control({ action: 'replay', id, session_id });
    assert.equal(result.statusCode, 302); assert.equal(result.followedRedirects, false); assert.equal(result.saved, true);
    assert.equal(seen.length, 1); assert.deepEqual(seen[0].body, Buffer.from([0, 255, 1, 128])); assert.equal(seen[0].headers.authorization, 'Bearer secret-credential');
    const edited = await f.service.control({ action: 'replay', id, session_id, request: { method: 'PUT', path: '/changed?x=1', headers: { 'x-fixture': 'edited' }, body: { encoding: 'hex', data: '0001ff' } } });
    assert.equal(edited.saved, true); assert.equal(seen.length, 2); assert.equal(seen[1].method, 'PUT'); assert.equal(seen[1].url, '/changed?x=1'); assert.deepEqual(seen[1].body, Buffer.from([0, 1, 255]));
    for (const candidate of ['//example.com/', '/\\example.com/', '/safe\r\nHost:evil']) await assert.rejects(f.service.control({ action: 'replay', id, session_id, request: { path: candidate } }), /Replay path/);
    assert.equal(seen.length, 2);
  } finally { await f.dispose(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

test('replay cancellation and plugin disposal abort network work without losing outcome uncertainty', async () => {
  let observed;
  const received = new Promise(resolve => { observed = resolve; });
  const server = http.createServer((_req, _res) => observed());
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const f = await fixture();
  try {
    const id = await seed(f, `http://127.0.0.1:${server.address().port}/slow`), session_id = f.service.status().session_id;
    const pending = f.service.control({ action: 'replay', id, session_id });
    const assertion = assert.rejects(pending, error => error.name === 'AbortError' && error.outcomeUnknown === true);
    await received; await f.service.dispose(); await assertion;
    assert.equal(f.service.status().running, false);
  } finally { await f.dispose(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

test('captured request trailers are retained by replay and response trailers by storage', async () => {
  let receivedTrailers;
  const upstream = http.createServer((req, res) => { req.resume(); req.on('end', () => { receivedTrailers = req.trailers; res.writeHead(200, { 'transfer-encoding': 'chunked', trailer: 'x-response-end' }); res.write('body'); res.addTrailers({ 'x-response-end': 'retained' }); res.end(); }); });
  upstream.listen(0, '127.0.0.1'); await once(upstream, 'listening');
  const f = await fixture();
  try {
    const url = `http://127.0.0.1:${upstream.address().port}/trailers`;
    const id = await seed(f, url, { request: { ...exchange(url).request, trailers: { 'x-request-end': 'retained' } } });
    const replay = await f.service.control({ action: 'replay', id, session_id: f.service.status().session_id });
    assert.equal(receivedTrailers['x-request-end'], 'retained');
    assert.equal(f.service.get(replay.id).response.trailers['x-response-end'], 'retained');
  } finally { await f.dispose(); upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve)); }
});

test('real streaming proxy persists exact observed exchange and exports it into analysis refs', async () => {
  const payload = Buffer.from([0, 127, 128, 255]);
  const upstream = http.createServer((req, res) => { const chunks = []; req.on('data', b => chunks.push(b)); req.on('end', () => { assert.deepEqual(Buffer.concat(chunks), payload); res.writeHead(201, { 'content-type': 'application/octet-stream' }); res.end(Buffer.from([255, 128, 127, 0])); }); });
  upstream.listen(0, '127.0.0.1'); await once(upstream, 'listening');
  const f = await fixture(), live = new CaptureService(f.mgr, f.cfg);
  try {
    const origin = `http://127.0.0.1:${upstream.address().port}`;
    const started = await live.control({ action: 'start', scope: [origin], port: 0 });
    await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: started.port, path: origin + '/binary', method: 'POST', headers: { host: new URL(origin).host, 'content-length': String(payload.length) } }, res => { const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('end', () => { try { assert.equal(res.statusCode, 201); assert.deepEqual(Buffer.concat(chunks), Buffer.from([255, 128, 127, 0])); resolve(); } catch (e) { reject(e); } }); });
      req.on('error', reject); req.end(payload);
    });
    await live.control({ action: 'stop' });
    assert.equal(live.status().persistenceErrors, 0); assert.equal(live.list().items.length, 1);
    const row = live.list().items[0], output = live.export({ id: row.id });
    assert.equal(row.complete, true); assert.deepEqual(f.mgr.analysis.artifacts.read(output.input.ref).data, Buffer.from([255, 128, 127, 0]));
  } finally { await live.dispose(); await f.dispose(); upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve)); }
});
