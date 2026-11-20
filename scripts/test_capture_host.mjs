import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { apply } from '../index.js';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-capture-host-'));
const definitions = new Map(), events = new Map(), routes = new Map(), effects = [];
let outcome = 'rejected', approvalCount = 0, requests = 0;
const ctx = {
  tools: { register(def) { definitions.set(def.name, def); return () => definitions.delete(def.name); } },
  on(name, fn) { events.set(name, fn); },
  get(name) { if (name === 'approval') return { request: async () => { approvalCount++; return outcome; } }; },
  inject(names, fn) { if (names.includes('webServer')) fn({ webServer: { register(spec) { routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } } }); return { dispose() {} }; },
  effect(fn) { const dispose = fn(); if (typeof dispose === 'function') effects.push(dispose); },
};
const origin = http.createServer((req, res) => { requests++; res.setHeader('content-type', 'application/octet-stream'); res.end(Buffer.from('01020304', 'hex')); });
const call = async (name, args) => {
  const execution = { agent: { id: 'capture-host-test' }, callId: 'capture-test-' + approvalCount, signal: new AbortController().signal };
  const gate = await events.get('tools/pre-execute')({ name, arguments: args, ...execution }, async () => ({ kind: 'allow' }));
  if (gate.kind !== 'allow') return { denied: true };
  return definitions.get(name).execute(args, execution);
};
const route = async query => new Promise(resolve => routes.get('/ig5-data')({ method: 'GET', url: '/ig5-data?' + query }, { writeHead() {}, end(body) { resolve(JSON.parse(body)); } }));
try {
  await new Promise(resolve => origin.listen(0, '127.0.0.1', resolve));
  apply(ctx, { artifactDir: root, toolset: 'full' });
  assert.equal(definitions.size, 44);
  const scope = ['http://127.0.0.1:' + origin.address().port];
  assert.deepEqual(await call('ig5_capture_control', { action: 'start', scope }), { denied: true });
  assert.equal((await route('type=capture_status')).data.running, false);
  assert.equal(requests, 0);
  outcome = 'allowed-once';
  const started = await call('ig5_capture_control', { action: 'start', scope, port: 0 });
  assert(started.running); assert(started.port > 0);
  const payload = await new Promise((resolve, reject) => http.get({ hostname: '127.0.0.1', port: started.port, path: scope[0] + '/binary', headers: { host: '127.0.0.1:' + origin.address().port } }, res => { const parts = []; res.on('data', chunk => parts.push(chunk)); res.on('end', () => resolve(Buffer.concat(parts))); }).on('error', reject));
  assert.equal(payload.toString('hex'), '01020304');
  // Stop drains the persistence queue while preserving the captured records.
  await call('ig5_capture_control', { action: 'stop', session_id: started.session_id });
  const list = await call('ig5_capture', { action: 'list', session_id: started.session_id });
  assert.equal(list.items.length, 1);
  const id = list.items[0].id;
  const exported = await call('ig5_capture', { action: 'export', id, body: 'response', session_id: started.session_id });
  assert(exported.input?.ref, JSON.stringify(exported));
  const analyzed = await call('ig5_protocol', { action: 'inspect', input: exported.input });
  assert(analyzed.result_id);
  const inspected = await call('ig5_capture', { action: 'inspect_payload', id, body: 'response', session_id: started.session_id });
  assert.equal(inspected.canMaterialize, true); assert.equal(inspected.executed, false);
  assert.equal(inspected.sha256, exported.body.sha256);
  const materialized = await call('ig5_capture', { action: 'materialize', id, body: 'response', session_id: started.session_id });
  assert.equal(materialized.sha256, exported.body.sha256); assert.equal(materialized.executed, false);
  assert.equal(fs.readFileSync(materialized.path).toString('hex'), '01020304');
  assert.equal(materialized.provenance.captureId, id);
  assert.equal(materialized.provenance.sessionId, started.session_id);
  assert.equal((await call('ig5_status', {})).sessions.length, 0);
  const extractedAnalysis = await call('ig5_protocol', { action: 'inspect', input: materialized.input });
  assert(extractedAnalysis.result_id);
  await assert.rejects(call('ig5_capture', { action: 'materialize', id, session_id: '00000000-0000-0000-0000-000000000000' }));
  const detail = await route('type=capture_detail&id=' + id + '&session_id=' + started.session_id);
  assert.equal(detail.data.id, id);
  const invalid = await route('type=capture_detail&id=' + id + '&session_id=00000000-0000-0000-0000-000000000000');
  assert(invalid.error);
  assert((await route('type=materialize&id=' + id)).error, 'GET must not expose file extraction');
  assert.equal(requests, 1, 'read routes, export and offline analysis cannot send extra requests');
  await events.get('tools/post-execute')({ name: 'ig5_capture_control', arguments: { action: 'replay', request: { path: '/?token=SECRET_PATH', headers: { authorization: 'SECRET_HEADER' }, body: { encoding: 'hex', data: 'SECRET_BODY' } } } }, { value: { sent: true } }, async () => ({}));
  const audit = fs.readFileSync(path.join(root, 'approvals.jsonl'), 'utf8');
  assert(!audit.includes('SECRET_'), 'Capture replay edit secrets must not enter the approval audit');
  console.log('PASS actual IG5 gate -> native HTTP proxy -> saved SHA body -> protocol analysis / inspected immutable sample; read-only routes and Core/Full catalog 40');
} finally {
  for (const dispose of effects.reverse()) await dispose();
  await new Promise(resolve => origin.close(resolve));
  fs.rmSync(root, { recursive: true, force: true });
}
