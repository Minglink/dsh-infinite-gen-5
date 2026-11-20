// Actual loopback delivery through the owned proxy, then an offline correlation with the
// saved bytes. No engine is opened and the delivered fixture is never executed.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { apply } from '../index.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-correlate-runtime-'));
const sourceRoot = fs.realpathSync(new URL('..', import.meta.url));
const reportDir = process.env.IG5_CORRELATE_REPORT_DIR || path.join(os.homedir(), '.dsh', 'ig5', 'artifacts', 'capture-v110');
const reportPath = path.join(reportDir, `correlate-runtime-${randomUUID()}.json`);
const fixture = buildPE64Fixture(1);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const sourceFiles = ['index.js', 'capture_tools.js', 'source/traffic_correlate.js', 'scripts/test_capture_correlate_runtime.mjs'];
const sourceHashes = Object.fromEntries(sourceFiles.map(file => [file, hash(fs.readFileSync(path.join(sourceRoot, file)))]));
const definitions = new Map(), events = new Map(), effects = [], approvals = [];
const checks = [], agent = { id: 'capture-correlate-runtime-test' };
let sequence = 0, requests = 0, failure, cleaned = false, actualNetwork = false, engineOpened = false;
let stageReached = 'setup';
const ctx = {
  tools: { register(def) { definitions.set(def.name, def); return () => definitions.delete(def.name); } },
  on(name, fn) { events.set(name, fn); return () => events.delete(name); },
  get(name) { if (name === 'approval') return { request: async request => { approvals.push(request.toolName); return 'allowed-once'; } }; },
  inject(names, fn) { if (names.includes('webServer')) fn({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(fn) { const dispose = fn(); if (typeof dispose === 'function') effects.push(dispose); },
};
const call = async (name, args) => {
  const execution = { agent, callId: 'correlate-runtime-' + (++sequence), signal: new AbortController().signal };
  const gate = await events.get('tools/pre-execute')({ name, arguments: args, ...execution }, async () => ({ kind: 'allow' }));
  assert.equal(gate.kind, 'allow');
  return definitions.get(name).execute(args, execution);
};
const pass = (label, evidence) => { checks.push({ label, evidence }); console.log('PASS', label); };
const origin = http.createServer((req, res) => {
  requests++;
  res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(delivered.length) });
  res.end(delivered);
});
let delivered;
try {
  await new Promise(resolve => origin.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + origin.address().port;
  const endpoint = `${base}/net/beacon`;
  // A real loader ignores trailing bytes; the appended block gives the sample literal
  // endpoint/API content to correlate with what the proxy actually observed.
  delivered = Buffer.concat([fixture.image, Buffer.from(`\0${endpoint}\0IG5-Correlate/1.0\0WinHttpOpen\0`)]);
  apply(ctx, { artifactDir: path.join(scratch, 'artifacts'), projectRoot: path.join(scratch, 'projects'),
    toolset: 'full', reverseProvider: 'bundled', defaultEngine: 'reverse', backgroundOpen: false,
    requestTimeoutMs: 120000, openTimeoutMs: 180000 });
  assert.equal(definitions.size, 44);
  const session = await call('ig5_capture_control', { action: 'start', scope: [base], port: 0 });
  const response = await new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port: session.port, path: `${base}/net/beacon?token=fixture-secret`,
      headers: { 'user-agent': 'IG5-Correlate/1.0', host: '127.0.0.1:' + origin.address().port } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('error', reject);
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
  assert.deepEqual(response, delivered);
  actualNetwork = true; stageReached = 'http-delivery';
  await call('ig5_capture_control', { action: 'stop', session_id: session.session_id });
  const history = await call('ig5_capture', { action: 'list', session_id: session.session_id });
  assert.equal(history.items.length, 1);
  const identity = { id: history.items[0].id, session_id: session.session_id, body: 'response' };
  const sample = await call('ig5_capture', { action: 'materialize', ...identity });
  assert.equal(sample.sha256, hash(delivered)); assert.equal(sample.executed, false);
  assert.deepEqual(fs.readFileSync(sample.path), delivered);
  stageReached = 'materialized';

  const result = await call('ig5_capture', { action: 'correlate', ...identity, sample: { path: sample.path, sha256: sample.sha256 } });
  assert.equal(result.schema, 'ig5.trafficCorrespondence.v1'); assert.equal(result.executed, false);
  assert.equal(result.networkRequests, 0); assert.equal(result.sample.sha256, sample.sha256);
  const bodyLink = result.links.find(row => row.kind === 'body-bytes-identity');
  assert.equal(bodyLink.direction, 'response'); assert.equal(bodyLink.evidenceLevel, 'E1'); assert.equal(bodyLink.captureComplete, true);
  const host = result.links.find(row => row.kind === 'endpoint-host');
  assert.equal(host.matches[0].offset, delivered.indexOf('127.0.0.1'));
  const endpointLink = result.links.find(row => row.kind === 'endpoint-origin');
  assert(endpointLink.matches.some(row => row.offset === delivered.indexOf(base)));
  assert(result.links.some(row => row.kind === 'endpoint-path' && row.needle === '/net/beacon'));
  assert(result.links.some(row => row.kind === 'request-header-value' && row.needle === 'IG5-Correlate/1.0'));
  assert(result.links.some(row => row.kind === 'communication-api-literal' && row.needle === 'winhttpopen'));
  const text = JSON.stringify(result);
  assert(!text.includes('fixture-secret')); assert(!text.includes('token='));
  assert.equal((await call('ig5_status', {})).sessions.length, 0, 'Correlation must not open an engine');
  assert.equal(requests, 1, 'Correlation must not contact the server again');
  assert.deepEqual(approvals, ['ig5_capture_control', 'ig5_capture_control']);
  assert.deepEqual(fs.readFileSync(sample.path), delivered, 'Correlation must not modify saved bytes');
  stageReached = 'correlated';
  pass('Loopback delivery, saved sample and offline correlation agree without an engine or a second request', {
    captureId: identity.id, sha256: sample.sha256, bytes: delivered.length,
    links: result.links.map(row => ({ kind: row.kind, label: row.label, level: row.evidenceLevel })),
    unmatched: result.unmatched.map(row => row.needle), executed: false, engineOpened,
  });
  for (const file of sourceFiles) assert.equal(hash(fs.readFileSync(path.join(sourceRoot, file))), sourceHashes[file], 'Source changed during acceptance: ' + file);
} catch (error) {
  failure = { name: error.name, code: error.code || null, message: error.message }; console.error(error);
} finally {
  try {
    for (const dispose of effects.reverse()) await dispose();
    await new Promise(resolve => origin.close(resolve));
    const relative = path.relative(fs.realpathSync(os.tmpdir()), fs.realpathSync(scratch));
    assert(relative.startsWith('ig5-correlate-runtime-') && !relative.includes(path.sep));
    fs.rmSync(scratch, { recursive: true, force: true }); cleaned = true;
  } catch (error) { failure ||= { message: error.message }; console.error(error); }
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, JSON.stringify({ at: new Date().toISOString(), ok: !failure, sourceRoot, checks, failure,
    requests, approvals, cleaned, actualNetwork, engineOpened, stageReached, targetExecuted: false, desktopGui: false, sourceHashes,
  }, null, 2));
  console.log('Evidence:', reportPath);
  if (failure) process.exitCode = 1;
}
