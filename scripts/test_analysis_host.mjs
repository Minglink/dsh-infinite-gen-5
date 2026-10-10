// Real Node data workers with isolated artifacts; no engine/sample execution.
import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createCipheriv } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { gzipSync } from 'node:zlib';
import { apply } from '../index.js';
import { compactAnalysis, createAnalysisService } from '../analysis_tools.js';
import { AnalysisArtifacts, decodeInline, hashBytes } from '../source/analysis_artifacts.js';
import { AnalysisJobs } from '../source/analysis_jobs.js';

const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-analysis-host-'));
const artifactRoot = path.join(scratch, 'artifacts');
const outcomes = [];
async function test(name, run) {
  try { await run(); outcomes.push({ name, ok: true }); console.log('PASS', name); }
  catch (error) { outcomes.push({ name, ok: false, error: error.stack }); console.error('FAIL', name, error.stack); }
}
const rejects = (run, code) => assert.rejects(run, error => error.code === code);
const inline = bytes => ({ encoding: 'hex', data: bytes.toString('hex') });

function host() {
  const tools = new Map(), routes = new Map(), hooks = new Map(), effects = [];
  const services = {
    tools: { register(definition) { assert(!tools.has(definition.name)); tools.set(definition.name, definition); return () => tools.delete(definition.name); } },
    webServer: { register(spec) { assert(!routes.has(spec.path)); routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } },
  };
  const context = {
    tools: services.tools,
    get: name => services[name],
    on(name, callback) { hooks.set(name, callback); },
    effect(body) { const remove = body(); if (typeof remove === 'function') effects.push(remove); },
    inject(names, callback) {
      let remove;
      if (names.every(name => services[name])) remove = callback({ ...context, ...services });
      let live = true;
      const fiber = { async dispose() { if (live) { live = false; await remove?.(); } } };
      effects.push(() => fiber.dispose()); return fiber;
    },
  };
  apply(context, { artifactDir: artifactRoot, projectRoot: path.join(scratch, 'projects'), toolset: 'full', reverse: false });
  return {
    tools, hooks, routes,
    call(name, args = {}, execution = {}) { assert(tools.has(name), name); return tools.get(name).execute(args, execution); },
    async dispose() { for (const remove of effects.reverse()) await remove(); },
  };
}
const fixtureHost = host();
const artifacts = new AnalysisArtifacts(path.join(artifactRoot, 'analysis-data'));
const plain = Buffer.from('00070148454c4c4f21', 'hex'); // len=7, type=1, HELLO!
const compressed = gzipSync(plain);
const key = Buffer.from('31067d2c8f59403ac4b1ed768a52399dc21563a427bf902dd17e483c069a55e8', 'hex');
const iv = Buffer.from('2971d3c54f906882ee650a1b', 'hex');
const aad = Buffer.from('IG5 generated fixture');
const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad);
const encrypted = Buffer.concat([cipher.update(compressed), cipher.final()]);
const tag = cipher.getAuthTag();
const ciphertextPath = path.join(scratch, 'generated ciphertext.bin'); fs.writeFileSync(ciphertextPath, encrypted);
const schema = { name: 'generated-message', fields: [
  { name: 'length', offset: 0, type: 'u16', endian: 'big' },
  { name: 'message_type', offset: 2, type: 'u8' },
  { name: 'message', offset: 3, type: 'utf8', length: 6 },
] };
const framing = { type: 'length-prefix', size: 2, endian: 'big', headerLength: 2 };
let decrypted, expanded, verified, decoded;

function assertNoRawParameters(value) {
  const text = JSON.stringify(value);
  for (const parameter of [key, iv, aad, tag]) {
    assert(!text.includes(parameter.toString('hex')), 'recipe parameter leaked as hex');
    assert(!text.includes(parameter.toString('base64')), 'recipe parameter leaked as base64');
  }
}

await test('Full38 → Core8 → Full38 and 12 original approval tools', async () => {
  assert.equal(fixtureHost.tools.size, 38);
  const core = await fixtureHost.call('ig5_profile', { toolset: 'core' });
  assert.equal(core.activeTools.length, 8); assert.equal(fixtureHost.tools.size, 8);
  assert(!fixtureHost.tools.has('ig5_crypto') && !fixtureHost.tools.has('ig5_protocol'));
  await fixtureHost.call('ig5_profile', { toolset: 'full' }); assert.equal(fixtureHost.tools.size, 38);
  const writeNames = ['rename', 'patch_bytes', 'comment', 'analyze', 'set_type', 'undo', 'run_idapython', 'dbg', 'struct', 'switch_repair', 'emulate', 'sync'].map(name => 'ig5_' + name);
  const pre = fixtureHost.hooks.get('tools/pre-execute');
  for (const name of writeNames) {
    let dispatched = false;
    const decision = await pre({ name, arguments: {} }, () => { dispatched = true; return 'continued'; });
    assert.equal(decision.kind, 'deny', 'No agent/approval service must deny ' + name);
    assert.equal(dispatched, false, 'Denied ' + name + ' must not delegate dispatch');
  }
  for (const name of ['ig5_crypto', 'ig5_protocol']) assert.equal(await pre({ name, arguments: {} }, () => 'continued'), 'continued');
});

await test('No open target: real AES-GCM → gzip → exact verification with reusable references', async () => {
  const status = await fixtureHost.call('ig5_status');
  assert.equal(status.sessions.length, 0);
  decrypted = await fixtureHost.call('ig5_crypto', { action: 'transform', input: { path: ciphertextPath },
    recipe: { kind: 'aes-gcm', key: inline(key), iv: inline(iv), tag: inline(tag), aad: inline(aad), padding: 'none' } });
  assert.equal(decrypted.value.authentication.status, 'passed');
  assert.equal(decrypted.output.sha256, hashBytes(compressed));
  assert.deepEqual(artifacts.read(decrypted.output.ref).data, compressed);
  expanded = await fixtureHost.call('ig5_crypto', { action: 'transform', input: { ref: decrypted.output.ref, result_id: decrypted.result_id }, recipe: { kind: 'gzip' } });
  assert.equal(expanded.output.sha256, hashBytes(plain));
  assert.deepEqual(artifacts.read(expanded.output.ref).data, plain);
  verified = await fixtureHost.call('ig5_crypto', { action: 'verify', input: { ref: expanded.output.ref, result_id: expanded.result_id }, expected: inline(plain) });
  assert.equal(verified.value.verification.matched, true);
  assert.equal((await fixtureHost.call('ig5_status')).sessions.length, 0);
  assert.deepEqual(fs.readFileSync(ciphertextPath), encrypted);
});

await test('Keys and AES parameters stay out of returned/saved reports', async () => {
  assert(decrypted && expanded && verified);
  for (const result of [decrypted, expanded, verified]) { assertNoRawParameters(result); assertNoRawParameters(artifacts.get(result.result_id)); }
  assert.equal(artifacts.get(decrypted.result_id).result.recipe.key_redacted, true);
});

await test('Historical result keeps input/output refs and result selection', async () => {
  assert(decrypted);
  const historical = await fixtureHost.call('ig5_crypto', { action: 'result', result_id: decrypted.result_id });
  assert.equal(historical.output.ref, decrypted.output.ref);
  assert.equal(historical.input.ref, decrypted.input.ref);
  const selected = await fixtureHost.call('ig5_crypto', { action: 'result', result_id: decrypted.result_id, select: 'authentication' });
  assert.equal(selected.value.status, 'passed');
  await rejects(() => fixtureHost.call('ig5_crypto', { action: 'result', result_id: decrypted.result_id, select: '__proto__' }), 'INVALID_INPUT');
  await rejects(() => fixtureHost.call('ig5_protocol', { action: 'result', result_id: decrypted.result_id }), 'INVALID_REF');
});

await test('Cross-lane decrypted blob → schema decode → frame refs, zero preview budget', async () => {
  assert(expanded);
  decoded = await fixtureHost.call('ig5_protocol', { action: 'decode', input: { ref: expanded.output.ref, result_id: expanded.result_id }, schema, framing, preview_limit: 0 });
  assert.equal(decoded.value.complete, true);
  assert.equal(decoded.value.frames.length, 1);
  const frame = decoded.value.frames[0];
  assert.equal(frame.fields.find(row => row.name === 'message').value, 'HELLO!');
  assert.equal(frame.fields.find(row => row.name === 'length').value, 7);
  assert.equal(frame.previewHex, '');
  assert.deepEqual(artifacts.read(frame.dataRef.ref).data, plain);
  assert(!JSON.stringify(artifacts.get(decoded.result_id).result).includes('dataHex'));
});

function capture(payload) {
  const udp = Buffer.alloc(8 + payload.length); udp.writeUInt16BE(5000, 0); udp.writeUInt16BE(5001, 2); udp.writeUInt16BE(udp.length, 4); payload.copy(udp, 8);
  const ip = Buffer.alloc(20); ip[0] = 0x45; ip.writeUInt16BE(ip.length + udp.length, 2); ip[8] = 64; ip[9] = 17;
  Buffer.from([10, 0, 0, 1]).copy(ip, 12); Buffer.from([10, 0, 0, 2]).copy(ip, 16);
  const packet = Buffer.concat([ip, udp]);
  const header = Buffer.alloc(24); header.writeUInt32LE(0xa1b2c3d4, 0); header.writeUInt16LE(2, 4); header.writeUInt16LE(4, 6); header.writeUInt32LE(65535, 16); header.writeUInt32LE(101, 20);
  const record = Buffer.alloc(16); record.writeUInt32LE(1, 0); record.writeUInt32LE(packet.length, 8); record.writeUInt32LE(packet.length, 12);
  return Buffer.concat([header, record, packet]);
}
await test('Explicit PCAP path → UDP payload blob → field decode; capture file untouched', async () => {
  const input = capture(plain), filename = path.join(scratch, 'generated capture.pcap'); fs.writeFileSync(filename, input);
  const result = await fixtureHost.call('ig5_protocol', { action: 'capture', input: { path: filename }, schema, framing });
  const datagram = result.value.flows[0].directions.flatMap(direction => direction.datagrams)[0];
  assert(datagram.dataRef?.ref); assert.deepEqual(artifacts.read(datagram.dataRef.ref).data, plain);
  const report = await fixtureHost.call('ig5_protocol', { action: 'decode', input: { ref: datagram.dataRef.ref, result_id: result.result_id }, schema, framing });
  assert.equal(report.value.frames[0].fields.find(row => row.name === 'message').value, 'HELLO!');
  assert.deepEqual(fs.readFileSync(filename), input);
});

await test('Malformed mixed input, changed blob hash and mismatched provenance ref are rejected', async () => {
  await rejects(() => fixtureHost.call('ig5_crypto', { action: 'inspect', input: { ...inline(plain), ref: 'sha256:' + 'a'.repeat(64) } }), 'INVALID_INPUT');
  const input = Buffer.from('unique hash mutation fixture'); const saved = artifacts.put(input);
  const filename = path.join(artifacts.root, 'blobs', `${saved.sha256}.bin`);
  fs.writeFileSync(filename, Buffer.alloc(input.length, 0x66));
  await rejects(() => fixtureHost.call('ig5_crypto', { action: 'inspect', input: { ref: saved.ref } }), 'ARTIFACT_CHANGED');
  fs.writeFileSync(filename, input);
  await rejects(() => fixtureHost.call('ig5_crypto', { action: 'inspect', input: { ref: saved.ref, result_id: decrypted.result_id } }), 'INVALID_REF');
});

function request(handler, query, method = 'GET') {
  return new Promise((resolve, reject) => {
    let status;
    try { handler({ method, url: '/ig5-data?' + new URLSearchParams(query) }, { writeHead(code) { status = code; }, end(body) { resolve({ status, body: JSON.parse(body) }); } }); }
    catch (error) { reject(error); }
  });
}
await test('Actual DSH read-only route lists/reads reports and rejects analysis execution over GET', async () => {
  const handler = fixtureHost.routes.get('/ig5-data'); assert.equal(typeof handler, 'function');
  const listed = await request(handler, { type: 'analyses' });
  assert.equal(listed.status, 200); assert(listed.body.data.total >= 3);
  const report = await request(handler, { type: 'analysis_result', id: decrypted.result_id });
  assert.equal(report.body.data.output.ref, decrypted.output.ref);
  for (const type of ['crypto', 'protocol', 'patch', 'patch_bytes', 'rename', 'analyze', 'emulate', 'analysis_execute']) {
    const rejected = await request(handler, { type, action: 'transform', input: 'not-executed' });
    assert.equal(rejected.status, 400); assert.match(rejected.body.error, /read-only/);
  }
  assert.equal((await request(handler, { type: 'analyses' }, 'POST')).status, 405);
  assert.equal((await fixtureHost.call('ig5_status')).sessions.length, 0);
});

function fakeManager() {
  const target = path.join(scratch, 'generated association.exe');
  const session = { target, engine: 'ghidra', dbRevision: 3, artifactId: 'fixture-artifact', attachmentId: 'fixture-attachment', sha256: 'e'.repeat(64), ready: true, data: Buffer.alloc(9000, 0x5a) };
  const mgr = {
    scope: new AsyncLocalStorage(), calls: [], locked: 0, session, queued: Promise.resolve(),
    get(target, engine) { return path.resolve(target) === session.target && engine === session.engine ? session : undefined; },
    alive(value) { return value?.ready === true; },
    checkCancelled() { if (mgr.scope.getStore()?.signal?.aborted) throw Object.assign(new Error('cancelled'), { code: 'ABORT_ERR' }); },
    evidence(value) { return { engine: value.engine, artifactId: value.artifactId, attachmentId: value.attachmentId, sha256: value.sha256, dbRevision: value.dbRevision }; },
    withSessions(values, run) {
      assert.deepEqual(values, [session]);
      const task = mgr.queued.catch(() => {}).then(async () => { mgr.checkCancelled(); mgr.locked++; try { return await run(); } finally { mgr.locked--; } });
      mgr.queued = task; return task;
    },
    async rpc(value, method, params) {
      assert.equal(mgr.locked, 1); assert.equal(value, session); assert.equal(method, 'bytes');
      const offset = Number(BigInt(params.ea) - 0x8000000000001000n);
      mgr.calls.push({ method, ...params });
      const data = session.data.subarray(offset, offset + params.size - (session.partial ? 1 : 0));
      return { ea: params.ea, hex: data.toString('hex') };
    },
  };
  return mgr;
}
const fake = fakeManager();
const service = createAnalysisService(fake, { artifactDir: path.join(scratch, 'fake-artifacts'), defaultEngine: 'ghidra' });
const sourceInput = (size = 9000, revision = fake.session.dbRevision) => ({ source: { target: fake.session.target, engine: 'ghidra', ea: '0x8000000000001000', size, expected_revision: revision } });
let associated;
await test('Static source captures only serialized read bytes with full 64-bit address/identity evidence', async () => {
  associated = await service.execute('crypto', { action: 'inspect', input: sourceInput() });
  assert.equal(fake.calls.length, 3); assert(fake.calls.every(row => row.method === 'bytes' && row.size <= 4096));
  assert.equal(fake.calls[1].ea, '0x8000000000002000');
  assert.equal(associated.association.attachmentId, fake.session.attachmentId);
  assert.equal(associated.association.dbRevision, 3);
  assert.equal(associated.input.origin.ea, '0x8000000000001000');
  assert.equal(fake.session.dbRevision, 3);
});

await test('Static source rechecks expected revision after queue admission and rejects partial reads', async () => {
  let release; fake.queued = new Promise(resolve => { release = resolve; });
  const before = fake.calls.length;
  const attempt = service.execute('crypto', { action: 'inspect', input: sourceInput(10, 3) });
  const rejected = rejects(() => attempt, 'STALE_REVISION');
  fake.session.dbRevision = 4; release(); await rejected;
  assert.equal(fake.calls.length, before);
  fake.session.partial = true;
  await rejects(() => service.execute('crypto', { action: 'inspect', input: sourceInput(10) }), 'PARTIAL_INPUT');
  fake.session.partial = false;
  assert.equal(fake.session.dbRevision, 4);
});

await test('Explicit result anchor preserves source association; unbound refs do not guess provenance', async () => {
  assert(associated);
  const bound = await service.execute('crypto', { action: 'inspect', input: { ref: associated.input.ref, result_id: associated.result_id } });
  assert.deepEqual(bound.association, associated.association);
  assert.equal(bound.input.origin.derivedFrom.resultId, associated.result_id);
  const unbound = await service.execute('crypto', { action: 'inspect', input: { ref: associated.input.ref } });
  assert.equal(unbound.association, undefined);
});

await test('Source provenance rejects conflicting target/engine and result anchors on non-ref input', async () => {
  const bound = { ref: associated.input.ref, result_id: associated.result_id };
  await rejects(() => service.execute('crypto', { action: 'inspect', input: bound, target: path.join(scratch, 'unrelated.exe') }), 'ASSOCIATION_CONFLICT');
  await rejects(() => service.execute('crypto', { action: 'inspect', input: bound, engine: 'reverse' }), 'ASSOCIATION_CONFLICT');
  await rejects(() => service.execute('crypto', { action: 'inspect', input: { ...inline(plain), result_id: associated.result_id } }), 'INVALID_INPUT');
  await rejects(() => service.execute('crypto', { action: 'inspect', input: { path: ciphertextPath, result_id: associated.result_id } }), 'INVALID_INPUT');
});

await test('Read-only report routes do not dispatch workers/RPC; target/engine scope rejects foreign result', async () => {
  const source = fs.readFileSync(new URL('../index.js', import.meta.url), 'utf8');
  const start = source.indexOf('function installDataRoute('), end = source.indexOf('function formatProgress(', start);
  const install = vm.runInNewContext(source.slice(start, end) + '\ninstallDataRoute;', { URL, path, fs, publicEngineError: error => error.message || String(error), diagAppend() {} });
  let handler, engineSpawns = 0, analysisRuns = 0, rpc = 0;
  const manager = { sessions: new Map(), alive: () => false,
    sessionKey: (target, engine) => path.resolve(target).toLowerCase() + '::' + engine,
    spawnWorker() { engineSpawns++; throw new Error('Must never spawn'); }, rpc() { rpc++; throw new Error('Must never RPC'); },
    analysis: { list: options => service.list(options), result: (id, select) => service.result(id, select), execute() { analysisRuns++; throw new Error('Must never execute'); } },
  };
  install({ inject(_names, callback) { callback({ webServer: { register(spec) { handler = spec.handler; return () => {}; } } }); } }, manager, { artifactDir: path.join(scratch, 'fake-artifacts') });
  const result = await request(handler, { type: 'analysis_result', id: associated.result_id, target: fake.session.target, engine: 'ghidra' });
  assert.equal(result.body.data.association.attachmentId, fake.session.attachmentId);
  const foreign = await request(handler, { type: 'analysis_result', id: associated.result_id, target: path.join(scratch, 'another.exe'), engine: 'ghidra' });
  assert.match(foreign.body.error, /another target/);
  const foreignEngine = await request(handler, { type: 'analysis_result', id: associated.result_id, engine: 'reverse' });
  assert.match(foreignEngine.body.error, /another engine/);
  assert.equal(engineSpawns + analysisRuns + rpc, 0);
});

await test('History pagination reads bounded metadata and never materializes large report payloads', async () => {
  const history = new AnalysisArtifacts(path.join(scratch, 'history-fixture'));
  for (let index = 0; index < 40; index++) history.save({ kind: 'protocol', action: 'decode', result: { action: 'decode', padding: 'x'.repeat(256 * 1024) } });
  const nativeRead = fs.readSync; let bytesRead = 0;
  fs.readSync = function (...args) { const count = Reflect.apply(nativeRead, this, args); bytesRead += count; return count; };
  let result;
  try { result = await history.list({ offset: 2, limit: 1 }); } finally { fs.readSync = nativeRead; }
  assert.equal(result.total, 40); assert.equal(result.items.length, 1);
  assert(bytesRead < 64 * 1024, `Metadata list read ${bytesRead} bytes`);
  assert.equal(result.metadataBytesRead, bytesRead);
  assert(!Object.hasOwn(result.items[0], 'result'));
});

await test('Report tampering and incomplete metadata commit fail closed', async () => {
  const history = new AnalysisArtifacts(path.join(scratch, 'tamper-fixture'));
  const record = history.save({ kind: 'crypto', action: 'inspect', result: { op: 'inspect', evidence: 'original' } });
  const filename = path.join(history.root, 'records', `${record.id}.json`);
  const changed = { ...record, result: { op: 'inspect', evidence: 'modified' } };
  fs.writeFileSync(filename, JSON.stringify(changed));
  assert.throws(() => history.get(record.id), error => error.code === 'ARTIFACT_CHANGED');
  const incomplete = history.save({ kind: 'protocol', action: 'inspect', result: { action: 'inspect' } });
  fs.unlinkSync(path.join(history.root, 'metadata', `${incomplete.id}.json`));
  assert.throws(() => history.get(incomplete.id), error => error.code === 'ENOENT');
});

await test('Per-record metadata is bounded and large history indexes resume without rejecting pagination', async () => {
  const history = new AnalysisArtifacts(path.join(scratch, 'metadata-budget-fixture'));
  assert.throws(() => history.save({ kind: 'crypto', action: 'inspect', result: { summary: 'x'.repeat(8192) } }), error => error.code === 'RESULT_LIMIT');
  const input = { kind: 'protocol', action: 'inspect', result: { summary: 'x'.repeat(7300) } };
  const first = history.save(input);
  const bytes = fs.statSync(path.join(history.root, 'metadata', `${first.id}.json`)).size;
  const count = Math.floor((16 * 1024 * 1024) / bytes) + 2;
  assert(count < 10000);
  for (let index = 1; index < count; index++) history.save(input);
  const cached = await history.list({ limit: 1 });
  assert.equal(cached.total, count); assert.equal(cached.items.length, 1);
  assert(cached.metadataBytesRead <= 8192);
  const reopened = new AnalysisArtifacts(history.root);
  let page = await reopened.list({ limit: 1 });
  assert.equal(page.partial, true); assert.equal(page.indexing, true);
  assert(page.indexBytesRead <= 16 * 1024 * 1024);
  page = await reopened.list({ limit: 1 });
  assert.equal(page.total, count); assert.equal(page.partial, false);
  assert.equal((await reopened.list({ limit: 1 })).cacheHit, true);
  await reopened.dispose(); await history.dispose();
});

await test('Compact model views bound serialized JSON including escaped controls, backslashes and large arrays', async () => {
  const samples = [
    { rows: Array.from({ length: 100 }, (_, index) => ({ index, text: '\0\n\r\t\\"'.repeat(5000) })) },
    { ['escaped\\\0'.repeat(900)]: '\0'.repeat(30000), rows: Array(10000).fill('\\'.repeat(3000)) },
    Array.from({ length: 200 }, () => ({ arrays: Array(100).fill('\0'.repeat(2500)) })),
  ];
  for (const sample of samples) {
    const result = compactAnalysis(sample);
    assert.equal(result.responseTruncated, true);
    assert(JSON.stringify(result.value).length <= 20000, `Escaped JSON exceeded budget: ${JSON.stringify(result.value).length}`);
  }
  const small = { message: 'small\\\0', counters: [1, 2, 3], ok: true };
  const retained = compactAnalysis(small);
  assert.equal(retained.responseTruncated, false); assert.deepEqual(JSON.parse(JSON.stringify(retained.value)), small);
});

await test('Canonical base64 accepts the full 8 MiB boundary without regex recursion and rejects padding bits', async () => {
  const data = Buffer.alloc(8 * 1024 * 1024, 0x7f);
  const decoded = decodeInline({ encoding: 'base64', data: data.toString('base64') }, data.length);
  assert.equal(decoded.data.length, data.length); assert.deepEqual(decoded.data, data);
  assert.throws(() => decodeInline({ encoding: 'base64', data: '/x==' }, 100), error => error.code === 'INVALID_INPUT');
  assert.throws(() => decodeInline({ encoding: 'base64', data: 'f39/\n' }, 100), error => error.code === 'INVALID_INPUT');
  const extra = Buffer.alloc(data.length + 1, 0x7f);
  assert.throws(() => decodeInline({ encoding: 'base64', data: extra.toString('base64') }, data.length), error => error.code === 'INPUT_LIMIT');
});

const requestInspect = { op: 'inspect', input: inline(Buffer.from('worker fixture')) };
await test('Real worker active/queued cancellation and worker error recover without touching engine state', async () => {
  const jobs = new AnalysisJobs();
  try {
    const controller = new AbortController(); const cancelled = jobs.run('crypto', requestInspect, controller.signal);
    const cancellation = rejects(() => cancelled, 'ABORT_ERR'); controller.abort(); await cancellation;
    assert((await jobs.run('crypto', requestInspect)).result.analysis);
    const first = jobs.run('crypto', requestInspect); const queuedController = new AbortController();
    const queued = jobs.run('crypto', requestInspect, queuedController.signal); const rejected = rejects(() => queued, 'ABORT_ERR'); queuedController.abort();
    await rejected; await first;
    await rejects(() => jobs.run('unknown', requestInspect), 'ANALYSIS_FAILED');
    assert.equal((await jobs.run('crypto', requestInspect)).result.op, 'inspect');
  } finally { await jobs.dispose(); }
});

await test('Real worker timeout, bounded queue, recovery and disposal settle every promise', async () => {
  const jobs = new AnalysisJobs({ timeoutMs: 1 });
  try {
    await rejects(() => jobs.run('crypto', requestInspect), 'TIMEOUT');
    jobs.timeoutMs = 15000;
    assert.equal((await jobs.run('crypto', requestInspect)).result.op, 'inspect');
    await jobs.active?.stopped;
    const queued = Array.from({ length: 6 }, () => jobs.run('crypto', requestInspect).then(() => 'ok', error => error.code));
    const outcomes = await Promise.all(queued); assert.equal(outcomes.filter(code => code === 'BUSY').length, 1);
    const active = jobs.run('crypto', requestInspect), waiting = jobs.run('crypto', requestInspect);
    const activeRejected = rejects(() => active, 'DISPOSED'), waitingRejected = rejects(() => waiting, 'DISPOSED');
    await jobs.dispose(); await Promise.all([activeRejected, waitingRejected]);
    await rejects(() => jobs.run('crypto', requestInspect), 'DISPOSED');
  } finally { await jobs.dispose(); }
});

await service.dispose(); await fixtureHost.dispose();
fs.writeFileSync(path.join(scratch, 'acceptance.json'), JSON.stringify({ ok: outcomes.every(result => result.ok), tests: outcomes, artifacts: scratch, nativeEnginesExecuted: false, sourceSamplesUsed: false }, null, 2));
console.log('Analysis host acceptance:', scratch);
if (outcomes.some(result => !result.ok)) process.exitCode = 1;
