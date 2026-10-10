// Actual Reverse/Ghidra static-memory → authenticated decrypt → decompress →
// verify → explicit protocol decode. Generated PE only; no process execution.
import assert from 'node:assert/strict';
import { createCipheriv, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { apply } from '../index.js';
import { AnalysisArtifacts, hashBytes } from '../source/analysis_artifacts.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const reportDir = path.resolve(process.env.IG5_ANALYSIS_REPORT_DIR || path.join(process.env.USERPROFILE || process.env.HOME, '.dsh', 'ig5', 'artifacts', 'crypto-protocol-20261010'));
const runRoot = path.join(reportDir, 'native-data-chain', randomUUID());
fs.mkdirSync(runRoot, { recursive: true });
const temporaryRoot = fs.realpathSync(os.tmpdir());
const nativeProjectRoot = fs.mkdtempSync(path.join(temporaryRoot, 'ig5-analysis-native-projects-'));
const artifactRoot = path.join(runRoot, 'artifacts');
const target = path.join(runRoot, '双引擎加密协议.exe');
const outcomes = [], reports = [], effects = [], tools = new Map(), events = new Map(), routes = new Map();
const inline = data => ({ encoding: 'hex', data: data.toString('hex') });
const refs = result => ({ ref: result.output.ref, result_id: result.result_id });
const reportFile = path.join(reportDir, 'test_analysis_runtime.report.json');
let cleanupSucceeded = false;

const schema = { fields: [
  { name: 'length', offset: 0, type: 'u16', endian: 'big' },
  { name: 'message_type', offset: 2, type: 'u8' },
  { name: 'flags', offset: 3, type: 'u8' },
  { name: 'counter', offset: 4, type: 'u32', endian: 'little' },
  { name: 'wide_id', offset: 8, type: 'u64', endian: 'big' },
  { name: 'text', offset: 16, type: 'utf8', length: 9 },
] };
const framing = { type: 'length-prefix', offset: 0, size: 2, endian: 'big', headerLength: 2, lengthIncludesHeader: false };
function frame(type, flags, counter, wide, text) {
  const value = Buffer.alloc(25);
  assert.equal(Buffer.byteLength(text), 9);
  value.writeUInt16BE(23, 0); value[2] = type; value[3] = flags;
  value.writeUInt32LE(counter, 4); value.writeBigUInt64BE(wide, 8); value.write(text, 16, 'utf8');
  return value;
}
const frames = [frame(0x11, 0x80, 0x12345678, 0xfedcba9876543210n, 'IG5配置'),
  frame(0x12, 0x40, 0x87654321, 0x1000000000000001n, '协议IG5')];
const plaintext = Buffer.concat(frames), compressed = gzipSync(plaintext);
const key = Buffer.from('31067d2c8f59403ac4b1ed768a52399dc21563a427bf902dd17e483c069a55e8', 'hex');
const iv = Buffer.from('2971d3c54f906882ee650a1b', 'hex');
const aad = Buffer.from('IG5 offline static protocol fixture:v1');
const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad);
const encrypted = Buffer.concat([cipher.update(compressed), cipher.final()]);
const tag = cipher.getAuthTag();
const recipe = { kind: 'aes-gcm', key: inline(key), iv: inline(iv), tag: inline(tag), aad: inline(aad), padding: 'none' };
const fixture = buildPE64Fixture(1), rva = 0x3500, fileOffset = 0xe00 + (rva - 0x3000), ea = '0x140003500';
assert.ok(encrypted.length <= 0x100, 'Encrypted fixture must not overlap export metadata at RVA 0x3600');
encrypted.copy(fixture.image, fileOffset); fs.writeFileSync(target, fixture.image, { flag: 'wx' });
const fileHash = hashBytes(fixture.image);
const artifacts = new AnalysisArtifacts(path.join(artifactRoot, 'analysis-data'));

const webServer = { register(spec) { assert.ok(!routes.has(spec.path)); routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } };
const ctx = {
  tools: { register(definition) { assert.ok(!tools.has(definition.name)); tools.set(definition.name, definition); return () => tools.delete(definition.name); } },
  get(name) { return name === 'webServer' ? webServer : undefined; },
  on(name, handler) { events.set(name, handler); },
  inject(names, callback) { if (names.includes('webServer')) callback({ webServer }); return { dispose() {} }; },
  effect(body) { const dispose = body(); if (typeof dispose === 'function') effects.push(dispose); },
};
async function call(name, args = {}) {
  assert.ok(tools.has(name), name);
  return tools.get(name).execute(args, { agent: { id: 'ig5-native-data-chain-validation' } });
}
async function check(name, run) {
  const started = Date.now();
  try { await run(); outcomes.push({ name, ok: true, milliseconds: Date.now() - started }); console.log('PASS', name); }
  catch (error) { outcomes.push({ name, ok: false, milliseconds: Date.now() - started, error: error.stack }); throw error; }
}
function association(result, opened, engine) {
  assert.equal(result.association.target, target); assert.equal(result.association.engine, engine);
  assert.equal(result.association.sha256, fileHash); assert.equal(result.association.artifactId, opened.artifactId);
  assert.equal(result.association.projectId, opened.projectId); assert.equal(result.association.attachmentId, opened.attachmentId);
  assert.equal(result.association.dbRevision, opened.dbRevision);
}
function noRawParameters(result) {
  for (const parameter of [key, iv, tag, aad]) for (const text of [parameter.toString('hex'), parameter.toString('base64')])
    assert.ok(!JSON.stringify(result).includes(text), 'Raw AES parameter must not appear in returned or saved reports');
}
function readRoute(query) {
  return new Promise((resolve, reject) => {
    try { routes.get('/ig5-data')({ method: 'GET', url: '/ig5-data?' + new URLSearchParams(query) }, {
      writeHead(code) { assert.equal(code, 200); }, end(body) { const data = JSON.parse(body); data.error ? reject(new Error(data.error)) : resolve(data.data); },
    }); } catch (error) { reject(error); }
  });
}
function snapshot() {
  const value = { ok: outcomes.length > 0 && outcomes.every(row => row.ok) && cleanupSucceeded,
    generatedFixture: { target, sha256: fileHash, byteLength: fixture.image.length, section: '.data',
      rva: '0x3500', ea, fileOffset, ciphertextBytes: encrypted.length, gzipBytes: compressed.length, protocolBytes: plaintext.length },
    runRoot, artifactRoot, nativeProjectRoot, checks: outcomes, engines: reports, cleanupSucceeded,
    execution: 'Static analysis only; no generated PE process, debugger or emulator was started.',
    limitations: 'Fixed, explicitly supplied AES key/IV/tag/AAD and explicit protocol schema/framing. This validates the data chain, not automatic key recovery or unknown-protocol inference.' };
  fs.mkdirSync(reportDir, { recursive: true }); fs.writeFileSync(reportFile, JSON.stringify(value, null, 2) + '\n');
  return value;
}

try {
  apply(ctx, { toolset: 'full', artifactDir: artifactRoot, projectRoot: nativeProjectRoot, requestTimeoutMs: 120000,
    ...(process.env.IG5_IDA_DIR ? { idaDir: process.env.IG5_IDA_DIR } : {}),
    ...(process.env.IG5_PYTHON ? { pythonExe: process.env.IG5_PYTHON } : {}),
  });
  await check('38 tools and real configured static engines are available', async () => {
    assert.equal(tools.size, 38);
    const profile = await call('ig5_profile');
    for (const id of ['reverse', 'ghidra']) assert.equal(profile.engines.find(row => row.id === id)?.available, true, `${id} actual runtime must be available`);
    const gate = events.get('tools/pre-execute');
    for (const name of ['ig5_crypto', 'ig5_protocol']) assert.equal(await gate({ name, arguments: {} }, () => 'read-only'), 'read-only');
  });
  for (const engine of ['reverse', 'ghidra']) {
    const openInfo = await call('ig5_open', { target, path: target, engine, background: false, analysis_profile: 'interactive', analysis_timeout: 60 });
    const initialStatus = (await call('ig5_status')).sessions.find(row => row.target === target && row.engine === engine);
    assert.ok(initialStatus, 'Opened engine must have a native session');
    const opened = { ...openInfo, ...initialStatus };
    assert.equal(opened.engine, engine); assert.equal(opened.dbRevision, 0); assert.equal(opened.sha256, fileHash);
    const source = { target, engine, ea, size: encrypted.length, expected_revision: opened.dbRevision };
    let decrypted, expanded, verified, decoded;
    await check(`${engine}: mapped static source bytes and stale revision guard`, async () => {
      const dataSection = opened.segments.find(row => row.name === '.data'); assert.ok(dataSection);
      assert.ok(BigInt(dataSection.start) <= BigInt(ea));
      assert.ok(BigInt(dataSection.end ?? (BigInt(dataSection.start) + BigInt(dataSection.size))) >= BigInt(ea) + BigInt(encrypted.length));
      const read = await call('ig5_bytes', { target, engine, ea, size: encrypted.length });
      assert.equal(read.hex.replace(/\s/g, '').toLowerCase(), encrypted.toString('hex'));
      await assert.rejects(() => call('ig5_crypto', { action: 'inspect', input: { source: { ...source, expected_revision: opened.dbRevision + 1 } } }), error => error.code === 'STALE_REVISION');
    });
    await check(`${engine}: real source capture → AES-GCM authentication/decrypt`, async () => {
      decrypted = await call('ig5_crypto', { action: 'transform', input: { source }, recipe, expected: inline(compressed), preview_limit: 16 });
      assert.equal(decrypted.value.authentication.status, 'passed'); assert.equal(decrypted.value.verification.matched, true);
      assert.deepEqual(artifacts.read(decrypted.input.ref).data, encrypted); assert.deepEqual(artifacts.read(decrypted.output.ref).data, compressed);
      assert.equal(decrypted.input.origin.kind, 'static-memory'); assert.equal(decrypted.input.origin.ea, ea);
      assert.equal(decrypted.input.origin.engine, engine); association(decrypted, opened, engine);
      noRawParameters(decrypted); noRawParameters(artifacts.get(decrypted.result_id));
    });
    await check(`${engine}: bound plaintext ref → gzip → independent exact verification`, async () => {
      expanded = await call('ig5_crypto', { action: 'transform', input: refs(decrypted), recipe: { kind: 'gzip' }, expected: inline(plaintext), preview_limit: 16 });
      assert.equal(expanded.value.verification.matched, true); assert.deepEqual(artifacts.read(expanded.output.ref).data, plaintext);
      assert.equal(expanded.input.origin.derivedFrom.resultId, decrypted.result_id); association(expanded, opened, engine);
      verified = await call('ig5_crypto', { action: 'verify', input: refs(expanded), expected: inline(plaintext) });
      assert.equal(verified.value.verification.matched, true); association(verified, opened, engine);
      const history = await call('ig5_crypto', { action: 'result', result_id: expanded.result_id });
      assert.equal(history.output.ref, expanded.output.ref); assert.equal(history.output.result_id, expanded.result_id);
    });
    await check(`${engine}: inherited ref → two protocol frames with endian/u64/UTF8 spans`, async () => {
      decoded = await call('ig5_protocol', { action: 'decode', input: refs(expanded), schema, framing });
      assert.equal(decoded.value.complete, true); assert.equal(decoded.value.frames.length, 2); association(decoded, opened, engine);
      assert.equal(decoded.input.origin.derivedFrom.resultId, expanded.result_id);
      const first = Object.fromEntries(decoded.value.frames[0].fields.map(row => [row.name, row]));
      const second = Object.fromEntries(decoded.value.frames[1].fields.map(row => [row.name, row]));
      assert.equal(first.length.value, 23); assert.equal(first.message_type.value, 0x11); assert.equal(first.counter.value, 0x12345678);
      assert.equal(first.wide_id.value, '18364758544493064720'); assert.equal(first.text.value, 'IG5配置');
      assert.equal(second.counter.value, 0x87654321); assert.equal(second.wide_id.value, '1152921504606846977'); assert.equal(second.text.value, '协议IG5');
      assert.equal(second.text.span.inputOffset, 41);
      decoded.value.frames.forEach((row, index) => { assert.equal(row.dataRef.result_id, decoded.result_id); assert.deepEqual(artifacts.read(row.dataRef.ref).data, frames[index]); });
      const persisted = artifacts.get(decoded.result_id); assert.ok(!JSON.stringify(persisted.result).includes('dataHex'));
      const throughHttp = await readRoute({ type: 'analysis_result', id: decoded.result_id, target, engine });
      assert.equal(throughHttp.association.engine, engine); assert.equal(throughHttp.value.frames[0].dataRef.ref, decoded.value.frames[0].dataRef.ref);
    });
    await check(`${engine}: source file, mapped bytes and dbRevision remain unchanged`, async () => {
      assert.equal(hashBytes(fs.readFileSync(target)), fileHash);
      const read = await call('ig5_bytes', { target, engine, ea, size: encrypted.length }); assert.equal(read.hex.replace(/\s/g, '').toLowerCase(), encrypted.toString('hex'));
      const status = await call('ig5_status'); const session = status.sessions.find(row => row.target === target && row.engine === engine);
      assert.equal(session.dbRevision, opened.dbRevision); assert.equal(session.sha256, fileHash);
    });
    reports.push({ engine, artifactId: opened.artifactId, projectId: opened.projectId, attachmentId: opened.attachmentId,
      dbRevision: opened.dbRevision, sha256: opened.sha256, decryptedResult: decrypted.result_id, expandedResult: expanded.result_id,
      verifiedResult: verified.result_id, protocolResult: decoded.result_id, sourceRef: decrypted.input.ref,
      gzipRef: decrypted.output.ref, plaintextRef: expanded.output.ref, frameRefs: decoded.value.frames.map(row => row.dataRef.ref) });
    await call('ig5_close', { target, engine });
  }
  await check('shared content refs retain explicit per-engine producer provenance', async () => {
    assert.equal(reports[0].artifactId, reports[1].artifactId); assert.equal(reports[0].sourceRef, reports[1].sourceRef);
    assert.equal(reports[0].gzipRef, reports[1].gzipRef); assert.equal(reports[0].plaintextRef, reports[1].plaintextRef);
    assert.notEqual(reports[0].attachmentId, reports[1].attachmentId);
    for (const report of reports) {
      const sourceRecord = artifacts.get(report.decryptedResult), decodeRecord = artifacts.get(report.protocolResult);
      assert.equal(sourceRecord.association.engine, report.engine); assert.equal(decodeRecord.association.engine, report.engine);
      assert.equal(decodeRecord.input.origin.derivedFrom.resultId, report.expandedResult);
      const list = await readRoute({ type: 'analyses', target, engine: report.engine });
      assert.equal(list.total, 4); assert.ok(list.items.every(row => row.association.engine === report.engine));
    }
    assert.equal((await call('ig5_status')).sessions.length, 0); assert.equal(hashBytes(fs.readFileSync(target)), fileHash);
  });
} catch (error) {
  console.error('FAIL native data chain:', error.stack);
  if (!outcomes.some(row => !row.ok)) outcomes.push({ name: 'runtime bootstrap or open', ok: false, error: error.stack });
  process.exitCode = 1;
} finally {
  try {
    for (const dispose of effects.reverse()) await dispose();
    assert.equal(path.dirname(path.resolve(nativeProjectRoot)), temporaryRoot);
    assert.ok(path.basename(nativeProjectRoot).startsWith('ig5-analysis-native-projects-'));
    await fs.promises.rm(nativeProjectRoot, { recursive: true, force: true, maxRetries: 30, retryDelay: 100 });
    cleanupSucceeded = true;
  }
  catch (error) { outcomes.push({ name: 'worker cleanup', ok: false, error: error.stack }); process.exitCode = 1; }
  const record = snapshot();
  console.log(JSON.stringify({ ok: record.ok, checks: outcomes.length, engines: reports.map(row => row.engine), reportFile, runRoot, cleanupSucceeded }));
  if (!record.ok) process.exitCode = 1;
}
