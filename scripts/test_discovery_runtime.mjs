// Real static-engine bytes -> key material search -> key-ref decrypt -> inferred framing.
// Generated PE only. No target process or debugger is started.
import assert from 'node:assert/strict';
import { createCipheriv, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { apply } from '../index.js';
import { AnalysisArtifacts, hashBytes } from '../source/analysis_artifacts.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const reportDir = path.resolve(process.env.IG5_DISCOVERY_REPORT_DIR || path.join(process.env.USERPROFILE || process.env.HOME, '.dsh', 'ig5', 'artifacts', 'auto-discovery-20261010'));
const runRoot = path.join(reportDir, 'native-discovery', randomUUID());
fs.mkdirSync(runRoot, { recursive: true });
const target = path.join(runRoot, '自动恢复与推断.exe');
const artifactRoot = path.join(runRoot, 'artifacts');
const tools = new Map(), events = new Map(), effects = [], outcomes = [], engines = [];
const inline = bytes => ({ encoding: 'hex', data: bytes.toString('hex') });
function frame(text, opcode) {
  const payload = Buffer.concat([Buffer.from([opcode, 0x80]), Buffer.from(text)]);
  const header = Buffer.alloc(2); header.writeUInt16BE(payload.length);
  return Buffer.concat([header, payload]);
}
const frames = [frame('hello', 1), frame('a longer request', 2), frame('third payload varies again', 1), frame('bye now', 3)];
const holdout = [frame('independent validation message', 4), frame('ok', 5)];
const plaintext = Buffer.concat(frames);
const key = Buffer.from('671abd5f083c990fe154376a4d8c2210', 'hex');
const iv = Buffer.from('d8e1b2c3a4f56789abcd0192', 'hex');
const aad = Buffer.from('IG5 native discovery fixture');
const cipher = createCipheriv('aes-128-gcm', key, iv); cipher.setAAD(aad);
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]), tag = cipher.getAuthTag();
const material = Buffer.alloc(128, 0x7f); key.copy(material, 64);
const fixture = buildPE64Fixture(1);
assert.ok(ciphertext.length < 256);
material.copy(fixture.image, 0xe00 + 0x400);
ciphertext.copy(fixture.image, 0xe00 + 0x500);
fs.writeFileSync(target, fixture.image, { flag: 'wx' });
const originalHash = hashBytes(fixture.image);
const artifacts = new AnalysisArtifacts(path.join(artifactRoot, 'analysis-data'));
const ctx = {
  tools: { register(tool) { assert.ok(!tools.has(tool.name)); tools.set(tool.name, tool); return () => tools.delete(tool.name); } },
  get() {}, on(name, handler) { events.set(name, handler); }, inject() { return { dispose() {} }; },
  effect(body) { const dispose = body(); if (typeof dispose === 'function') effects.push(dispose); },
};
const call = (name, args = {}) => tools.get(name).execute(args, { agent: { id: 'ig5-discovery-runtime-validation' } });
async function check(name, run) {
  const start = Date.now();
  try { await run(); outcomes.push({ name, ok: true, milliseconds: Date.now() - start }); console.log('PASS', name); }
  catch (error) { outcomes.push({ name, ok: false, error: error.stack }); throw error; }
}
function noSecrets(record) {
  const text = JSON.stringify(record);
  for (const secret of [key, iv, tag, aad]) for (const encoded of [secret.toString('hex'), secret.toString('base64')]) assert.ok(!text.includes(encoded), 'Raw AES parameters must not enter reports');
}
let disposed = false;
try {
  apply(ctx, { toolset: 'full', artifactDir: artifactRoot, projectRoot: path.join(runRoot, 'projects'), requestTimeoutMs: 120000 });
  assert.equal(tools.size, 38);
  for (const engine of ['reverse', 'ghidra']) {
    await call('ig5_open', { target, path: target, engine, background: false, analysis_profile: 'interactive', analysis_timeout: 60 });
    const opened = (await call('ig5_status')).sessions.find(row => row.target === target && row.engine === engine);
    assert.ok(opened); assert.equal(opened.dbRevision, 0);
    const source = { target, engine, ea: '0x140003500', size: ciphertext.length, expected_revision: 0 };
    const keySource = { source: { target, engine, ea: '0x140003400', size: material.length, expected_revision: 0 } };
    let recovered, decrypted, inferred, selected;
    await check(`${engine}: recover unknown AES key from real mapped candidate material`, async () => {
      recovered = await call('ig5_crypto', { action: 'recover', input: { source }, preview_limit: 8,
        recovery: { method: 'aes-candidates', key_source: keySource, max_trials: 4096,
          aes: { kind: 'aes-gcm', iv: inline(iv), tag: inline(tag), aad: inline(aad), padding: 'none' } } });
      assert.equal(recovered.value.recovery.status, 'verified');
      assert.deepEqual(artifacts.read(recovered.output.ref).data, plaintext);
      const record = artifacts.get(recovered.result_id); noSecrets(record); noSecrets(recovered);
      selected = record.result.recovery.candidates.find(row => row.keyComplete && row.keyMaterial?.dataRef && row.validation?.status !== 'failed');
      assert.ok(selected, 'A complete sensitive key ref must be available');
      assert.deepEqual(artifacts.read(selected.keyMaterial.dataRef.ref).data, key);
      assert.equal(recovered.association.engine, engine);
    });
    await check(`${engine}: recovered key ref decrypts without repeating secret bytes`, async () => {
      decrypted = await call('ig5_crypto', { action: 'transform', input: { source }, expected: inline(plaintext), preview_limit: 8,
        recipe: { kind: 'aes-gcm', key_ref: { ref: selected.keyMaterial.dataRef.ref, result_id: recovered.result_id },
          iv: inline(iv), tag: inline(tag), aad: inline(aad), padding: 'none' } });
      assert.equal(decrypted.value.verification.matched, true);
      assert.deepEqual(artifacts.read(decrypted.output.ref).data, plaintext);
      noSecrets(decrypted); noSecrets(artifacts.get(decrypted.result_id));
    });
    await check(`${engine}: unknown framing inference proposes an independently usable decoder`, async () => {
      inferred = await call('ig5_protocol', { action: 'infer', input: { ref: decrypted.output.ref, result_id: decrypted.result_id },
        inference: { format: 'stream', boundary: 'message-start', min_frames: 3, max_candidates: 8,
          holdout_samples: holdout.map(inline) } });
      const record = artifacts.get(inferred.result_id);
      const candidates = record.result.inference.candidates;
      assert.ok(candidates.length > 0);
      let usable;
      for (const candidate of candidates) {
        const decoded = await call('ig5_protocol', { action: 'decode', input: { ref: decrypted.output.ref, result_id: decrypted.result_id }, framing: candidate.framing, schema: candidate.schema });
        if (decoded.value.complete && decoded.value.frames.length === frames.length && decoded.value.frames.every((row, i) => row.dataRef && artifacts.read(row.dataRef.ref).data.equals(frames[i]))) { usable = candidate; break; }
      }
      assert.ok(usable, 'An inferred candidate must recover every independent original frame');
      const validation = await call('ig5_protocol', { action: 'decode', input: inline(Buffer.concat(holdout)), framing: usable.framing, schema: usable.schema });
      assert.equal(validation.value.complete, true); assert.equal(validation.value.frames.length, holdout.length);
      validation.value.frames.forEach((row, i) => assert.deepEqual(artifacts.read(row.dataRef.ref).data, holdout[i]));
      assert.equal(inferred.association.engine, engine);
    });
    await check(`${engine}: sample, native bytes and database revision unchanged`, async () => {
      assert.equal(hashBytes(fs.readFileSync(target)), originalHash);
      const state = (await call('ig5_status')).sessions.find(row => row.target === target && row.engine === engine);
      assert.equal(state.dbRevision, opened.dbRevision);
      const read = await call('ig5_bytes', { target, engine, ea: source.ea, size: source.size });
      assert.equal(read.hex.replace(/\s/g, '').toLowerCase(), ciphertext.toString('hex'));
    });
    engines.push({ engine, sha256: originalHash, recovery: recovered.result_id, decrypt: decrypted.result_id, inference: inferred.result_id });
    await call('ig5_close', { target, engine });
  }
} catch (error) { process.exitCode = 1; console.error(error.stack); }
finally {
  try { for (const dispose of effects.reverse()) await dispose(); disposed = true; }
  catch (error) { process.exitCode = 1; outcomes.push({ name: 'dispose', ok: false, error: error.stack }); }
  const report = { ok: engines.length === 2 && outcomes.every(row => row.ok) && disposed, runRoot, target, originalHash, outcomes, engines, disposed,
    execution: 'Generated PE static analysis only; no target process, debugger, network or emulator execution.',
    scope: 'Bounded candidate-material key recovery with supplied GCM IV/tag/AAD, and heuristic framing inference with independent holdout decoding.' };
  fs.writeFileSync(path.join(runRoot, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ ok: report.ok, report: path.join(runRoot, 'report.json') }));
  if (!report.ok) process.exitCode = 1;
}
