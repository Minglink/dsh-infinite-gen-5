// ig5_package through the public tool definition and a real isolated worker: input validation, saved report, section
// reads, bounded responses. The APK is generated here; nothing in it is executed.
import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createAnalysisService, defineAnalysisTools } from '../analysis_tools.js';
import { buildZip } from './fixtures/apk_builder.mjs';
import { minimalApk } from './fixtures/apk_sample.mjs';

const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-apk-tool-'));
const cfg = { artifactDir: path.join(scratch, 'artifacts'), defaultEngine: 'ghidra' };
const mgr = { scope: new AsyncLocalStorage(), checkCancelled() {} };
const service = createAnalysisService(mgr, cfg); mgr.analysis = service;
const definitions = defineAnalysisTools(mgr, cfg, value => value), tools = new Map(definitions.map(tool => [tool.name, tool]));
const apk = tools.get('ig5_package'), call = args => apk.execute(args);
test.after(async () => { await service.dispose(); fs.rmSync(scratch, { recursive: true, force: true }); });

const bytes = minimalApk();
const file = path.join(scratch, 'sample.apk'); fs.writeFileSync(file, bytes);
const rejects = (run, code) => assert.rejects(run, error => error.code === code, `expected ${code}`);

test('the tool is registered as a data tool with a path-only input', () => {
  assert.ok(apk); assert.deepEqual(apk.parameters.properties.action.enum, ['apk', 'firmware', 'unpack', 'js_app', 'trace_diff', 'result']); assert.deepEqual(apk.parameters.properties.input.required, ['path']);
  assert.equal(apk.parameters.properties.input.additionalProperties, false); assert.ok(apk.description.length < 2100, 'the description is part of every Full-toolset prompt');
});

let saved;
test('analyze saves the full report and returns a bounded brief', async () => {
  const before = createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  saved = await call({ action: 'apk', input: { path: file } });
  assert.equal(saved.kind, 'apk'); assert.match(saved.result_id, /^[0-9a-f-]{36}$/); assert.equal(saved.association.target, file);
  assert.equal(saved.input.sha256, before); assert.equal(saved.input.bytes, bytes.length); assert.equal(createHash('sha256').update(fs.readFileSync(file)).digest('hex'), before, 'the sample is untouched');
  assert.equal(saved.value.schema, 'ig5.apk.v1'); assert.match(saved.value.summary, /com\.example\.tool/); assert.equal(saved.value.overview.package, 'com.example.tool');
  assert.ok(Buffer.byteLength(JSON.stringify(saved)) < 30000, 'the response stays within the model-facing budget');
  assert.ok(saved.value.notRun.some(text => /signature verification/.test(text)));
});

test('sections of the saved report are read with select, and bad selections are refused', async () => {
  const rules = await call({ action: 'result', result_id: saved.result_id, select: 'capabilities.rules' });
  assert.ok(rules.value.some(rule => rule.id === 'sms.send' && rule.samples[0].method === 'Lcom/example/tool/Main;->go()V'));
  const component = await call({ action: 'result', result_id: saved.result_id, select: 'manifest.components.0' });
  assert.deepEqual([component.value.name, component.value.exported], ['com.example.tool.Main', true]);
  const cert = await call({ action: 'result', result_id: saved.result_id, select: 'signatures.certificates.0.flags' }); assert.deepEqual(cert.value, ['android-debug-key']);
  await rejects(() => call({ action: 'result', result_id: saved.result_id, select: '__proto__' }), 'INVALID_INPUT');
  await rejects(() => call({ action: 'result', result_id: saved.result_id, select: 'nothing.here' }), 'NOT_FOUND');
  await rejects(() => call({ action: 'result', result_id: '00000000-0000-0000-0000-000000000000' }), 'NOT_FOUND');
});

test('only an explicit file path is accepted', async () => {
  for (const input of [undefined, null, [], {}, { path: 5 }, { path: file, extra: 1 }, { encoding: 'hex', data: '00' }, { ref: 'sha256:' + '0'.repeat(64) }, { source: { target: file } }]) await rejects(() => call({ action: 'apk', input }), 'INVALID_INPUT');
  await rejects(() => call({ action: 'apk', input: { path: file }, select: 'x' }), 'INVALID_INPUT');
  await rejects(() => call({ action: 'apk', input: { path: file }, result_id: saved.result_id }), 'INVALID_INPUT');
  await rejects(() => call({ action: 'explode', input: { path: file } }), 'INVALID_INPUT');
});

test('files that are not APKs fail with a code that survives the worker boundary', async () => {
  const text = path.join(scratch, 'text.apk'); fs.writeFileSync(text, 'plain text, not an archive at all'.repeat(3));
  await rejects(() => call({ action: 'apk', input: { path: text } }), 'ZIP_FORMAT');
  const bare = path.join(scratch, 'bare.zip'); fs.writeFileSync(bare, buildZip([{ name: 'a.txt', data: 'x' }]));
  await rejects(() => call({ action: 'apk', input: { path: bare } }), 'APK_FORMAT');
  await rejects(() => call({ action: 'apk', input: { path: scratch } }), 'ZIP_INPUT');
  await rejects(() => call({ action: 'apk', input: { path: path.join(scratch, 'missing.apk') } }), 'ANALYSIS_FAILED');
});

test('a report from another analysis lane is not readable as an APK report', async () => {
  const other = await tools.get('ig5_crypto').execute({ action: 'inspect', input: { encoding: 'hex', data: '00112233' } });
  await rejects(() => call({ action: 'result', result_id: other.result_id }), 'INVALID_REF');
  await rejects(() => tools.get('ig5_crypto').execute({ action: 'result', result_id: saved.result_id }), 'INVALID_REF');
});

test('an optional target only labels the result', async () => {
  const labelled = await call({ action: 'apk', input: { path: file }, target: path.join(scratch, 'libnative.so') });
  assert.equal(labelled.association.target, path.join(scratch, 'libnative.so'));
});
