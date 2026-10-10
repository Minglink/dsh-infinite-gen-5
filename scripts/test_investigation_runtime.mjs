// Real bundled static workers on disposable generated PE files. The controlled
// approval service authorizes one fixture comment; no target process is executed.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomUUID } from 'node:crypto';
import { apply } from '../index.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const sourceRoot = fs.realpathSync(new URL('..', import.meta.url));
const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-investigation-runtime-中文-'));
const reportFile = path.resolve(process.env.IG5_INVESTIGATION_REPORT || path.join(os.homedir(), '.dsh', 'ig5', 'artifacts', `investigation-runtime-${randomUUID()}.json`));
const relativeReport = path.relative(sourceRoot, reportFile);
assert(relativeReport.startsWith('..') || path.isAbsolute(relativeReport), 'Evidence report must be outside plugin source');
const target = path.join(scratch, '版本一.exe'), other = path.join(scratch, '版本二.exe');
const fixture = buildPE64Fixture(1);
fs.writeFileSync(target, fixture.image); fs.writeFileSync(other, buildPE64Fixture(2).image);
const tools = new Map(), events = new Map(), effects = [], checks = [], approvals = [];
const agent = { id: 'investigation-runtime-acceptance' };
const ctx = {
  tools: { register(definition) { assert(!tools.has(definition.name)); tools.set(definition.name, definition); return () => tools.delete(definition.name); } },
  on(name, callback) { events.set(name, callback); return () => events.delete(name); },
  get(name) { return name === 'approval' ? { async request(request) { approvals.push(request); return 'allowed-once'; } } : undefined; },
  inject() { return { dispose() {} }; },
  effect(body) { const dispose = body(); if (typeof dispose === 'function') effects.push(dispose); },
};
let sequence = 0, failure, cleanupSucceeded = false;
const call = (name, args = {}, execution = {}) => {
  assert(tools.has(name), `${name} must be available`);
  return tools.get(name).execute({ target, ...args }, { agent, callId: `investigation-${++sequence}`, ...execution });
};
const workspace = value => call('ig5_profile', { workspace: value });
const task = async id => (await workspace({ action: 'get', id })).workspace;
const pass = (name, evidence) => { checks.push({ name, evidence }); console.log('PASS', name, JSON.stringify(evidence)); };
const expectError = async (work, pattern) => assert.rejects(work, error => pattern.test(`${error.code || ''} ${error.message}`));

try {
  apply(ctx, { defaultEngine: 'reverse', reverseProvider: 'bundled', toolset: 'core', backgroundOpen: false,
    artifactDir: path.join(scratch, 'artifacts'), requestTimeoutMs: 120000, openTimeoutMs: 180000 });
  assert.equal(tools.size, 8);
  const opened = await call('ig5_open', { path: target, background: false });
  assert.equal(opened.provider, 'ghidra');
  const created = (await workspace({ action: 'create', goal: '还原测试函数的分支', hypothesis: '返回值取决于输入是否为零', next_step: '聚合并核对函数上下文' })).workspace;
  const id = created.taskId;
  assert.equal(created.progressIsCallerDeclared, true); assert.equal(created.taskRevision, 0);
  const args = { ea: fixture.addresses.branch, style: 'dossier', task_id: id, dossier_max_bytes: 16000, dossier_max_rows: 32 };
  const dossier = await call('ig5_decompile', args);
  assert.equal(dossier.kind, 'function-dossier'); assert.equal(dossier.provenance.dbRevision, opened.dbRevision);
  assert.equal(dossier.provenance.artifactId, opened.artifactId);
  assert.deepEqual(Object.keys(dossier.sections).sort(), ['callees', 'callers', 'cfg', 'decompile', 'stack']);
  for (const [name, section] of Object.entries(dossier.sections)) assert(['ok', 'truncated'].includes(section.status), `${name}: ${JSON.stringify(section)}`);
  assert.equal(dossier.investigation.ok, true);
  assert.equal(dossier.function.ea, fixture.addresses.branch);
  assert.equal((await call('ig5_status')).sessions.find(row => row.target === target).dbRevision, opened.dbRevision);
  const body = { ...dossier }; delete body.investigation; delete body._ig5;
  assert(Buffer.byteLength(JSON.stringify(body)) <= 16000);
  pass('Core8 executes five real static dossier sections and captures a report without database mutation', {
    provenance: dossier.provenance, sections: Object.fromEntries(Object.entries(dossier.sections).map(([name, row]) => [name, row.status])), digest: dossier.snapshotDigest,
  });

  const repeated = await call('ig5_decompile', args);
  assert.equal(repeated.cache.hit, true); assert.equal(repeated.investigation.duplicate, true);
  assert.equal(repeated.snapshotDigest, dossier.snapshotDigest);
  assert.equal(repeated.investigation.reportId, dossier.investigation.reportId);
  const recorded = await task(id); assert.equal(recorded.systemEvidence.length, 1);
  const historical = await workspace({ action: 'evidence', id, snapshot_id: recorded.systemEvidence[0].snapshot_id });
  assert.equal(historical.workspace.report.snapshotDigest, dossier.snapshotDigest);
  assert.equal(historical.workspace.snapshot.stale, false);
  pass('Repeated dossier hits cache, deduplicates persistent evidence and reads its authenticated report', { taskId: id, taskRevision: recorded.taskRevision, reportId: dossier.investigation.reportId });

  await expectError(() => workspace({ action: 'update', id, expected_task_revision: created.taskRevision, status: 'completed' }), /STALE_TASK_REVISION/);
  await expectError(() => workspace({ action: 'update', id, expected_task_revision: recorded.taskRevision, verified: true }), /field.*valid|unsupported field/);
  await expectError(() => workspace({ action: 'evidence', id, snapshot_id: randomUUID() }), /INVALID_REF/);
  const paused = (await workspace({ action: 'update', id, expected_task_revision: recorded.taskRevision, status: 'paused', next_step: '复核原始字节' })).workspace;
  assert.equal(paused.status, 'paused'); assert.equal(paused.verified, undefined);
  pass('Task CAS and evidence ownership reject stale updates and caller-forged verification', { taskRevision: paused.taskRevision });

  const full = await call('ig5_profile', { toolset: 'full' }); assert.equal(full.activeTools.length, 38);
  const mutation = { target, ea: fixture.addresses.branch, text: 'IG5 dossier revision fixture', expected_revision: opened.dbRevision };
  let dispatched = false;
  const execution = { agent, callId: `comment-${++sequence}` };
  const decision = await events.get('tools/pre-execute')({ name: 'ig5_comment', arguments: mutation, ...execution }, async () => { dispatched = true; return { kind: 'allow' }; });
  assert.equal(decision.kind, 'allow'); assert.equal(dispatched, true);
  await tools.get('ig5_comment').execute(mutation, execution);
  assert.equal(approvals.length, 1);
  const revised = await call('ig5_decompile', args);
  assert.equal(revised.cache.hit, false); assert.notEqual(revised.snapshotDigest, dossier.snapshotDigest);
  assert.equal(revised.provenance.dbRevision, opened.dbRevision + 1);
  const revisedTask = await task(id);
  assert.equal(revisedTask.systemEvidence.length, 2);
  assert.equal(revisedTask.systemEvidence[0].stale, true); assert.equal(revisedTask.systemEvidence[1].stale, false);
  pass('Approved fixture mutation invalidates cache and preserves old evidence at its original revision', { dbRevision: revised.provenance.dbRevision, staleReasons: revisedTask.systemEvidence[0].staleReasons });

  await call('ig5_open', { path: target, engine: 'ghidra', background: false });
  await expectError(() => call('ig5_profile', { engine: 'ghidra', workspace: { action: 'get', id } }), /IDENTITY_MISMATCH/);
  const ghidra = await call('ig5_decompile', { engine: 'ghidra', ea: fixture.addresses.branch, style: 'dossier' });
  assert.equal(ghidra.provenance.engine, 'ghidra'); assert.notEqual(ghidra.provenance.attachmentId, dossier.provenance.attachmentId);
  await call('ig5_open', { path: other, background: false });
  await expectError(() => call('ig5_profile', { target: other, workspace: { action: 'get', id } }), /IDENTITY_MISMATCH/);
  pass('Same-address independent Ghidra lane and another binary cannot reuse this task', { ghidraAttachment: ghidra.provenance.attachmentId });

  await call('ig5_close'); await call('ig5_open', { path: target, background: false });
  const reopened = await task(id);
  assert.equal(reopened.status, 'paused'); assert.equal(reopened.systemEvidence.length, 2);
  assert(reopened.systemEvidence.every(entry => entry.stale && entry.staleReasons.includes('attachment-changed')));
  const beforeAbort = reopened.taskRevision;
  const controller = new AbortController(); controller.abort();
  await expectError(() => call('ig5_decompile', args, { signal: controller.signal }), /cancelled/i);
  assert.equal((await task(id)).taskRevision, beforeAbort);
  const list = await workspace({ action: 'list' }); assert.equal(list.workspace.tasks[0].taskId, id);
  assert.equal(list.workspace.tasks[0].staleObservations, 2);
  pass('Reopen restores task statements, marks all former attachments stale and cancels without capture', { taskId: id, taskRevision: beforeAbort });
} catch (error) {
  failure = { code: error.code || null, message: error.message, stack: error.stack };
} finally {
  try {
    for (const dispose of effects.reverse()) await dispose();
    const relative = path.relative(fs.realpathSync(os.tmpdir()), path.resolve(scratch));
    assert(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
    await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
    cleanupSucceeded = true;
  } catch (error) { failure ||= { code: error.code || null, message: error.message, stack: error.stack }; }
  const files = ['index.js', 'source/function_dossier.js', 'source/investigation_workflow.js', 'source/investigation_store.js', 'source/project_store.js'];
  fs.mkdirSync(path.dirname(reportFile), { recursive: true });
  fs.writeFileSync(reportFile, JSON.stringify({ ok: !failure, createdAt: new Date().toISOString(), scope: 'Real bundled Reverse and explicit Ghidra static workers; generated PE only; no target process execution',
    source: Object.fromEntries(files.map(file => [file, createHash('sha256').update(fs.readFileSync(path.join(sourceRoot, file))).digest('hex')])),
    fixtureSha256: createHash('sha256').update(fixture.image).digest('hex'), checks, cleanupSucceeded, failure }, null, 2));
}
if (failure) throw new Error(JSON.stringify(failure));
console.log('ALL INVESTIGATION RUNTIME ASSERTIONS PASSED', reportFile);
