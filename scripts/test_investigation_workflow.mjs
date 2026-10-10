// Host bridge fixtures with real metadata/report storage and synthetic dossiers.
// No native engine, executable sample, debugger or user project is opened.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { InvestigationStore } from '../source/investigation_store.js';
import { runWorkspace, captureDossier } from '../source/investigation_workflow.js';

const hash = value => createHash('sha256').update(value).digest('hex');
const failure = (call, code) => assert.throws(call, error => error.code === code);
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
function syntheticDossier(context, { name = 'decode', ea = '0x140001000', salt = '' } = {}) {
  const value = { kind: 'function-dossier', schemaVersion: 1, provenance: { ...context }, _ig5: { ...context },
    function: { ea, name, size: 8, resolved: true }, analysis: { partial: true, analysisComplete: false, analysisProfile: 'fixture' },
    sections: {
      decompile: { status: 'ok', method: 'decompile', data: { ea, name, code: `int decode(int x) { return x + 1; } /* ${salt} */` } },
      cfg: { status: 'ok', method: 'cfg', data: { ea, total_blocks: 1, blocks: [{ id: 0, start: ea, end: '0x140001008' }], edges: [] } },
      callers: { status: 'ok', method: 'calls', direction: 'callers', data: { ea, calls: [] } },
      callees: { status: 'ok', method: 'calls', direction: 'callees', data: { ea, calls: [] } },
      stack: { status: 'ok', method: 'stack', data: { ea, members: [] } },
    }, cache: { hit: false }, responseTruncated: false, limitations: ['Synthetic host fixture; no engine observation.'] };
  const { cache, ...content } = value;
  value.snapshotDigest = hash(JSON.stringify(canonical(content)));
  return value;
}
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-investigation-workflow-test-'));
  const artifacts = new AnalysisArtifacts(path.join(root, 'reports'));
  const cfg = { projectRoot: path.join(root, 'projects') }, target = path.join(root, 'fixture.exe');
  const sha256 = hash('synthetic fixture bytes');
  const context = { target, projectId: `project_${randomUUID()}`, artifactId: `artifact_${sha256}`, sha256,
    engine: 'reverse', provider: 'ghidra', attachmentId: `attachment_${randomUUID()}`, dbRevision: 3 };
  const session = { engine: 'reverse', target, alive: true }, execution = { agent: { id: 'fixture-agent' } };
  const mgr = { analysis: { artifacts }, get(selected) { return selected === target ? session : undefined; },
    alive(value) { return value?.alive === true; }, evidence() { return { ...context }; }, checkCancelled() {
      if (mgr.cancelled) throw Object.assign(new Error('IG5 fixture cancelled'), { code: 'ABORT_ERR' });
    } };
  t.after(async () => {
    await artifacts.dispose();
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('ig5-investigation-workflow-test-'));
    fs.rmSync(root, { recursive: true, force: true });
  });
  const workspace = (input, who = execution, extras = {}) => runWorkspace(mgr, cfg, { target, workspace: input, ...extras }, who).workspace;
  const create = (values = {}) => workspace({ action: 'create', goal: '解释测试函数', hypothesis: '模型假设', ...values });
  const capture = (taskId, options = {}) => captureDossier(mgr, cfg, syntheticDossier(context, options), taskId, execution);
  const recordFiles = () => fs.readdirSync(path.join(artifacts.root, 'records')).filter(file => file.endsWith('.json'));
  return { root, cfg, context, session, execution, mgr, artifacts, workspace, create, capture, recordFiles };
}

test('workspace create/get/list/update preserves caller declarations and task CAS', t => {
  const f = fixture(t), created = f.create({ goal: '目标'.repeat(300) });
  assert(f.mgr.investigations instanceof InvestigationStore);
  assert.equal(created.taskRevision, 0); assert.equal(created.progressIsCallerDeclared, true);
  assert.equal(f.workspace({ action: 'get', id: created.taskId }, {}).hypothesis, '模型假设', 'read operations do not need a writer identity');
  const listed = f.workspace({ action: 'list' }, {});
  assert.equal(listed.tasks[0].goal.length, 256); assert.equal(listed.tasks[0].goalTruncated, true);
  assert.equal(listed.tasks[0].observations, 0); assert.equal(listed.tasks[0].progressIsCallerDeclared, true);
  const completed = f.workspace({ action: 'update', id: created.taskId, expected_task_revision: 0, status: 'completed', conclusion: '调用者声明已完成' });
  assert.equal(completed.taskRevision, 1); assert.equal(completed.status, 'completed');
  assert.equal(completed.statementOrigin, 'caller-statement'); assert.equal(completed.verified, undefined);
  failure(() => f.workspace({ action: 'update', id: created.taskId, expected_task_revision: 0, status: 'paused' }), 'STALE_TASK_REVISION');
  failure(() => f.workspace({ action: 'create', goal: 'x' }, {}), 'AGENT_SCOPE_REQUIRED');
  failure(() => f.workspace({ action: 'update', id: created.taskId, expected_task_revision: 1, goal: 'x' }, {}), 'AGENT_SCOPE_REQUIRED');
  failure(() => f.workspace({ action: 'update', id: created.taskId, expected_task_revision: 1, verified: true }), 'INVALID_ARGUMENT');
  failure(() => f.workspace({ action: 'get', id: created.taskId }, f.execution, { toolset: 'full' }), 'INVALID_ARGUMENT');
  failure(() => f.workspace({ action: 'list' }, f.execution, { target: '' }), 'INVALID_ARGUMENT');
});

test('capture persists authenticated reports, deduplicates and reads only task-bound snapshot IDs', t => {
  const f = fixture(t), task = f.create(), captured = f.capture(task.taskId);
  assert.equal(captured.ok, true); assert.equal(captured.duplicate, false); assert.equal(captured.taskRevision, 1);
  const record = f.artifacts.get(captured.reportId);
  assert.equal(record.kind, 'function-dossier'); assert.equal(record.result.analysis.partial, true);
  const actual = fs.readFileSync(path.join(f.artifacts.root, 'records', `${captured.reportId}.json`));
  assert.equal(hash(actual), captured.reportSha256);
  const observed = f.workspace({ action: 'evidence', id: task.taskId, snapshot_id: captured.snapshotId }, {});
  assert.equal(observed.snapshot.stale, false); assert.equal(observed.report.snapshotDigest, record.result.snapshotDigest);
  const again = f.capture(task.taskId);
  assert.equal(again.duplicate, true); assert.equal(again.reportId, captured.reportId); assert.equal(again.snapshotId, captured.snapshotId);
  assert.equal(f.recordFiles().length, 1); assert.equal(f.workspace({ action: 'get', id: task.taskId }).systemEvidence.length, 1);
  failure(() => f.workspace({ action: 'evidence', id: task.taskId, report_id: captured.reportId }), 'INVALID_ARGUMENT');
  const otherTask = f.create({ goal: '另一任务' });
  failure(() => f.workspace({ action: 'evidence', id: otherTask.taskId, snapshot_id: captured.snapshotId }), 'INVALID_REF');
  assert.equal(f.artifacts.archive([captured.reportId]).ok, true);
  assert.equal(f.workspace({ action: 'evidence', id: task.taskId, snapshot_id: captured.snapshotId }).report.snapshotDigest, record.result.snapshotDigest, 'archival keeps task report references usable');
});

test('database revisions and attachment changes remain historical observations, not promoted evidence', t => {
  const f = fixture(t), task = f.create(), captured = f.capture(task.taskId);
  const original = { ...f.context };
  f.context.dbRevision++;
  const revised = f.workspace({ action: 'evidence', id: task.taskId, snapshot_id: captured.snapshotId });
  assert.equal(revised.snapshot.stale, true); assert.deepEqual(revised.snapshot.staleReasons, ['database-revision-changed']);
  assert.equal(revised.report.provenance.dbRevision, original.dbRevision);
  f.context.attachmentId = `attachment_${randomUUID()}`;
  const listed = f.workspace({ action: 'list' }); assert.equal(listed.tasks[0].staleObservations, 1);
  f.context.engine = 'ghidra';
  failure(() => f.workspace({ action: 'get', id: task.taskId }), 'INVESTIGATION_IDENTITY_MISMATCH');
});

test('long C++ symbol capture marks short metadata and retains the complete report name', t => {
  const f = fixture(t), task = f.create(), name = `namespace::${'TemplateArgument'.repeat(40)}`;
  const captured = f.capture(task.taskId, { name }); assert.equal(captured.ok, true);
  const entry = f.workspace({ action: 'get', id: task.taskId }).systemEvidence[0];
  assert.equal(entry.function.name.length, 256); assert.equal(entry.function.nameTruncated, true);
  const observed = f.workspace({ action: 'evidence', id: task.taskId, snapshot_id: captured.snapshotId });
  assert.equal(observed.report.function.name, name); assert.equal(observed.snapshot.function.nameTruncated, true);
});

test('report save failure exposes its stage without claiming a saved report or task link', t => {
  const f = fixture(t), task = f.create(), save = f.artifacts.save;
  f.artifacts.save = () => { throw Object.assign(new Error('injected report save failure'), { code: 'FIXTURE_SAVE_FAILURE' }); };
  let result;
  try { result = f.capture(task.taskId); } finally { f.artifacts.save = save; }
  assert.equal(result.ok, false); assert.equal(result.stage, 'report-save'); assert.equal(result.reportSaved, false); assert.equal(result.taskLinked, false);
  assert.equal(result.reportId, undefined); assert.equal(result.reportSha256, null); assert.equal(result.code, 'FIXTURE_SAVE_FAILURE');
  assert.match(result.note, /Partial report files may remain/);
  assert.equal(f.recordFiles().length, 0); assert.equal(f.workspace({ action: 'get', id: task.taskId }).taskRevision, 0);
});

test('post-save metadata failure preserves report identity and explicitly leaves task unlinked', t => {
  const f = fixture(t), task = f.create(), metadata = f.artifacts.metadata;
  f.artifacts.metadata = () => { throw Object.assign(new Error('injected metadata verification failure'), { code: 'FIXTURE_METADATA_FAILURE' }); };
  let result;
  try { result = f.capture(task.taskId); } finally { f.artifacts.metadata = metadata; }
  assert.equal(result.ok, false); assert.equal(result.stage, 'report-verify'); assert.equal(result.reportSaved, true); assert.equal(result.taskLinked, false);
  assert.match(result.reportId, /^[a-f0-9-]{36}$/); assert.equal(result.reportSha256, null); assert.equal(result.code, 'FIXTURE_METADATA_FAILURE');
  assert.equal(f.artifacts.get(result.reportId).kind, 'function-dossier'); assert.equal(f.recordFiles().length, 1);
  assert.equal(f.workspace({ action: 'get', id: task.taskId }).taskRevision, 0);
  assert.deepEqual(f.workspace({ action: 'get', id: task.taskId }).systemEvidence, []);
});

test('task-link failure reports its retained report and checked hash without implying cross-file rollback', t => {
  const f = fixture(t), task = f.create(), recordSnapshot = f.mgr.investigations.recordSnapshot;
  f.mgr.investigations.recordSnapshot = () => { throw Object.assign(new Error('injected task linkage failure'), { code: 'FIXTURE_LINK_FAILURE' }); };
  let result;
  try { result = f.capture(task.taskId); } finally { f.mgr.investigations.recordSnapshot = recordSnapshot; }
  assert.equal(result.ok, false); assert.equal(result.stage, 'task-link'); assert.equal(result.reportSaved, true); assert.equal(result.taskLinked, false);
  assert.equal(result.code, 'FIXTURE_LINK_FAILURE'); assert.match(result.reportSha256, /^[a-f0-9]{64}$/);
  assert.equal(f.artifacts.metadata(result.reportId).result.recordSha256, result.reportSha256);
  assert.equal(f.workspace({ action: 'get', id: task.taskId }).taskRevision, 0);
  assert.deepEqual(f.workspace({ action: 'get', id: task.taskId }).systemEvidence, []);
});

test('system evidence budget failure retains all prior links and discloses the extra report', t => {
  const f = fixture(t), task = f.create();
  for (let index = 0; index < 64; index++) assert.equal(f.capture(task.taskId, { salt: String(index) }).ok, true);
  const result = f.capture(task.taskId, { salt: 'overflow' });
  assert.equal(result.ok, false); assert.equal(result.code, 'INVESTIGATION_EVIDENCE_LIMIT'); assert.equal(result.stage, 'task-link');
  assert.equal(result.reportSaved, true); assert.equal(result.taskLinked, false);
  assert.equal(f.recordFiles().length, 65); assert.equal(f.artifacts.metadata(result.reportId).result.recordSha256, result.reportSha256);
  const unchanged = f.workspace({ action: 'get', id: task.taskId });
  assert.equal(unchanged.systemEvidence.length, 64); assert.equal(unchanged.taskRevision, 64);
});

test('a valid report hash cannot authorize a report from another scope under a task reference', t => {
  const f = fixture(t), task = f.create(), captured = f.capture(task.taskId), foreignHash = hash('another sample');
  const foreignContext = { ...f.context, projectId: `project_${randomUUID()}`, artifactId: `artifact_${foreignHash}`, sha256: foreignHash, attachmentId: `attachment_${randomUUID()}` };
  const foreign = syntheticDossier(foreignContext), report = f.artifacts.save({ kind: 'function-dossier', action: 'capture', association: foreignContext, result: foreign });
  const reportHash = f.artifacts.metadata(report.id).result.recordSha256;
  // Simulate an internal mislink with valid UUID/hash fields and unchanged task scope.
  // This is not a public caller path; it isolates report-scope validation from hashing.
  f.mgr.investigations.metadata.updateInvestigationRecords(records => {
    const entry = records[task.taskId].systemEvidence[0];
    entry.report_id = report.id; entry.report_sha256 = reportHash; entry.digest = foreign.snapshotDigest;
  });
  const stored = f.workspace({ action: 'get', id: task.taskId });
  assert.equal(stored.scope.artifactId, f.context.artifactId); assert.equal(stored.systemEvidence[0].report_sha256, reportHash);
  assert.equal(f.artifacts.get(report.id).result.snapshotDigest, stored.systemEvidence[0].digest);
  failure(() => f.workspace({ action: 'evidence', id: task.taskId, snapshot_id: captured.snapshotId }), 'ARTIFACT_CHANGED');
  // Even a duplicate-looking system capture cannot bless the mismatched report.
  const duplicateProbe = { ...syntheticDossier(f.context), snapshotDigest: foreign.snapshotDigest };
  failure(() => captureDossier(f.mgr, f.cfg, duplicateProbe, task.taskId, f.execution), 'ARTIFACT_CHANGED');
});

test('report bytes and claimed digest changes reject historical evidence and duplicate reuse', t => {
  const f = fixture(t), task = f.create(), captured = f.capture(task.taskId);
  const filename = path.join(f.artifacts.root, 'records', `${captured.reportId}.json`);
  const data = JSON.parse(fs.readFileSync(filename, 'utf8')); data.result.sections.decompile.data.code = 'tampered fixture text';
  fs.writeFileSync(filename, JSON.stringify(data));
  failure(() => f.workspace({ action: 'evidence', id: task.taskId, snapshot_id: captured.snapshotId }), 'ARTIFACT_CHANGED');
  failure(() => f.capture(task.taskId), 'ARTIFACT_CHANGED');
  assert.equal(f.workspace({ action: 'get', id: task.taskId }).systemEvidence.length, 1);
});

test('cancelled, unowned or mismatched captures cannot write reports or certify observations', t => {
  const f = fixture(t), task = f.create(), dossier = syntheticDossier(f.context);
  failure(() => captureDossier(f.mgr, f.cfg, dossier, task.taskId, {}), 'AGENT_SCOPE_REQUIRED');
  f.mgr.cancelled = true;
  failure(() => f.capture(task.taskId), 'ABORT_ERR');
  f.mgr.cancelled = false;
  const foreign = { ...f.context, provider: 'commercial' };
  failure(() => captureDossier(f.mgr, f.cfg, syntheticDossier(foreign), task.taskId, f.execution), 'INVESTIGATION_IDENTITY_MISMATCH');
  assert.equal(f.recordFiles().length, 0); assert.equal(f.workspace({ action: 'get', id: task.taskId }).taskRevision, 0);
});
