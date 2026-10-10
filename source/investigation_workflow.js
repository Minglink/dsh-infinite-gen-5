import { InvestigationStore } from './investigation_store.js';
import { jsonToolOutput } from './json_output.js';

export const workspaceSchema = {
  type: 'object', properties: {
    action: { type: 'string', enum: ['create', 'get', 'list', 'update', 'evidence'] },
    id: { type: 'string', description: 'Task UUID returned by create or list' },
    snapshot_id: { type: 'string', description: 'System snapshot UUID from this task; evidence action only' },
    expected_task_revision: { type: 'number', description: 'Required for update: use the returned taskRevision, independent of the database revision' },
    goal: { type: 'string', maxLength: 4096 },
    hypothesis: { type: 'string', maxLength: 4096, description: 'Caller statement, not verified evidence; do not include secrets' },
    next_step: { type: 'string', maxLength: 4096 },
    conclusion: { type: 'string', maxLength: 4096, description: 'Caller interpretation, not automatic verification' },
    status: { type: 'string', enum: ['active', 'paused', 'completed'], description: 'Caller-declared work progress' },
  }, required: ['action'], additionalProperties: false,
};

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
function store(mgr, cfg) { return mgr.investigations ||= new InvestigationStore({ root: cfg.projectRoot }); }
function context(mgr, args) {
  if (typeof args.target !== 'string' || !args.target.trim()) fail('INVALID_ARGUMENT', 'workspace requires an explicit opened target');
  const session = mgr.get(args.target);
  if (!mgr.alive(session) || session.engine === 'x64dbg') fail('INVALID_ARGUMENT', 'workspace requires an opened static target');
  mgr.checkCancelled();
  return mgr.evidence(session);
}
function actor(execution) {
  const id = execution?.agent?.id || execution?.agent?.sessionId;
  if (typeof id !== 'string' || !id.trim()) fail('AGENT_SCOPE_REQUIRED', 'Task changes require the executing agent identity');
  return id;
}
function fields(input, allowed) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('INVALID_ARGUMENT', 'workspace must be an object');
  for (const name of Object.keys(input)) if (!allowed.includes(name)) fail('INVALID_ARGUMENT', `workspace field is not valid for this action: ${name}`);
}
function validateSnapshotReport(snapshot, report) {
  const result = report?.result;
  const keys = ['projectId', 'artifactId', 'sha256', 'engine', 'provider', 'attachmentId', 'dbRevision'];
  if (report?.kind !== 'function-dossier' || result?.snapshotDigest !== snapshot.digest
    || keys.some(key => report.association?.[key] !== snapshot.context[key] || result.provenance?.[key] !== snapshot.context[key] || result._ig5?.[key] !== snapshot.context[key])
    || result.function?.ea !== snapshot.function.ea
    || JSON.stringify(Object.keys(result.sections || {}).sort()) !== JSON.stringify([...snapshot.sections].sort())) {
    fail('ARTIFACT_CHANGED', 'Stored report does not match the scope and function of this system observation');
  }
  if (snapshot.function.name !== undefined && (snapshot.function.nameTruncated
    ? result.function.name?.slice(0, 256) !== snapshot.function.name : result.function.name !== snapshot.function.name)) {
    fail('ARTIFACT_CHANGED', 'Stored report function name differs from the system observation');
  }
}

/** Called under the selected session queue. This changes analysis notes only. */
export function runWorkspace(mgr, cfg, args, execution) {
  if (args.toolset !== undefined || args.history !== undefined) fail('INVALID_ARGUMENT', 'Use workspace separately from toolset/history changes');
  const scope = context(mgr, args), notes = store(mgr, cfg), input = args.workspace;
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('INVALID_ARGUMENT', 'workspace must be an object');
  const { action, id } = input;
  if (action === 'create') {
    fields(input, ['action', 'goal', 'hypothesis', 'next_step']);
    const { action: unused, ...value } = input;
    return { workspace: notes.create(scope, value, actor(execution)) };
  }
  if (action === 'get') {
    fields(input, ['action', 'id']);
    return { workspace: notes.get(scope, id) };
  }
  if (action === 'list') {
    fields(input, ['action']);
    const result = notes.list(scope);
    return { workspace: { ...result, tasks: result.tasks.map(task => ({
      taskId: task.taskId, taskRevision: task.taskRevision, status: task.status,
      goal: task.goal.slice(0, 256), goalTruncated: task.goal.length > 256,
      observations: task.systemEvidence.length,
      staleObservations: task.systemEvidence.filter(entry => entry.stale).length,
      progressIsCallerDeclared: true,
    })) } };
  }
  if (action === 'update') {
    fields(input, ['action', 'id', 'expected_task_revision', 'goal', 'hypothesis', 'next_step', 'conclusion', 'status']);
    const { action: unused, id: unusedId, ...value } = input;
    return { workspace: notes.update(scope, id, value, actor(execution)) };
  }
  if (action === 'evidence') {
    fields(input, ['action', 'id', 'snapshot_id']);
    const task = notes.get(scope, id);
    const snapshot = task.systemEvidence.find(entry => entry.snapshot_id === input.snapshot_id);
    if (!snapshot) fail('INVALID_REF', 'Choose a system snapshot belonging to this task');
    const artifacts = mgr.analysis.artifacts;
    const metadata = artifacts.metadata(snapshot.report_id).result;
    if (metadata.recordSha256 !== snapshot.report_sha256) fail('ARTIFACT_CHANGED', 'Stored report digest differs from the task reference');
    const report = artifacts.get(snapshot.report_id);
    validateSnapshotReport(snapshot, report);
    return { workspace: { taskId: task.taskId, taskRevision: task.taskRevision, snapshot, report: report.result,
      note: 'Historical observations retain their original scope; stale observations require another capture.' } };
  }
  fail('INVALID_ARGUMENT', 'workspace action must be create, get, list, update or evidence');
}

/** Only a system-produced, queued dossier can reach this evidence-writing path. */
export function captureDossier(mgr, cfg, dossier, taskId, execution) {
  const notes = store(mgr, cfg), scope = dossier.provenance, agentId = actor(execution);
  const task = notes.get(scope, taskId);
  const existing = task.systemEvidence.find(entry => entry.digest === dossier.snapshotDigest);
  if (existing) {
    const meta = mgr.analysis.artifacts.metadata(existing.report_id).result;
    if (meta.recordSha256 !== existing.report_sha256) fail('ARTIFACT_CHANGED', 'Existing observation report has changed');
    validateSnapshotReport(existing, mgr.analysis.artifacts.get(existing.report_id));
    return { ok: true, taskId: task.taskId, taskRevision: task.taskRevision, snapshotId: existing.snapshot_id,
      reportId: existing.report_id, reportSha256: existing.report_sha256, duplicate: true };
  }
  mgr.checkCancelled();
  let record, reportSha256 = null, stage = 'report-save';
  try {
    record = mgr.analysis.artifacts.save({ kind: 'function-dossier', action: 'capture', association: scope,
      result: jsonToolOutput(dossier) });
    stage = 'report-verify';
    reportSha256 = mgr.analysis.artifacts.metadata(record.id).result.recordSha256;
    stage = 'task-link';
    const updated = notes.recordSnapshot(scope, taskId, { digest: dossier.snapshotDigest, report_id: record.id,
      report_sha256: reportSha256, function: { ea: dossier.function.ea,
        ...(dossier.function.name ? { name: dossier.function.name.slice(0, 256), ...(dossier.function.name.length > 256 ? { nameTruncated: true } : {}) } : {}) },
      sections: Object.keys(dossier.sections) }, agentId);
    const snapshot = updated.systemEvidence.find(entry => entry.digest === dossier.snapshotDigest);
    return { ok: true, taskId: updated.taskId, taskRevision: updated.taskRevision, snapshotId: snapshot.snapshot_id,
      reportId: snapshot.report_id, reportSha256: snapshot.report_sha256, duplicate: updated.snapshotDeduplicated === true,
      ...(updated.snapshotDeduplicated ? { unusedReportId: record.id, note: 'A concurrent capture already linked this observation; the additional saved report remains retained.' } : {}) };
  } catch (error) {
    // Report creation and task linkage are separate commits. Preserve that fact.
    return { ok: false, taskId, ...(record ? { reportId: record.id } : {}), reportSha256, reportSaved: !!record, taskLinked: false, stage,
      error: String(error.message).slice(0, 512), code: error.code || 'TASK_LINK_FAILED',
      note: record ? 'The report save returned successfully, but verification or task linkage failed. Read the task before retrying; no engine database was changed.'
        : 'Report saving did not complete. Partial report files may remain; no task link or engine database change was made.' };
  }
}
