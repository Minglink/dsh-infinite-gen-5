import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { ProjectStore } from './project_store.js';
import { normalizeHex } from './address_ref.js';
import { jsonToolOutput } from './json_output.js';

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const STATUSES = new Set(['active', 'paused', 'completed']);
const SECTIONS = new Set(['decompile', 'cfg', 'callers', 'callees', 'stack']);
const SCOPE = ['projectId', 'artifactId', 'sha256', 'engine', 'provider'];
const MAX_TASKS = 128, MAX_EVIDENCE = 64, MAX_TEXT = 4096;
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };

function plain(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('INVALID_INVESTIGATION', `${label} must be a plain object`);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || !fields.includes(key) || !descriptor.enumerable || !('value' in descriptor)) fail('INVALID_INVESTIGATION', `${label} has an unsupported field`);
  }
  return jsonToolOutput(value);
}
function text(value, label, { required = false, maximum = MAX_TEXT } = {}) {
  if (typeof value !== 'string' || value.length > maximum || value.includes('\0') || (required && !value.trim())) fail('INVALID_INVESTIGATION', `${label} must be ${required ? 'nonempty ' : ''}text of at most ${maximum} characters`);
  return value;
}
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) fail('INVALID_INVESTIGATION', `${label} must be a UUID`);
  return value;
}
function sha(value, label) {
  if (typeof value !== 'string' || !SHA.test(value)) fail('INVALID_INVESTIGATION', `${label} must be a SHA-256 digest`);
  return value;
}
function revision(value, label = 'expected_task_revision') {
  if (!Number.isSafeInteger(value) || value < 0) fail('INVALID_INVESTIGATION', `${label} must be a nonnegative safe integer`);
  return value;
}
function next(value) {
  if (value === Number.MAX_SAFE_INTEGER) fail('TASK_REVISION_OVERFLOW', 'Task revision cannot be incremented safely');
  return value + 1;
}
function validateScope(context) {
  if (typeof context.projectId !== 'string' || !context.projectId.startsWith('project_')) fail('INVALID_INVESTIGATION', 'projectId must identify an IG5 project');
  uuid(context.projectId.slice(8), 'projectId');
  sha(context.sha256, 'sha256');
  if (context.artifactId !== `artifact_${context.sha256}`) fail('INVESTIGATION_IDENTITY_MISMATCH', 'Artifact identity does not match its SHA-256');
  if (!['reverse', 'ghidra'].includes(context.engine) || !['ghidra', 'commercial'].includes(context.provider) || context.engine === 'ghidra' && context.provider !== 'ghidra') fail('INVALID_INVESTIGATION', 'Investigation context requires an explicit static engine/provider');
}
function contextOf(input) {
  const context = plain(input, [...SCOPE, 'target', 'attachmentId', 'dbRevision'], 'context');
  validateScope(context);
  if (typeof context.attachmentId !== 'string' || !context.attachmentId.startsWith('attachment_')) fail('INVALID_INVESTIGATION', 'attachmentId must identify an IG5 database attachment');
  uuid(context.attachmentId.slice(11), 'attachmentId');
  revision(context.dbRevision, 'dbRevision');
  return context;
}
const scopeOf = context => Object.fromEntries(SCOPE.map(key => [key, context[key]]));
function actor(value) { return text(value, 'actorId', { required: true, maximum: 256 }); }
function snapshotFunction(value) {
  const func = plain(value, ['ea', 'name', 'nameTruncated'], 'function');
  func.ea = normalizeHex(func.ea, 'function.ea');
  if (func.name !== undefined) text(func.name, 'function.name', { maximum: 256 });
  if (Object.hasOwn(func, 'nameTruncated') && (typeof func.nameTruncated !== 'boolean' || typeof func.name !== 'string' || func.name.length !== 256)) fail('INVALID_INVESTIGATION', 'function.nameTruncated requires a boolean flag and a 256-character name');
  return func;
}
function validateRecord(task, id) {
  try {
    plain(task, ['schemaVersion', 'taskId', 'taskRevision', 'scope', 'status', 'goal', 'hypothesis', 'next_step', 'conclusion', 'systemEvidence', 'createdAt', 'updatedAt', 'createdBy', 'updatedBy'], 'stored task');
    uuid(id, 'taskId'); revision(task.taskRevision, 'taskRevision');
    if (task.schemaVersion !== 1 || task.taskId !== id || !STATUSES.has(task.status) || !Array.isArray(task.systemEvidence) || task.systemEvidence.length > MAX_EVIDENCE) throw new Error('Invalid stored task');
    validateScope(plain(task.scope, SCOPE, 'stored scope'));
    text(task.goal, 'goal', { required: true });
    for (const field of ['hypothesis', 'next_step', 'conclusion']) text(task[field], field);
    actor(task.createdBy); actor(task.updatedBy);
    for (const field of ['createdAt', 'updatedAt']) if (typeof task[field] !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(task[field]) || !Number.isFinite(Date.parse(task[field]))) throw new Error('Invalid stored timestamp');
    const digests = new Set(), snapshots = new Set();
    for (const entry of task.systemEvidence) {
      plain(entry, ['snapshot_id', 'provenance', 'context', 'digest', 'report_id', 'report_sha256', 'function', 'sections', 'recordedAt', 'recordedBy'], 'stored snapshot');
      uuid(entry.snapshot_id, 'snapshot_id'); uuid(entry.report_id, 'report_id'); sha(entry.digest, 'digest'); sha(entry.report_sha256, 'report_sha256');
      const context = contextOf(entry.context);
      if (entry.provenance !== 'system-tool-snapshot' || SCOPE.some(key => context[key] !== task.scope[key]) || digests.has(entry.digest) || snapshots.has(entry.snapshot_id)) throw new Error('Invalid stored provenance');
      digests.add(entry.digest); snapshots.add(entry.snapshot_id);
      snapshotFunction(entry.function);
      if (!Array.isArray(entry.sections) || !entry.sections.length || entry.sections.length > SECTIONS.size || new Set(entry.sections).size !== entry.sections.length || entry.sections.some(section => !SECTIONS.has(section))) throw new Error('Invalid stored sections');
      actor(entry.recordedBy);
      if (typeof entry.recordedAt !== 'string' || !Number.isFinite(Date.parse(entry.recordedAt))) throw new Error('Invalid stored timestamp');
    }
  } catch { fail('INVESTIGATION_STORE_CORRUPT', 'Investigation metadata is invalid; no update was applied'); }
}
function taskOf(records, id, context) {
  uuid(id, 'taskId');
  if (!Object.hasOwn(records, id)) fail('INVESTIGATION_NOT_FOUND', 'Investigation task was not found');
  const task = records[id];
  validateRecord(task, id);
  if (SCOPE.some(key => task.scope?.[key] !== context[key])) fail('INVESTIGATION_IDENTITY_MISMATCH', 'Task belongs to another project, artifact, engine or provider');
  return task;
}
function view(task, context) {
  return jsonToolOutput({ ...structuredClone(task), progressIsCallerDeclared: true, statementOrigin: 'caller-statement', systemEvidence: task.systemEvidence.map(entry => {
    const staleReasons = [];
    if (entry.context.attachmentId !== context.attachmentId) staleReasons.push('attachment-changed');
    if (entry.context.dbRevision !== context.dbRevision) staleReasons.push('database-revision-changed');
    return { ...structuredClone(entry), stale: staleReasons.length > 0, staleReasons };
  }) });
}

/** Task statements and immutable report references; never engine writes or execution. */
export class InvestigationStore {
  constructor({ root } = {}) {
    if (typeof root !== 'string' || !root.trim()) fail('INVALID_INVESTIGATION', 'Investigation root is required');
    this.metadata = new ProjectStore({ root: path.join(path.resolve(root), 'investigations') });
  }
  create(inputContext, input, actorId) {
    const context = contextOf(inputContext), values = plain(input, ['goal', 'hypothesis', 'next_step'], 'create'), by = actor(actorId);
    text(values.goal, 'goal', { required: true });
    for (const key of ['hypothesis', 'next_step']) if (values[key] !== undefined) text(values[key], key);
    return this.metadata.updateInvestigationRecords(records => {
      for (const [id, task] of Object.entries(records)) validateRecord(task, id);
      if (Object.values(records).filter(task => task.scope.artifactId === context.artifactId && task.scope.engine === context.engine).length >= MAX_TASKS) fail('INVESTIGATION_LIMIT', 'At most 128 tasks are retained per artifact and engine');
      const taskId = randomUUID(), now = new Date().toISOString();
      const task = records[taskId] = { schemaVersion: 1, taskId, taskRevision: 0, scope: scopeOf(context), status: 'active', goal: values.goal,
        hypothesis: values.hypothesis ?? '', next_step: values.next_step ?? '', conclusion: '', systemEvidence: [], createdAt: now, updatedAt: now, createdBy: by, updatedBy: by };
      return view(task, context);
    });
  }
  get(inputContext, id) {
    const context = contextOf(inputContext);
    return view(taskOf(this.metadata.readInvestigationRecords(), id, context), context);
  }
  list(inputContext) {
    const context = contextOf(inputContext), records = this.metadata.readInvestigationRecords();
    for (const [id, task] of Object.entries(records)) validateRecord(task, id);
    const tasks = Object.values(records).filter(task => SCOPE.every(key => task.scope?.[key] === context[key])).map(task => view(taskOf(records, task.taskId, context), context));
    tasks.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt) || a.taskId.localeCompare(b.taskId));
    return { scope: scopeOf(context), tasks, limit: MAX_TASKS, progressIsCallerDeclared: true, statementOrigin: 'caller-statement' };
  }
  update(inputContext, id, input, actorId) {
    const context = contextOf(inputContext), values = plain(input, ['expected_task_revision', 'status', 'goal', 'hypothesis', 'next_step', 'conclusion'], 'update'), by = actor(actorId);
    revision(values.expected_task_revision);
    if (Object.keys(values).length < 2) fail('INVALID_INVESTIGATION', 'Choose at least one task field to update');
    if (values.status !== undefined && !STATUSES.has(values.status)) fail('INVALID_INVESTIGATION', 'Invalid caller-declared task status');
    for (const key of ['goal', 'hypothesis', 'next_step', 'conclusion']) if (values[key] !== undefined) text(values[key], key, { required: key === 'goal' });
    return this.metadata.updateInvestigationRecords(records => {
      const task = taskOf(records, id, context);
      if (task.taskRevision !== values.expected_task_revision) fail('STALE_TASK_REVISION', 'Task changed; read its current revision before updating');
      for (const key of ['status', 'goal', 'hypothesis', 'next_step', 'conclusion']) if (values[key] !== undefined) task[key] = values[key];
      task.taskRevision = next(task.taskRevision); task.updatedAt = new Date().toISOString(); task.updatedBy = by;
      return view(task, context);
    });
  }
  /** Internal system channel only: callers cannot submit this object through public tools. */
  recordSnapshot(inputContext, id, input, actorId) {
    const context = contextOf(inputContext), values = plain(input, ['digest', 'report_id', 'report_sha256', 'function', 'sections'], 'snapshot'), by = actor(actorId);
    sha(values.digest, 'digest'); uuid(values.report_id, 'report_id'); sha(values.report_sha256, 'report_sha256');
    const func = snapshotFunction(values.function);
    if (!Array.isArray(values.sections) || !values.sections.length || values.sections.length > SECTIONS.size || new Set(values.sections).size !== values.sections.length || values.sections.some(section => !SECTIONS.has(section))) fail('INVALID_INVESTIGATION', 'Snapshot sections must name distinct supported dossier sections');
    return this.metadata.updateInvestigationRecords(records => {
      const task = taskOf(records, id, context);
      if (task.systemEvidence.some(entry => entry.digest === values.digest)) return { ...view(task, context), snapshotDeduplicated: true };
      if (task.systemEvidence.length >= MAX_EVIDENCE) fail('INVESTIGATION_EVIDENCE_LIMIT', 'At most 64 system snapshot references are retained per task');
      task.systemEvidence.push({ snapshot_id: randomUUID(), provenance: 'system-tool-snapshot', context: { ...scopeOf(context), attachmentId: context.attachmentId, dbRevision: context.dbRevision },
        digest: values.digest, report_id: values.report_id, report_sha256: values.report_sha256, function: func, sections: values.sections, recordedAt: new Date().toISOString(), recordedBy: by });
      task.taskRevision = next(task.taskRevision); task.updatedAt = new Date().toISOString(); task.updatedBy = by;
      return { ...view(task, context), snapshotDeduplicated: false };
    });
  }
}
