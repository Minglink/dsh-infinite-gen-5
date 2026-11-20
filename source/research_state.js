import path from 'node:path';
import fs from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { DiagnosticStore } from './diagnostic_store.js';
import { jsonToolOutput } from './json_output.js';
import { validatePropertyScope, propertyScopeSchema, PROPERTY_IDS } from './research_properties.js';
import { VM_CONTEXT_PROPERTY } from './evidence_adapters/vm_context.js';

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const SCOPE = ['projectId', 'artifactId', 'sha256', 'engine', 'provider'];
const CONTEXT = [...SCOPE, 'attachmentId', 'dbRevision'];
const MAX_BYTES = 256 * 1024;
class ResearchMetadata extends DiagnosticStore { get maximumBytes() { return 1024 * 1024; } }
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
export function researchDigest(value) {
  const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object'
    ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
  return createHash('sha256').update(JSON.stringify(canonical(jsonToolOutput(value)))).digest('hex');
}
export const researchScopeDigest = scope => researchDigest(Object.fromEntries(SCOPE.map(k => [k, scope[k]])));
function object(value, keys, label) {
  const v = jsonToolOutput(value);
  if (!v || Array.isArray(v) || typeof v !== 'object' || Object.keys(v).some(k => !keys.includes(k))) fail('INVALID_RESEARCH', `${label}: unsupported object fields`);
  return v;
}
function text(v, label, required = true, maximum = 2048) {
  if (typeof v !== 'string' || v.includes('\0') || v.length > maximum || required && !v.trim()) fail('INVALID_RESEARCH', `${label}: bounded text required`);
  return v;
}
function id(v) { if (typeof v !== 'string' || !UUID.test(v)) fail('INVALID_RESEARCH', 'UUID required'); return v; }
function revision(v) { if (!Number.isSafeInteger(v) || v < 0) fail('INVALID_RESEARCH', 'Nonnegative revision required'); return v; }
function hash(v) { if (typeof v !== 'string' || !SHA.test(v)) fail('INVALID_RESEARCH', 'SHA-256 required'); return v; }
function refs(v, maximum = 32) {
  if (!Array.isArray(v) || v.length > maximum || new Set(v).size !== v.length) fail('INVALID_RESEARCH', 'Distinct bounded UUID references required');
  return v.map(id);
}
function known(ids, rows) { if (ids.some(value => !rows.some(row => row.id === value))) fail('INVALID_RESEARCH_REF', 'Reference does not belong to this research state'); }
function contract(value) {
  const v = object(value, ['question', 'inputDomain', 'returns', 'outputs', 'sideEffects', 'environment', 'exclusions'], 'contract');
  for (const k of ['question', 'inputDomain', 'returns', 'outputs', 'sideEffects', 'environment', 'exclusions']) text(v[k], k);
  return v;
}
function hypothesis(value, state) {
  const v = object(value, ['proposition', 'supporting', 'opposing', 'competingExplanations'], 'hypothesis');
  text(v.proposition, 'proposition'); refs(v.supporting); refs(v.opposing);
  if (state) known([...v.supporting, ...v.opposing], state.evidenceLinks);
  if (!Array.isArray(v.competingExplanations) || v.competingExplanations.length > 8) fail('INVALID_RESEARCH', 'At most eight competing explanations');
  v.competingExplanations.forEach(x => text(x, 'competing explanation', true, 512));
  return v;
}
function obligation(value, state) {
  const v = object(value, ['property', 'dependencies', 'scope', 'verifier', 'propertyScope'], 'obligation');
  text(v.property, 'property'); text(v.scope, 'scope'); text(v.verifier, 'verifier', true, 128);
  if(v.propertyScope!==undefined)validatePropertyScope(v.propertyScope);
  // Dependencies can only point to existing obligations: a new row cannot create a cycle.
  refs(v.dependencies, 64); if (state) known(v.dependencies, state.obligations);
  return v;
}
export const EXPERIMENT_TEMPLATES = Object.freeze(['refresh-static-source', 'review-evidence', 'compare-inputs', 'inspect-counterexample', 'locate-first-divergence']);
const boundedText = { type: 'string', minLength: 1, maxLength: 2048 };
const references = { type: 'array', maxItems: 32, uniqueItems: true, items: { type: 'string', pattern: UUID.source } };
const shape = properties => ({ type: 'object', properties, required: Object.keys(properties), additionalProperties: false });
export const researchMutationSchema = shape({
  operation: { type: 'string', enum: ['initialize', 'set-contract', 'add-hypothesis', 'add-obligation', 'add-experiment', 'revise-hypothesis', 'revise-obligation', 'revise-experiment', 'acknowledge-context', 'link-evidence', 'link-vm-context', 'link-verifier-evidence'] },
  expected_research_revision: { type: 'integer', minimum: 0 },
  expected_task_revision: { type: 'integer', minimum: 0 },
  scope_digest: { type: 'string', pattern: SHA.source },
});
researchMutationSchema.properties.entity_id = { type: 'string', pattern: UUID.source };
researchMutationSchema.properties.value = { oneOf: [
  shape(Object.fromEntries(['question', 'inputDomain', 'returns', 'outputs', 'sideEffects', 'environment', 'exclusions'].map(k => [k, boundedText]))),
  shape({ proposition: boundedText, supporting: references, opposing: references,
    competingExplanations: { type: 'array', maxItems: 8, items: { type: 'string', minLength: 1, maxLength: 512 } } }),
  { ...shape({ property: boundedText, dependencies: { ...references, maxItems: 64 }, scope: boundedText, verifier: { type: 'string', minLength: 1, maxLength: 128 } }), properties: {property:boundedText,dependencies:{...references,maxItems:64},scope:boundedText,verifier:{type:'string',minLength:1,maxLength:128},propertyScope:propertyScopeSchema} },
  shape({ template: { type: 'string', enum: [...EXPERIMENT_TEMPLATES] }, question: boundedText, inputs: references, hypotheses: references,
    obligations: { ...references, maxItems: 64 }, predictedDivergence: boundedText,
    budget: shape({ toolCalls: { type: 'integer', minimum: 1, maximum: 32 }, timeoutMs: { type: 'integer', minimum: 1, maximum: 60000 }, bytes: { type: 'integer', minimum: 1, maximum: 8388608 } }) }),
] };
function experiment(value, state) {
  const v = object(value, ['template', 'question', 'inputs', 'hypotheses', 'obligations', 'budget', 'predictedDivergence'], 'experiment');
  if (!EXPERIMENT_TEMPLATES.includes(v.template)) fail('INVALID_RESEARCH', 'Unknown fixed experiment template');
  text(v.question, 'question'); text(v.predictedDivergence, 'predictedDivergence');
  refs(v.inputs); refs(v.hypotheses); refs(v.obligations, 64);
  if (state) { known(v.inputs, state.evidenceLinks); known(v.hypotheses, state.hypotheses); known(v.obligations, state.obligations); }
  v.budget = object(v.budget, ['toolCalls', 'timeoutMs', 'bytes'], 'budget');
  for (const [k, max] of Object.entries({ toolCalls: 32, timeoutMs: 60000, bytes: 8 * 1024 * 1024 })) {
    if (!Number.isSafeInteger(v.budget[k]) || v.budget[k] < 1 || v.budget[k] > max) fail('INVALID_RESEARCH', `Invalid experiment ${k} budget`);
  }
  return v;
}
/** Runtime validation is independent of the host's JSON-schema enforcement. */
export function validateResearchMutation(input) {
  const v = object(input, ['operation', 'expected_research_revision', 'expected_task_revision', 'scope_digest', 'entity_id', 'value'], 'research mutation');
  revision(v.expected_task_revision); revision(v.expected_research_revision); hash(v.scope_digest);
  if (!researchMutationSchema.properties.operation.enum.includes(v.operation)) fail('INVALID_RESEARCH', 'Unknown research operation');
  if (v.operation.startsWith('revise-')) id(v.entity_id);
  else if (v.entity_id !== undefined) fail('INVALID_RESEARCH', 'entity_id is only valid for proposal revisions');
  if (['initialize', 'set-contract'].includes(v.operation)) contract(v.value);
  else if (v.operation.endsWith('hypothesis')) hypothesis(v.value, null);
  else if (v.operation.endsWith('obligation')) obligation(v.value, null);
  else if (v.operation.endsWith('experiment')) experiment(v.value, null);
  else if (v.value !== undefined) fail('INVALID_RESEARCH', 'This operation takes no caller value');
  return v;
}
function validate(state, task) {
  try {
    object(state, ['schema', 'taskId', 'scope', 'scopeDigest', 'researchRevision', 'taskRevision', 'context', 'contracts', 'contractDigest', 'contractRevision', 'hypotheses', 'obligations', 'experiments', 'evidenceLinks', 'verificationRefs', 'createdAt', 'updatedAt', 'updatedBy'], 'state');
    if (!['ig5-research-state-v1', 'ig5-research-state-v2'].includes(state.schema) || state.taskId !== task.taskId || researchScopeDigest(state.scope) !== state.scopeDigest || state.scopeDigest !== researchScopeDigest(task.scope)) throw Error();
    if (state.schema === 'ig5-research-state-v1' && state.verificationRefs !== undefined || state.schema === 'ig5-research-state-v2' && !Array.isArray(state.verificationRefs)) throw Error();
    revision(state.researchRevision); revision(state.taskRevision);
    object(state.scope, SCOPE, 'scope'); object(state.context, CONTEXT, 'context');
    if (SCOPE.some(k => state.context[k] !== state.scope[k])) throw Error();
    id(state.context.attachmentId?.slice(11)); revision(state.context.dbRevision);
    for (const k of ['createdAt', 'updatedAt']) if (typeof state[k] !== 'string' || !Number.isFinite(Date.parse(state[k]))) throw Error();
    text(state.updatedBy, 'actor', true, 256);
    if (!Array.isArray(state.contracts) || !state.contracts.length || state.contracts.length > 64) throw Error();
    state.contracts.forEach(c => { object(c, ['digest', 'value'], 'contract version'); if (researchDigest(contract(c.value)) !== c.digest) throw Error(); });
    if (state.contractRevision !== state.contracts.length - 1 || state.contracts.at(-1).digest !== state.contractDigest) throw Error();
    const allIds = new Set();
    for (const [key, max] of Object.entries({ hypotheses: 32, obligations: 64, experiments: 128, evidenceLinks: 256 })) {
      if (!Array.isArray(state[key]) || state[key].length > max) throw Error();
      for (const row of state[key]) {
        id(row.id); hash(row.contractDigest); revision(row.contractRevision);
        if (allIds.has(row.id) || state.contracts[row.contractRevision]?.digest !== row.contractDigest) throw Error();
        allIds.add(row.id);
        if (key === 'evidenceLinks') {
          if (['vm-function-assessment','vm-role-validation'].includes(row.kind)) {
            if(state.schema!=='ig5-research-state-v2')throw Error();
            object(row,['id','contractDigest','contractRevision','kind','assurance','reportId','sha256','targetSha256','dependencyType','parents','supportedProperties','propertyScopes','limitations'],'fixed evidence link');
            id(row.reportId);hash(row.sha256);
            if(row.targetSha256!==task.scope.sha256||row.assurance!=='committed-fixed-property-inputs'||row.dependencyType!=='immutable-bytes'
              ||!Array.isArray(row.parents)||row.parents.length>48||!Array.isArray(row.supportedProperties)||!row.supportedProperties.length||row.supportedProperties.some(p=>!PROPERTY_IDS.includes(p)))throw Error();
            for(const parent of row.parents){object(parent,['id','sha256','kind'],'fixed parent');id(parent.id);hash(parent.sha256);text(parent.kind,'kind',true,128);}
            object(row.propertyScopes,row.supportedProperties,'typed scopes');
            Object.values(row.propertyScopes).forEach(validatePropertyScope);
            if(researchDigest(row.limitations)!==researchDigest(['Exact structured scope only; no whole-function, universal CPU or unexecuted native-input acceptance.']))throw Error();
          } else if (row.kind === 'vm-context-model') {
            if (state.schema !== 'ig5-research-state-v2') throw Error();
            object(row, ['id', 'contractDigest', 'contractRevision', 'kind', 'assurance', 'reportId', 'sha256', 'targetSha256', 'dependencyType', 'parents', 'supportedProperties', 'limitations'], 'VM evidence link');
            id(row.reportId); hash(row.sha256);
            if (row.assurance !== 'committed-candidate-input-integrity' || row.targetSha256 !== task.scope.sha256 || row.dependencyType !== 'immutable-bytes'
              || !Array.isArray(row.parents) || !row.parents.length || row.parents.length > 48 || new Set(row.parents.map(p => p.id)).size !== row.parents.length
              || researchDigest(row.supportedProperties) !== researchDigest([VM_CONTEXT_PROPERTY])
              || researchDigest(row.limitations) !== researchDigest(['Only committed context/handlers/recurrence/selection bytes; earlier capture, decoder and CPU semantics are premises.', 'No VM-role, phase, bytecode-program or function-contract acceptance.'])) throw Error();
            for (const parent of row.parents) {
              object(parent, ['id', 'sha256', 'kind'], 'VM parent'); id(parent.id); hash(parent.sha256);
              if (!['vm-recorded-handlers', 'vm-flow-recurrences', 'vm-handler-windows'].includes(parent.kind)) throw Error();
            }
          } else {
          object(row, ['id', 'contractDigest', 'contractRevision', 'kind', 'assurance', 'snapshotId', 'reportId', 'sha256', 'context', 'function', 'sections', 'supportedProperties', 'limitations'], 'evidence link');
          if (row.kind !== 'function-dossier' || row.assurance !== 'system-snapshot-integrity') throw Error();
          id(row.snapshotId); id(row.reportId); hash(row.sha256);
          object(row.context, CONTEXT, 'evidence context');
          const snapshot = task.systemEvidence.find(s => s.snapshot_id === row.snapshotId);
          if (!snapshot || snapshot.report_id !== row.reportId || snapshot.report_sha256 !== row.sha256
            || researchDigest(row.context) !== researchDigest(snapshot.context) || researchDigest(row.function) !== researchDigest(snapshot.function)
            || researchDigest(row.sections) !== researchDigest(snapshot.sections)
            || researchDigest(row.supportedProperties) !== researchDigest(['dossier-provenance-and-structure'])
            || researchDigest(row.limitations) !== researchDigest(['No semantic, execution, VM-role or function-contract acceptance.'])) throw Error();
          }
        } else {
          object(row, ['id', 'contractDigest', 'contractRevision', 'supersedes', 'value'], key);
          if (row.supersedes !== null) {
            id(row.supersedes);
            const previous = state[key].slice(0, state[key].indexOf(row));
            if (!previous.some(r => r.id === row.supersedes) || previous.some(r => r.supersedes === row.supersedes)) throw Error();
          }
          if (key === 'hypotheses') hypothesis(row.value, state);
          if (key === 'obligations') obligation(row.value, { ...state, obligations: state.obligations.slice(0, state.obligations.indexOf(row)) });
          if (key === 'experiments') experiment(row.value, state);
        }
      }
    }
    if (state.verificationRefs !== undefined) {
      if (!Array.isArray(state.verificationRefs) || state.verificationRefs.length > 128 || new Set(state.verificationRefs.map(r => r.reportId)).size !== state.verificationRefs.length) throw Error();
      for (const ref of state.verificationRefs) { object(ref, ['reportId', 'sha256'], 'verification reference'); id(ref.reportId); hash(ref.sha256); }
    }
    if (Buffer.byteLength(JSON.stringify(state)) > MAX_BYTES) throw Error();
  } catch { fail('RESEARCH_STORE_CORRUPT', 'Invalid research state; no update applied'); }
}
export function researchStaleness(state, task, context) {
  const reasons = [];
  if (state.taskRevision !== task.taskRevision) reasons.push('task-revision-changed');
  if (state.context.attachmentId !== context.attachmentId) reasons.push('attachment-changed');
  if (state.context.dbRevision !== context.dbRevision) reasons.push('database-revision-changed');
  return reasons;
}
function view(state, task, context) {
  const staleReasons = researchStaleness(state, task, context);
  return { ...structuredClone(state), stale: staleReasons.length > 0, staleReasons,
    objectStates: {
      hypotheses: state.hypotheses.map(h => ({ id: h.id, status: state.hypotheses.some(r => r.supersedes === h.id) ? 'superseded' : 'proposed', staleContract: h.contractRevision !== state.contractRevision })),
      obligations: state.obligations.map(o => ({ id: o.id, status: state.obligations.some(r => r.supersedes === o.id) ? 'superseded' : 'open', staleContract: o.contractRevision !== state.contractRevision })),
      experiments: state.experiments.map(e => ({ id: e.id, status: state.experiments.some(r => r.supersedes === e.id) ? 'superseded' : 'planned', staleContract: e.contractRevision !== state.contractRevision, resultRefs: [] })),
    },
    workStatus: task.status, acceptanceStatus: 'not-assessed', resourceStatus: 'retained-unknown',
    statementOrigin: 'caller-statement', executionAuthorized: false,
    note: 'Research proposals do not close obligations. Resource state must be checked with its original lifecycle owner.' };
}

/** Independent per-task CAS; old task schema and revision are untouched. */
export class ResearchState {
  constructor({ root }) { this.root = path.resolve(root); }
  metadata(taskId) { id(taskId); return new ResearchMetadata({ root: path.join(this.root, 'investigations', 'research-v1', taskId) }); }
  get(task, context) {
    id(task.taskId);
    if (!fs.existsSync(path.join(this.root, 'investigations', 'research-v1', task.taskId))) return null;
    const rows = this.metadata(task.taskId).readInvestigationRecords();
    if (!Object.keys(rows).length) return null;
    if (Object.keys(rows).length !== 1 || !Object.hasOwn(rows, task.taskId)) fail('RESEARCH_STORE_CORRUPT', 'Unexpected research task namespace');
    const state = rows[task.taskId]; validate(state, task); return view(state, task, context);
  }
  /** Internal verifier receipt association only. Complete results remain in AnalysisArtifacts. */
  linkVerification(task, context, expected, ref, actor) {
    revision(expected.expected_research_revision); revision(expected.expected_task_revision);
    if (expected.expected_task_revision !== task.taskRevision) fail('STALE_TASK_REVISION', 'Task changed during verification');
    if (expected.scope_digest !== researchScopeDigest(task.scope) || expected.scope_digest !== researchScopeDigest(context)) fail('RESEARCH_SCOPE_MISMATCH', 'Verifier target changed');
    id(ref.reportId); hash(ref.sha256); text(actor, 'actor', true, 256);
    return this.metadata(task.taskId).updateInvestigationRecords(rows => {
      const state = rows[task.taskId];
      if (!state) fail('RESEARCH_NOT_FOUND', 'Research state is missing');
      validate(state, task);
      if (state.researchRevision !== expected.expected_research_revision) fail('STALE_RESEARCH_REVISION', 'Research changed during verification; immutable result retained');
      if (researchStaleness(state, task, context).length) fail('STALE_RESEARCH_CONTEXT', 'Research context changed during verification');
      const refs = state.verificationRefs ??= [];
      if (refs.some(r => r.reportId === ref.reportId)) return view(state, task, context);
      if (refs.length >= 128) fail('RESEARCH_LIMIT', 'Verification reference limit reached');
      if (state.researchRevision === Number.MAX_SAFE_INTEGER) fail('RESEARCH_REVISION_OVERFLOW', 'Research revision exhausted');
      refs.push({ reportId: ref.reportId, sha256: ref.sha256 }); state.researchRevision++;
      state.updatedAt = new Date().toISOString(); state.updatedBy = actor;
      if (Buffer.byteLength(JSON.stringify(state)) > MAX_BYTES) fail('RESEARCH_LIMIT', 'Research state exceeds 256 KiB');
      validate(state, task); return view(state, task, context);
    });
  }
  mutate(task, context, input, actor, { evidence = null } = {}) {
    const v = validateResearchMutation(input);
    text(actor, 'actor', true, 256); revision(v.expected_task_revision); revision(v.expected_research_revision);
    if (v.expected_task_revision !== task.taskRevision) fail('STALE_TASK_REVISION', 'Read current task revision before changing research');
    if (v.scope_digest !== researchScopeDigest(task.scope) || v.scope_digest !== researchScopeDigest(context)) fail('RESEARCH_SCOPE_MISMATCH', 'Research scope digest differs from current task/target');
    const allowed = ['initialize', 'set-contract', 'add-hypothesis', 'add-obligation', 'add-experiment', 'revise-hypothesis', 'revise-obligation', 'revise-experiment', 'acknowledge-context', 'link-evidence', 'link-vm-context', 'link-verifier-evidence'];
    if (!allowed.includes(v.operation)) fail('INVALID_RESEARCH', 'Unknown research operation');
    if (!v.operation.startsWith('revise-') && v.entity_id !== undefined) fail('INVALID_RESEARCH', 'entity_id is only valid for proposal revisions');
    const now = new Date().toISOString();
    return this.metadata(task.taskId).updateInvestigationRecords(rows => {
      let state = rows[task.taskId];
      if (Object.keys(rows).some(k => k !== task.taskId)) fail('RESEARCH_STORE_CORRUPT', 'Unexpected research task namespace');
      if (state) validate(state, task);
      if (v.operation === 'initialize') {
        if (state || v.expected_research_revision !== 0) fail('STALE_RESEARCH_REVISION', 'Research already exists or initial revision is not zero');
        const c = contract(v.value), d = researchDigest(c);
        state = { schema: 'ig5-research-state-v1', taskId: task.taskId, scope: task.scope, scopeDigest: v.scope_digest,
          researchRevision: 0, taskRevision: task.taskRevision, context: Object.fromEntries(CONTEXT.map(k => [k, context[k]])),
          contracts: [{ digest: d, value: c }], contractDigest: d, contractRevision: 0, hypotheses: [], obligations: [], experiments: [], evidenceLinks: [], createdAt: now, updatedAt: now, updatedBy: actor };
      } else {
        if (!state) fail('RESEARCH_NOT_FOUND', 'Initialize research first');
        if (state.researchRevision !== v.expected_research_revision) fail('STALE_RESEARCH_REVISION', 'Research changed; reread before updating');
        if (state.researchRevision === Number.MAX_SAFE_INTEGER) fail('RESEARCH_REVISION_OVERFLOW', 'Research revision exhausted');
        if (v.operation !== 'acknowledge-context' && researchStaleness(state, task, context).length) fail('STALE_RESEARCH_CONTEXT', 'Review changes, then explicitly acknowledge current context');
        if (v.operation === 'set-contract') {
          const c = contract(v.value), d = researchDigest(c);
          if (d === state.contractDigest) fail('INVALID_RESEARCH', 'Contract is unchanged');
          if (state.contracts.length >= 64) fail('RESEARCH_LIMIT', 'Contract history limit reached; no history was discarded');
          state.contracts.push({ digest: d, value: c }); state.contractDigest = d; state.contractRevision = state.contracts.length - 1;
        } else if (v.operation === 'acknowledge-context') {
          if (v.value !== undefined) fail('INVALID_RESEARCH', 'Context acknowledgment takes no caller value');
          state.taskRevision = task.taskRevision; state.context = Object.fromEntries(CONTEXT.map(k => [k, context[k]]));
        } else if (['link-evidence','link-vm-context','link-verifier-evidence'].includes(v.operation)) {
          if (!evidence) fail('INVALID_RESEARCH', 'Evidence requires the fixed system adapter');
          if (v.value !== undefined) fail('INVALID_RESEARCH', 'Caller cannot supply an evidence object');
          if(v.operation==='link-verifier-evidence'&&!['vm-function-assessment','vm-role-validation'].includes(evidence.kind))fail('INVALID_RESEARCH','No fixed property evidence adapter');
          if ((v.operation === 'link-vm-context') !== (evidence.kind === 'vm-context-model')) fail('INVALID_RESEARCH', 'Evidence type differs from fixed operation');
          if (['link-vm-context','link-verifier-evidence'].includes(v.operation) && state.schema === 'ig5-research-state-v1') { state.schema = 'ig5-research-state-v2'; state.verificationRefs = []; }
          if (state.evidenceLinks.some(e => e.kind === evidence.kind && e.reportId === evidence.reportId && e.contractRevision === state.contractRevision)) fail('RESEARCH_DUPLICATE', 'Evidence already linked to this contract');
          if (state.evidenceLinks.length >= 256) fail('RESEARCH_LIMIT', 'Evidence link limit reached');
          state.evidenceLinks.push({ ...evidence, id: randomUUID(), contractDigest: state.contractDigest, contractRevision: state.contractRevision });
        } else {
          const kind = v.operation.replace('revise-', 'add-');
          const [key, limit, check] = kind === 'add-hypothesis' ? ['hypotheses', 32, hypothesis]
            : kind === 'add-obligation' ? ['obligations', 64, obligation] : ['experiments', 128, experiment];
          if (state[key].length >= limit) fail('RESEARCH_LIMIT', `${key} limit reached; no unresolved rows were discarded`);
          let supersedes = null;
          if (v.operation.startsWith('revise-')) {
            supersedes = id(v.entity_id);
            if (!state[key].some(r => r.id === supersedes) || state[key].some(r => r.supersedes === supersedes)) fail('INVALID_RESEARCH_REF', 'Choose an unsuperseded proposal in this task');
          }
          state[key].push({ supersedes, id: randomUUID(), contractDigest: state.contractDigest, contractRevision: state.contractRevision, value: check(v.value, state) });
        }
        state.researchRevision++;
      }
      state.updatedAt = now; state.updatedBy = actor;
      if (Buffer.byteLength(JSON.stringify(state)) > MAX_BYTES) fail('RESEARCH_LIMIT', 'Research state exceeds 256 KiB; no write applied');
      validate(state, task); rows[task.taskId] = state;
      return view(state, task, context);
    });
  }
}
