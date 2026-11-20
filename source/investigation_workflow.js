import {cffActions,validateCffInput,runCffWorkflow} from './cff_workflow.js';
import { investigationResume } from './investigation_resume.js';
import { caseIndexActions, runCaseIndex, validateCaseIndexInput } from './research_case_bridge.js';
import { methodActions, runMethodQuery, validateMethodInput } from './method_applicability.js';
import { runExperimentShadow, validateShadowInput } from './experiment_shadow.js';
import { candidateActions, validateCandidateInput, runCandidateWorkflow, bitvectorASTSchema } from './candidate_workflow.js';
import { LiftJobs } from './lift_jobs.js';
import { InvestigationStore } from './investigation_store.js';
import { planningContext, investigationPlan } from './investigation_planning.js';
import { jsonToolOutput } from './json_output.js';
import { capabilityCatalog } from './capability_catalog.js';
import { investigationBrief } from './investigation_brief.js';
import { validateSnapshotReport } from './evidence_adapters/dossier.js';
import { ResearchState, researchScopeDigest, researchMutationSchema, researchDigest, validateResearchMutation } from './research_state.js';
import { linkDossierEvidence, inspectResearchEvidence } from './evidence_registry.js';
import { evidenceDependencies } from './evidence_dependencies.js';
import { vmContextEvidence, exactReportRef } from './evidence_adapters/vm_context.js';
import { fixedPropertyEvidence } from './evidence_adapters/fixed_properties.js';
import { verifyResearch, verificationOverlay, loadVerification, readVerificationReport, verificationRequestSchema, validateVerificationRequest } from './verification_registry.js';
import { RootInvestigationStore, renderDeterministicRootBrief } from './investigation_root.js';
import { assessRootInvestigation } from './investigation_assessment.js';
import { planRootInvestigation } from './experiment_planner.js';

export const rootWorkspaceActions = [
  'root-create', 'root-get', 'root-list', 'root-update', 'root-control',
  'root-brief', 'root-plan', 'root-resume',
  'select', 'evaluate', 'assess', 'recover-receipts',
  'delegate-brief', 'accept-child-finding',
];

export const workspaceSchema = {
  type: 'object', properties: {
    action: { type: 'string', enum: ['create', 'get', 'brief', 'list', 'update', 'evidence', 'handoff', 'claim', 'submit', 'review', 'plan', 'resume', 'research-get', 'research-update', 'research-dependencies', 'research-verify', 'research-link-verification', 'research-verification', ...caseIndexActions, ...methodActions, 'experiment-shadow', ...candidateActions, ...cffActions, ...rootWorkspaceActions] },
    root: { type: 'object', additionalProperties: true },
    include_task: { type: 'boolean', description: 'Return full task snapshot' },
    source_ref: { type:'object',properties:{id:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['id','sha256'],additionalProperties:false },
    verification_ref: { type:'object',properties:{id:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['id','sha256'],additionalProperties:false },
    candidate_ref: { type:'object',properties:{id:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['id','sha256'],additionalProperties:false },
    root_node: { type:'integer',minimum:0,maximum:2047 },
    candidate_ast: bitvectorASTSchema,
    premise: bitvectorASTSchema,
    mode: { type: 'string', enum: ['off','shadow'] },
    method_id: { type: 'string', maxLength: 64 },
    query: { type: 'string', minLength: 1, maxLength: 256 },
    ref: { type: 'object', properties: { id: { type: 'string', maxLength: 64 }, sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' } }, required: ['id','sha256'], additionalProperties: false },
    generation: { type: 'string' },
    expected_generation: { type: 'string' },
    expected_research_revision: { type: 'integer', minimum: 0 },
    research: researchMutationSchema,
    verification: verificationRequestSchema,
    report_ref: { type: 'object', properties: { id: { type: 'string' }, sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' } }, required: ['id', 'sha256'], additionalProperties: false },
    verification_id: { type: 'string' },
    evidence_id: { type: 'string' },
    max_bytes: { type: 'integer', minimum: 4096, maximum: 32768 },
    cursor: { type: 'string' },
    handoff_id: { type: 'string' },
    question: { type: 'string', maxLength: 2048 },
    acceptance: { type: 'string', maxLength: 2048 },
    constraints: { type: 'string', maxLength: 2048 },
    snapshot_ids: { type: 'array', minItems: 1, maxItems: 8, uniqueItems: true, items: { type: 'string' } },
    id: { type: 'string' },
    snapshot_id: { type: 'string' },
    expected_task_revision: { type: 'number' },
    goal: { type: 'string', maxLength: 4096 },
    hypothesis: { type: 'string', maxLength: 4096 },
    next_step: { type: 'string', maxLength: 4096 },
    conclusion: { type: 'string', maxLength: 4096 },
    status: { type: 'string', enum: ['active', 'paused', 'completed'] },
  }, required: ['action'], additionalProperties: false,
};

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
function store(mgr, cfg) { return mgr.investigations ||= new InvestigationStore({ root: cfg.projectRoot }); }
export function rootStore(mgr, cfg) { return mgr.rootInvestigations ||= new RootInvestigationStore({ projectRoot: cfg.projectRoot }); }
function research(mgr, cfg) { return mgr.researchState ||= new ResearchState({ root: cfg.projectRoot }); }

function summarizeDeliverables(deliverables) {
  if (!Array.isArray(deliverables)) return [];
  return deliverables.map(d => ({
    id: d.id,
    kind: d.kind,
    requiredObservations: d.requiredObservations,
    minDistinctInputs: d.minDistinctInputs,
    holdoutRequired: d.holdoutRequired,
    nonCooperativeRequired: d.nonCooperativeRequired,
    candidateRevision: d.candidateRevision ?? 0,
    hasCandidate: Boolean(d.candidateExplanation),
    ruleSha256: d.candidateExplanation?.ruleSha256 ?? null,
  }));
}

function summarizeComponents(components) {
  if (!Array.isArray(components)) return [];
  return components.map(c => ({
    componentId: c.componentId,
    role: c.role,
    path: c.path,
    sha256: c.sha256,
    bytes: c.bytes,
    format: c.format,
    parentComponentId: c.parentComponentId ?? null,
    ipcChannel: c.ipcChannel ?? null,
    requiresParentOrIpc: Boolean(c.requiresParentOrIpc),
  }));
}

export function summarizeRootTask(task) {
  if (!task || typeof task !== 'object') return null;
  const deliverables = summarizeDeliverables(task.deliverables);
  const rawReceipts = Array.isArray(task.receipts) ? task.receipts : Object.values(task.receipts || {});
  return {
    rootId: task.rootId,
    revision: task.revision,
    planRevision: task.planRevision ?? null,
    status: task.status ?? (task.terminalFinding ? 'terminal' : 'active'),
    origin: task.origin ?? null,
    deliverables,
    counts: {
      deliverables: deliverables.length,
      components: Array.isArray(task.components) ? task.components.length : 0,
      scenarios: Array.isArray(task.scenarios) ? task.scenarios.length : 0,
      questions: Array.isArray(task.questions) ? task.questions.length : 0,
      routes: Array.isArray(task.routes) ? task.routes.length : 0,
      experiments: Array.isArray(task.experiments) ? task.experiments.length : 0,
      receipts: rawReceipts.length,
    },
    recentSuccessReceiptIds: rawReceipts.filter(r => r.outcome === 'success').slice(-6).map(r => r.reportId || r.receiptId),
    hasCandidate: Boolean(task.candidate || deliverables.some(d => d.hasCandidate)),
    hasTerminalFinding: Boolean(task.terminalFinding),
  };
}

function resolveRootSessionSubject(mgr, execution) {
  if (mgr.coordination) {
    try {
      return mgr.coordination.resolveRootSubject(execution?.agent, {
        allowLocalFallback: execution?.agent?.session === undefined,
      }).rootId;
    } catch {
      return null;
    }
  }
  return execution?.agent?.id || null;
}

function runRootWorkspaceAction(mgr, cfg, input, execution) {
  const { action, id } = input;
  const rStore = rootStore(mgr, cfg);
  const rootSessionId = resolveRootSessionSubject(mgr, execution);
  const hostGoal = mgr.autonomyHost?.currentGoalForAgent?.(execution?.agent) || execution?.hostGoal || null;
  const payload = input.root || {};

  if (action === 'root-create') {
    fields(input, ['action', 'goal', 'root', 'include_task']);
    if (input.include_task !== undefined && typeof input.include_task !== 'boolean') {
      fail('INVALID_ARGUMENT', 'include_task must be a boolean');
    }
    const goalText = input.goal || payload.goal || hostGoal?.goal || '';
    const originKind = payload.origin?.kind || (hostGoal ? 'host-goal' : (execution?.agent?.session ? 'direct-human' : 'manual'));
    const created = rStore.create({
      rootSessionId,
      workspaceCwd: payload.workspaceCwd || execution?.agent?.session?.header?.cwd || null,
      goal: goalText,
      deliverables: payload.deliverables || [],
      origin: {
        kind: originKind,
        hostGoalId: payload.origin?.hostGoalId || hostGoal?.goalId || null,
        hostGoalRevision: payload.origin?.hostGoalRevision ?? hostGoal?.revision ?? null,
        hostGoalObjective: payload.origin?.hostGoalObjective || hostGoal?.goal || null,
      },
    });
    // Allow optional atomic initial setup of components, scenarios, questions, and routes in root-create
    // to reduce management call round-trips while enforcing identical registration & provenance checks!
    const initComps = [...(payload.component ? [payload.component] : []), ...(Array.isArray(payload.components) ? payload.components : [])];
    for (const c of initComps) rStore.registerComponent(created.rootId, c);
    const artifacts = mgr.analysis?.artifacts || null;
    if (Array.isArray(payload.prepareInputs) && payload.prepareInputs.length > 0) {
      rStore.prepareScenarioInputs(created.rootId, payload.prepareInputs, artifacts);
    }
    const initScens = [...(payload.scenario ? [payload.scenario] : []), ...(Array.isArray(payload.scenarios) ? payload.scenarios : [])];
    for (const s of initScens) rStore.upsertScenario(created.rootId, s, artifacts);
    const initQs = [...(payload.question ? [payload.question] : []), ...(Array.isArray(payload.questions) ? payload.questions : [])];
    for (const q of initQs) rStore.upsertQuestion(created.rootId, q);
    const initRts = [...(payload.route ? [payload.route] : []), ...(Array.isArray(payload.routes) ? payload.routes : [])];
    for (const r of initRts) rStore.upsertRoute(created.rootId, r);
    const fullTask = rStore.get(created.rootId);
    return {
      workspace: input.include_task === true
        ? fullTask
        : { ...summarizeRootTask(fullTask), created: true },
    };
  }
  if (action === 'root-get') {
    fields(input, ['action', 'id', 'include_task']);
    if (typeof id !== 'string' || !id.trim()) {
      fail('INVALID_ARGUMENT', 'workspace.id (root investigation UUID) is required: {"workspace":{"action":"root-get","id":"<rootId>"}}');
    }
    return { workspace: rStore.get(id) };
  }
  if (action === 'root-list') {
    fields(input, ['action', 'root']);
    return {
      workspace: {
        investigations: rStore.list({
          rootSessionId: payload.sessionOnly ? rootSessionId : null,
        }),
      },
    };
  }
  if (action === 'root-update') {
    fields(input, ['action', 'id', 'root', 'expected_task_revision', 'include_task']);
    if (input.include_task !== undefined && typeof input.include_task !== 'boolean') {
      fail('INVALID_ARGUMENT', 'include_task must be a boolean');
    }
    if (!input.root || typeof input.root !== 'object') fail('INVALID_ARGUMENT', 'root-update requires a root payload object');
    if (input.expected_task_revision !== undefined) {
      if (!Number.isSafeInteger(input.expected_task_revision) || input.expected_task_revision < 1) {
        fail('INVALID_ARGUMENT', 'expected_task_revision must be a positive integer matching current root revision');
      }
      const current = rStore.get(id);
      if (current.revision !== input.expected_task_revision) {
        fail('TASK_REVISION_MISMATCH', `expected_task_revision (${input.expected_task_revision}) does not match current root investigation revision (${current.revision})`);
      }
    }
    const updated = { deliverables: [], components: [], preparedInputs: [], scenarios: [], questions: [], routes: [], candidate: null, terminalFinding: null };
    const delivs = [...(payload.deliverable ? [payload.deliverable] : []), ...(Array.isArray(payload.deliverables) ? payload.deliverables : [])];
    for (const d of delivs) updated.deliverables.push(rStore.upsertDeliverable(id, d));
    const comps = [...(payload.component ? [payload.component] : []), ...(Array.isArray(payload.components) ? payload.components : [])];
    for (const c of comps) updated.components.push(rStore.registerComponent(id, c));
    const artifacts = mgr.analysis?.artifacts || null;
    if (Array.isArray(payload.prepareInputs) && payload.prepareInputs.length > 0) {
      updated.preparedInputs = rStore.prepareScenarioInputs(id, payload.prepareInputs, artifacts);
    }
    const scens = [...(payload.scenario ? [payload.scenario] : []), ...(Array.isArray(payload.scenarios) ? payload.scenarios : [])];
    for (const s of scens) updated.scenarios.push(rStore.upsertScenario(id, s, artifacts));
    const qs = [...(payload.question ? [payload.question] : []), ...(Array.isArray(payload.questions) ? payload.questions : [])];
    for (const q of qs) updated.questions.push(rStore.upsertQuestion(id, q));
    const rts = [...(payload.route ? [payload.route] : []), ...(Array.isArray(payload.routes) ? payload.routes : [])];
    for (const r of rts) updated.routes.push(rStore.upsertRoute(id, r));
    const effectiveCandidate = payload.candidate
      || (Array.isArray(payload.candidates) && payload.candidates.length === 1 ? payload.candidates[0] : null)
      || (Array.isArray(payload.testVectors) ? { testVectors: payload.testVectors } : null);
    if (effectiveCandidate) updated.candidate = rStore.submitCandidateExplanation(id, effectiveCandidate, artifacts);
    if (payload.terminalFinding !== undefined) {
      updated.terminalFinding = rStore.submitTerminalFinding(id, payload.terminalFinding, artifacts);
    }
    if (payload.hostGoalBinding) rStore.bindHostGoal(id, payload.hostGoalBinding, hostGoal);
    if (!delivs.length && !comps.length && !updated.preparedInputs.length && !scens.length && !qs.length && !rts.length && !effectiveCandidate && payload.terminalFinding === undefined && !payload.hostGoalBinding) {
      fail('INVALID_ARGUMENT', 'root-update requires at least one of deliverable(s), component(s), prepareInputs, scenario(s), question(s), route(s), candidate, terminalFinding, or hostGoalBinding');
    }
    const latest = rStore.get(id);
    const summary = summarizeRootTask(latest);
    return {
      workspace: {
        rootId: id,
        revision: latest.revision,
        planRevision: latest.planRevision ?? null,
        updated,
        summary,
        task: input.include_task === true
          ? latest
          : {
              rootId: latest.rootId,
              revision: latest.revision,
              planRevision: latest.planRevision ?? null,
              summaryOnly: true,
              deliverables: summary.deliverables,
              components: summarizeComponents(latest.components),
            },
      },
    };
  }
  if (action === 'delegate-brief') {
    fields(input, ['action', 'id', 'root']);
    const parentAgentId = execution?.agent?.id || execution?.agent?.sessionId || 'local-parent';
    if (execution?.agent?.session?.header?.parentSession) {
      fail('DELEGATION_PARENT_REQUIRED', 'Only a root parent session can issue root delegation briefs');
    }
    return {
      workspace: rStore.issueDelegationBrief(id, {
        parentAgentId,
        childRole: payload.childRole,
        componentId: payload.componentId,
        scenarioId: payload.scenarioId || null,
        objective: payload.objective || '',
      }),
    };
  }
  if (action === 'accept-child-finding') {
    fields(input, ['action', 'id', 'root']);
    if (execution?.agent?.session?.header?.parentSession) {
      fail('DELEGATION_PARENT_REQUIRED', 'Only the root parent session can accept child findings into the root investigation');
    }
    return {
      workspace: rStore.acceptChildFinding(id, {
        briefId: payload.briefId,
        childReport: payload.childReport,
        artifacts: mgr.analysis?.artifacts || null,
      }),
    };
  }
  if (action === 'root-control') {
    fields(input, ['action', 'id', 'root']);
    if (!mgr.coordination) fail('DELEGATION_UNAVAILABLE', 'Root control requires DelegationControl');
    const controlAction = payload.controlAction;
    const coordOptions = { allowLocalFallback: execution?.agent?.session === undefined };
    if (controlAction === 'cancel') {
      return { workspace: mgr.coordination.acceptCancel(execution?.agent, payload.reason || 'explicit-workspace-cancel', coordOptions) };
    }
    if (controlAction === 'resume') {
      if (mgr.autonomyHost) {
        if (!mgr.autonomyHost.hasDirectHumanTurnAuthority(execution?.agent)) {
          fail('RESUME_REQUIRES_DIRECT_HUMAN', 'Explicit cancellation resume requires an authenticated direct-human turn on a root agent');
        }
      } else if (execution?.agent?.session?.header?.parentSession) {
        fail('RESUME_REQUIRES_DIRECT_HUMAN', 'Subagents cannot clear root session cancellation');
      }
      return { workspace: mgr.coordination.resumeControlGeneration(execution?.agent, 'explicit-human-resume', coordOptions) };
    }
    fail('INVALID_ARGUMENT', 'root-control requires root.controlAction = "cancel" | "resume"');
  }
  if (action === 'select') {
    fields(input, ['action', 'id', 'root']);
    const expSpec = payload.experiment || payload;
    const selected = rStore.selectExperiment(id, expSpec, mgr.analysis?.artifacts || null);
    return { workspace: { ...selected, executionAuthorized: false } };
  }
  if (action === 'evaluate') {
    fields(input, ['action', 'id', 'root']);
    const evalSpec = payload.evaluation || payload;
    return { workspace: rStore.evaluateExperiment(id, evalSpec) };
  }
  if (action === 'recover-receipts') {
    fields(input, ['action', 'id']);
    return { workspace: rStore.recoverPendingReceipts({ rootId: id, mgr, execution }) };
  }
  if (['assess', 'root-brief', 'root-plan', 'root-resume'].includes(action)) {
    fields(input, ['action', 'id', 'max_bytes']);
    const rootTask = id
      ? rStore.get(id)
      : (hostGoal?.goalId ? rStore.findForHostGoal(rootSessionId, hostGoal.goalId).task : rStore.latestForSession(rootSessionId));
    if (!rootTask) fail('ROOT_INVESTIGATION_NOT_FOUND', 'Provide root investigation id or create one bound to the current goal/session first');
    const assessment = assessRootInvestigation({ rootTask, mgr, execution, hostGoal });
    if (action === 'assess') return { workspace: assessment };
    const brief = renderDeterministicRootBrief(rootTask, assessment);
    if (action === 'root-brief') {
      return {
        workspace: {
          rootId: rootTask.rootId,
          revision: rootTask.revision,
          planRevision: rootTask.planRevision,
          brief,
          assessment,
          executionAuthorized: false,
        },
      };
    }
    const capabilities = capabilityCatalog(mgr, cfg, { ownQueue: true });
    const plan = planRootInvestigation({ rootTask, assessment, capabilities });
    if (action === 'root-plan') return { workspace: plan };
    return {
      workspace: {
        schema: 'ig5-root-resume-v1',
        rootId: rootTask.rootId,
        revision: rootTask.revision,
        planRevision: rootTask.planRevision,
        brief,
        assessment,
        plan,
        executionAuthorized: false,
      },
    };
  }
  fail('INVALID_ARGUMENT', `Unsupported root workspace action: ${action}`);
}
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

/** Called under the selected session queue. This changes analysis notes only. */
export function runWorkspace(mgr, cfg, args, execution) {
  if (args.toolset !== undefined || args.history !== undefined) fail('INVALID_ARGUMENT', 'Use workspace separately from toolset/history changes');
  for (const stray of ['action', 'id', 'root', 'evaluate', 'evaluation', 'experiment']) {
    if (args[stray] !== undefined) {
      fail('INVALID_ARGUMENT', `Top-level "${stray}" is ignored on ig5_workspace; nest all workspace fields inside args.workspace: {"workspace":{"action":...,"id":...,"root":{...}}}`);
    }
  }
  let input = args.workspace;
  if (typeof input === 'string' && input.length <= 65536) {
    try { input = JSON.parse(input); } catch { input = null; }
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('INVALID_ARGUMENT', 'workspace must be an object');
  const { action, id } = input;
  if (caseIndexActions.includes(action)) validateCaseIndexInput(input);
  if (methodActions.includes(action)) validateMethodInput(input);
  if (action === 'experiment-shadow') validateShadowInput(input);
  if (candidateActions.includes(action)) validateCandidateInput(input);
  if (cffActions.includes(action)) validateCffInput(input);
  if (['plan', 'resume'].includes(action)) fields(input, ['action', 'id', 'max_bytes']);
  if (action === 'research-update') validateResearchMutation(input.research);
  if (['research-verify', 'research-link-verification'].includes(action)) validateVerificationRequest(input.verification);
  if (rootWorkspaceActions.includes(action)) return runRootWorkspaceAction(mgr, cfg, input, execution);
  const scope = context(mgr, args), notes = store(mgr, cfg);
  if (candidateActions.includes(action)||cffActions.includes(action)) {
    if (!execution?.agent?.id) fail('AGENT_SCOPE_REQUIRED','Candidate access requires the actual executing agent');
    mgr.lifter ||= new LiftJobs(cfg);
    const read=()=>{const current=context(mgr,args),task=notes.get(current,id);return {context:current,task,research:research(mgr,cfg).get(task,current)};};
    const controller=new AbortController(),parent=execution?.signal||mgr.scope?.getStore()?.signal,cancel=()=>controller.abort();
    if(parent?.aborted)cancel();else parent?.addEventListener('abort',cancel,{once:true});
    const timer=setTimeout(cancel,Math.min(cfg.requestTimeoutMs||60000,60000));
    const execute=cffActions.includes(action)?runCffWorkflow:runCandidateWorkflow;
    return execute({artifacts:mgr.analysis.artifacts,jobs:mgr.lifter,dataJobs:mgr.analysis.jobs,input,read,signal:controller.signal})
      .then(result=>({workspace:result})).catch(error=>{if(error.code==='UNSUPPORTED_BITVECTOR')return {workspace:{schema:'ig5-bitvector-unsupported-v1',status:'unsupported',reason:error.message,nativeTargetExecuted:false,businessAccepted:false,databaseModified:false,assistEnabled:false}};throw error;})
      .finally(()=>{clearTimeout(timer);parent?.removeEventListener('abort',cancel);});
  }
  if (action === 'experiment-shadow') {
    if (!execution?.agent?.id) fail('AGENT_SCOPE_REQUIRED', 'Shadow access requires the actual executing agent');
    const read = () => {
      const current=context(mgr,args),task=notes.get(current,id),state=research(mgr,cfg).get(task,current);
      let failures=[],failureError=null;
      try { failures=mgr.failures?.recent(current,3)||[]; } catch(error) { failureError=error.code||'FAILURE_HISTORY_UNAVAILABLE'; }
      return {context:current,task,research:state,failures,failureError,relatedTasks:notes.list(current).tasks.filter(other=>other.taskId!==task.taskId)};
    };
    return {workspace:runExperimentShadow({projectRoot:cfg.projectRoot,input,read,artifacts:mgr.analysis.artifacts,
      readPlanning:data=>planningContext({mgr,cfg,args,execution,context:data.context,task:data.task,research:verificationOverlay(mgr.analysis.artifacts,data.task,data.research)}),
      readLegacy:()=>runWorkspace(mgr,cfg,{...args,workspace:{action:'plan',id,...(input.max_bytes!==undefined?{max_bytes:input.max_bytes}:{})}},execution).workspace,
      readFailures:(keys,runtime)=>mgr.failures?.forPlanning?mgr.failures.forPlanning(context(mgr,args),keys,runtime):{records:[],completeHistory:false,error:'FAILURE_HISTORY_UNAVAILABLE'},
    })};
  }
  if (methodActions.includes(action)) {
    if (!execution?.agent?.id) fail('AGENT_SCOPE_REQUIRED', 'Method access requires the actual executing agent');
    return { workspace: runMethodQuery({ projectRoot: cfg.projectRoot, input, artifacts: mgr.analysis.artifacts, read: () => {
      const current = context(mgr, args), task = notes.get(current, id), state = research(mgr, cfg).get(task, current);
      let failures = [], failureError = null;
      try { failures = mgr.failures?.recent(current, 3) || []; } catch (error) { failureError = error.code || 'FAILURE_HISTORY_UNAVAILABLE'; }
      return { context: current, task, research: state, failures, failureError, relatedTasks: notes.list(current).tasks.filter(other => other.taskId !== task.taskId) };
    } }) };
  }
  if (caseIndexActions.includes(action)) {
    return runCaseIndex({ projectRoot: cfg.projectRoot, input, execution, artifacts: mgr.analysis.artifacts, memory: mgr.memory,
      read: () => {
        const current = context(mgr, args), task = notes.get(current, id), state = research(mgr, cfg).get(task, current);
        let failures = [], failureError = null;
        try { failures = mgr.failures?.recent(current, 3) || []; } catch (error) { failureError = error.code || 'FAILURE_HISTORY_UNAVAILABLE'; }
        return { context: current, task, research: state, failures, failureError,
          relatedTasks: notes.list(current).tasks.filter(other => other.taskId !== task.taskId) };
      } }).then(result => ({ workspace: result }));
  }
  if (['plan', 'resume'].includes(action)) {
    fields(input, ['action', 'id', 'max_bytes']);
    return { workspace: (action === 'resume' ? investigationResume : investigationPlan)({ maxBytes: input.max_bytes, read: () => {
      const current = context(mgr, args), task = notes.get(current, id);
      const state = verificationOverlay(mgr.analysis.artifacts, task, research(mgr, cfg).get(task, current));
      return planningContext({ mgr, cfg, args, execution, context: current, task, research: state });
    } }) };
  }
  if (action === 'research-get' || action === 'research-dependencies') {
    fields(input, action === 'research-get' ? ['action', 'id'] : ['action', 'id', 'evidence_id']);
    for (let attempt = 0; attempt < 2; attempt++) {
      const currentScope = context(mgr, args), task = notes.get(currentScope, id), state = verificationOverlay(mgr.analysis.artifacts, task, research(mgr, cfg).get(task, currentScope));
      if (action === 'research-dependencies') {
        if (!state?.evidenceLinks.some(e => e.id === input.evidence_id)) fail('INVALID_RESEARCH_REF', 'Choose linked evidence from this research state');
      }
      const result = action === 'research-dependencies' ? evidenceDependencies(state, input.evidence_id)
        : { taskId: id, taskRevision: task.taskRevision, scopeDigest: researchScopeDigest(task.scope),
          research: state, evidence: state ? inspectResearchEvidence(mgr.analysis.artifacts, task, currentScope, state) : [],
          initialized: state !== null, executionAuthorized: false };
      const endScope = context(mgr, args), endTask = notes.get(endScope, id), endState = research(mgr, cfg).get(endTask, endScope);
      if (task.taskRevision !== endTask.taskRevision || (state?.researchRevision ?? null) !== (endState?.researchRevision ?? null)
        || researchDigest(currentScope) !== researchDigest(endScope)) continue;
      return { workspace: result };
    }
    fail('SNAPSHOT_INCONSISTENT', 'Task, research or database changed during both research reads');
  }
  if (action === 'research-verify' || action === 'research-link-verification') {
    fields(input, action === 'research-verify' ? ['action', 'id', 'verification'] : ['action', 'id', 'verification', 'report_ref']);
    const task = notes.get(scope, id), service = research(mgr, cfg), state = service.get(task, scope), by = actor(execution);
    return runResearchVerification(mgr, args, input, notes, service, task, state, by, execution?.signal);
  }
  if (action === 'research-verification') {
    fields(input, ['action', 'id', 'verification_id']);
    const task = notes.get(scope, id), state = research(mgr, cfg).get(task, scope);
    const ref = state?.verificationRefs?.find(r => r.reportId === input.verification_id);
    if (!ref) fail('INVALID_RESEARCH_REF', 'Verification report is not associated with this research');
    return { workspace: { reportId: ref.reportId, sha256: ref.sha256, ...readVerificationReport(mgr.analysis.artifacts, task, state, ref) } };
  }
  if (action === 'research-update') {
    fields(input, ['action', 'id', 'research', 'snapshot_id', 'report_ref']);
    const task = notes.get(scope, id), service = research(mgr, cfg);
    const vmLink = input.research?.operation === 'link-vm-context', dossierLink = input.research?.operation === 'link-evidence';
    const fixedLink=input.research?.operation==='link-verifier-evidence';
    const linking = vmLink || dossierLink || fixedLink;
    if (!dossierLink && input.snapshot_id !== undefined) fail('INVALID_ARGUMENT', 'snapshot_id is only valid for link-evidence');
    if (!vmLink && !fixedLink && input.report_ref !== undefined) fail('INVALID_ARGUMENT', 'report_ref is only valid for a fixed research evidence link');
    const evidence = dossierLink ? linkDossierEvidence(mgr.analysis.artifacts, task, input.snapshot_id)
      : vmLink ? vmContextEvidence(mgr.analysis.artifacts, task, input.report_ref).link : fixedLink ? fixedPropertyEvidence(mgr.analysis.artifacts,task,input.report_ref).link : null;
    mgr.checkCancelled();
    let result;
    try {
      result = service.mutate(task, scope, input.research, actor(execution), { evidence });
    } catch (error) {
      if (!linking) throw error;
      return { workspace: { reportSaved: true, linked: false, reportId: evidence.reportId, reportSha256: evidence.sha256,
        code: error.code || 'RESEARCH_LINK_FAILED', stage: 'research-cas',
        note: 'Existing immutable report retained; reread research/task state before linking again. No collection was repeated.' } };
    }
    const committed = { researchSaved: true, writtenResearchRevision: result.researchRevision,
      ...(linking ? { reportSaved: true, linked: true, reportId: evidence.reportId, reportSha256: evidence.sha256 } : {}),
      atomicAcrossTaskAndResearch: false };
    try {
      const endScope = context(mgr, args), endTask = notes.get(endScope, id), current = service.get(endTask, endScope);
      return { workspace: { ...committed, research: verificationOverlay(mgr.analysis.artifacts, endTask, current), postCommitContext: 'read' } };
    } catch (error) {
      return { workspace: { ...committed, research: { ...result, stale: true, staleReasons: ['post-commit-context-unavailable'] },
        postCommitContext: 'unavailable', code: error.code || 'RESEARCH_CONTEXT_UNAVAILABLE',
        note: 'Research was committed. Read current task/context before any further change; this is not a rollback.' } };
    }
  }
  if (action === 'brief') {
    fields(input, ['action', 'id', 'max_bytes', 'cursor']);
    let failures = [], failureHistoryError = null;
    try { failures = mgr.failures?.recent(scope) || []; }
    catch(error) { failureHistoryError = error.code || 'FAILURE_HISTORY_UNAVAILABLE'; }
    return { workspace: investigationBrief({ readContext: () => context(mgr, args), readTask: current => notes.get(current, id),
      readResearch: (task, current) => verificationOverlay(mgr.analysis.artifacts, task, research(mgr, cfg).get(task, current)),
      readPlanning: (task, current, state) => planningContext({ mgr, cfg, args, execution, context: current, task, research: state }),
      readEvidence: snapshot => {
        const artifacts = mgr.analysis.artifacts;
        if (artifacts.metadata(snapshot.report_id).result.recordSha256 !== snapshot.report_sha256) fail('ARTIFACT_CHANGED', 'Stored report digest differs from the task reference');
        const report = artifacts.get(snapshot.report_id);
        validateSnapshotReport(snapshot, report);
        return report.result;
      }, capabilities: capabilityCatalog(mgr, cfg, { engine: scope.engine, ownQueue: true }), failures, failureHistoryError,
      maxBytes: input.max_bytes, cursor: input.cursor }) };
  }
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
  if (action === 'claim' || action === 'submit') {
    fields(input, ['action', 'id', 'handoff_id', 'expected_task_revision', ...(action === 'submit' ? ['snapshot_ids'] : [])]);
    const task = notes.get(scope, id);
    if (task.taskRevision !== input.expected_task_revision) fail('STALE_TASK_REVISION', 'Read current task revision before claim or submit');
    if (!mgr.coordination) fail('DELEGATION_UNAVAILABLE', 'Controlled delegation requires the DSH lifecycle bridge');
    if (action === 'claim') return { workspace: mgr.coordination.claim(execution?.agent, input.handoff_id, task, scope) };
    const ids = input.snapshot_ids;
    if (!Array.isArray(ids) || !ids.length || ids.length > 8 || new Set(ids).size !== ids.length || ids.some(x => typeof x !== 'string')) fail('INVALID_ARGUMENT', 'submit requires 1..8 distinct snapshot IDs');
    const snapshots = ids.map(snapshot_id => {
      const snapshot = task.systemEvidence.find(s => s.snapshot_id === snapshot_id);
      if (!snapshot) fail('INVALID_REF', 'Submitted snapshot does not belong to the task');
      return snapshot;
    });
    return { workspace: mgr.coordination.submit(execution?.agent, input.handoff_id, task, scope, snapshots) };
  }
  if (action === 'handoff' || action === 'review') {
    fields(input, action === 'handoff'
      ? ['action', 'id', 'expected_task_revision', 'question', 'acceptance', 'constraints']
      : ['action', 'id', 'expected_task_revision', 'snapshot_ids', 'handoff_id']);
    const by = actor(execution), task = notes.get(scope, id);
    if (!Number.isSafeInteger(input.expected_task_revision) || input.expected_task_revision !== task.taskRevision) {
      fail('STALE_TASK_REVISION', 'Read the task and provide its current expected_task_revision before handoff or review');
    }
    const base = { schemaVersion: 1, taskId: id, taskRevision: task.taskRevision, context: scope,
      requestedBy: by, goal: task.goal, taskStatus: task.status,
      statements: { hypothesis: task.hypothesis, next_step: task.next_step, conclusion: task.conclusion },
      statementOrigin: 'caller-statement', executionAuthorized: false, databaseModified: false,
      taskModified: false, semanticAcceptanceVerified: false };
    if (action === 'handoff') {
      for (const key of ['question', 'acceptance', 'constraints']) {
        if (typeof input[key] !== 'string' || !input[key].trim() || input[key].length > 2048 || input[key].includes('\0')) {
          fail('INVALID_ARGUMENT', `handoff requires nonempty ${key} of at most 2048 characters`);
        }
      }
      return { workspace: { ...base, kind: 'investigation-handoff',
        ...(mgr.coordination && execution?.agent?.session?.header
          ? mgr.coordination.handoff(execution.agent, task, scope)
          : { mode: 'untracked', delegationVerified: false, note: 'No reliable DSH session lineage; formal post-return review unavailable.' }),
        contract: { question: input.question, acceptance: input.acceptance, constraints: input.constraints,
          origin: 'caller-statement', enforced: false },
        evidence: task.systemEvidence, reportsVerified: false,
        startup: [
          'Read ig5_workspace in your own agent scope; enable full only when needed.',
          'Claim handoffId via workspace claim/handoff_id, then read this task again with explicit target and engine; stop if task/database/attachment changed.',
          'Locate the relevant input, processing functions, output and unresolved question; reuse existing evidence before collecting more.',
          'Read selected workspace evidence reports, including partial/truncated/unavailable sections; references alone are not verified reports.',
          'Submit actually read snapshot_ids via workspace submit/handoff_id/current expected_task_revision, then return candidates, coverage and unknowns and finish. Do not mark the shared task completed.',
        ],
        coordination: { sessionsShared: true, constraintsEnforced: false,
          staticWrites: 'Coordinate one writer per database; queues serialize execution, not conflicting intentions.',
          debugControl: 'Existing agent ownership, takeover and public approvals still apply.',
          scheduling: 'The DSH parent dispatches agents; this packet does not spawn or message them.' },
        returnContract: ['taskId', 'taskRevision', 'context', 'candidateConclusion', 'snapshot_ids', 'coverage', 'unknowns', 'next_action'],
      } };
    }
    const ids = input.snapshot_ids;
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 8 || new Set(ids).size !== ids.length
      || ids.some(value => typeof value !== 'string')) fail('INVALID_ARGUMENT', 'review requires 1..8 distinct task snapshot IDs');
    let delegation = { reviewStage: 'integrity-precheck', delegationVerified: false };
    if (input.handoff_id !== undefined) {
      if (!mgr.coordination) fail('DELEGATION_UNAVAILABLE', 'Controlled review requires the DSH lifecycle bridge');
      delegation = mgr.coordination.review(execution.agent, input.handoff_id, task, scope, ids);
    }
    const evidence = ids.map(snapshot_id => {
      const checked = runWorkspace(mgr, cfg, { target: args.target, workspace: { action: 'evidence', id, snapshot_id } }, execution).workspace;
      return { snapshot: checked.snapshot, analysis: checked.report.analysis,
        responseTruncated: checked.report.responseTruncated,
        sections: Object.fromEntries(Object.entries(checked.report.sections).map(([key, section]) => [key, { status: section.status }])),
        limitations: checked.report.limitations };
    });
    return { workspace: { ...base, ...delegation, kind: 'investigation-evidence-review', reportsVerified: true,
      evidence, staleEvidence: evidence.some(row => row.snapshot.stale),
      note: 'Digest, task membership and provenance were checked. Inspect complete evidence reports and independently assess the acceptance criteria; this does not approve a conclusion or complete a task.' } };
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
    mgr.coordination?.read(execution?.agent, snapshot);
    return { workspace: { taskId: task.taskId, taskRevision: task.taskRevision, snapshot, report: report.result,
      note: 'Historical observations retain their original scope; stale observations require another capture.' } };
  }
  fail('INVALID_ARGUMENT', 'workspace action must be create, get, list, update, evidence, handoff, claim, submit or review');
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

/** Await only the fixed owned data job. Association is a separate CAS commit. */
async function runResearchVerification(mgr, args, input, notes, service, task, state, by, signal) {
  let receipt;
  if (input.action === 'research-link-verification') {
    exactReportRef(input.report_ref);
    const ref = { reportId: input.report_ref.id, sha256: input.report_ref.sha256 };
    if (!state) fail('RESEARCH_NOT_FOUND', 'Initialize research first');
    const result = loadVerification(mgr.analysis.artifacts, task, state, ref);
    if (result.evidenceId !== input.verification.evidence_id || result.obligationId !== input.verification.obligation_id
      || (result.experimentId || undefined) !== input.verification.experiment_id) fail('INVALID_RESEARCH_REF', 'Receipt does not match requested evidence/obligation/experiment');
    receipt = { ref, result, reportSaved: true, dataWorkerCleanupConfirmed: null };
  } else receipt = await verifyResearch(mgr, task, state, input.verification, mgr.scope?.getStore()?.signal || signal);
  if (receipt.publicationFailure) return { workspace: { reportSaved: receipt.reportSaved, recordSaved: receipt.recordSaved,
    ...(receipt.ref ? { reportId: receipt.ref.reportId, reportSha256: receipt.ref.sha256 } : {}), linked: false, stage: 'verification-publication',
    verifierStatus: receipt.result.status, status: 'error', code: receipt.code, error: receipt.error,
    dataWorkerCleanupConfirmed: receipt.dataWorkerCleanupConfirmed, executionAuthorized: false, businessAccepted: false } };
  const base = { reportSaved: true, reportId: receipt.ref.reportId, reportSha256: receipt.ref.sha256,
    status: receipt.result.status, dataWorkerCleanupConfirmed: receipt.dataWorkerCleanupConfirmed, executionAuthorized: false, businessAccepted: false };
  let linked;
  try {
    const currentScope = context(mgr, args), currentTask = notes.get(currentScope, task.taskId), current = service.get(currentTask, currentScope);
    loadVerification(mgr.analysis.artifacts, currentTask, current, receipt.ref);
    linked = service.linkVerification(currentTask, currentScope, input.verification, receipt.ref, by);
  } catch (error) {
    return { workspace: { ...base, linked: false, stage: 'research-cas', code: error.code || 'VERIFICATION_LINK_FAILED',
      note: 'Full immutable verifier result retained. Reread revisions and recover with research-link-verification; do not rerun the experiment.' } };
  }
  try {
    const finalScope = context(mgr, args), finalTask = notes.get(finalScope, task.taskId), finalState = service.get(finalTask, finalScope);
    return { workspace: { ...base, linked: true, writtenResearchRevision: linked.researchRevision,
      research: verificationOverlay(mgr.analysis.artifacts, finalTask, finalState), postCommitContext: 'read' } };
  } catch (error) {
    return { workspace: { ...base, linked: true, writtenResearchRevision: linked.researchRevision,
      postCommitContext: 'unavailable', code: error.code || 'VERIFICATION_CONTEXT_UNAVAILABLE' } };
  }
}
