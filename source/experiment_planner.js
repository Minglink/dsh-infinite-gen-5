import { planningDigest, planningRequestKey } from './planning_identity.js';

const stableScope = ['projectId', 'artifactId', 'sha256', 'engine', 'provider'];
const property = 'vm-context-candidate-derivation-and-provenance';
const fail = message => { throw Object.assign(new Error(message), { code: 'INVALID_PLANNING_INPUT' }); };
const clip = value => typeof value === 'string' ? value.slice(0, 160) : '';
const sameScope = (a, b) => stableScope.every(k => a?.[k] === b?.[k]);
const rowState = (research, key, id) => research?.objectStates?.[key]?.find(r => r.id === id);

/** Pure, deterministic suggestions only. It never reads files, runs tools or changes research. */
export function planExperiments({ context, task, research = null, evidence = [], capabilities = { entries: [] }, resources = {},
  failures = [], failureHistoryError = null, budgets = {}, maxCandidates = 3, implementationDigest = null }) {
  if (!context || !task || !Array.isArray(task.systemEvidence) || task.systemEvidence.length > 64
    || !Array.isArray(evidence) || evidence.length > 256 || !Array.isArray(capabilities.entries) || capabilities.entries.length > 64
    || !Array.isArray(failures) || failures.length > 67 || !Number.isSafeInteger(maxCandidates) || maxCandidates < 1 || maxCandidates > 3) fail('Bounded planning context is required');
  const calls = budgets.publicToolCalls ?? 3, inputBytes = budgets.inputBytes ?? 8 * 1024 ** 2;
  if (!Number.isSafeInteger(calls) || calls < 0 || calls > 3 || !Number.isSafeInteger(inputBytes) || inputBytes < 0 || inputBytes > 8 * 1024 ** 2) fail('Planning budget exceeds its fixed envelope');
  if (research && (research.hypotheses.length > 32 || research.obligations.length > 64 || research.experiments.length > 128 || research.evidenceLinks.length > 256)) fail('Research object limit exceeded');
  const snapshot = { taskId: task.taskId, taskRevision: task.taskRevision, researchRevision: research?.researchRevision ?? null,
    contractRevision: research?.contractRevision ?? null, ...Object.fromEntries([...stableScope, 'attachmentId', 'dbRevision'].map(k => [k, context[k]])) };
  const deferred = [], candidates = [], seen = new Set();
  const defer = (reason, id = null) => deferred.push({ reason, ...(id ? { id } : {}) });
  const currentFailures = failures.filter(f => !f.historical);
  const capability = capabilities.entries.find(c => c.operation === 'function-context' && c.engine === context.engine && c.provider === context.provider);
  const runtimeDigest = capability?.runtimeDigest || null;
  const nativeBlocked = resources.static?.state && resources.static.state !== 'compatible' ? `static-${resources.static.state}`
    : !capability ? 'static-capability-unknown' : capability.declared !== 'declared' ? 'static-unsupported'
      : capability.policy === 'blocked' ? 'static-policy-blocked' : capability.files !== 'present' ? 'static-files-unverified'
        : capability.startup !== 'verified' ? 'static-startup-unverified' : capability.session !== 'compatible' ? `static-${capability.session}` : null;
  function add(candidate, priority, compute = false) {
    const sourceId = candidate.inputRefs?.[0]?.snapshotId || candidate.inputRefs?.[0]?.evidenceId || candidate.draft?.experimentId || null;
    const key = planningRequestKey(candidate.request || {}, context, implementationDigest);
    if (compute && failureHistoryError) { defer('failure-history-unavailable', sourceId); return; }
    const repeated = key && currentFailures.find(f => f.planningKey === key && (!f.runtimeDigest || !runtimeDigest || f.runtimeDigest === runtimeDigest));
    const stage = candidate.request?.workspace?.action || null;
    const oldUnknown = compute && currentFailures.find(f => !f.planningKey && f.operation === candidate.request?.tool && f.advice?.occurrences >= 2
      && !['usage', 'environment'].includes(f.advice?.category) && (!stage || f.failedStage === stage));
    if (repeated || oldUnknown) { defer(repeated ? 'unchanged-failed-request' : 'repeated-input-not-comparable', sourceId); return; }
    const cost = candidate.estimatedCost?.publicToolCalls || 0;
    if (cost > calls || (candidate.estimatedCost?.inputBytes || 0) > inputBytes) { defer('planning-budget-insufficient', candidate.id); return; }
    const identity = planningDigest(candidate.request ? { request: candidate.request } : { kind: candidate.kind, inputs: candidate.inputRefs, draft: candidate.draft || null });
    if (seen.has(identity)) return;
    seen.add(identity);
    candidates.push({ ...candidate, id: identity, priority, planningKey: key, executionAuthorized: false,
      approval: 'Original tool entry, ownership, identity checks and approvals remain mandatory.' });
  }
  const navigation = (kind, rationale, workspace, priority, extra = {}) => add({ kind, rationale,
    request: { tool: 'ig5_workspace', target: context.target, engine: context.engine, workspace: { id: task.taskId, ...workspace } },
    inputRefs: [], predictedDivergence: 'Read current source-bound state; unresolved content remains unknown.',
    prerequisites: ['Recheck current task and target identity'], interpretation: 'Reading is not acceptance or execution authorization.',
    estimatedCost: { publicToolCalls: 1, inputBytes: 0, band: 'low' }, ...extra }, priority);
  if (task.scope && !sameScope(task.scope, context) || research && (!sameScope(research.scope, context) || research.taskId !== task.taskId)) {
    defer('target-identity-mismatch');
  } else {
    if (failureHistoryError) defer('failure-history-unavailable');
    const retained = currentFailures.find(f => f.original?.cleanupConfirmed === false || f.original?.guestCleanupConfirmed === false || f.failureCode === 'CLEANUP_UNCONFIRMED');
    if (retained) add({ kind: 'inspect-resource-owner', rationale: 'A prior receipt did not confirm cleanup. Inspect its original owner before any new execution.', request: null,
      inputRefs: retained.reportRef ? [{ kind: 'failure', ...retained.reportRef }] : [], ownerRef: { operation: retained.operation, runId: retained.original?.runId || null },
      predictedDivergence: 'An owner-bound cleanup receipt resolves the hold; absent confirmation remains unknown.', prerequisites: ['Use the original owner and approved recovery entry'],
      interpretation: 'A completed task or new session does not prove cleanup.', estimatedCost: { publicToolCalls: 0, inputBytes: 0, band: 'review' } }, 0);
    if (research?.stale) navigation('review-research-context', 'Task, attachment or database changed; review the research before explicitly acknowledging the new context.', { action: 'research-get' }, 5);
    const pending = task.systemEvidence.filter(e => e.stale && !task.systemEvidence.some(c => !c.stale && c.function.ea === e.function.ea));
    for (const entry of pending) {
      if (nativeBlocked || retained && ['ig5_decompile', 'ig5_ir'].includes(retained.operation)) { defer(nativeBlocked || 'static-resource-owner-unresolved', entry.snapshot_id); continue; }
      add({ kind: 'refresh-stale-dossier', rationale: 'This function has only an old attachment/database observation.',
        request: { tool: 'ig5_decompile', target: context.target, engine: context.engine, ea: entry.function.ea, style: 'dossier', task_id: task.taskId },
        inputRefs: [{ snapshotId: entry.snapshot_id, reportId: entry.report_id, sha256: entry.report_sha256 }],
        predictedDivergence: 'A new snapshot may confirm or revise the old observation; collection failure leaves it stale.',
        prerequisites: ['Check the historical function address against the current mapping; original dossier limits apply'],
        interpretation: 'A fresh dossier is an observation, not semantic or function acceptance.',
        estimatedCost: { publicToolCalls: 1, inputBytes: 0, band: 'static-existing-limits' } }, 10, true);
    }
    const byEvidence = new Map(evidence.map(e => [e.id, e]));
    const links = new Map((research?.evidenceLinks || []).map(e => [e.id, e]));
    const importance = id => (research?.obligations || []).filter(o => o.value.dependencies.includes(id) && rowState(research, 'obligations', o.id)?.status === 'open').length;
    for (const proof of research?.verification?.checked || []) if (proof.integrity === 'verified' && ['fail', 'unknown', 'unsupported', 'error'].includes(proof.status)) {
      navigation('inspect-verifier-feedback', 'Read the full failure, unknown or unsupported result before proposing another experiment.',
        { action: 'research-verification', verification_id: proof.reportId }, 15,
        { inputRefs: [{ reportId: proof.reportId, sha256: proof.sha256 }], interpretation: 'A non-pass is feedback; preserve its witness and premises instead of repeating unchanged input.' });
    }
    for (const h of research?.hypotheses || []) {
      if (rowState(research, 'hypotheses', h.id)?.status === 'superseded' || h.contractRevision !== research.contractRevision) continue;
      if (h.value.supporting.length && h.value.opposing.length) navigation('review-contested-hypothesis', 'This caller hypothesis cites support and opposition; inspect both before accepting it.',
        { action: 'research-get' }, 20, { inputRefs: [...new Set([...h.value.supporting, ...h.value.opposing])].slice(0, 8).map(id => ({ evidenceId: id })),
          draft: { hypothesisId: h.id, status: 'caller-declared-contest', omittedReferences: Math.max(0, new Set([...h.value.supporting, ...h.value.opposing]).size - 8) } });
    }
    const auditInputs = new Set();
    const orderedObligations = [...(research?.obligations || [])].sort((a, b) => importance(b.id) - importance(a.id) || a.id.localeCompare(b.id));
    for (const obligation of orderedObligations) {
      const status = rowState(research, 'obligations', obligation.id);
      if (status?.status !== 'open' || status.staleContract) continue;
      const id = obligation.value.scope.startsWith('evidence:') ? obligation.value.scope.slice(9) : null, link = links.get(id), checked = byEvidence.get(id);
      if (obligation.value.property !== property || obligation.value.verifier !== 'vm-context-audit-v1' || link?.kind !== 'vm-context-model') { defer('no-registered-verifier-for-property', obligation.id); continue; }
      if (research.stale) { defer('research-context-stale', obligation.id); continue; }
      if (!checked || checked.integrity !== 'verified' || checked.stale) { defer('input-evidence-not-current-and-verified', obligation.id); continue; }
      if (obligation.value.dependencies.some(id => rowState(research, 'obligations', id)?.status !== 'closed-in-scope')) { defer('prerequisite-obligation-open', obligation.id); continue; }
      if (resources.data?.state !== 'compatible' || resources.data?.timeoutMs !== 15000) { defer('data-worker-not-ready', obligation.id); continue; }
      const previous = (research.verification?.checked || []).find(p => p.obligationId === obligation.id && p.evidenceId === id && p.code !== 'VERIFIER_IDENTITY_CHANGED');
      const incomplete = research.verification && (research.verification.omittedOlder > 0 || research.verification.checked.some(p => p.integrity !== 'verified' && p.code !== 'VERIFIER_IDENTITY_CHANGED'));
      if (previous || incomplete) { defer(previous ? 'existing-verifier-result-read-before-retry' : 'verification-history-incomplete', obligation.id); continue; }
      const semanticInput = checked.candidateInputDigest || link.sha256;
      const equivalentResult = research.verification?.checked?.some(p => p.integrity === 'verified' && p.property === property
        && byEvidence.get(p.evidenceId)?.candidateInputDigest && byEvidence.get(p.evidenceId).candidateInputDigest === semanticInput);
      if (auditInputs.has(semanticInput) || equivalentResult) { defer('equivalent-candidate-input-already-covered', obligation.id); continue; }
      const experiment = research.experiments.find(e => e.contractRevision === research.contractRevision && rowState(research, 'experiments', e.id)?.status === 'planned'
        && e.value.template === 'review-evidence' && e.value.inputs.includes(id) && e.value.obligations.includes(obligation.id));
      if (experiment && (experiment.value.budget.timeoutMs < 15000 || experiment.value.budget.bytes < (checked.inputBytes ?? 8 * 1024 ** 2))) { defer('experiment-budget-insufficient', experiment.id); continue; }
      const beforeAdd = candidates.length;
      const changedVerifier = research.verification?.checked?.some(p => p.obligationId === obligation.id && p.evidenceId === id && p.code === 'VERIFIER_IDENTITY_CHANGED');
      add({ kind: 'verify-scoped-candidate', rationale: changedVerifier ? 'Verifier rules or runtime changed; refresh the historical receipt against current rules over the same immutable inputs.'
        : 'A fixed independent audit can resolve this input-bound obligation; it blocks ' + importance(obligation.id) + ' downstream obligations.',
        request: { tool: 'ig5_workspace', target: context.target, engine: context.engine, workspace: { action: 'research-verify', id: task.taskId, verification: {
          expected_task_revision: task.taskRevision, expected_research_revision: research.researchRevision, scope_digest: research.scopeDigest,
          evidence_id: id, obligation_id: obligation.id, ...(experiment ? { experiment_id: experiment.id } : {}),
        } } }, inputRefs: [{ evidenceId: id, reportId: link.reportId, sha256: link.sha256 }],
        predictedDivergence: 'pass closes only this derivation/provenance property; fail supplies a witness; unknown/unsupported leaves it open.',
        prerequisites: ['Recheck revisions, exact committed inputs, dependencies and owned data-worker readiness'],
        interpretation: 'No VM role, phase, full function or business acceptance follows.',
        estimatedCost: { publicToolCalls: 1, inputBytes: checked.inputBytes ?? 8 * 1024 ** 2, band: 'bounded-offline-15s-64MiB' } }, 30 - Math.min(importance(obligation.id), 8), true);
      if (candidates.length > beforeAdd) auditInputs.add(semanticInput);
    }
    for (const experiment of research?.experiments || []) {
      if (rowState(research, 'experiments', experiment.id)?.status !== 'planned' || experiment.contractRevision !== research.contractRevision || research.stale) continue;
      if (experiment.value.template === 'review-evidence' || experiment.value.template === 'refresh-static-source') continue;
      if (experiment.value.inputs.some(id => !byEvidence.has(id) || byEvidence.get(id).integrity !== 'verified' || byEvidence.get(id).stale)) { defer('experiment-inputs-unverified', experiment.id); continue; }
      if (experiment.value.hypotheses.some(id => rowState(research, 'hypotheses', id)?.status !== 'proposed')) { defer('experiment-hypothesis-superseded', experiment.id); continue; }
      navigation('prepare-discriminating-experiment', 'Review this caller-proposed experiment and fill only the missing operation-specific inputs through original tools.', { action: 'research-get' }, 40,
        { draft: { experimentId: experiment.id, template: experiment.value.template, question: clip(experiment.value.question), predictedDivergence: clip(experiment.value.predictedDivergence),
          hypotheses: experiment.value.hypotheses.slice(0, 8), needsOperationSpecificParameters: true },
          inputRefs: experiment.value.inputs.slice(0, 8).map(id => ({ evidenceId: id })),
          interpretation: 'This is preparation only; caller predictions do not establish independent inputs, a counterexample, or permission to execute.' });
    }
    const first = task.systemEvidence.find(e => !e.stale);
    if (first) add({ kind: 'read-complete-evidence', rationale: 'Reuse the saved complete dossier before collecting again.',
      request: { tool: 'ig5_workspace', target: context.target, engine: context.engine, workspace: { action: 'evidence', id: task.taskId, snapshot_id: first.snapshot_id } },
      inputRefs: [{ snapshotId: first.snapshot_id, reportId: first.report_id, sha256: first.report_sha256 }], predictedDivergence: 'Report sections distinguish available, truncated and unknown observations.',
      prerequisites: ['Read the exact source-bound report'], interpretation: 'Reading does not accept caller claims.', estimatedCost: { publicToolCalls: 1, inputBytes: 0, band: 'low' } }, 50);
    if (currentFailures[0] && !retained) add({ kind: 'diagnose-failure', rationale: clip(currentFailures[0].advice?.nextCheck || 'Inspect the original failure before another attempt.'), request: null,
      inputRefs: currentFailures[0].reportRef ? [{ kind: 'failure', ...currentFailures[0].reportRef }] : [], predictedDivergence: 'Resolve the failed prerequisite or choose a different discriminating experiment.',
      prerequisites: ['Read original error and owner receipts'], interpretation: 'Failure advice grants no execution or cleanup.', estimatedCost: { publicToolCalls: 0, inputBytes: 0, band: 'review' } }, 60);
  }
  candidates.sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));
  let remainingCalls = calls, remainingBytes = inputBytes;
  const selected = [];
  for (const candidate of candidates) {
    if (selected.length >= maxCandidates) break;
    if (candidate.estimatedCost.publicToolCalls > remainingCalls || candidate.estimatedCost.inputBytes > remainingBytes) { defer('combined-planning-budget', candidate.id); continue; }
    remainingCalls -= candidate.estimatedCost.publicToolCalls; remainingBytes -= candidate.estimatedCost.inputBytes;
    const { priority, ...view } = candidate; selected.push(view);
  }
  return { schema: 'ig5-experiment-plan-v1', snapshot, candidates: selected, deferred: deferred.slice(0, 8), deferredCount: deferred.length,
    omittedDeferred: Math.max(0, deferred.length - 8), candidateCount: candidates.length,
    budget: { publicToolCalls: calls, inputBytes, plannedPublicToolCalls: calls - remainingCalls, plannedInputBytes: inputBytes - remainingBytes },
    mode: 'suggestions-only', executionAuthorized: false, taskModified: false, databaseModified: false,
    assurance: 'Deterministic planning over supplied state; caller hypotheses and predictions remain unverified.' };
}

/**
 * Backward-chained short-route planner for root investigations (v0.2).
 * Separates route feasibility from immediate executability so missing scenario parameters
 * lead to scenario preparation rather than unbounded static pseudocode export.
 */
export function planRootInvestigation({ rootTask, assessment, capabilities = { entries: [] }, maxCandidates = 4 }) {
  if (!rootTask || rootTask.kind !== 'root-investigation' || !assessment) {
    fail('Root investigation and derived assessment are required');
  }
  const candidates = [];
  const deferred = [];
  const debugCap = (capabilities.entries || []).find(e => e.operation === 'debug-scenario' || e.operation === 'record-execution');
  const debugRouteFeasible = !debugCap
    ? true
    : (debugCap.declared === 'declared' && debugCap.policy !== 'blocked' && debugCap.files !== 'missing');

  const push = (priority, item) => candidates.push({
    priority,
    executionAuthorized: false,
    ...item,
  });

  if (assessment.pendingReceiptsCount > 0) {
    push(0, {
      kind: 'recover-pending-receipts',
      routeFeasible: true,
      operationExecutableNow: true,
      rationale: 'System artifacts committed with unlinked root investigation receipts; link them without re-executing tools.',
      request: { tool: 'ig5_workspace', workspace: { action: 'recover-receipts', id: rootTask.rootId } },
    });
  }

  const normPathKey = p => (typeof p === 'string' && p.trim() ? p.trim().replaceAll('/', '\\').toLowerCase() : null);
  for (const item of assessment.pendingCleanup || []) {
    if (item.status === 'active') {
      const rawKey = String(item.resourceKey || '');
      const isDbg = rawKey.startsWith('dbg:') || rawKey.startsWith('live-dbg:');
      const isApp = rawKey.startsWith('app:');
      const isAndroid = rawKey.startsWith('android:');
      const fallbackTarget = rawKey.startsWith('dbg:') ? rawKey.slice(4)
        : rawKey.startsWith('live-dbg:') ? rawKey.slice(9)
        : isApp ? rawKey.slice(4) : '';
      const matchedComponent = fallbackTarget
        ? rootTask.components.find(c => normPathKey(c.path) === normPathKey(fallbackTarget))
        : null;
      const targetPath = item.targetPath || matchedComponent?.path || fallbackTarget;
      let cleanupReq = null;
      if (isDbg && targetPath) {
        cleanupReq = { tool: 'ig5_dbg', op: 'stop', target: targetPath };
      } else if (isApp && targetPath) {
        cleanupReq = { tool: 'ig5_app_observe', action: 'stop', target: targetPath };
      } else if (isAndroid) {
        const parts = rawKey.slice('android:'.length);
        const colonIdx = parts.indexOf(':');
        const serial = item.deviceSerial || (colonIdx > 0 ? parts.slice(0, colonIdx) : '');
        const pkg = item.packageName || (colonIdx > 0 ? parts.slice(colonIdx + 1) : '');
        if (serial && pkg) {
          cleanupReq = { tool: 'ig5_app_observe', action: 'android_session_stop', device_serial: serial, package_name: pkg };
        }
      } else if (!isDbg && !isApp && !isAndroid) {
        cleanupReq = { tool: 'ig5_capture_control', action: 'stop' };
      }
      if (cleanupReq) {
        push(1, {
          kind: 'cleanup-owned-resource',
          routeFeasible: true,
          operationExecutableNow: true,
          rationale: `Active managed resource "${item.resourceKey}" requires owner stop before completion or stop.`,
          request: cleanupReq,
        });
      }
    }
  }

  if (assessment.unknownEffectsCount > 0) {
    push(2, {
      kind: 'inspect-unknown-execution-effect',
      routeFeasible: true,
      operationExecutableNow: true,
      rationale: 'An interrupted operation has status=effect-unknown; inspect session/runtime state rather than replaying automatically.',
      request: { tool: 'ig5_doctor', operation: 'session' },
    });
  }

  if (assessment.stopReason === 'user-cancelled' || assessment.stopReason === 'host-goal-paused') {
    candidates.sort((a, b) => a.priority - b.priority);
    return {
      schema: 'ig5-root-plan-v1',
      rootId: rootTask.rootId,
      planRevision: rootTask.planRevision,
      workState: assessment.workState,
      stopReason: assessment.stopReason,
      debugRouteFeasible,
      candidates: candidates.slice(0, maxCandidates).map(({ priority: _p, ...rest }) => rest),
      deferred: [{ reason: `business-dispatch-halted:${assessment.stopReason}` }],
      mode: 'backward-chained-short-route',
      executionAuthorized: false,
    };
  }

  if (assessment.unresolvedCounterexamples?.length > 0) {
    const cx = assessment.unresolvedCounterexamples[0];
    push(5, {
      kind: 'revise-after-counterexample',
      routeFeasible: true,
      operationExecutableNow: false,
      missingParameters: ['workspace.root.route | workspace.root.scenario | workspace.root.candidate'],
      rationale: `Counterexample ${cx.counterexampleId} refuted prior hypothesis; update route/scenario or formulate a revised experiment.`,
      request: null,
      requestTemplate: { tool: 'ig5_workspace', workspace: { action: 'root-update', id: rootTask.rootId, root: {} } },
    });
  }

  const activeExp = rootTask.experiments.find(e => e.mode === 'explicit' && ['selected', 'running'].includes(e.status));
  if (activeExp && activeExp.receiptIds.length > 0) {
    push(10, {
      kind: 'evaluate-active-experiment',
      routeFeasible: true,
      operationExecutableNow: false,
      missingParameters: ['workspace.root.observationClass', 'workspace.root.verdict', 'workspace.root.whyNextChanged', 'workspace.root.nextAction'],
      rationale: `Experiment ${activeExp.expId} has ${activeExp.receiptIds.length} recorded receipt(s); classify observations and update route premises.`,
      request: null,
      requestTemplate: {
        tool: 'ig5_workspace',
        workspace: { action: 'evaluate', id: rootTask.rootId, root: { expId: activeExp.expId } },
      },
    });
  }

  if (rootTask.components.length === 0) {
    push(12, {
      kind: 'register-target-component',
      routeFeasible: true,
      operationExecutableNow: false,
      missingParameters: ['workspace.root.component.path'],
      rationale: 'Register primary target binary/component bytes and SHA-256 before planning experiments.',
      request: null,
      requestTemplate: {
        tool: 'ig5_workspace',
        workspace: { action: 'root-update', id: rootTask.rootId, root: { component: { componentId: 'comp-1' } } },
      },
    });
  } else {
    const mainComp = rootTask.components[0];
    const hasStaticReceipt = rootTask.receipts.some(r => ['ig5_open', 'ig5_funcs', 'ig5_decompile', 'ig5_bytes', 'ig5_package'].includes(r.tool) && r.outcome === 'success');
    if (!hasStaticReceipt) {
      const staticReq = mainComp.role === 'electron-app'
        ? {
            tool: 'ig5_package',
            action: 'js_app',
            target: mainComp.path,
            input: { path: mainComp.path },
            research: { id: rootTask.rootId, key: `js-app-${mainComp.componentId}`, note: 'Static JS/Electron structure & helper candidate reconstruction' },
          }
        : mainComp.role === 'apk'
        ? {
            tool: 'ig5_package',
            action: 'apk',
            target: mainComp.path,
            input: { path: mainComp.path },
            research: { id: rootTask.rootId, key: `apk-static-${mainComp.componentId}`, note: 'Static APK manifest/DEX/JNI library inspection' },
          }
        : {
            tool: 'ig5_open',
            path: mainComp.path,
            research: { id: rootTask.rootId, key: `open-${mainComp.componentId}`, note: 'Open component for targeted entry location' },
          };
      push(15, {
        kind: 'inline-static-locate',
        routeFeasible: true,
        operationExecutableNow: true,
        rationale: 'Locate target structure/entry statically with inline research receipt instead of bulk pseudocode export.',
        request: staticReq,
      });
    }

    // Budget-headroom guard (P3): if candidate is pre-committed and dynamic holdout receipts already exist
    // while testVectors are still unattached, prioritize attaching testVectors immediately!
    const primaryDeliv = rootTask.deliverables[0];
    const hasHoldoutReceipt = rootTask.experiments.some(e => e.kind === 'holdout-verify' && e.receiptIds.length > 0);
    if (primaryDeliv?.candidateExplanation?.ruleSha256
      && hasHoldoutReceipt
      && (!primaryDeliv.candidateExplanation.testVectors || primaryDeliv.candidateExplanation.testVectors.length === 0)) {
      push(4, {
        kind: 'attach-verified-test-vectors',
        routeFeasible: true,
        operationExecutableNow: false,
        missingParameters: ['workspace.root.testVectors'],
        rationale: 'Pre-committed candidate and holdout execution receipt already exist; attach discovery + holdout testVectors before spending remaining budget on extra calls.',
        request: null,
        requestTemplate: {
          tool: 'ig5_workspace',
          workspace: { action: 'root-update', id: rootTask.rootId, root: { testVectors: [] } },
        },
      });
    }

    if (debugRouteFeasible && rootTask.scenarios.length === 0) {
      push(18, {
        kind: 'prepare-runtime-scenario',
        routeFeasible: true,
        operationExecutableNow: false,
        missingPrerequisites: ['runtime-scenario(args,cwd,trigger,observationWindow)'],
        missingParameters: ['workspace.root.scenario.args', 'workspace.root.scenario.cwd', 'workspace.root.scenario.inputSpec.sampleHex', 'workspace.root.scenario.trigger'],
        rationale: 'Dynamic debugging is feasible on this host, but no reproducible runtime scenario is defined yet; prepare scenario parameters instead of defaulting to static bulk export.',
        request: null,
        requestTemplate: {
          tool: 'ig5_workspace',
          workspace: { action: 'root-update', id: rootTask.rootId, root: { scenario: { componentId: mainComp.componentId } } },
        },
      });
    } else if (!debugRouteFeasible) {
      deferred.push({ reason: `dynamic-debug-not-feasible:${debugCap?.policy === 'blocked' ? 'policy-blocked' : 'runtime-unavailable'}` });
    }

    const activeRoute = rootTask.routes.find(r => r.status === 'active');
    if (!activeRoute) {
      push(19, {
        kind: 'define-short-route',
        routeFeasible: debugRouteFeasible,
        operationExecutableNow: false,
        missingParameters: ['workspace.root.route.question', 'workspace.root.route.targetObservation', 'workspace.root.route.discriminatingExperiment'],
        rationale: 'Define backward-chained short route from deliverable -> target observation -> preparation -> discriminating experiment.',
        request: null,
        requestTemplate: {
          tool: 'ig5_workspace',
          workspace: { action: 'root-update', id: rootTask.rootId, root: { route: { deliverableId: rootTask.deliverables[0]?.id || 'deliv-primary' } } },
        },
      });
    } else {
      const prepLedger = rootTask.preparationLedger?.[activeRoute.objectiveKey];
      const prepExhausted = Boolean(prepLedger && prepLedger.usedCalls >= prepLedger.limit);
      if (prepExhausted && !activeRoute.operationExecutableNow) {
        deferred.push({ reason: `preparation-budget-exhausted:${activeRoute.routeId}` });
      }
      if (debugRouteFeasible && rootTask.scenarios.length > 0 && !activeExp) {
        const evaluatedScenarioIds = new Set(
          rootTask.experiments.filter(e => e.status === 'evaluated' && e.routeId === activeRoute.routeId).map(e => e.scenarioId),
        );
        const nextScenario = rootTask.scenarios.find(s => !evaluatedScenarioIds.has(s.scenarioId)) || null;
        if (nextScenario) {
          const isHoldoutScenario = Boolean(nextScenario.inputSpec?.isHoldout);
          const routeDeliv = rootTask.deliverables.find(d => d.id === activeRoute.deliverableId) || rootTask.deliverables[0] || null;
          const hasPrecommittedCandidate = Boolean(routeDeliv?.candidateExplanation?.ruleSha256 && !routeDeliv?.candidateExplanation?.needsReassessment);
          if (isHoldoutScenario && !hasPrecommittedCandidate) {
            push(20, {
              kind: 'precommit-candidate-before-holdout',
              routeFeasible: true,
              operationExecutableNow: false,
              missingParameters: ['workspace.root.candidate.summary', 'workspace.root.candidate.outputSpec', 'workspace.root.candidate.executableRule'],
              rationale: `Holdout scenario "${nextScenario.scenarioId}" cannot be selected until candidate outputSpec and executableRule (ig5-bounded-byte-rule-v1) are pre-committed.`,
              request: null,
              requestTemplate: {
                tool: 'ig5_workspace',
                workspace: {
                  action: 'root-update',
                  id: rootTask.rootId,
                  root: {
                    candidate: {
                      deliverableId: routeDeliv?.id || 'deliv-1',
                      executableRule: { schema: 'ig5-bounded-byte-rule-v1' },
                    },
                  },
                },
              },
            });
          } else {
            const expKind = isHoldoutScenario ? 'holdout-verify' : 'dynamic-breakpoint-read';
            const scenarioCompId = nextScenario.componentId || mainComp.componentId;
            push(20, {
              kind: 'select-discriminating-experiment',
              routeFeasible: true,
              operationExecutableNow: true,
              rationale: `Scenario "${nextScenario.scenarioId}" is ready; select explicit dynamic experiment for "${activeRoute.targetObservation}".`,
              request: {
                tool: 'ig5_workspace',
                workspace: {
                  action: 'select',
                  id: rootTask.rootId,
                  root: {
                    kind: expKind,
                    routeId: activeRoute.routeId,
                    scenarioId: nextScenario.scenarioId,
                    componentId: scenarioCompId,
                    observer: activeRoute.targetObservation,
                    hypothesis: `Scenario "${nextScenario.scenarioId}" produces observable ${activeRoute.targetObservation} via ${activeRoute.discriminatingExperiment}`,
                  },
                },
              },
            });
          }
        } else {
          push(20, {
            kind: 'formulate-new-scenario-or-hypothesis',
            routeFeasible: true,
            operationExecutableNow: false,
            missingParameters: ['workspace.root.hypothesis', 'workspace.root.scenarioId'],
            rationale: 'All registered scenarios on this route were already evaluated; define a new scenario or revised hypothesis.',
            request: null,
            requestTemplate: {
              tool: 'ig5_workspace',
              workspace: { action: 'select', id: rootTask.rootId, root: { routeId: activeRoute.routeId, componentId: mainComp.componentId } },
            },
          });
        }
      }
    }

    const needsHoldout = assessment.deliverables.some(d => d.missing?.includes('missing-independent-holdout-verification'));
    if (needsHoldout && debugRouteFeasible) {
      const hasHoldoutScenario = rootTask.scenarios.some(s => s.inputSpec?.isHoldout);
      if (!hasHoldoutScenario) {
        push(25, {
          kind: 'prepare-holdout-scenario',
          routeFeasible: true,
          operationExecutableNow: false,
          missingParameters: ['workspace.root.scenario(isHoldout=true,inputSpec.sampleHex,args)'],
          rationale: 'Deliverable requires an independent holdout input scenario disjoint from discovery inputs.',
          request: null,
          requestTemplate: {
            tool: 'ig5_workspace',
            workspace: {
              action: 'root-update',
              id: rootTask.rootId,
              root: { scenario: { componentId: mainComp.componentId, inputSpec: { isHoldout: true } } },
            },
          },
        });
      }
    }
  }

  if (!assessment.canCompleteHostGoal) {
    push(35, {
      kind: 'assess-deliverables',
      routeFeasible: true,
      operationExecutableNow: true,
      rationale: 'Check independent artifact-backed deliverable verification and cleanup alignment.',
      request: { tool: 'ig5_workspace', workspace: { action: 'assess', id: rootTask.rootId } },
    });
  }

  candidates.sort((a, b) => a.priority - b.priority);
  return {
    schema: 'ig5-root-plan-v1',
    rootId: rootTask.rootId,
    planRevision: rootTask.planRevision,
    workState: assessment.workState,
    stopReason: assessment.stopReason,
    debugRouteFeasible,
    candidates: candidates.slice(0, maxCandidates).map(({ priority: _p, ...rest }) => rest),
    deferred,
    mode: 'backward-chained-short-route',
    executionAuthorized: false,
  };
}
