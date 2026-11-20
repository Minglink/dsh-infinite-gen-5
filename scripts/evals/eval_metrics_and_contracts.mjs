// Independent offline event, token, call-partition, cleanup-attribution, and root-contract auditor.
// Zero personal paths, credentials, or sealed oracle secrets.

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const sha256 = (textOrBuf) => createHash('sha256').update(textOrBuf).digest('hex');

export const KNOWN_USAGE_KEYS = new Set([
  'input', 'inputTokens', 'prompt_tokens',
  'output', 'outputTokens', 'completion_tokens',
  'cacheRead', 'cacheReadTokens', 'cache_read_input_tokens',
  'cacheWrite', 'cacheWriteTokens', 'cache_creation_input_tokens',
  'total', 'totalTokens', 'total_tokens',
  'cost',
]);

export const CLEANUP_TOOL_CHECK = (toolName, rawArgs = {}) => (
  (toolName === 'ig5_dbg' && rawArgs?.op === 'stop')
  || (toolName === 'ig5_capture_control' && rawArgs?.action === 'stop')
  || (toolName === 'ig5_app_observe' && ['stop', 'android_session_stop'].includes(rawArgs?.action))
  || toolName === 'ig5_close'
);

export const TERMINAL_GOAL_ACTIONS = new Set(['complete', 'blocked', 'pause']);

export function parseJsonSafe(raw, fallback = {}) {
  if (raw && typeof raw === 'object') return raw;
  if (typeof raw !== 'string' || !raw.trim()) return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

/**
 * Classify prompt guidance level objectively from the exact prompt text delivered to the model.
 */
export function classifyPromptGuidance(promptText) {
  const text = String(promptText || '');
  const promptSha256 = sha256(Buffer.from(text, 'utf8'));
  const hasAddressesOrSelectors = /\b0x[0-9a-fA-F]{3,16}\b|#[a-zA-Z0-9_-]{3,}/.test(text);
  const hasNamedTargetBinaries = /\b(?:ingest_runner|stage_alpha|stage_beta|seal_codec64|ping_check|frame_sealer64|spool_router|telemetry_cli)\.exe\b/i.test(text);
  const hasExplicitContractFields = /\b(?:nonCooperativeRequired|requiredObservations|deliverable\s+kind=|process-chain-transform|electron-native-chain|structured-frame-transform|worker-pe|main-pe)\b/.test(text);
  const hasSkillPointer = /\big5-reverse-agent\b/.test(text);

  let guidanceLevel = 'pure-business-only';
  const cues = [];
  if (hasAddressesOrSelectors) {
    guidanceLevel = 'step-or-address-guided';
    cues.push('addresses-or-dom-selectors');
  } else if (hasNamedTargetBinaries && hasExplicitContractFields) {
    guidanceLevel = 'named-components-and-contract';
    cues.push('named-component-binaries', 'explicit-root-contract-fields');
  } else if (hasExplicitContractFields || hasNamedTargetBinaries) {
    guidanceLevel = 'contract-hinted';
    if (hasExplicitContractFields) cues.push('explicit-root-contract-fields');
    if (hasNamedTargetBinaries) cues.push('named-component-binaries');
  }
  if (hasSkillPointer) cues.push('skill-name-pointer');

  return {
    promptSha256,
    promptByteLength: Buffer.byteLength(text, 'utf8'),
    guidanceLevel,
    detectedGuidanceCues: cues,
    qualifiesAsUnguidedBusinessPrompt: guidanceLevel === 'pure-business-only',
  };
}

/**
 * Extract accurate token usage from DSH session JSONL records and/or session events,
 * deduplicating by assistant message ID / responseId and surfacing any unknown usage keys.
 */
export function analyzeTokenUsage({ dshSessionObjects = [], sessionEvents = [] } = {}) {
  let uncachedInputTokens = 0;
  let cacheReadTokens = 0;
  let cacheWriteTokens = 0;
  let outputTokens = 0;
  let reportedTotalTokens = 0;
  let usageRecordsCount = 0;
  const seenKeys = new Set();
  const unknownUsageKeys = new Set();

  const ingestUsage = (u, dedupKey) => {
    if (!u || typeof u !== 'object') return;
    if (dedupKey && seenKeys.has(dedupKey)) return;
    if (dedupKey) seenKeys.add(dedupKey);

    for (const k of Object.keys(u)) {
      if (!KNOWN_USAGE_KEYS.has(k)) unknownUsageKeys.add(k);
    }

    const inp = Number(u.inputTokens ?? u.input ?? u.prompt_tokens ?? 0);
    const out = Number(u.outputTokens ?? u.output ?? u.completion_tokens ?? 0);
    const cRead = Number(u.cacheReadTokens ?? u.cacheRead ?? u.cache_read_input_tokens ?? 0);
    const cWrite = Number(u.cacheWriteTokens ?? u.cacheWrite ?? u.cache_creation_input_tokens ?? 0);
    const tot = Number(u.totalTokens ?? u.total ?? u.total_tokens ?? (inp + out + cRead + cWrite));

    uncachedInputTokens += inp;
    outputTokens += out;
    cacheReadTokens += cRead;
    cacheWriteTokens += cWrite;
    reportedTotalTokens += tot;
    usageRecordsCount += 1;
  };

  for (const [idx, obj] of dshSessionObjects.entries()) {
    const msg = obj?.message || obj?.data?.message || null;
    const u = msg?.usage || obj?.usage || obj?.data?.usage || null;
    if (u) {
      const key = msg?.id || msg?.source?.replayState?.response?.responseId || obj?.id || `sess-obj-${idx}`;
      ingestUsage(u, key);
    }
  }

  // Fallback to sessionEvents assistant/message if dshSessionObjects had none
  if (usageRecordsCount === 0) {
    for (const [idx, ev] of sessionEvents.entries()) {
      const msg = ev?.data?.message || null;
      const u = msg?.usage || ev?.data?.usage || null;
      if (u) {
        const key = msg?.id || msg?.source?.replayState?.response?.responseId || `ev-msg-${idx}`;
        ingestUsage(u, key);
      }
    }
  }

  const componentSum = uncachedInputTokens + outputTokens + cacheReadTokens + cacheWriteTokens;
  return {
    usageRecordsCount,
    uncachedInputTokens,
    cacheReadTokens,
    cacheWriteTokens,
    outputTokens,
    componentSumTokens: componentSum,
    reportedTotalTokens,
    sumMatchesReportedTotal: usageRecordsCount > 0 ? componentSum === reportedTotalTokens : null,
    unknownUsageFields: [...unknownUsageKeys].sort(),
  };
}

/**
 * Compute deduplicated, mutually exclusive call & error partitions from session events + guard log.
 *
 * Partition Invariants:
 *   1. `attemptedCalls = guardAllowedCalls + guardDeniedCalls` (when guard is mounted; otherwise `attemptedCalls = dispatchedCalls`).
 *   2. `guardAllowedCalls = allowedOrdinaryCalls + allowedTerminalCalls + allowedCleanupCalls` (mutually exclusive roles).
 *   3. Every `tool/result` is deduplicated by `toolCallId` (`e.data.message.isError` or `e.data.isError`),
 *      and every error result is classified into EXACTLY ONE of:
 *        - `guardDeniedErrorResults`: blocked pre-execute by evaluation guard (`denied-*`), never entered tool/host handler.
 *        - `hostGoalGateOrThresholdErrors`: `create_goal`/`get_goal`/`update_goal` rejected by host threshold (e.g. `<3 rounds`) or IG5 completion gate.
 *        - `toolExecutionErrors`: actual tool handler execution errors on allowed calls.
 */
export function analyzeCallAndErrorPartitions({ sessionEvents = [], guardEntries = [], ordinaryCallLimit = 70 } = {}) {
  const callsById = new Map();
  const orderedCallIds = [];

  for (const [idx, ev] of sessionEvents.entries()) {
    if (ev?.type !== 'tool/call') continue;
    const d = ev.data || {};
    const callId = d.callId || d.id || `anon-call-${idx}`;
    if (callsById.has(callId)) continue;
    const rawArgs = parseJsonSafe(d.arguments, {});
    const toolName = d.name || 'unknown';
    const isCleanup = CLEANUP_TOOL_CHECK(toolName, rawArgs);
    const isTerminal = toolName === 'get_goal' || (toolName === 'update_goal' && TERMINAL_GOAL_ACTIONS.has(rawArgs?.action));
    callsById.set(callId, {
      callId,
      seqIndex: orderedCallIds.length + 1,
      turn: d.turn ?? null,
      step: d.step ?? null,
      toolName,
      rawArgs,
      role: isCleanup ? 'cleanup' : isTerminal ? 'terminal' : 'ordinary',
      resultReceived: false,
      isError: false,
      errorText: null,
      guardDecision: null, // 'allowed' | 'denied-*'
    });
    orderedCallIds.push(callId);
  }

  // Pair pre-execute guard decisions in exact call order
  const preExecGuard = guardEntries.filter((g) => g && (g.event === 'allowed' || (typeof g.event === 'string' && g.event.startsWith('denied-'))));
  for (let i = 0; i < Math.min(orderedCallIds.length, preExecGuard.length); i += 1) {
    const rec = callsById.get(orderedCallIds[i]);
    if (rec && (!preExecGuard[i].toolName || preExecGuard[i].toolName === rec.toolName)) {
      rec.guardDecision = preExecGuard[i].event;
    }
  }

  // Deduplicate tool/result by toolCallId and read `e.data.message.isError` (with fallback to `e.data.isError`)
  const seenResultCallIds = new Set();
  for (const ev of sessionEvents) {
    if (ev?.type !== 'tool/result') continue;
    const msg = ev.data?.message || {};
    const callId = msg.toolCallId || ev.data?.callId || msg.source?.callId || null;
    if (callId && seenResultCallIds.has(callId)) continue;
    if (callId) seenResultCallIds.add(callId);

    const isError = Boolean(msg.isError === true || ev.data?.isError === true);
    const contentArr = Array.isArray(msg.content) ? msg.content : [];
    const textPart = contentArr.find((c) => typeof c?.text === 'string')?.text
      || (typeof ev.data?.error === 'string' ? ev.data.error : '');

    const callRec = callId ? callsById.get(callId) : null;
    if (callRec) {
      callRec.resultReceived = true;
      callRec.isError = isError;
      if (isError) callRec.errorText = textPart.slice(0, 512);
    }
  }

  const allCalls = orderedCallIds.map((id) => callsById.get(id));
  const guardMounted = preExecGuard.length > 0;

  let guardAllowedCalls = 0;
  let guardDeniedCalls = 0;
  let guardDeniedBudgetCalls = 0;
  let guardDeniedRoundThresholdCalls = 0;
  let guardDeniedPolicyCalls = 0;

  let allowedOrdinaryCalls = 0;
  let allowedTerminalCalls = 0;
  let allowedCleanupCalls = 0;

  let guardDeniedErrorResults = 0;
  let hostGoalGateOrThresholdErrors = 0;
  let toolExecutionErrors = 0;
  let actuallyDispatchedCalls = 0;
  let dispatchedSucceededCalls = 0;

  for (const c of allCalls) {
    const isGuardDenied = guardMounted
      ? (typeof c.guardDecision === 'string' && c.guardDecision.startsWith('denied-'))
      : false;

    if (isGuardDenied) {
      guardDeniedCalls += 1;
      if (c.guardDecision === 'denied-budget') guardDeniedBudgetCalls += 1;
      else if (c.guardDecision === 'denied-host-round-threshold-not-met') guardDeniedRoundThresholdCalls += 1;
      else guardDeniedPolicyCalls += 1;
      if (c.isError) guardDeniedErrorResults += 1;
      continue;
    }

    guardAllowedCalls += 1;
    if (c.role === 'cleanup') allowedCleanupCalls += 1;
    else if (c.role === 'terminal') allowedTerminalCalls += 1;
    else allowedOrdinaryCalls += 1;

    const isGoalTool = ['get_goal', 'create_goal', 'update_goal'].includes(c.toolName);
    if (isGoalTool && c.isError) {
      hostGoalGateOrThresholdErrors += 1;
    } else {
      actuallyDispatchedCalls += 1;
      if (c.isError) toolExecutionErrors += 1;
      else if (c.resultReceived) dispatchedSucceededCalls += 1;
    }
  }

  const totalErrorResults = guardDeniedErrorResults + hostGoalGateOrThresholdErrors + toolExecutionErrors;

  return {
    partitionExclusivityNote: 'attemptedCalls = guardAllowedCalls + guardDeniedCalls; guardAllowedCalls = allowedOrdinaryCalls + allowedTerminalCalls + allowedCleanupCalls; totalErrorResults = guardDeniedErrorResults + hostGoalGateOrThresholdErrors + toolExecutionErrors (all deduplicated by callId).',
    attemptedCalls: allCalls.length,
    guardMounted,
    guardAllowedCalls,
    guardDeniedCalls,
    guardDeniedBreakdown: {
      deniedBudget: guardDeniedBudgetCalls,
      deniedHostRoundThreshold: guardDeniedRoundThresholdCalls,
      deniedPolicyOrPath: guardDeniedPolicyCalls,
    },
    guardAllowedByRole: {
      allowedOrdinaryCalls,
      allowedTerminalCalls,
      allowedCleanupCalls,
    },
    executionAndErrors: {
      actuallyDispatchedCalls,
      dispatchedSucceededCalls,
      totalErrorResults,
      guardDeniedErrorResults,
      hostGoalGateOrThresholdErrors,
      toolExecutionErrors,
    },
    budgetCompliant: allowedOrdinaryCalls <= ordinaryCallLimit && guardDeniedBudgetCalls === 0,
    explicitCleanupCallsCount: allowedCleanupCalls,
  };
}

/**
 * Attribute cleanup confirmation transparently across provider auto-reclaim, explicit model calls,
 * and evaluation runner fallback termination (never inferring `null` as explicit model cleanup!).
 */
export function buildTransparentCleanupReport({
  processCheck,
  cleanupReservations = [],
  explicitCleanupCallsCount = 0,
  ephemeralJobContainersAutoReclaimedCount = 0,
  runnerFallbackKillUsed = false,
} = {}) {
  const activeOrUnknown = cleanupReservations.filter((r) => r.status === 'active' || r.status === 'unknown');
  const confirmedLongLived = cleanupReservations.filter((r) => r.status === 'confirmed' || r.status === 'released-unstarted');
  const processCheckClean = processCheck?.status === 'checked' && Array.isArray(processCheck.processes) && processCheck.processes.length === 0;
  const cleanupConfirmed = activeOrUnknown.length === 0 && processCheckClean;

  let primaryCleanupSource = 'none-needed';
  if (runnerFallbackKillUsed) primaryCleanupSource = 'runner-fallback-kill';
  else if (confirmedLongLived.length > 0 || explicitCleanupCallsCount > 0) {
    primaryCleanupSource = ephemeralJobContainersAutoReclaimedCount > 0
      ? 'model-explicit-and-provider-auto-job-reclaim'
      : 'model-explicit-stop-or-close';
  } else if (ephemeralJobContainersAutoReclaimedCount > 0) {
    primaryCleanupSource = 'provider-auto-job-reclaim';
  }

  return {
    cleanupConfirmed,
    primaryCleanupSource,
    attribution: {
      modelExplicitCleanupCallsCount: explicitCleanupCallsCount,
      longLivedReservationsConfirmedByModelCount: confirmedLongLived.length,
      longLivedReservationsPendingOrUnknownCount: activeOrUnknown.length,
      providerAutoReclaimedJobRunsCount: ephemeralJobContainersAutoReclaimedCount,
      runnerFallbackKillUsed: Boolean(runnerFallbackKillUsed),
    },
    hostNativeProcessCheck: processCheck || { status: 'not-checked', processes: null },
  };
}

/**
 * Independent evaluator-side audit checking whether the model's created root investigation
 * actually enforces the evaluation task's required contract (so omitting `nonCooperativeRequired`
 * or `worker-pe` components CANNOT silently lower verification standards!).
 */
export function auditRootContractAgainstSpec(rootTask, expectedContract = {}) {
  const issues = [];
  if (!rootTask) {
    return {
      contractFullyEnforced: false,
      effectiveNonCooperativeGateActive: false,
      issues: ['missing-root-investigation'],
    };
  }
  const deliv = rootTask.deliverables?.[0] || null;
  if (!deliv) {
    return {
      contractFullyEnforced: false,
      effectiveNonCooperativeGateActive: false,
      issues: ['missing-primary-deliverable'],
    };
  }

  if (Array.isArray(expectedContract.allowedDeliverableKinds) && expectedContract.allowedDeliverableKinds.length > 0) {
    if (!expectedContract.allowedDeliverableKinds.includes(deliv.kind)) {
      issues.push(`unexpected-deliverable-kind(actual=${deliv.kind},expected=${expectedContract.allowedDeliverableKinds.join('|')})`);
    }
  }

  const reqObs = new Set(deliv.requiredObservations || []);
  for (const mustObs of expectedContract.requiredObservations || []) {
    if (!reqObs.has(mustObs)) {
      issues.push(`missing-required-observation-obligation(${mustObs})`);
    }
  }

  if (expectedContract.holdoutRequired === true && deliv.holdoutRequired !== true) {
    issues.push('holdout-requirement-disabled-on-deliverable');
  }

  // Check whether `fixtureOnlyProtocol` rejection was effectively enforced:
  // In investigation_assessment.js, `fixtureOnlyProtocol === true` is rejected iff
  // `deliv.nonCooperativeRequired === true` OR `reqObs.has('non-cooperative-ui-trigger')`.
  const effectiveNonCooperativeGateActive = Boolean(
    deliv.nonCooperativeRequired === true || reqObs.has('non-cooperative-ui-trigger'),
  );
  if (expectedContract.mustRejectFixtureOnlyProtocol === true) {
    if (deliv.nonCooperativeRequired !== true && !reqObs.has('non-cooperative-ui-trigger')) {
      issues.push('non-cooperative-fixture-rejection-not-enforced(nonCooperativeRequired=false and non-cooperative-ui-trigger absent)');
    }
  }
  if (expectedContract.requireExplicitNonCooperativeFlag === true && deliv.nonCooperativeRequired !== true) {
    issues.push('explicit-nonCooperativeRequired-flag-omitted');
  }

  if (Array.isArray(expectedContract.requiredComponentRoles)) {
    const roleCounts = {};
    for (const c of rootTask.components || []) {
      roleCounts[c.role] = (roleCounts[c.role] || 0) + 1;
    }
    for (const { role, minCount = 1 } of expectedContract.requiredComponentRoles) {
      if ((roleCounts[role] || 0) < minCount) {
        issues.push(`insufficient-registered-component-role(${role}:actual=${roleCounts[role] || 0},min=${minCount})`);
      }
    }
  }

  // Also verify zero attached testVectors used legacy fixtureOnlyProtocol when non-cooperative is expected
  return {
    deliverableKind: deliv.kind,
    declaredNonCooperativeRequired: Boolean(deliv.nonCooperativeRequired),
    declaredRequiredObservations: [...reqObs],
    effectiveNonCooperativeGateActive,
    contractFullyEnforced: issues.length === 0,
    issues,
  };
}

/**
 * Multi-dimensional outcome evaluation separating positive deliverable completion from negative-case
 * truthful rejection, legal host stopping, budget compliance, timeout, and runner termination.
 */
export function buildMultiDimensionalOutcome({
  isNegativeControl = false,
  finalGoalPhase = 'active',
  postRunAssess = null,
  oracleScore = null,
  contractAudit = null,
  callPartitions = null,
  cleanupReport = null,
  timedOut = false,
  runnerTerminated = false,
} = {}) {
  const hostGoalCompleted = finalGoalPhase === 'complete' || finalGoalPhase === 'completed';
  const hostGoalBlocked = finalGoalPhase === 'blocked';

  if (isNegativeControl) {
    const truthfulRejection = !hostGoalCompleted && postRunAssess?.canCompleteHostGoal === false;
    const hostStoppedLegally = hostGoalBlocked && !timedOut && !runnerTerminated;
    return {
      caseCategory: 'negative-control',
      falseCompletion: hostGoalCompleted,
      truthfulRejection,
      hostStoppedLegally,
      finalGoalPhase,
      budgetCompliant: Boolean(callPartitions?.budgetCompliant),
      cleanupConfirmed: Boolean(cleanupReport?.cleanupConfirmed),
      contractAligned: Boolean(contractAudit?.contractFullyEnforced),
      timeout: Boolean(timedOut),
      runnerTerminated: Boolean(runnerTerminated),
      // Strict end-to-end negative autonomy requires ALL of truthfulRejection + legal host stop + no timeout + no runner termination + cleanup!
      strictEndToEndAutonomousClosure: Boolean(
        truthfulRejection
        && hostStoppedLegally
        && cleanupReport?.cleanupConfirmed
        && contractAudit?.contractFullyEnforced,
      ),
    };
  }

  const algorithmOraclePassed = Boolean(oracleScore?.allPassed);
  const evidenceVerified = postRunAssess?.assessment === 'satisfied' && postRunAssess?.canCompleteHostGoal === true;
  const contractAligned = Boolean(contractAudit?.contractFullyEnforced);
  const deliverableVerifiedAndComplete = Boolean(
    hostGoalCompleted
    && algorithmOraclePassed
    && evidenceVerified
    && contractAligned
    && !timedOut
    && !runnerTerminated,
  );
  const falseCompletion = hostGoalCompleted && (!algorithmOraclePassed || !evidenceVerified);

  return {
    caseCategory: 'positive-generalization',
    falseCompletion,
    algorithmOraclePassed,
    evidenceVerified,
    contractAligned,
    hostStoppedLegally: hostGoalCompleted && !timedOut && !runnerTerminated,
    finalGoalPhase,
    budgetCompliant: Boolean(callPartitions?.budgetCompliant),
    cleanupConfirmed: Boolean(cleanupReport?.cleanupConfirmed),
    timeout: Boolean(timedOut),
    runnerTerminated: Boolean(runnerTerminated),
    strictEndToEndAutonomousClosure: Boolean(deliverableVerifiedAndComplete && cleanupReport?.cleanupConfirmed),
  };
}
