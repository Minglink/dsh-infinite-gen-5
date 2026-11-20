import { createHash } from 'node:crypto';
import { IG5_WRITE_TOOLS } from './approval_gate.js';
import { classifyManagedResourceCall } from './delegation_control.js';
import { jsonToolOutput } from './json_output.js';

const SHA = /^[a-f0-9]{64}$/;
const PRINTABLE_ID = /^[^\x00-\x1f\x7f]{1,128}$/;
const RESEARCH_KEYS = new Set(['id', 'key', 'exp', 'step', 'rev', 'pre', 'note']);
const INLINE_MAX_BYTES = 1024 * 1024;

export const RESEARCH_BINDING_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    key: { type: 'string' },
    exp: { type: 'string' },
    step: { type: 'integer' },
    rev: { type: 'integer' },
    pre: { type: 'string' },
    note: { type: 'string' },
  },
  required: ['id'],
  additionalProperties: false,
};

function fail(code, message, extra = {}) {
  throw Object.assign(new Error(message), { code, retryable: false, ...extra });
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).filter(k => value[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export function hashCanonical(value) {
  return createHash('sha256').update(canonical(value)).digest('hex');
}

export function parseAndStripResearch(rawArgs) {
  if (!rawArgs || typeof rawArgs !== 'object' || Array.isArray(rawArgs)) {
    return { research: null, cleanArgs: rawArgs ?? {} };
  }
  if (rawArgs.research === undefined) {
    return { research: null, cleanArgs: rawArgs };
  }
  const r = rawArgs.research;
  if (!r || typeof r !== 'object' || Array.isArray(r)) {
    fail('INVALID_ARGUMENT', 'research must be an object');
  }
  for (const k of Object.keys(r)) {
    if (!RESEARCH_KEYS.has(k)) fail('INVALID_ARGUMENT', `Unsupported research field "${k}"`);
  }
  if (typeof r.id !== 'string' || !PRINTABLE_ID.test(r.id.trim())) {
    fail('INVALID_ARGUMENT', 'research.id must be a non-empty printable identifier (1..128 chars)');
  }
  if (r.key !== undefined && (typeof r.key !== 'string' || !PRINTABLE_ID.test(r.key.trim()))) {
    fail('INVALID_ARGUMENT', 'research.key must be a non-empty printable request key (1..128 chars)');
  }
  if (r.exp !== undefined && (typeof r.exp !== 'string' || !PRINTABLE_ID.test(r.exp.trim()))) {
    fail('INVALID_ARGUMENT', 'research.exp must be a non-empty printable experiment ID (1..128 chars)');
  }
  if (r.step !== undefined && (!Number.isSafeInteger(r.step) || r.step < 0 || r.step > 64)) {
    fail('INVALID_ARGUMENT', 'research.step must be an integer in 0..64');
  }
  if (r.rev !== undefined && (!Number.isSafeInteger(r.rev) || r.rev < 1)) {
    fail('INVALID_ARGUMENT', 'research.rev must be a positive integer plan revision');
  }
  if (r.pre !== undefined && (typeof r.pre !== 'string' || !SHA.test(r.pre))) {
    fail('INVALID_ARGUMENT', 'research.pre must be a 64-hex SHA-256 precondition digest');
  }
  if (r.note !== undefined && (typeof r.note !== 'string' || r.note.length > 512 || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(r.note))) {
    fail('INVALID_ARGUMENT', 'research.note must be a printable string of at most 512 chars');
  }
  const { research: _removed, ...cleanArgs } = rawArgs;
  return {
    research: {
      id: r.id.trim(),
      ...(r.key !== undefined ? { key: r.key.trim() } : {}),
      ...(r.exp !== undefined ? { exp: r.exp.trim() } : {}),
      ...(r.step !== undefined ? { step: r.step } : {}),
      ...(r.rev !== undefined ? { rev: r.rev } : {}),
      ...(r.pre !== undefined ? { pre: r.pre } : {}),
      ...(r.note !== undefined ? { note: r.note } : {}),
    },
    cleanArgs,
  };
}

/**
 * Code-owned boundary between low-impact inline exploration and multi-step / mutating / dynamic experiments.
 * Model hints cannot downgrade a write or debugger operation into inline exploration.
 */
export function assertResearchModeAllowed(toolName, cleanArgs, research, classification) {
  if (!research) return;
  if (toolName === 'ig5_workspace' || toolName === 'ig5_profile' && cleanArgs?.collaboration !== undefined) {
    fail('INVALID_ARGUMENT', `${toolName} control actions do not accept inline research execution bindings`);
  }
  if (classification.kind === 'cleanup') return;
  const isReadOnlyStruct = toolName === 'ig5_struct' && ['get', 'list'].includes(cleanArgs?.action);
  const requiresSelectedExperiment = IG5_WRITE_TOOLS.has(toolName) && !isReadOnlyStruct;
  if (requiresSelectedExperiment && !research.exp) {
    fail('INLINE_EXPLORATION_NOT_PERMITTED', `${toolName} modifies state or executes dynamic runtime operations; select an explicit experiment via ig5_workspace action=select and pass research.exp`);
  }
}

function summarizeCleanArgs(toolName, cleanArgs) {
  if (!cleanArgs || typeof cleanArgs !== 'object') return {};
  const summary = {};
  for (const key of [
    'path', 'target', 'op', 'action', 'operation', 'backend', 'engine', 'ea', 'rva',
    'address_space', 'name', 'size', 'args', 'cwd', 'payload', 'payload_hex', 'stdin_hex',
    'corr_id', 'scenario_mode', 'trigger_mode', 'ui_actions', 'output_channel', 'legacy_fixture_protocol',
    'device_serial', 'package_name', 'abi', 'capture', 'expected_run_id', 'expected_stop_seq',
  ]) {
    if (cleanArgs[key] !== undefined) summary[key] = cleanArgs[key];
  }
  if (toolName === 'ig5_run_idapython' && typeof cleanArgs.code === 'string') {
    summary.codeSha256 = createHash('sha256').update(cleanArgs.code).digest('hex');
    summary.codeLength = cleanArgs.code.length;
  }
  return summary;
}

function extractRuntimeObservation(toolName, cleanArgs, output) {
  if (!output || typeof output !== 'object' || Array.isArray(output)) {
    return { runtimeIdentity: null, observedMetrics: { nonEmpty: Boolean(output) } };
  }
  const runtimeIdentity = {};
  for (const key of ['runId', 'stopSeq', 'pid', 'tid', 'state', 'reason', 'eventName', 'backend', 'arch', 'ip', 'imageBase']) {
    if (output[key] !== undefined) runtimeIdentity[key] = output[key];
  }
  if (output.context && typeof output.context === 'object') {
    runtimeIdentity.context = {
      ip: output.context.ip || null,
      module: output.context.module || null,
      modulePath: output.context.modulePath || null,
      moduleSha256: output.context.moduleSha256 || null,
      moduleBase: output.context.moduleBase || null,
      RVA: output.context.RVA || null,
      mainModuleBase: output.context.mainModuleBase || null,
    };
  }
  if (output._ig5 && typeof output._ig5 === 'object') {
    runtimeIdentity.evidence = {
      sha256: output._ig5.sha256 || null,
      engine: output._ig5.engine || null,
      provider: output._ig5.provider || null,
      attachmentId: output._ig5.attachmentId || null,
      dbRevision: output._ig5.dbRevision ?? null,
    };
  }
  if (output.launchScenario && typeof output.launchScenario === 'object') {
    runtimeIdentity.launchScenario = output.launchScenario;
  }
  const stopEvent = output.eventName || output.reason || null;
  const observedMetrics = {
    tool: toolName,
    op: cleanArgs?.op || cleanArgs?.action || cleanArgs?.operation || null,
    ok: output.ok !== false && !output.error,
    state: output.state || null,
    reason: stopEvent,
    hitBreakpoint: toolName === 'ig5_dbg' && ['breakpoint', 'hardware-breakpoint', 'memory-breakpoint'].includes(stopEvent),
    dataHex: typeof output.hex === 'string' ? output.hex.slice(0, 512) : null,
    regsSample: output.regs && typeof output.regs === 'object'
      ? Object.fromEntries(Object.entries(output.regs).filter(([k]) => ['rip', 'eip', 'rax', 'eax', 'rcx', 'rdx', 'r8', 'r9', 'rsp'].includes(k.toLowerCase())))
      : null,
    queryStatus: output.queryState?.status || null,
    returnedCount: output.queryState?.returned ?? (Array.isArray(output.funcs) ? output.funcs.length : Array.isArray(output.rows) ? output.rows.length : Array.isArray(output.functions) ? output.functions.length : Array.isArray(output.strings) ? output.strings.length : null),
  };
  return {
    runtimeIdentity: Object.keys(runtimeIdentity).length ? runtimeIdentity : null,
    observedMetrics,
  };
}

function attachExecutionMeta(output, meta) {
  if (output && typeof output === 'object' && !Array.isArray(output)) {
    return jsonToolOutput({ ...output, _managedExecution: meta });
  }
  return output;
}

function reconstructSavedReplay(mgr, op, researchLinkStatus) {
  if (!op.reportRef) {
    fail('RECEIPT_PERSISTENCE_FAILED', `Operation ${op.operationId} completed earlier without a readable receipt artifact; automatic replay is forbidden`, {
      operationId: op.operationId,
    });
  }
  const report = mgr.analysis.artifacts.get(op.reportRef);
  const body = report.result || {};
  if (op.outcome === 'success') {
    let payload = body.replayOutput;
    if (payload === undefined && body.replayBlobRef) {
      const { data } = mgr.analysis.artifacts.read(body.replayBlobRef);
      payload = JSON.parse(data.toString('utf8'));
    }
    return attachExecutionMeta(payload ?? { ok: true }, {
      operationId: op.operationId,
      reportId: report.id,
      recordSha256: createHash('sha256').update(JSON.stringify(report)).digest('hex'),
      replayed: true,
      outcome: op.outcome,
      researchLinkStatus,
    });
  }
  const err = body.error || {};
  throw Object.assign(new Error(err.message || `Previously recorded ${op.outcome} for request key ${op.requestKey}`), {
    code: err.code || op.errorCode || 'RECORDED_OPERATION_FAILURE',
    retryable: false,
    replayed: true,
    replayedReceipt: {
      operationId: op.operationId,
      reportId: report.id,
      outcome: op.outcome,
      researchLinkStatus,
    },
  });
}

function buildExecutionInputWitness(mgr, { toolName, cleanArgs, output, dispatchBinding }) {
  if (!mgr?.analysis?.artifacts?.put || !output || typeof output !== 'object') return null;
  const snap = dispatchBinding?.scenarioSnapshot || null;
  const contractRevision = dispatchBinding?.contractRevision ?? null;
  let hex = null;
  let channel = null;
  let consumptionProof = 'unverified';

  if (toolName === 'ig5_app_observe') {
    if (cleanArgs?.action === 'process_chain_scenario') {
      const w = output.inputChannelWitness;
      if (w && !w.channelBindingConflict && typeof output.observedInputHex === 'string' && output.observedInputHex.length > 0) {
        hex = output.observedInputHex.toLowerCase();
        channel = w.boundChannel || snap?.inputChannel || null;
        consumptionProof = w.consumptionProof || 'channel-delivered-prelaunch-verified-not-syscall-traced';
      }
    } else if (cleanArgs?.action === 'electron_scenario' && output.scenarioMode !== 'discover' && typeof output.observedInputHex === 'string' && output.observedInputHex.length > 0) {
      hex = output.observedInputHex.toLowerCase();
      channel = snap?.inputChannel || { kind: 'ipc' };
      consumptionProof = 'electron-ui-or-ipc-delivered';
    } else if (cleanArgs?.action === 'android_session_poll' && typeof output.observedInputHex === 'string' && output.observedInputHex.length > 0) {
      hex = output.observedInputHex.toLowerCase();
      channel = snap?.inputChannel || { kind: 'android-intent' };
      consumptionProof = 'frida-hook-argument-observed';
    }
  } else if (toolName === 'ig5_dbg' && cleanArgs?.op === 'start' && dispatchBinding?.verifiedLaunchInputHex) {
    hex = dispatchBinding.verifiedLaunchInputHex.toLowerCase();
    channel = snap?.inputChannel || null;
    consumptionProof = 'debugger-prelaunch-channel-verified';
  } else if (toolName === 'ig5_emulate' && snap?.inputHex) {
    hex = snap.inputHex.toLowerCase();
    channel = snap.inputChannel || { kind: 'emulate' };
    consumptionProof = 'emulator-initial-state-bound';
  }

  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) return null;
  const rawBytes = Buffer.from(hex, 'hex');
  const inputSha256 = createHash('sha256').update(rawBytes).digest('hex');
  const isSensitive = Boolean(snap?.sensitiveInput);
  const blobOut = isSensitive && typeof mgr.analysis.artifacts.putSensitive === 'function'
    ? mgr.analysis.artifacts.putSensitive(rawBytes)
    : mgr.analysis.artifacts.put(rawBytes);

  return {
    schema: 'ig5-execution-input-witness-v1',
    witnessBlobRef: blobOut.ref,
    sensitiveBlob: isSensitive,
    inputSha256,
    byteLength: rawBytes.length,
    channel,
    consumptionProof,
    contractRevision,
  };
}

function saveOperationReceipt(mgr, { operation, toolName, cleanArgs, argsDigest, research, outcome, output, error, runtimeIdentity, observedMetrics, dispatchBinding }) {
  let replayOutput;
  let replayBlobRef = null;
  let executionInputWitness = null;
  if (outcome === 'success' && output !== undefined) {
    executionInputWitness = buildExecutionInputWitness(mgr, { toolName, cleanArgs, output, dispatchBinding });
    const serialized = Buffer.from(JSON.stringify(output), 'utf8');
    if (serialized.length <= INLINE_MAX_BYTES) {
      replayOutput = output;
    } else {
      replayBlobRef = mgr.analysis.artifacts.put(serialized).ref;
    }
  }
  const opLabel = cleanArgs?.op || cleanArgs?.action || cleanArgs?.operation || null;
  return mgr.analysis.artifacts.save({
    kind: 'managed-operation-receipt',
    action: opLabel ? `${toolName}:${opLabel}` : toolName,
    operationId: operation.operationId,
    tool: toolName,
    investigationId: research?.id || null,
    experimentId: research?.exp || null,
    stepIndex: research?.step ?? null,
    outcome,
    argsDigest,
    result: {
      summary: `${toolName}${opLabel ? ':' + opLabel : ''} -> ${outcome}`,
      requestKey: research?.key || null,
      research: research || null,
      cleanArgsSummary: summarizeCleanArgs(toolName, cleanArgs),
      outcome,
      runtimeIdentity,
      observedMetrics,
      ...(executionInputWitness ? { executionInputWitness } : {}),
      ...(replayOutput !== undefined ? { replayOutput } : {}),
      ...(replayBlobRef ? { replayBlobRef } : {}),
      ...(error ? {
        error: {
          code: error.code || 'TOOL_EXECUTION_ERROR',
          message: String(error.message || error).slice(0, 2048),
          retryable: Boolean(error.retryable),
          cleanedUp: error.cleanedUp ?? null,
        },
      } : {}),
    },
  });
}

/**
 * Unified managed execution protocol wrapping public IG5 tools.
 * Handles:
 * - research binding validation & stripping
 * - atomic idempotency / budget / cleanup reservation in DelegationControl
 * - serial cancel control point & owner cleanup signal isolation
 * - immutable receipt persistence before RootInvestigationStore linkage
 */
export async function runManagedToolExecution({ mgr, toolName, rawArgs, execution, runCore }) {
  const { research, cleanArgs } = parseAndStripResearch(rawArgs);
  if (toolName === 'ig5_doctor' && cleanArgs?.operation === 'session' && !research) {
    return jsonToolOutput(mgr.coordination.diagnose(execution?.agent, cleanArgs));
  }
  const classification = classifyManagedResourceCall(toolName, cleanArgs);
  assertResearchModeAllowed(toolName, cleanArgs, research, classification);

  const hasHostSession = execution?.agent?.session !== undefined;
  const shouldManage = Boolean(hasHostSession || research);
  const coordOptions = { allowLocalFallback: !hasHostSession && Boolean(research) };

  if (!shouldManage) {
    if (execution?.signal?.aborted) throw new Error('IG5 operation cancelled');
    return runCore(cleanArgs, execution?.signal);
  }

  const argsDigest = hashCanonical({
    tool: toolName,
    args: cleanArgs,
    researchScope: research ? { id: research.id, exp: research.exp || null, step: research.step ?? null } : null,
  });

  let dispatchBinding = null;
  const admission = mgr.coordination.admitOperation(execution?.agent, {
    requestKey: research?.key || null,
    tool: toolName,
    cleanArgs,
    argsDigest,
    investigationId: research?.id || null,
    experimentId: research?.exp || null,
    stepIndex: research?.step ?? null,
    checkPreconditions: research ? () => {
      if (!mgr.rootInvestigations) {
        fail('ROOT_INVESTIGATION_UNAVAILABLE', 'Root investigation store is not initialized on this manager');
      }
      dispatchBinding = mgr.rootInvestigations.validateDispatchBinding({
        research,
        toolName,
        cleanArgs,
        isCleanup: classification.kind === 'cleanup',
        mgr,
      });
    } : null,
  }, coordOptions);

  if (admission.replayed) {
    const existing = admission.operation;
    if (existing.status === 'effect-unknown') {
      fail('IG5_EXECUTION_EFFECT_UNKNOWN', `Previous execution of request "${research?.key}" (${existing.operationId}) interrupted across host restart; effect is unknown and automatic replay is forbidden`, {
        operationId: existing.operationId,
      });
    }
    if (existing.status === 'cancelled-before-dispatch') {
      fail('IG5_CANCELLED_BEFORE_DISPATCH', `Request "${research?.key}" was cancelled before dispatch`, {
        operationId: existing.operationId,
      });
    }
    if (existing.status === 'admitted' || existing.status === 'dispatching') {
      fail('IG5_DUPLICATE_IN_FLIGHT', `Request "${research?.key}" (${existing.operationId}) is already in flight`, {
        operationId: existing.operationId,
      });
    }
    let linkStatus = existing.researchLinkStatus;
    if (linkStatus === 'receipt-pending' && existing.reportRef && mgr.rootInvestigations && existing.investigationId) {
      const savedReport = mgr.analysis.artifacts.get(existing.reportRef);
      mgr.rootInvestigations.recordSystemReceipt({
        rootId: existing.investigationId,
        receiptRecord: savedReport,
        operation: existing,
      });
      mgr.coordination.markOperationLinked(execution?.agent, existing.slotKey, coordOptions);
      linkStatus = 'linked';
    }
    return reconstructSavedReplay(mgr, existing, linkStatus);
  }

  const dispatched = mgr.coordination.beginDispatch(execution?.agent, admission.operation.slotKey, {
    signalAborted: Boolean(execution?.signal?.aborted),
  }, coordOptions);

  if (dispatched.status === 'cancelled-before-dispatch') {
    fail('IG5_CANCELLED_BEFORE_DISPATCH', 'Operation cancelled at serial dispatch control point before provider execution', {
      operationId: dispatched.operationId,
    });
  }

  const effectiveSignal = dispatched.isCleanup && execution?.signal?.aborted
    ? AbortSignal.timeout(10_000)
    : execution?.signal;

  let output;
  let execError = null;
  try {
    output = await runCore(cleanArgs, effectiveSignal, {
      boundScenarioSnapshot: dispatchBinding?.scenarioSnapshot || null,
    });
  } catch (error) {
    execError = error;
  }

  const outcome = execError
    ? (effectiveSignal?.aborted || execError.code === 'ABORT_ERR' || /cancelled/i.test(String(execError.message || '')) ? 'cancelled' : 'failure')
    : (output && typeof output === 'object' && output.ok === false ? 'failure' : 'success');

  const { runtimeIdentity, observedMetrics } = extractRuntimeObservation(toolName, cleanArgs, output);

  // Settle cleanup reservation state based on real execution outcome.
  try {
    if (toolName === 'ig5_dbg' && classification.kind === 'ordinary' && output?.state === 'no-task' && cleanArgs?.target) {
      mgr.coordination.noteTargetExited(execution?.agent, cleanArgs.target, coordOptions);
    } else if (classification.resourceKey) {
      mgr.coordination.settleResourceCall(execution?.agent, classification, {
        ok: outcome === 'success',
        stateName: output?.state || output?.stateName || null,
        cleanedUp: execError?.cleanedUp,
        runId: output?.runId || null,
        pid: output?.pid ?? output?.rootPid ?? null,
        creationIdentity: output?.creationIdentity ?? null,
        procStarttimeTicks: output?.procStarttimeTicks ?? null,
        containerId: output?.containerId ?? null,
        cleanupDisposition: output?.cleanupDisposition ?? output?.cleanup?.cleanupDisposition ?? null,
      }, coordOptions);
    }
  } catch {
    // Reservation settlement failure must not mask receipt persistence.
  }

  // Persist receipt artifact whenever research is bound OR requestKey deduplication was requested.
  const persistReceipt = Boolean(research);
  let savedReport = null;
  let linkStatus = research ? 'receipt-pending' : 'not-applicable';
  if (persistReceipt) {
    try {
      savedReport = saveOperationReceipt(mgr, {
        operation: dispatched,
        toolName,
        cleanArgs,
        argsDigest,
        research,
        outcome,
        output,
        error: execError,
        runtimeIdentity,
        observedMetrics,
        dispatchBinding,
      });
    } catch (receiptError) {
      mgr.coordination.completeOperation(execution?.agent, dispatched.slotKey, {
        outcome,
        errorCode: execError?.code || receiptError.code || 'RECEIPT_PERSISTENCE_FAILED',
        reportRef: null,
        runtimeIdentity,
        researchLinkStatus: 'receipt-save-failed',
      }, coordOptions);
      fail('RECEIPT_PERSISTENCE_FAILED', `Tool executed (${outcome}), but receipt artifact persistence failed: ${receiptError.message}`, {
        operationId: dispatched.operationId,
        executedBeforeFailure: true,
      });
    }
  }

  const completed = mgr.coordination.completeOperation(execution?.agent, dispatched.slotKey, {
    outcome,
    errorCode: execError?.code || (outcome === 'failure' ? 'TOOL_RESULT_NOT_OK' : null),
    reportRef: savedReport?.id || null,
    runtimeIdentity,
    researchLinkStatus: research ? 'receipt-pending' : 'not-applicable',
  }, coordOptions);

  let linkError = null;
  if (research && savedReport && mgr.rootInvestigations) {
    try {
      mgr.rootInvestigations.recordSystemReceipt({
        rootId: research.id,
        receiptRecord: savedReport,
        operation: completed,
      });
      mgr.coordination.markOperationLinked(execution?.agent, dispatched.slotKey, coordOptions);
      linkStatus = 'linked';
    } catch (err) {
      linkError = err;
      linkStatus = 'receipt-pending';
    }
  }

  if (execError) {
    if (savedReport && typeof execError === 'object' && Object.isExtensible(execError)) {
      execError.managedReceipt = {
        operationId: completed.operationId,
        reportId: savedReport.id,
        outcome,
        researchLinkStatus: linkStatus,
      };
    }
    throw execError;
  }

  if (research && savedReport) {
    return attachExecutionMeta(output, {
      operationId: completed.operationId,
      reportId: savedReport.id,
      replayed: false,
      outcome,
      researchLinkStatus: linkStatus,
      ...(linkError ? { linkPendingReason: String(linkError.message || linkError).slice(0, 256) } : {}),
    });
  }
  return output;
}
