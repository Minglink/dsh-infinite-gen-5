import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { ProjectStore } from './project_store.js';

const fail = (code, message, extra = {}) => {
  throw Object.assign(new Error(message), {
    code,
    phase: code.includes('BUDGET') ? 'shared-budget' : 'delegation-control',
    retryable: false,
    observedAt: new Date().toISOString(),
    faultStartedAt: null,
    diagnosticId: randomUUID(),
    recoveryActions: ['Use ig5_doctor operation=session for local metadata; retain the original shared ledger.'],
    ...extra,
  });
};
const same = (a, b) => ['projectId', 'artifactId', 'sha256', 'engine', 'provider', 'attachmentId', 'dbRevision'].every(k => a?.[k] === b?.[k]);
const key = id => createHash('sha256').update(id).digest('hex');
const SHA = /^[a-f0-9]{64}$/;
const EXEC_STATUSES = new Set(['admitted', 'dispatching', 'result-recorded', 'cancelled-before-dispatch', 'effect-unknown']);
const OUTCOMES = new Set(['success', 'failure', 'cancelled', 'inconclusive']);
const LINK_STATUSES = new Set(['not-applicable', 'receipt-pending', 'linked', 'receipt-save-failed']);
const MAX_OPS = 256;
const MAX_EMERGENCY_HEADROOM = 64;
const MAX_COMPACTED_OPS = 4096;
const MAX_STEP_LOCKS = 4096;
const MAX_RESERVATIONS = 64;

const lineageFailure = (reason, message) => {
  throw Object.assign(new Error(message), {
    code: 'AGENT_LINEAGE_UNAVAILABLE', reason, phase: 'session-lineage',
    retryable: reason === 'PARENT_SESSION_UNAVAILABLE', observedAt: new Date().toISOString(),
    diagnosticId: randomUUID(), evidenceStatus: 'observed-metadata-only', faultStartedAt: null,
    recoveryActions: [
      'Call ig5_doctor with operation=session for local session metadata.',
      'Ask the host to restore/index the original session ancestry, then retry. Existing shared usage remains in force.',
    ],
    automaticRecoverySupported: false,
  });
};

export function normalizeTargetResourceKey(target) {
  if (typeof target !== 'string' || !target.trim()) return null;
  const resolved = path.resolve(target.trim());
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

const CLEANUP_DBG_KEYS = new Set(['target', 'op', 'backend', 'engine', 'guest_profile', 'guest_binding_sha256', 'timeout', 'control']);
const CLEANUP_CAPTURE_KEYS = new Set(['action', 'session_id']);
const CLEANUP_APP_OBSERVE_KEYS = new Set(['action', 'target', 'timeout_ms']);
const CLEANUP_ANDROID_SESSION_KEYS = new Set(['action', 'device_serial', 'package_name', 'timeout_ms']);
const CLEANUP_CLOSE_KEYS = new Set(['target', 'engine']);

/** Classify resource acquisition vs strict owner-bound cleanup without trusting caller labels. */
export function classifyManagedResourceCall(name, args = {}) {
  if (name === 'ig5_dbg') {
    const targetKey = normalizeTargetResourceKey(args?.target);
    const targetPath = typeof args?.target === 'string' && args.target.trim() ? path.resolve(args.target.trim()) : null;
    if (['load', 'start'].includes(args?.op) && targetKey) {
      return { kind: 'acquire', resourceKey: `dbg:${targetKey}`, resourceType: 'debugger', targetKey, targetPath };
    }
    if (args?.op === 'stop' && targetKey) {
      const invalidField = Object.keys(args).find(k => args[k] !== undefined && !CLEANUP_DBG_KEYS.has(k));
      if (invalidField) {
        return { kind: 'invalid-cleanup', reason: `dbg op=stop cleanup cannot carry business parameter "${invalidField}"` };
      }
      return { kind: 'cleanup', resourceKey: `dbg:${targetKey}`, resourceType: 'debugger', targetKey, targetPath };
    }
  }
  if (name === 'ig5_capture_control') {
    if (args?.action === 'start') {
      return { kind: 'acquire', resourceKey: 'capture:proxy', resourceType: 'capture', targetKey: 'proxy' };
    }
    if (args?.action === 'stop') {
      const invalidField = Object.keys(args).find(k => args[k] !== undefined && !CLEANUP_CAPTURE_KEYS.has(k));
      if (invalidField) {
        return { kind: 'invalid-cleanup', reason: `capture stop cleanup cannot carry parameter "${invalidField}"` };
      }
      return { kind: 'cleanup', resourceKey: 'capture:proxy', resourceType: 'capture', targetKey: 'proxy' };
    }
  }
  if (name === 'ig5_app_observe') {
    if (['android_session_start', 'android_session_stop'].includes(args?.action)) {
      const serial = typeof args?.device_serial === 'string' ? args.device_serial.trim() : '';
      const pkg = typeof args?.package_name === 'string' ? args.package_name.trim() : '';
      if (serial && pkg) {
        const resourceKey = `android:${serial}:${pkg}`;
        const targetPath = typeof args?.target === 'string' && args.target.trim() ? path.resolve(args.target.trim()) : null;
        if (args.action === 'android_session_start') {
          return {
            kind: 'acquire',
            resourceKey,
            resourceType: 'android-device-session',
            targetKey: `${serial}:${pkg}`,
            deviceSerial: serial,
            packageName: pkg,
            targetPath,
          };
        }
        const invalidField = Object.keys(args).find(k => args[k] !== undefined && !CLEANUP_ANDROID_SESSION_KEYS.has(k));
        if (invalidField) {
          return { kind: 'invalid-cleanup', reason: `android_session_stop cleanup cannot carry parameter "${invalidField}"` };
        }
        return {
          kind: 'cleanup',
          resourceKey,
          resourceType: 'android-device-session',
          targetKey: `${serial}:${pkg}`,
          deviceSerial: serial,
          packageName: pkg,
        };
      }
    }
    const targetKey = normalizeTargetResourceKey(args?.target);
    const targetPath = typeof args?.target === 'string' && args.target.trim() ? path.resolve(args.target.trim()) : null;
    if (args?.action === 'start' && targetKey) {
      return { kind: 'acquire', resourceKey: `app:${targetKey}`, resourceType: 'app-observer', targetKey, targetPath };
    }
    if (args?.action === 'stop' && targetKey) {
      const invalidField = Object.keys(args).find(k => args[k] !== undefined && !CLEANUP_APP_OBSERVE_KEYS.has(k));
      if (invalidField) {
        return { kind: 'invalid-cleanup', reason: `app_observe stop cleanup cannot carry parameter "${invalidField}"` };
      }
      return { kind: 'cleanup', resourceKey: `app:${targetKey}`, resourceType: 'app-observer', targetKey, targetPath };
    }
  }
  if (name === 'ig5_close') {
    const targetKey = normalizeTargetResourceKey(args?.target);
    const invalidField = Object.keys(args).find(k => args[k] !== undefined && !CLEANUP_CLOSE_KEYS.has(k));
    if (!invalidField && targetKey) {
      return { kind: 'passive-close', resourceKey: `static:${targetKey}`, resourceType: 'static-session', targetKey };
    }
  }
  return { kind: 'ordinary', resourceKey: null, resourceType: null, targetKey: null };
}

function validateBudget(budget) {
  if (!budget) return true;
  const reserved = budget.reserved ?? 0;
  return Number.isSafeInteger(budget.limit) && Number.isSafeInteger(budget.used) && Number.isSafeInteger(reserved)
    && budget.limit >= 1 && budget.used >= 0 && reserved >= 0
    && budget.used + reserved <= budget.limit
    && budget.byAgent && typeof budget.byAgent === 'object' && !Array.isArray(budget.byAgent)
    && Object.values(budget.byAgent).every(n => Number.isSafeInteger(n) && n >= 0)
    && Object.values(budget.byAgent).reduce((a, b) => a + b, 0) === budget.used;
}

function validateOperations(operations) {
  if (operations === undefined) return true;
  if (!operations || typeof operations !== 'object' || Array.isArray(operations) || Object.keys(operations).length > MAX_OPS + MAX_EMERGENCY_HEADROOM) return false;
  for (const op of Object.values(operations)) {
    if (!op || typeof op !== 'object' || typeof op.operationId !== 'string' || typeof op.tool !== 'string'
      || typeof op.callerId !== 'string' || !SHA.test(op.argsDigest || '')
      || !EXEC_STATUSES.has(op.status) || !LINK_STATUSES.has(op.researchLinkStatus || 'not-applicable')
      || op.outcome !== null && op.outcome !== undefined && !OUTCOMES.has(op.outcome)) return false;
  }
  return true;
}

function validateReservations(reservations) {
  if (reservations === undefined) return true;
  if (!reservations || typeof reservations !== 'object' || Array.isArray(reservations) || Object.keys(reservations).length > MAX_RESERVATIONS) return false;
  for (const res of Object.values(reservations)) {
    if (!res || typeof res !== 'object' || typeof res.resourceKey !== 'string' || typeof res.ownerAgentId !== 'string'
      || !['active', 'confirmed', 'unknown', 'released-unstarted'].includes(res.status)
      || !Number.isSafeInteger(res.reservedCalls) || res.reservedCalls < 0 || res.reservedCalls > 2
      || !Number.isSafeInteger(res.attemptsUsed) || res.attemptsUsed < 0 || res.attemptsUsed > 4) return false;
  }
  return true;
}

function validateControl(control) {
  if (control === undefined) return true;
  if (!control || typeof control !== 'object' || Array.isArray(control)
    || !Number.isSafeInteger(control.generation) || control.generation < 0
    || (control.cancelledGeneration !== null && (!Number.isSafeInteger(control.cancelledGeneration) || control.cancelledGeneration < 0 || control.cancelledGeneration > control.generation))) {
    return false;
  }
  return true;
}

function validateCompactedOperations(compacted) {
  if (compacted === undefined) return true;
  if (!compacted || typeof compacted !== 'object' || Array.isArray(compacted) || Object.keys(compacted).length > MAX_COMPACTED_OPS) return false;
  for (const op of Object.values(compacted)) {
    if (!op || typeof op !== 'object' || typeof op.operationId !== 'string' || typeof op.tool !== 'string'
      || typeof op.callerId !== 'string' || !SHA.test(op.argsDigest || '')
      || op.status !== 'result-recorded' || !LINK_STATUSES.has(op.researchLinkStatus || 'not-applicable')
      || op.outcome !== null && op.outcome !== undefined && !OUTCOMES.has(op.outcome)) return false;
  }
  return true;
}

function validateState(state, rootId) {
  if (![1, 2].includes(state.schemaVersion) || state.rootId !== rootId
    || !state.tickets || typeof state.tickets !== 'object' || Array.isArray(state.tickets) || Object.keys(state.tickets).length > 128
    || !validateBudget(state.budget) || !validateOperations(state.operations) || !validateCompactedOperations(state.compactedOperations)
    || !validateReservations(state.cleanupReservations) || !validateControl(state.control)
    || (state.stepLocks !== undefined && (!state.stepLocks || typeof state.stepLocks !== 'object' || Array.isArray(state.stepLocks)
      || Object.keys(state.stepLocks).length > MAX_STEP_LOCKS || Object.values(state.stepLocks).some(v => typeof v !== 'string' || !v)))) {
    fail('DELEGATION_STORE_CORRUPT', 'Invalid delegation accounting; refusing controlled dispatch');
  }
}

function ensureExtended(state) {
  state.schemaVersion = 2;
  state.operations ||= {};
  state.compactedOperations ||= {};
  state.stepLocks ||= {};
  state.cleanupReservations ||= {};
  state.control ||= { generation: 0, cancelledGeneration: null, cancelReason: null, cancelAcceptedAt: null };
  if (state.budget && state.budget.reserved === undefined) state.budget.reserved = 0;
  return state;
}

function trimOperations(state, { emergency = false } = {}) {
  const keys = Object.keys(state.operations);
  const cap = emergency ? (MAX_OPS + MAX_EMERGENCY_HEADROOM) : MAX_OPS;
  if (keys.length < MAX_OPS && !emergency) return;
  if (emergency && keys.length < cap) {
    // Still opportunistically prune unkeyed cancelled/control rows so emergency headroom stays clean.
    const freeable = keys.filter(k => {
      const op = state.operations[k];
      return op.status === 'cancelled-before-dispatch'
        || (op.status === 'result-recorded' && !op.requestKey && ['not-applicable', 'linked'].includes(op.researchLinkStatus));
    }).sort((a, b) => String(state.operations[a].admittedAt || '').localeCompare(String(state.operations[b].admittedAt || '')));
    while (Object.keys(state.operations).length >= MAX_OPS && freeable.length) {
      delete state.operations[freeable.shift()];
    }
    return;
  }

  // Prefer reclaiming rows that require zero compactedOperations capacity first
  // (`cancelled-before-dispatch` never dispatched to a provider; unkeyed `result-recorded` needs no key index).
  const zeroCostRemovable = keys
    .filter(k => {
      const op = state.operations[k];
      return op.status === 'cancelled-before-dispatch'
        || (op.status === 'result-recorded' && !op.requestKey && ['not-applicable', 'linked'].includes(op.researchLinkStatus));
    })
    .sort((a, b) => String(state.operations[a].admittedAt || '').localeCompare(String(state.operations[b].admittedAt || '')));

  const keyedRemovable = keys
    .filter(k => {
      const op = state.operations[k];
      return op.status === 'result-recorded' && Boolean(op.requestKey) && ['not-applicable', 'linked'].includes(op.researchLinkStatus);
    })
    .sort((a, b) => String(state.operations[a].admittedAt || '').localeCompare(String(state.operations[b].admittedAt || '')));

  const targetFloor = emergency ? cap : MAX_OPS;
  while (Object.keys(state.operations).length >= targetFloor && zeroCostRemovable.length) {
    delete state.operations[zeroCostRemovable.shift()];
  }
  while (Object.keys(state.operations).length >= targetFloor && keyedRemovable.length) {
    const victim = keyedRemovable.shift();
    const op = state.operations[victim];
    if (!Object.hasOwn(state.compactedOperations, victim) && Object.keys(state.compactedOperations).length >= MAX_COMPACTED_OPS) {
      if (emergency) {
        // Emergency cleanup/control must never drop deduplication history nor fail on history saturation.
        break;
      }
      fail('DELEGATION_HISTORY_LIMIT', `Persistent deduplication history reached capacity (${MAX_COMPACTED_OPS}); refusing to drop idempotency records`);
    }
    state.compactedOperations[victim] = {
      operationId: op.operationId,
      slotKey: op.slotKey,
      requestKey: op.requestKey,
      callerId: op.callerId,
      tool: op.tool,
      argsDigest: op.argsDigest,
      investigationId: op.investigationId,
      experimentId: op.experimentId,
      stepIndex: op.stepIndex,
      status: 'result-recorded',
      outcome: op.outcome,
      errorCode: op.errorCode,
      reportRef: op.reportRef,
      researchLinkStatus: op.researchLinkStatus,
    };
    delete state.operations[victim];
  }
  if (Object.keys(state.operations).length >= targetFloor) {
    fail('DELEGATION_OPERATION_LIMIT', `Active/pending managed operation ledger reached capacity (${targetFloor}); recover pending receipts before continuing`);
  }
}

function chargeWithCleanupPolicy(state, agentId, classification, allowTakeover = false) {
  if (classification.kind === 'invalid-cleanup') {
    fail('INVALID_CLEANUP_OPERATION', classification.reason);
  }
  const reservations = state.cleanupReservations || {};
  const existingRes = classification.resourceKey ? reservations[classification.resourceKey] : null;
  const activeRes = existingRes?.status === 'active' ? existingRes : null;

  if (classification.kind === 'cleanup') {
    if (activeRes) {
      if (activeRes.ownerAgentId !== agentId && !allowTakeover) {
        fail('CLEANUP_OWNER_REQUIRED', 'Cleanup is restricted to the original resource owner unless approved takeover is specified');
      }
      if (activeRes.attemptsUsed >= (activeRes.maxAttempts || 2)) {
        activeRes.status = 'unknown';
        fail('CLEANUP_ATTEMPT_LIMIT_EXCEEDED', 'Bounded cleanup retry limit reached; resource remains unknown for manual inspection');
      }
      if (state.budget) {
        if (activeRes.reservedCalls > 0) {
          state.budget.reserved = Math.max(0, (state.budget.reserved || 0) - 1);
          activeRes.reservedCalls -= 1;
        } else if (state.budget.used + (state.budget.reserved || 0) >= state.budget.limit) {
          activeRes.status = 'unknown';
          fail('IG5_SHARED_BUDGET_EXHAUSTED', 'Shared IG5 call budget exhausted and reserved cleanup slot was already spent; resource cleanup remains unknown');
        }
        state.budget.used += 1;
        state.budget.byAgent[agentId] = (state.budget.byAgent[agentId] || 0) + 1;
      }
      activeRes.attemptsUsed += 1;
      activeRes.lastAttemptAt = new Date().toISOString();
      return { usedReservedCleanup: true, reservationKey: activeRes.resourceKey };
    }
    // Unreserved / legacy cleanup: allowed if budget has capacity, never enlarges limit.
    if (state.budget) {
      if (state.budget.used + (state.budget.reserved || 0) >= state.budget.limit) {
        ensureExtended(state);
        if (Object.keys(state.cleanupReservations).length < MAX_RESERVATIONS) {
          state.cleanupReservations[classification.resourceKey] = {
            resourceKey: classification.resourceKey, resourceType: classification.resourceType,
            ownerAgentId: agentId, status: 'unknown', reservedCalls: 0, attemptsUsed: 0, maxAttempts: 2,
            createdAt: new Date().toISOString(), note: 'Historical unreserved resource encountered exhausted budget',
          };
        }
        fail('IG5_SHARED_BUDGET_EXHAUSTED', 'Shared parent/child IG5 call budget exhausted; unreserved historical resource remains unknown without enlarging budget');
      }
      state.budget.used += 1;
      state.budget.byAgent[agentId] = (state.budget.byAgent[agentId] || 0) + 1;
    }
    return { usedReservedCleanup: false, reservationKey: classification.resourceKey };
  }

  // Ordinary or acquire call:
  const needsNewReserve = classification.kind === 'acquire' && !activeRes;
  if (state.budget) {
    const reserved = state.budget.reserved || 0;
    const available = state.budget.limit - state.budget.used - reserved;
    if (available < 1) {
      const reserveNote = reserved > 0 ? ` (${reserved} call(s) reserved exclusively for owner resource cleanup)` : '';
      fail('IG5_SHARED_BUDGET_EXHAUSTED', `Shared parent/child IG5 call budget exhausted${reserveNote}; only collaboration status and owner cleanup remain available`);
    }
    if (needsNewReserve && available < 2) {
      fail('BUDGET_INSUFFICIENT_FOR_CLEANUP_RESERVE', 'Remaining shared IG5 budget cannot cover both resource acquisition and its mandatory cleanup stop; refusing resource acquisition');
    }
    state.budget.used += 1;
    state.budget.byAgent[agentId] = (state.budget.byAgent[agentId] || 0) + 1;
  }
  if (needsNewReserve) {
    ensureExtended(state);
    if (Object.keys(state.cleanupReservations).length >= MAX_RESERVATIONS && !state.cleanupReservations[classification.resourceKey]) {
      fail('CLEANUP_RESERVATION_LIMIT', 'Maximum tracked cleanup reservations (64) reached');
    }
    const reserveCount = state.budget ? 1 : 0;
    if (state.budget) state.budget.reserved = (state.budget.reserved || 0) + 1;
    state.cleanupReservations[classification.resourceKey] = {
      resourceKey: classification.resourceKey,
      resourceType: classification.resourceType,
      ...(classification.targetPath ? { targetPath: classification.targetPath } : {}),
      ...(classification.deviceSerial ? { deviceSerial: classification.deviceSerial } : {}),
      ...(classification.packageName ? { packageName: classification.packageName } : {}),
      ownerAgentId: agentId,
      status: 'active',
      reservedCalls: reserveCount,
      attemptsUsed: 0,
      maxAttempts: 2,
      createdAt: new Date().toISOString(),
    };
    return { usedReservedCleanup: false, acquiredReservationKey: classification.resourceKey };
  }
  return { usedReservedCleanup: false, reservationKey: activeRes?.resourceKey || null };
}

/** Persistent accounting is separate from task notes and database revisions. */
export class DelegationControl {
  constructor({ root, getAgent = () => undefined }) {
    // Defer ledger opening so a corrupt ledger cannot prevent metadata-only diagnosis.
    let store;
    Object.defineProperty(this, 'store', { get: () => store ||= new ProjectStore({ root: path.join(root, 'delegation-control') }) });
    this.getAgent = getAgent;
    this.agents = new Map();
    this.runs = new Map();
    this.epoch = randomUUID();
  }
  remember(agent) { if (agent?.id && agent.session?.header?.id === agent.id) this.agents.set(agent.id, agent); }
  lineage(agent) {
    this.remember(agent);
    if (!agent?.id || agent.session?.header?.id !== agent.id) lineageFailure('SESSION_IDENTITY_MISMATCH', 'Reliable DSH session identity is required for controlled delegation');
    const ids = [], seen = new Set();
    for (let at = agent; at; ) {
      if (seen.has(at.id)) lineageFailure('SESSION_LINEAGE_CYCLE', 'Invalid cyclic DSH parent lineage');
      if (ids.length >= 32) lineageFailure('SESSION_LINEAGE_LIMIT', 'Excessive DSH parent lineage');
      seen.add(at.id); ids.push(at.id); this.remember(at);
      const parent = at.session.header.parentSession;
      if (parent === undefined || parent === null) return ids;
      if (typeof parent !== 'string' || !parent.trim()) lineageFailure('SESSION_IDENTITY_MISMATCH', 'Invalid DSH parent session identity');
      if (seen.has(parent)) lineageFailure('SESSION_LINEAGE_CYCLE', 'Invalid cyclic DSH parent lineage');
      at = this.getAgent(parent) || this.agents.get(parent);
      if (!at) lineageFailure('PARENT_SESSION_UNAVAILABLE', 'DSH parent session is unavailable; shared budget cannot be bypassed');
      if (at.id !== parent || at.session?.header?.id !== parent) lineageFailure('PARENT_IDENTITY_MISMATCH', 'DSH parent session identity conflicts with the host index');
    }
  }
  resolveRootSubject(agent, { allowLocalFallback = false } = {}) {
    if (agent?.session !== undefined) {
      const ids = this.lineage(agent);
      return { ids, rootId: ids.at(-1), callerId: agent.id };
    }
    if (allowLocalFallback) {
      const id = typeof agent?.id === 'string' && agent.id.trim() ? agent.id.trim() : 'standalone-local';
      return { ids: [id], rootId: `local:${id}`, callerId: id };
    }
    lineageFailure('SESSION_IDENTITY_MISMATCH', 'Reliable DSH session identity is required for controlled delegation');
  }
  hasActiveOwnerCleanup(agent, name, cleanArgs, options = {}) {
    const classification = classifyManagedResourceCall(name, cleanArgs);
    if (classification.kind !== 'cleanup' || !classification.resourceKey) return false;
    try {
      const { rootId, callerId } = this.resolveRootSubject(agent, options);
      const state = this.store.readInvestigationRecords()[key(rootId)];
      if (!state) return false;
      validateState(state, rootId);
      const res = state.cleanupReservations?.[classification.resourceKey];
      if (!res || res.status !== 'active') return false;
      return res.ownerAgentId === callerId || cleanArgs?.control === 'takeover';
    } catch {
      return false;
    }
  }
  transaction(agent, fn, options = {}) {
    const { ids, rootId } = options.allowLocalFallback ? this.resolveRootSubject(agent, options) : { ids: this.lineage(agent), rootId: this.lineage(agent).at(-1) };
    return this.store.updateInvestigationRecords(records => {
      const k = key(rootId);
      const record = records[k] ||= { schemaVersion: 1, rootId, budget: null, tickets: {} };
      validateState(record, rootId);
      const result = fn(record, ids);
      validateState(record, rootId);
      return result;
    });
  }
  /** Exact local control-plane operation: no RPC, content, ledger writes or inferred parent ownership. */
  diagnose(agent, args = {}) {
    if (Object.keys(args).some(k => k !== 'operation') || args.operation !== 'session') fail('INVALID_ARGUMENT', 'Use operation=session alone for local session diagnosis');
    const result = { schemaVersion: 1, kind: 'session-diagnostic', diagnosticId: randomUUID(), observedAt: new Date().toISOString(),
      faultStartedAt: null, phase: 'session-lineage', evidenceStatus: 'observed-metadata-only',
      rpcPerformed: false, budgetModified: false, automaticRecoverySupported: false, budget: null };
    try {
      const ids = this.lineage(agent), rootId = ids.at(-1);
      const state = this.store.readInvestigationRecords()[key(rootId)];
      if (state) validateState(state, rootId);
      return { ...result, status: 'available', code: 'SESSION_LINEAGE_AVAILABLE', retryable: false,
        lineageDepth: ids.length, budget: state?.budget ? { active: true, used: state.budget.used, ...(state.budget.reserved ? { reserved: state.budget.reserved } : {}), limit: state.budget.limit } : { active: false },
        recoveryActions: [] };
    } catch (error) {
      const code = error.code === 'AGENT_LINEAGE_UNAVAILABLE' ? error.reason
        : ['STORE_CORRUPT', 'STORE_SCHEMA_MISMATCH', 'DELEGATION_STORE_CORRUPT'].includes(error.code) ? 'DELEGATION_STORE_CORRUPT' : 'SESSION_METADATA_UNAVAILABLE';
      return { ...result, status: 'unavailable', code, retryable: code === 'PARENT_SESSION_UNAVAILABLE',
        recoveryActions: error.recoveryActions || ['Inspect the original host session and retained ledger; do not recreate or reset shared accounting.'] };
    }
  }
  budget(agent, input) {
    if (!input || Object.keys(input).some(k => !['action', 'max_calls'].includes(k)) || !['start', 'status'].includes(input.action)) fail('INVALID_ARGUMENT', 'collaboration action must be start or status');
    return this.transaction(agent, (state, ids) => {
      if (input.action === 'start') {
        if (ids.length !== 1) fail('BUDGET_OWNER_REQUIRED', 'Only the root agent may establish the shared IG5 budget');
        if (!Number.isSafeInteger(input.max_calls) || input.max_calls < 1 || input.max_calls > 1000) fail('INVALID_ARGUMENT', 'max_calls must be 1..1000');
        if (state.budget) fail('BUDGET_ALREADY_STARTED', 'Shared budget already exists; it cannot be reset or enlarged by another tool call');
        state.budget = { limit: input.max_calls, used: 0, reserved: 0, byAgent: {} };
      } else if (input.max_calls !== undefined) fail('INVALID_ARGUMENT', 'status does not accept max_calls');
      const reserved = state.budget?.reserved || 0;
      return { rootId: state.rootId, active: !!state.budget, ...(state.budget || {}),
        ...(state.budget ? { reserved, availableForOrdinaryCalls: state.budget.limit - state.budget.used - reserved } : {}),
        scope: 'all IG5 tool dispatches across this DSH root and descendants', persistent: true,
        statusExempt: true, note: 'Activation/status are control-plane queries. Resource acquisition pre-reserves owner cleanup inside max_calls without enlarging the cap. Failed dispatched calls count; exhausted calls do not run.' };
    });
  }
  /** Read-only planning hint. Dispatch remains the sole authority that charges the shared budget. */
  planningBudget(agent) {
    if (!agent?.session?.header) return { status: 'unavailable', active: false, remaining: null };
    const ids = this.lineage(agent), rootId = ids.at(-1), state = this.store.readInvestigationRecords()[key(rootId)];
    if (!state) return { status: 'read', active: false, remaining: null };
    validateState(state, rootId);
    const reserved = state.budget?.reserved || 0;
    return { status: 'read', active: !!state.budget,
      remaining: state.budget ? Math.max(0, state.budget.limit - state.budget.used - reserved) : null,
      ...(state.budget ? { reservedForCleanup: reserved } : {}) };
  }
  /** Serial control point: accept cancellation for this root session; blocks new business dispatches. */
  acceptCancel(agent, reason = 'user-cancelled', options = {}) {
    return this.transaction(agent, state => {
      ensureExtended(state);
      const now = new Date().toISOString();
      state.control.cancelledGeneration = state.control.generation;
      state.control.cancelReason = String(reason).slice(0, 128);
      state.control.cancelAcceptedAt = now;
      const cancelledBeforeDispatch = [];
      for (const op of Object.values(state.operations)) {
        if (op.status === 'admitted' && !op.isCleanup) {
          op.status = 'cancelled-before-dispatch';
          op.settledAt = now;
          cancelledBeforeDispatch.push(op.operationId);
        }
      }
      return { rootId: state.rootId, cancelled: true, generation: state.control.generation, cancelledGeneration: state.control.cancelledGeneration,
        cancelReason: state.control.cancelReason, cancelAcceptedAt: now, cancelledBeforeDispatch };
    }, options);
  }
  /** Advance control generation ONLY on an explicit resume action (never on ordinary human messages). */
  resumeControlGeneration(agent, sourceKind, options = {}) {
    if (!['explicit-human-resume', 'host-goal-resume', 'host-goal-create'].includes(sourceKind)) {
      return { resumed: false, reason: 'explicit-resume-authority-required' };
    }
    return this.transaction(agent, state => {
      ensureExtended(state);
      if (state.control.cancelledGeneration === null) {
        return { resumed: false, cancelled: false, generation: state.control.generation, cancelledGeneration: null };
      }
      state.control.generation += 1;
      state.control.cancelledGeneration = null;
      state.control.cancelReason = null;
      state.control.cancelAcceptedAt = null;
      return { resumed: true, cancelled: false, generation: state.control.generation, cancelledGeneration: null, sourceKind };
    }, options);
  }
  controlStatus(agent, options = {}) {
    try {
      const { rootId } = this.resolveRootSubject(agent, options);
      const state = this.store.readInvestigationRecords()[key(rootId)];
      if (!state) return { active: false, generation: 0, cancelled: false, cleanupReservations: [], pendingReceipts: [] };
      validateState(state, rootId);
      const control = state.control || { generation: 0, cancelledGeneration: null, cancelReason: null, cancelAcceptedAt: null };
      const cleanupReservations = Object.values(state.cleanupReservations || {});
      const pendingReceipts = Object.values(state.operations || {}).filter(op => op.researchLinkStatus === 'receipt-pending');
      return {
        rootId,
        hasHistory: Boolean(
          Object.keys(state.operations || {}).length > 0
          || Object.keys(state.compactedOperations || {}).length > 0
          || state.budget,
        ),
        generation: control.generation,
        cancelled: control.cancelledGeneration !== null && control.cancelledGeneration >= control.generation,
        cancelReason: control.cancelReason || null,
        cancelAcceptedAt: control.cancelAcceptedAt || null,
        budget: state.budget ? { limit: state.budget.limit, used: state.budget.used, reserved: state.budget.reserved || 0 } : null,
        cleanupReservations,
        pendingReceipts: pendingReceipts.map(op => ({ operationId: op.operationId, investigationId: op.investigationId, tool: op.tool, outcome: op.outcome, reportRef: op.reportRef })),
      };
    } catch {
      return { active: false, generation: 0, cancelled: false, cleanupReservations: [], pendingReceipts: [] };
    }
  }
  charge(agent, name, args) {
    // Legacy fixture/service callers have no session metadata. They cannot opt
    // into controlled delegation. Real DSH descendants with missing parents fail.
    if (!agent?.session?.header) return null;
    if (name === 'ig5_profile' && args?.collaboration !== undefined) return null;
    const classification = classifyManagedResourceCall(name, args);
    return this.transaction(agent, state => {
      const control = state.control;
      if (control && control.cancelledGeneration !== null && control.cancelledGeneration >= control.generation && classification.kind !== 'cleanup') {
        fail('IG5_CANCELLED_BEFORE_DISPATCH', `Root session cancellation (${control.cancelReason || 'cancelled'}) is active; new business dispatches are blocked until human resume`);
      }
      if (!state.budget && classification.kind === 'ordinary') return null;
      return chargeWithCleanupPolicy(state, agent.id, classification, args?.control === 'takeover');
    });
  }
  /** Settle cleanup reservation state after a resource-acquiring or cleanup call finishes. */
  settleResourceCall(agent, classification, {
    ok,
    stateName,
    cleanedUp,
    runId,
    pid = null,
    creationIdentity = null,
    procStarttimeTicks = null,
    containerId = null,
    cleanupDisposition = null,
  } = {}, options = {}) {
    if (!classification?.resourceKey) return null;
    if (!agent?.session?.header && !options.allowLocalFallback) return null;
    return this.transaction(agent, state => {
      const res = state.cleanupReservations?.[classification.resourceKey];
      if (!res) return null;
      const now = new Date().toISOString();
      if (runId) res.lastRunId = runId;
      if (pid !== null && pid !== undefined) res.pid = pid;
      if (creationIdentity) res.creationIdentity = String(creationIdentity);
      if (procStarttimeTicks) res.procStarttimeTicks = String(procStarttimeTicks);
      if (containerId) res.containerId = String(containerId);
      if (cleanupDisposition) res.cleanupDisposition = String(cleanupDisposition);
      if (classification.kind === 'acquire') {
        res.dispatched = true;
        if (ok === false && cleanedUp !== false) {
          if (state.budget && res.reservedCalls > 0) {
            state.budget.reserved = Math.max(0, (state.budget.reserved || 0) - res.reservedCalls);
            res.reservedCalls = 0;
          }
          res.status = 'released-unstarted';
          res.settledAt = now;
        } else if (ok === false && cleanedUp === false) {
          res.status = 'unknown';
          res.settledAt = now;
        }
      } else if (classification.kind === 'cleanup' || stateName === 'no-task') {
        if (stateName === 'cleanup-unknown') {
          res.status = 'unknown';
          res.settledAt = now;
        } else if (ok !== false && (stateName === 'no-task' || classification.resourceType === 'capture')) {
          if (state.budget && res.reservedCalls > 0) {
            state.budget.reserved = Math.max(0, (state.budget.reserved || 0) - res.reservedCalls);
            res.reservedCalls = 0;
          }
          res.status = 'confirmed';
          res.confirmedAt = now;
        } else if (ok === false) {
          if (res.attemptsUsed >= (res.maxAttempts || 2)) res.status = 'unknown';
        }
      }
      return structuredClone(res);
    }, options);
  }
  /** Release reservation when an intermediate operation (e.g. dbg cont) naturally exits to no-task. */
  noteTargetExited(agent, target, options = {}) {
    const targetKey = normalizeTargetResourceKey(target);
    if (!targetKey || (!agent?.session?.header && !options.allowLocalFallback)) return null;
    const resourceKey = `dbg:${targetKey}`;
    return this.transaction(agent, state => {
      const res = state.cleanupReservations?.[resourceKey];
      if (!res || res.status !== 'active') return null;
      if (state.budget && res.reservedCalls > 0) {
        state.budget.reserved = Math.max(0, (state.budget.reserved || 0) - res.reservedCalls);
        res.reservedCalls = 0;
      }
      res.status = 'confirmed';
      res.confirmedAt = new Date().toISOString();
      return structuredClone(res);
    }, options);
  }
  /**
   * Single-ledger operation admission + exact retransmission lookup + budget/cleanup charge.
   * Exact retransmission checks happen BEFORE current precondition validation so old
   * completed operations remain retrievable after runId/stopSeq changes.
   */
  inspectOperation(agent, { requestKey, tool, argsDigest }, options = {}) {
    if (!requestKey) return null;
    const { callerId } = this.resolveRootSubject(agent, options);
    const opSlot = `${callerId}:${requestKey}`;
    return this.transaction(agent, state => {
      const existing = state.operations?.[opSlot] ?? state.compactedOperations?.[opSlot];
      if (!existing) return null;
      if (existing.tool !== tool || existing.argsDigest !== argsDigest) {
        fail('IDEMPOTENCY_CONFLICT', 'Same request key cannot be reused with a different tool or parameters');
      }
      if ((existing.status === 'admitted' || existing.status === 'dispatching') && existing.epoch !== this.epoch) {
        existing.status = 'effect-unknown';
        existing.settledAt = new Date().toISOString();
      }
      return structuredClone(existing);
    }, options);
  }
  admitOperation(agent, spec, options = {}) {
    const { requestKey, tool, cleanArgs, argsDigest, investigationId = null, experimentId = null, stepIndex = null, checkPreconditions = null } = spec;
    const { callerId } = this.resolveRootSubject(agent, options);
    const classification = classifyManagedResourceCall(tool, cleanArgs);
    const opSlot = `${callerId}:${requestKey || randomUUID()}`;
    const stepLockKey = investigationId && experimentId && Number.isSafeInteger(stepIndex)
      ? `${investigationId}:${experimentId}:${stepIndex}` : null;
    const isExemptControlCall = (tool === 'ig5_profile' && cleanArgs?.collaboration !== undefined)
      || (tool === 'ig5_workspace' && cleanArgs?.workspace?.action === 'root-control'
        && ['cancel', 'resume'].includes(cleanArgs?.workspace?.root?.controlAction));

    return this.transaction(agent, state => {
      ensureExtended(state);
      // 1) Re-check request-key deduplication across BOTH live and compacted history inside the atomic transaction.
      const existing = requestKey ? (state.operations[opSlot] ?? state.compactedOperations[opSlot]) : null;
      if (existing) {
        if (existing.tool !== tool || existing.argsDigest !== argsDigest) {
          fail('IDEMPOTENCY_CONFLICT', 'Same request key cannot be reused with a different tool or parameters');
        }
        if ((existing.status === 'admitted' || existing.status === 'dispatching') && existing.epoch !== this.epoch) {
          existing.status = 'effect-unknown';
          existing.settledAt = new Date().toISOString();
        }
        return { admitted: false, replayed: true, operation: structuredClone(existing), classification };
      }
      // 2) Durable step deduplication across different request keys (never deleted on trim).
      if (stepLockKey && Object.hasOwn(state.stepLocks, stepLockKey)) {
        const lockedRef = state.stepLocks[stepLockKey];
        const lockedOpId = state.operations[lockedRef]?.operationId || lockedRef;
        fail('EXPERIMENT_STEP_ALREADY_CONSUMED', `Experiment step ${stepIndex} was already consumed by operation ${lockedOpId}`);
      }
      if (stepLockKey && Object.keys(state.stepLocks).length >= MAX_STEP_LOCKS) {
        fail('DELEGATION_STEP_LOCK_LIMIT', `Maximum tracked step locks (${MAX_STEP_LOCKS}) reached`);
      }
      // 3) Check live cancellation state before charging new business calls.
      const isCleanup = classification.kind === 'cleanup';
      if (!isCleanup && !isExemptControlCall && state.control.cancelledGeneration !== null && state.control.cancelledGeneration >= state.control.generation) {
        fail('IG5_CANCELLED_BEFORE_DISPATCH', `Root session cancellation (${state.control.cancelReason || 'cancelled'}) is active; new business dispatches are blocked until explicit resume`);
      }
      // 4) Run caller-supplied current precondition check ONLY for genuinely new operations.
      if (typeof checkPreconditions === 'function') checkPreconditions();
      // 5) Compact old terminal operations if needed, charge budget & reserve cleanup atomically.
      // Owner cleanup and exempt control operations use dedicated emergency headroom and never drop history.
      trimOperations(state, { emergency: isCleanup || isExemptControlCall });
      const chargeReceipt = isExemptControlCall
        ? { exempt: true }
        : chargeWithCleanupPolicy(state, callerId, classification, cleanArgs?.control === 'takeover');
      const now = new Date().toISOString();
      const opId = randomUUID();
      const op = {
        operationId: opId,
        slotKey: opSlot,
        requestKey: requestKey || null,
        callerId,
        tool,
        op: cleanArgs?.op || cleanArgs?.action || cleanArgs?.workspace?.action || null,
        argsDigest,
        investigationId,
        experimentId,
        stepIndex,
        stepLockKey,
        isCleanup,
        isExemptControlCall,
        resourceKey: classification.resourceKey,
        epoch: this.epoch,
        admittedGeneration: state.control.generation,
        status: 'admitted',
        outcome: null,
        errorCode: null,
        reportRef: null,
        researchLinkStatus: investigationId ? 'receipt-pending' : 'not-applicable',
        runtimeIdentity: null,
        admittedAt: now,
        dispatchedAt: null,
        settledAt: null,
      };
      state.operations[opSlot] = op;
      if (stepLockKey) state.stepLocks[stepLockKey] = opId;
      return { admitted: true, replayed: false, operation: structuredClone(op), classification, chargeReceipt };
    }, options);
  }
  /** Serial control-point handoff: recheck cancel generation right before invoking provider. */
  beginDispatch(agent, slotKey, { signalAborted = false } = {}, options = {}) {
    return this.transaction(agent, state => {
      ensureExtended(state);
      const op = state.operations[slotKey];
      if (!op) fail('OPERATION_NOT_FOUND', 'Managed operation record missing before dispatch');
      if (op.status !== 'admitted') return structuredClone(op);
      const bypassCancel = op.isCleanup || op.isExemptControlCall;
      const cancelledByControl = !bypassCancel && state.control.cancelledGeneration !== null && state.control.cancelledGeneration >= op.admittedGeneration;
      const cancelledBySignal = !op.isCleanup && signalAborted;
      if (cancelledByControl || cancelledBySignal) {
        op.status = 'cancelled-before-dispatch';
        op.outcome = 'cancelled';
        op.errorCode = 'IG5_CANCELLED_BEFORE_DISPATCH';
        op.settledAt = new Date().toISOString();
        // Release newly created unstarted cleanup reservation if this acquire never dispatched; keep call fee.
        if (op.resourceKey && state.cleanupReservations?.[op.resourceKey]?.status === 'active'
          && state.cleanupReservations[op.resourceKey].attemptsUsed === 0 && !state.cleanupReservations[op.resourceKey].dispatched) {
          const res = state.cleanupReservations[op.resourceKey];
          if (state.budget && res.reservedCalls > 0) {
            state.budget.reserved = Math.max(0, (state.budget.reserved || 0) - res.reservedCalls);
            res.reservedCalls = 0;
          }
          res.status = 'released-unstarted';
        }
        return structuredClone(op);
      }
      op.status = 'dispatching';
      op.dispatchedAt = new Date().toISOString();
      if (op.resourceKey && state.cleanupReservations?.[op.resourceKey]?.status === 'active') {
        state.cleanupReservations[op.resourceKey].dispatched = true;
      }
      return structuredClone(op);
    }, options);
  }
  completeOperation(agent, slotKey, patch, options = {}) {
    return this.transaction(agent, state => {
      ensureExtended(state);
      const op = state.operations[slotKey];
      if (!op) fail('OPERATION_NOT_FOUND', 'Managed operation record missing on completion');
      op.status = 'result-recorded';
      op.outcome = patch.outcome;
      op.errorCode = patch.errorCode || null;
      op.reportRef = patch.reportRef || null;
      op.runtimeIdentity = patch.runtimeIdentity || null;
      op.researchLinkStatus = patch.researchLinkStatus || (op.investigationId ? 'receipt-pending' : 'not-applicable');
      op.settledAt = new Date().toISOString();
      return structuredClone(op);
    }, options);
  }
  markOperationLinked(agent, slotKey, options = {}) {
    return this.transaction(agent, state => {
      ensureExtended(state);
      const op = state.operations[slotKey];
      if (!op) fail('OPERATION_NOT_FOUND', 'Managed operation record not found');
      if (op.status === 'result-recorded' && op.reportRef) op.researchLinkStatus = 'linked';
      return structuredClone(op);
    }, options);
  }
  operationsForInvestigation(agent, investigationId, options = {}) {
    const { rootId } = this.resolveRootSubject(agent, options);
    const state = this.store.readInvestigationRecords()[key(rootId)];
    if (!state) return [];
    validateState(state, rootId);
    const now = new Date().toISOString();
    let needsPersist = false;
    for (const op of Object.values(state.operations || {})) {
      if (op.investigationId === investigationId && (op.status === 'admitted' || op.status === 'dispatching') && op.epoch !== this.epoch) {
        needsPersist = true;
      }
    }
    if (needsPersist) {
      return this.transaction(agent, mutable => {
        ensureExtended(mutable);
        for (const op of Object.values(mutable.operations)) {
          if (op.investigationId === investigationId && (op.status === 'admitted' || op.status === 'dispatching') && op.epoch !== this.epoch) {
            op.status = 'effect-unknown';
            op.settledAt = now;
          }
        }
        return Object.values(mutable.operations).filter(op => op.investigationId === investigationId).map(op => structuredClone(op));
      }, options);
    }
    return Object.values(state.operations || {}).filter(op => op.investigationId === investigationId).map(op => structuredClone(op));
  }
  handoff(agent, task, scope) {
    return this.transaction(agent, state => {
      if (Object.keys(state.tickets).length >= 128) fail('HANDOFF_LIMIT', 'At most 128 handoffs per root session');
      const handoffId = randomUUID();
      state.tickets[handoffId] = { parentId: agent.id, taskId: task.taskId, taskRevision: task.taskRevision,
        scope, epoch: this.epoch, childId: null, reads: [], submitted: null, terminal: null, runId: null };
      return { handoffId, mode: 'tracked', coordinationModified: true,
        next: 'Child must workspace claim with handoff_id, read complete evidence, then submit snapshot_ids. Parent review with handoff_id waits for the observed completed child run.' };
    });
  }
  ticket(state, id, task, scope) {
    const ticket = state.tickets[id];
    if (!ticket) fail('HANDOFF_NOT_FOUND', 'Choose a tracked handoff from this root');
    if (ticket.epoch !== this.epoch) fail('HANDOFF_RESTARTED', 'Host reloaded; create a new handoff rather than trusting old lifecycle observations');
    if (ticket.taskId !== task.taskId || ticket.taskRevision !== task.taskRevision || !same(ticket.scope, scope)) fail('STALE_HANDOFF', 'Task, database or attachment changed; prepare a new handoff');
    return ticket;
  }
  claim(agent, id, task, scope) {
    return this.transaction(agent, (state, ids) => {
      const ticket = this.ticket(state, id, task, scope);
      if (ids[1] !== ticket.parentId || ticket.childId && ticket.childId !== agent.id) fail('HANDOFF_CHILD_REQUIRED', 'Only one actual direct DSH child of the handing-off agent may claim this packet');
      const run = this.runs.get(agent.id);
      if (!run || run.ended) fail('CHILD_LIFECYCLE_UNAVAILABLE', 'No observed active DSH subagent run; controlled acceptance is unavailable');
      ticket.childId = agent.id; ticket.runId = run.runId;
      return { handoffId: id, taskId: task.taskId, taskRevision: task.taskRevision, childId: agent.id, claimed: true, semanticAcceptanceVerified: false };
    });
  }
  read(agent, snapshot) {
    if (!agent?.session?.header) return;
    this.transaction(agent, state => {
      for (const ticket of Object.values(state.tickets)) {
        if (ticket.epoch === this.epoch && ticket.childId === agent.id && same(ticket.scope, snapshot.context) && !snapshot.stale
          && !ticket.reads.includes(snapshot.snapshot_id) && ticket.reads.length < 64) ticket.reads.push(snapshot.snapshot_id);
      }
    });
  }
  submit(agent, id, task, scope, snapshots) {
    return this.transaction(agent, state => {
      const ticket = this.ticket(state, id, task, scope);
      const run = this.runs.get(agent.id);
      if (!run || run.ended || run.runId !== ticket.runId) fail('CHILD_LIFECYCLE_UNAVAILABLE', 'Submit must occur within the same observed active child run that claimed the handoff');
      if (ticket.childId !== agent.id || !snapshots.length || snapshots.some(s => s.stale || !ticket.reads.includes(s.snapshot_id))) fail('EVIDENCE_READ_REQUIRED', 'Claiming child must actually read every current submitted system report first');
      if (ticket.submitted) fail('HANDOFF_ALREADY_SUBMITTED', 'This handoff already has a submission');
      ticket.submitted = snapshots.map(s => s.snapshot_id);
      return { handoffId: id, submitted: true, snapshot_ids: ticket.submitted, childFinished: false, semanticAcceptanceVerified: false };
    });
  }
  review(agent, id, task, scope, ids) {
    return this.transaction(agent, state => {
      const ticket = this.ticket(state, id, task, scope);
      if (ticket.parentId !== agent.id) fail('HANDOFF_PARENT_REQUIRED', 'Only the handoff owner can perform post-return review');
      if (!ticket.submitted || !ticket.terminal || ticket.terminal.stopReason !== 'completed' || !ticket.terminal.hasOutput) fail('CHILD_RETURN_REQUIRED', 'Child has not submitted evidence and finished with observed output; this is not post-return review');
      if (JSON.stringify([...ids].sort()) !== JSON.stringify([...ticket.submitted].sort())) fail('RETURN_SNAPSHOT_MISMATCH', 'Review exactly the child-submitted snapshot IDs');
      return { handoffId: id, childId: ticket.childId, childRunId: ticket.runId, delegationVerified: true,
        reviewStage: 'post-return', note: 'Observed child termination and evidence submission, not proof of model understanding or semantic correctness.' };
    });
  }
  start(info) {
    if (info?.local === true && typeof info.id === 'string' && typeof info.runId === 'string') this.runs.set(info.id, { runId: info.runId, ended: false });
  }
  end(info) {
    const run = this.runs.get(info?.id), agent = this.getAgent(info?.id) || this.agents.get(info?.id);
    if (!run || run.ended || run.runId !== info.runId || !agent) return;
    run.ended = true;
    this.transaction(agent, state => {
      for (const ticket of Object.values(state.tickets)) if (ticket.epoch === this.epoch && ticket.childId === info.id && ticket.runId === info.runId) {
        ticket.terminal = { stopReason: info.stopReason, hasOutput: Array.isArray(info.lastAssistantMessage)
          && info.lastAssistantMessage.some(b => b.type === 'text' && typeof b.text === 'string' && !!b.text.trim()) };
      }
    });
  }
}

export function installDelegationControl(ctx, cfg) {
  const getAgent = id => { try { return ctx.get('agents')?.get(id); } catch { return undefined; } };
  const control = new DelegationControl({ root: cfg.projectRoot, getAgent });
  ctx.on('agent/created', ({ agent }) => control.remember(agent));
  ctx.on('subagent/start', info => control.start(info));
  ctx.on('subagent/end', info => control.end(info));
  return control;
}
