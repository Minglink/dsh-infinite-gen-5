import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { ProjectStore } from './project_store.js';
import { readStableFile } from './analysis_artifacts.js';
import {
  validateOutputSpec,
  validateExecutableRule,
  hashExecutableCandidate,
  hashOutputSpec,
  canonicalPathKey,
  deriveCanonicalScenarioInput,
} from './investigation_verifier.js';
import { createChildResearchBrief, verifyAndAcceptChildFinding } from './delegation_messages.js';

const SHA = /^[a-f0-9]{64}$/;
const SECRET_ENV_RE = /(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|COOKIE|CREDENTIAL|AUTH)/i;
const VALID_OBS_CLASSES = new Set([
  'non-empty',
  'not-triggered',
  'observer-failed',
  'window-insufficient',
  'negative-within-verified-scope',
]);
const VALID_VERDICTS = new Set(['supports', 'refutes', 'inconclusive', 'environment-blocked']);

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

function sha256(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return createHash('sha256').update(value).digest('hex');
  }
  return createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex');
}

function cleanText(value, field, maxLen = 1024, allowEmpty = false) {
  if (typeof value !== 'string') fail('INVALID_ARGUMENT', `${field} must be a string`);
  const trimmed = value.trim();
  if (!allowEmpty && !trimmed) fail('INVALID_ARGUMENT', `${field} must not be empty`);
  if (trimmed.length > maxLen || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(trimmed)) {
    fail('INVALID_ARGUMENT', `${field} must be printable text within ${maxLen} characters`);
  }
  return trimmed;
}

function detectBinaryFormat(buf, filePath) {
  if (buf.length >= 64 && buf[0] === 0x4d && buf[1] === 0x5a) {
    const peOffset = buf.readUInt32LE(0x3c);
    if (peOffset + 6 <= buf.length && buf.subarray(peOffset, peOffset + 4).equals(Buffer.from('PE\0\0'))) {
      const machine = buf.readUInt16LE(peOffset + 4);
      if (machine === 0x8664 || machine === 0xaa64) return 'PE64';
      if (machine === 0x014c) return 'PE32';
      return 'PE';
    }
  }
  if (buf.length >= 5 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    return buf[4] === 2 ? 'ELF64' : 'ELF32';
  }
  if (filePath.toLowerCase().endsWith('.asar')) return 'ASAR';
  if (filePath.toLowerCase().endsWith('.apk')) return 'APK';
  const printable = buf.subarray(0, Math.min(buf.length, 512)).every(b => b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126));
  return printable ? 'TEXT' : 'BINARY';
}

function computePathIdentity(filePath) {
  const resolvedPath = path.resolve(filePath);
  if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isDirectory()) {
    let totalBytes = 0;
    const manifestParts = [];
    const walkDir = (dir, depth = 0) => {
      if (depth > 4) return;
      for (const ent of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
        if (ent.name === 'node_modules' || ent.name === '.git' || ent.name.startsWith('.')) continue;
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) walkDir(full, depth + 1);
        else if (ent.isFile() && (/\.(?:js|mjs|cjs|html|asar)$/i.test(ent.name) || ent.name.toLowerCase() === 'package.json')) {
          const b = readStableFile(full, 16 * 1024 * 1024).data;
          totalBytes += b.length;
          manifestParts.push(`${path.relative(resolvedPath, full).replaceAll('\\', '/')}:${sha256(b)}`);
        }
      }
    };
    walkDir(resolvedPath);
    return { resolvedPath, sha256: sha256(manifestParts.join('\n')), bytes: totalBytes, format: 'JS_APP_DIR' };
  }
  const { data, origin } = readStableFile(filePath, 64 * 1024 * 1024);
  return { resolvedPath: origin.path, sha256: sha256(data), bytes: data.length, format: detectBinaryFormat(data, origin.path) };
}

function validateEnvDiff(envDiff) {
  if (envDiff === undefined || envDiff === null) return {};
  if (typeof envDiff !== 'object' || Array.isArray(envDiff)) fail('INVALID_ARGUMENT', 'scenario.envDiff must be a plain object');
  const entries = Object.entries(envDiff);
  if (entries.length > 16) fail('INVALID_ARGUMENT', 'scenario.envDiff supports at most 16 environment overrides');
  const out = {};
  for (const [k, v] of entries) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(k)) fail('INVALID_ARGUMENT', `Invalid envDiff variable name "${k}"`);
    if (SECRET_ENV_RE.test(k)) fail('SECRET_ENV_FORBIDDEN', `envDiff cannot persist secret-like variable "${k}" in investigation state`);
    out[k] = cleanText(String(v), `scenario.envDiff.${k}`, 512, true);
  }
  return out;
}

function computeScenarioDigest(scenario) {
  return sha256({
    componentId: scenario.componentId,
    targetSha256: scenario.targetSha256,
    launchMode: scenario.launchMode,
    args: scenario.args,
    cwd: scenario.cwd,
    envDiff: scenario.envDiff,
    inputChannel: scenario.inputSpec?.channel || null,
    canonicalInputSha256: scenario.inputSpec?.canonicalInputSha256 || scenario.inputSpec?.plannedInputSha256 || null,
    provenanceState: scenario.inputSpec?.provenanceState || null,
    isHoldout: Boolean(scenario.inputSpec?.isHoldout),
    trigger: scenario.trigger,
    observationWindow: scenario.observationWindow,
    resetMethod: scenario.resetMethod,
  });
}

function nextSeq(task) {
  task.nextEventSeq = (task.nextEventSeq || 0) + 1;
  return task.nextEventSeq;
}

export class RootInvestigationStore {
  constructor({ projectRoot }) {
    this.root = path.join(path.resolve(projectRoot), 'investigations-root-v1');
    let store;
    Object.defineProperty(this, 'store', {
      get: () => (store ||= new ProjectStore({ root: this.root })),
    });
  }

  _readAll() {
    return this.store.readInvestigationRecords();
  }

  _mutate(rootId, fn) {
    return this.store.updateInvestigationRecords(records => {
      const task = records[rootId];
      if (!task || task.kind !== 'root-investigation') {
        fail('ROOT_INVESTIGATION_NOT_FOUND', `Root investigation "${rootId}" does not exist`);
      }
      const res = fn(task, records);
      task.revision += 1;
      task.updatedAt = new Date().toISOString();
      return res;
    });
  }

  create({ rootSessionId = null, workspaceCwd = null, goal, deliverables = [], origin = null, hostGoal = null }) {
    const cleanGoal = cleanText(goal, 'goal', 2000);
    if (!Array.isArray(deliverables) || deliverables.length > 16) {
      fail('INVALID_ARGUMENT', 'deliverables must be an array of 0..16 deliverable specs');
    }
    const resolvedOrigin = origin || (hostGoal?.goalId ? {
      kind: 'host-goal',
      hostGoalId: hostGoal.goalId,
      hostGoalRevision: hostGoal.revision,
      hostGoalObjective: hostGoal.goal || cleanGoal,
    } : null);
    const isHostGoalOrigin = resolvedOrigin?.kind === 'host-goal' || Boolean(resolvedOrigin?.hostGoalId);
    const normalizedDeliverables = (deliverables.length ? deliverables : [{
      id: 'deliv-primary',
      kind: 'io-transform',
      description: cleanGoal,
      requiredObservations: ['static-locate', 'dynamic-runtime-observation'],
      minDistinctInputs: 2,
    }]).map((d, idx) => {
      const kind = d.kind === undefined ? 'io-transform' : cleanText(String(d.kind), `deliverables[${idx}].kind`, 64);
      const isTransformChain = ['io-transform', 'structured-frame-transform', 'electron-native-chain', 'dll-host-transform', 'process-chain-transform', 'apk-jni-chain'].includes(kind);
      const isNonCoopAppKind = ['structured-frame-transform', 'electron-native-chain', 'process-chain-transform'].includes(kind);
      if (isHostGoalOrigin && isTransformChain && d.holdoutRequired === false) {
        fail('CONTRACT_DOWNGRADE_FORBIDDEN', `Host-goal deliverable "${kind}" requires holdoutRequired=true; disabling holdout verification is forbidden`);
      }
      if (isHostGoalOrigin && isNonCoopAppKind && d.nonCooperativeRequired === false && d.allowLegacyCooperativeFixture !== true) {
        fail('CONTRACT_DOWNGRADE_FORBIDDEN', `Host-goal deliverable "${kind}" enforces nonCooperativeRequired=true; downgrading to cooperative fixture protocol is forbidden`);
      }
      if (isHostGoalOrigin && isTransformChain && d.minDistinctInputs !== undefined && d.minDistinctInputs < 2) {
        fail('CONTRACT_DOWNGRADE_FORBIDDEN', `Host-goal deliverable "${kind}" requires minDistinctInputs >= 2`);
      }
      return {
        id: d.id ? cleanText(d.id, `deliverables[${idx}].id`, 64) : `deliv-${idx + 1}`,
        kind,
        description: cleanText(d.description || cleanGoal, `deliverables[${idx}].description`, 1000),
        requiredObservations: Array.isArray(d.requiredObservations)
          ? d.requiredObservations.map((x, i) => cleanText(x, `requiredObservations[${i}]`, 64))
          : ['static-locate', 'dynamic-runtime-observation'],
        minDistinctInputs: Number.isSafeInteger(d.minDistinctInputs) && d.minDistinctInputs >= 1 && d.minDistinctInputs <= 16
          ? d.minDistinctInputs
          : (isTransformChain ? 2 : 1),
        holdoutRequired: d.holdoutRequired !== false && (isTransformChain || d.holdoutRequired === true),
        nonCooperativeRequired: d.nonCooperativeRequired !== undefined
          ? Boolean(d.nonCooperativeRequired)
          : Boolean(isHostGoalOrigin && isNonCoopAppKind),
        candidateRevision: 0,
        candidateExplanation: null,
      };
    });

    const now = new Date().toISOString();
    const rootId = randomUUID();
    const hostGoalId = resolvedOrigin?.hostGoalId ? cleanText(String(resolvedOrigin.hostGoalId), 'origin.hostGoalId', 128) : null;
    const hostGoalObjective = typeof resolvedOrigin?.hostGoalObjective === 'string' && resolvedOrigin.hostGoalObjective.trim()
      ? resolvedOrigin.hostGoalObjective.trim()
      : (hostGoalId ? cleanGoal : null);
    const record = {
      schemaVersion: 1,
      kind: 'root-investigation',
      rootId,
      rootSessionId: rootSessionId ? String(rootSessionId) : null,
      workspaceCwd: workspaceCwd ? path.resolve(workspaceCwd) : null,
      goal: cleanGoal,
      supersededBy: null,
      nextEventSeq: 1,
      origin: {
        kind: resolvedOrigin?.kind || 'manual',
        hostGoalId,
        hostGoalRevision: Number.isSafeInteger(resolvedOrigin?.hostGoalRevision) ? resolvedOrigin.hostGoalRevision : null,
        hostGoalObjectiveDigest: hostGoalObjective ? sha256(hostGoalObjective) : null,
        recordedAt: now,
      },
      deliverables: normalizedDeliverables,
      components: [],
      scenarios: [],
      questions: [],
      routes: [],
      preparationLedger: {},
      experiments: [],
      receipts: [],
      evaluations: [],
      counterexamples: [],
      terminalFinding: null,
      preparedInputs: [],
      revision: 1,
      planRevision: 1,
      contractRevision: 1,
      createdAt: now,
      updatedAt: now,
    };

    this.store.updateInvestigationRecords(records => {
      if (Object.keys(records).length >= 256) fail('INVESTIGATION_LIMIT', 'Maximum root investigations (256) reached');
      if (hostGoalId && record.rootSessionId) {
        for (const existing of Object.values(records)) {
          if (existing?.kind === 'root-investigation'
            && existing.rootSessionId === record.rootSessionId
            && !existing.supersededBy
            && existing.origin?.hostGoalId === hostGoalId) {
            existing.supersededBy = rootId;
            existing.updatedAt = now;
          }
        }
      }
      records[rootId] = record;
    });
    return structuredClone(record);
  }

  upsertDeliverable(rootId, dSpec = {}) {
    return this._mutate(rootId, task => {
      if (!dSpec || typeof dSpec !== 'object') fail('INVALID_ARGUMENT', 'deliverable spec must be an object');
      const isHostGoalOrigin = task.origin?.kind === 'host-goal' || Boolean(task.origin?.hostGoalId);
      const delivId = dSpec.id ? cleanText(String(dSpec.id), 'deliverable.id', 64) : (task.deliverables[0]?.id || 'deliv-1');
      const existingIdx = task.deliverables.findIndex(d => d.id === delivId);
      const existing = existingIdx >= 0 ? task.deliverables[existingIdx] : null;
      const kind = dSpec.kind !== undefined
        ? cleanText(String(dSpec.kind), 'deliverable.kind', 64)
        : (existing?.kind || 'io-transform');
      const isTransformChain = ['io-transform', 'structured-frame-transform', 'electron-native-chain', 'dll-host-transform', 'process-chain-transform', 'apk-jni-chain'].includes(kind);
      const isNonCoopAppKind = ['structured-frame-transform', 'electron-native-chain', 'process-chain-transform'].includes(kind);

      if (isHostGoalOrigin) {
        if (isTransformChain && dSpec.holdoutRequired === false) {
          fail('CONTRACT_DOWNGRADE_FORBIDDEN', `Host-goal deliverable "${kind}" requires holdoutRequired=true; disabling holdout verification is forbidden`);
        }
        if ((isNonCoopAppKind || existing?.nonCooperativeRequired) && dSpec.nonCooperativeRequired === false && dSpec.allowLegacyCooperativeFixture !== true) {
          fail('CONTRACT_DOWNGRADE_FORBIDDEN', `Host-goal deliverable "${kind}" enforces nonCooperativeRequired=true; downgrading to cooperative fixture protocol is forbidden`);
        }
        if (isTransformChain && dSpec.minDistinctInputs !== undefined && dSpec.minDistinctInputs < 2) {
          fail('CONTRACT_DOWNGRADE_FORBIDDEN', `Host-goal deliverable "${kind}" requires minDistinctInputs >= 2`);
        }
        if (existing && Array.isArray(dSpec.requiredObservations)) {
          const nextSet = new Set(dSpec.requiredObservations);
          for (const prevObs of existing.requiredObservations || []) {
            if (!nextSet.has(prevObs)) {
              fail('CONTRACT_DOWNGRADE_FORBIDDEN', `Host-goal deliverable update cannot remove existing requiredObservation "${prevObs}"`);
            }
          }
        }
      }

      const nextObs = Array.isArray(dSpec.requiredObservations)
        ? [...new Set([...(existing?.requiredObservations || []), ...dSpec.requiredObservations.map((x, i) => cleanText(x, `requiredObservations[${i}]`, 64))])]
        : (existing?.requiredObservations || ['static-locate', 'dynamic-runtime-observation']);

      const updatedDeliv = {
        id: delivId,
        kind,
        description: cleanText(dSpec.description || existing?.description || task.goal, 'deliverable.description', 1000),
        requiredObservations: nextObs,
        minDistinctInputs: Number.isSafeInteger(dSpec.minDistinctInputs) && dSpec.minDistinctInputs >= 1 && dSpec.minDistinctInputs <= 16
          ? dSpec.minDistinctInputs
          : (existing?.minDistinctInputs ?? (isTransformChain ? 2 : 1)),
        holdoutRequired: dSpec.holdoutRequired !== false && (existing?.holdoutRequired || isTransformChain || dSpec.holdoutRequired === true),
        nonCooperativeRequired: dSpec.nonCooperativeRequired !== undefined
          ? Boolean(dSpec.nonCooperativeRequired)
          : Boolean(existing?.nonCooperativeRequired || (isHostGoalOrigin && isNonCoopAppKind)),
        candidateRevision: existing?.candidateRevision || 0,
        candidateExplanation: existing?.candidateExplanation || null,
      };

      const changedContract = !existing
        || existing.kind !== updatedDeliv.kind
        || JSON.stringify(existing.requiredObservations) !== JSON.stringify(updatedDeliv.requiredObservations)
        || existing.holdoutRequired !== updatedDeliv.holdoutRequired
        || existing.nonCooperativeRequired !== updatedDeliv.nonCooperativeRequired
        || existing.minDistinctInputs !== updatedDeliv.minDistinctInputs;

      if (existingIdx >= 0) task.deliverables[existingIdx] = updatedDeliv;
      else {
        if (task.deliverables.length >= 16) fail('INVESTIGATION_LIMIT', 'Maximum deliverables (16) reached');
        task.deliverables.push(updatedDeliv);
      }
      if (changedContract) {
        task.contractRevision = (task.contractRevision || 1) + 1;
        task.planRevision += 1;
      }
      return structuredClone(updatedDeliv);
    });
  }

  get(rootId) {
    if (typeof rootId !== 'string' || !rootId.trim()) fail('INVALID_ARGUMENT', 'root investigation id is required');
    const rec = this._readAll()[rootId.trim()];
    if (!rec || rec.kind !== 'root-investigation') {
      fail('ROOT_INVESTIGATION_NOT_FOUND', `Root investigation "${rootId}" does not exist`);
    }
    return structuredClone(rec);
  }

  list({ rootSessionId = null } = {}) {
    const all = Object.values(this._readAll()).filter(r => r?.kind === 'root-investigation');
    const filtered = rootSessionId ? all.filter(r => r.rootSessionId === rootSessionId) : all;
    return filtered
      .sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')))
      .map(r => ({
        rootId: r.rootId,
        rootSessionId: r.rootSessionId,
        goal: r.goal,
        revision: r.revision,
        planRevision: r.planRevision,
        componentsCount: r.components.length,
        scenariosCount: r.scenarios.length,
        experimentsCount: r.experiments.length,
        receiptsCount: r.receipts.length,
        unresolvedCounterexamples: r.counterexamples.filter(c => c.status === 'unresolved').length,
        updatedAt: r.updatedAt,
      }));
  }

  latestForSession(rootSessionId) {
    if (!rootSessionId) return null;
    const all = Object.values(this._readAll())
      .filter(r => r?.kind === 'root-investigation' && r.rootSessionId === rootSessionId && !r.supersededBy)
      .sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')));
    return all[0] ? structuredClone(all[0]) : null;
  }

  findForHostGoal(rootSessionId, hostGoalId) {
    if (!rootSessionId || !hostGoalId) return { task: null, ambiguousIds: [] };
    const matches = Object.values(this._readAll())
      .filter(r => r?.kind === 'root-investigation'
        && r.rootSessionId === rootSessionId
        && !r.supersededBy
        && r.origin?.hostGoalId === hostGoalId)
      .sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')));
    if (matches.length === 0) return { task: null, ambiguousIds: [] };
    if (matches.length > 1) return { task: null, ambiguousIds: matches.map(m => m.rootId) };
    return { task: structuredClone(matches[0]), ambiguousIds: [] };
  }

  bindHostGoal(rootId, { hostGoalId, hostGoalRevision, hostGoalObjective, syncLifecycleRevisionOnly = false } = {}, liveHostGoal = null) {
    return this._mutate(rootId, (task, records) => {
      const cleanId = hostGoalId ? cleanText(String(hostGoalId), 'hostGoalBinding.hostGoalId', 128) : task.origin.hostGoalId;
      if (task.origin.hostGoalId && cleanId && cleanId !== task.origin.hostGoalId) {
        fail('HOST_GOAL_REBIND_FORBIDDEN', `Investigation "${rootId}" is permanently bound to host goal "${task.origin.hostGoalId}" and cannot be rebound to "${cleanId}"`);
      }
      if (!task.origin.hostGoalId && cleanId && (task.receipts.length > 0 || task.experiments.length > 0)) {
        fail('HOST_GOAL_LATE_BIND_FORBIDDEN', `Investigation "${rootId}" already recorded execution receipts before binding a host goal; create a fresh investigation for "${cleanId}"`);
      }
      if (cleanId && task.rootSessionId) {
        const conflict = Object.values(records).find(r => r?.kind === 'root-investigation'
          && r.rootId !== rootId
          && r.rootSessionId === task.rootSessionId
          && !r.supersededBy
          && r.origin?.hostGoalId === cleanId);
        if (conflict) {
          fail('DUPLICATE_GOAL_INVESTIGATION', `Host goal "${cleanId}" is already bound to active investigation "${conflict.rootId}"`);
        }
      }
      const prevRev = task.origin.hostGoalRevision;
      const nextRev = Number.isSafeInteger(hostGoalRevision) ? hostGoalRevision : prevRev;
      const effectiveObj = typeof hostGoalObjective === 'string' && hostGoalObjective.trim()
        ? hostGoalObjective.trim()
        : (liveHostGoal && liveHostGoal.goalId === cleanId && typeof liveHostGoal.goal === 'string' ? liveHostGoal.goal.trim() : null);
      const nextObjDigest = effectiveObj ? sha256(effectiveObj) : task.origin.hostGoalObjectiveDigest;
      const objectiveChanged = Boolean(
        task.origin.hostGoalObjectiveDigest
        && nextObjDigest
        && nextObjDigest !== task.origin.hostGoalObjectiveDigest,
      );
      const revisionChanged = prevRev !== null && nextRev !== null && nextRev !== prevRev;

      task.origin.hostGoalId = cleanId || null;
      if (cleanId && task.origin.kind === 'manual') task.origin.kind = 'host-goal';
      task.origin.hostGoalRevision = nextRev;
      if (nextObjDigest) task.origin.hostGoalObjectiveDigest = nextObjDigest;

      if (objectiveChanged || (revisionChanged && !syncLifecycleRevisionOnly)) {
        if (effectiveObj) task.goal = cleanText(effectiveObj, 'goal', 2000);
        task.contractRevision = (task.contractRevision || 1) + 1;
        nextSeq(task);
        for (const d of task.deliverables) {
          d.contractRevisedRequiresUpdate = true;
          if (d.candidateExplanation) d.candidateExplanation.needsReassessment = true;
        }
      }
      return structuredClone(task);
    });
  }

  registerComponent(rootId, spec = {}) {
    const filePath = cleanText(spec.path, 'component.path', 1024);
    const { resolvedPath, sha256: digest, bytes: totalBytes, format } = computePathIdentity(filePath);
    const allowedRoles = ['main-pe', 'dll', 'helper-pe', 'broker-pe', 'worker-pe', 'electron-app', 'electron-asar', 'apk', 'jni-so', 'script', 'config', 'sample-input'];
    const role = allowedRoles.includes(spec.role)
      ? spec.role
      : (format === 'JS_APP_DIR' ? 'electron-app' : format === 'APK' ? 'apk' : format.startsWith('ELF') ? 'jni-so' : format.startsWith('PE') ? 'main-pe' : 'BINARY');
    const parentComponentId = spec.parentComponentId ? cleanText(spec.parentComponentId, 'component.parentComponentId', 64) : null;
    const ipcChannel = spec.ipcChannel ? cleanText(spec.ipcChannel, 'component.ipcChannel', 128) : null;

    return this._mutate(rootId, task => {
      if (parentComponentId && !task.components.some(c => c.componentId === parentComponentId)) {
        fail('COMPONENT_NOT_FOUND', `parentComponentId "${parentComponentId}" is not registered in this investigation`);
      }
      const rawCompId = spec.componentId || spec.id;
      const componentId = rawCompId
        ? cleanText(rawCompId, 'component.componentId', 64)
        : `comp-${task.components.length + 1}`;
      const entry = {
        componentId,
        role,
        path: resolvedPath,
        sha256: digest,
        bytes: totalBytes,
        format,
        parentComponentId,
        ipcChannel,
        requiresParentOrIpc: Boolean(parentComponentId || ipcChannel || (['helper-pe', 'dll', 'worker-pe'].includes(role) && spec.standaloneAllowed !== true)),
        relationOrigin: parentComponentId || ipcChannel ? 'caller-inferred' : 'observed-file',
        note: spec.note ? cleanText(spec.note, 'component.note', 512) : null,
        registeredAt: new Date().toISOString(),
      };
      const idx = task.components.findIndex(c => c.componentId === componentId || c.path === resolvedPath);
      if (idx >= 0) task.components[idx] = entry;
      else {
        if (task.components.length >= 64) fail('COMPONENT_LIMIT', 'At most 64 components per root investigation');
        task.components.push(entry);
      }
      task.planRevision += 1;
      return structuredClone(entry);
    });
  }

  upsertScenario(rootId, spec = {}, artifacts = null) {
    return this._mutate(rootId, task => {
      const rawCompRef = spec.componentId || (task.components.length === 1 ? task.components[0].componentId : undefined);
      const componentId = cleanText(rawCompRef, 'scenario.componentId', 64);
      const comp = task.components.find(c => c.componentId === componentId);
      if (!comp) fail('COMPONENT_NOT_FOUND', `Component "${componentId}" must be registered before defining a runtime scenario`);
      const normalizedLaunch = spec.launchMode === 'parent-app' ? 'via-parent' : spec.launchMode;
      const launchMode = ['standalone', 'via-parent', 'attach-existing'].includes(normalizedLaunch) ? normalizedLaunch : 'standalone';
      if (comp.requiresParentOrIpc && launchMode === 'standalone') {
        fail('HELPER_SCENARIO_MISMATCH', `Component "${componentId}" depends on parent/IPC (${comp.parentComponentId || comp.ipcChannel || comp.role}) and cannot use standalone launchMode to substitute the real runtime scenario`);
      }
      const args = spec.args === undefined ? [] : spec.args;
      if (!Array.isArray(args) || args.length > 32 || args.some(a => typeof a !== 'string' || a.length > 512 || /[\x00\r\n]/.test(a))) {
        fail('INVALID_ARGUMENT', 'scenario.args must be an array of 0..32 single-line strings (<= 512 chars each)');
      }
      const cwdRaw = spec.cwd
        ? cleanText(spec.cwd, 'scenario.cwd', 1024)
        : (fs.existsSync(comp.path) && fs.statSync(comp.path).isDirectory() ? comp.path : path.dirname(comp.path));
      const cwd = path.resolve(cwdRaw);
      if (!fs.existsSync(cwd) || !fs.statSync(cwd).isDirectory()) {
        fail('INVALID_ARGUMENT', `scenario.cwd "${cwd}" must be an existing directory`);
      }
      const envDiff = validateEnvDiff(spec.envDiff);
      const trigger = cleanText(spec.trigger || 'process-entry-and-cli-args', 'scenario.trigger', 512);
      const timeoutSec = spec.observationWindow?.timeoutSec ?? 20;
      if (!Number.isSafeInteger(timeoutSec) || timeoutSec < 1 || timeoutSec > 120) {
        fail('INVALID_ARGUMENT', 'scenario.observationWindow.timeoutSec must be 1..120');
      }
      const rawScenId = spec.scenarioId || spec.id;
      const scenarioId = rawScenId ? cleanText(rawScenId, 'scenario.scenarioId', 64) : `scen-${task.scenarios.length + 1}`;
      const rawKind = ['cli-arg', 'stdin', 'file', 'ipc', 'emulate', 'android-intent', 'none'].includes(spec.inputSpec?.kind)
        ? spec.inputSpec.kind
        : (args.length ? 'cli-arg' : 'none');
      const rawSampleSource = spec.inputSpec?.sampleHex ?? (rawKind === 'emulate' ? spec.inputSpec?.inputHex : undefined);
      const claimedSampleHex = typeof rawSampleSource === 'string' && rawSampleSource.length > 0
        ? rawSampleSource.trim().toLowerCase()
        : null;
      if (claimedSampleHex !== null && (!/^[0-9a-f]+$/.test(claimedSampleHex) || claimedSampleHex.length % 2 !== 0)) {
        fail('INVALID_ARGUMENT', 'scenario.inputSpec.sampleHex must be a non-empty even-length hex string');
      }
      const effectiveIpcPayload = spec.inputSpec?.ipcPayload ?? spec.inputSpec?.payloadHex;
      const derivedInput = deriveCanonicalScenarioInput({
        args,
        cwd,
        inputSpec: {
          ...(spec.inputSpec || {}),
          ...(effectiveIpcPayload !== undefined ? { ipcPayload: String(effectiveIpcPayload) } : {}),
          kind: rawKind,
          sampleHex: claimedSampleHex,
        },
      });
      let inputBlobRef = null;
      let plannedInputBlobRef = null;
      const sensitiveInput = Boolean(spec.inputSpec?.sensitiveInput);
      const putBlob = (buf) => (
        sensitiveInput && typeof artifacts?.putSensitive === 'function'
          ? artifacts.putSensitive(buf).ref
          : artifacts?.put ? artifacts.put(buf).ref : null
      );
      if (derivedInput.verified && derivedInput.canonicalInputHex) {
        inputBlobRef = putBlob(Buffer.from(derivedInput.canonicalInputHex, 'hex'));
      } else if (derivedInput.provenanceState === 'planned-awaiting-materialization' && derivedInput.plannedInputHex) {
        plannedInputBlobRef = putBlob(Buffer.from(derivedInput.plannedInputHex, 'hex'));
      }
      const scenario = {
        scenarioId,
        componentId,
        targetPath: comp.path,
        targetSha256: comp.sha256,
        launchMode,
        args: [...args],
        cwd,
        envDiff,
        inputSpec: {
          kind: rawKind,
          summary: cleanText(spec.inputSpec?.summary || (args.length ? `CLI args (${args.length})` : 'no external input'), 'scenario.inputSpec.summary', 256),
          ...(spec.inputSpec?.argIndex !== undefined ? { argIndex: spec.inputSpec.argIndex } : {}),
          ...(spec.inputSpec?.prefix !== undefined ? { prefix: String(spec.inputSpec.prefix) } : {}),
          ...(spec.inputSpec?.suffix !== undefined ? { suffix: String(spec.inputSpec.suffix) } : {}),
          ...(spec.inputSpec?.encoding !== undefined ? { encoding: String(spec.inputSpec.encoding) } : {}),
          ...(spec.inputSpec?.filePath !== undefined ? { filePath: String(spec.inputSpec.filePath) } : {}),
          ...(spec.inputSpec?.fixedFilename !== undefined ? { fixedFilename: String(spec.inputSpec.fixedFilename) } : {}),
          ...(spec.inputSpec?.stdinHex !== undefined ? { stdinHex: String(spec.inputSpec.stdinHex) } : {}),
          ...(spec.inputSpec?.extraKey !== undefined ? { extraKey: String(spec.inputSpec.extraKey) } : {}),
          ...(spec.inputSpec?.extraValue !== undefined ? { extraValue: String(spec.inputSpec.extraValue) } : {}),
          ...(effectiveIpcPayload !== undefined ? { ipcPayload: String(effectiveIpcPayload) } : {}),
          ...(sensitiveInput ? { sensitiveInput: true } : {}),
          claimedSampleHex,
          sampleHex: derivedInput.verified ? derivedInput.canonicalInputHex : null,
          plannedInputHex: derivedInput.plannedInputHex || null,
          plannedInputSha256: derivedInput.plannedInputSha256 || null,
          plannedInputBlobRef,
          canonicalInputHex: derivedInput.verified ? derivedInput.canonicalInputHex : null,
          canonicalInputSha256: derivedInput.verified ? derivedInput.canonicalInputSha256 : null,
          inputBlobRef,
          provenanceState: derivedInput.provenanceState || (derivedInput.verified ? 'verified' : 'unverified'),
          provenanceVerified: derivedInput.verified,
          provenanceReason: derivedInput.verified ? 'channel-derived' : derivedInput.reason,
          channel: derivedInput.channel || null,
          caseId: spec.inputSpec?.caseId ? cleanText(spec.inputSpec.caseId, 'scenario.inputSpec.caseId', 64) : null,
          isHoldout: Boolean(spec.inputSpec?.isHoldout),
        },
        trigger,
        observationWindow: {
          timeoutSec,
          stopCondition: cleanText(spec.observationWindow?.stopCondition || 'breakpoint-or-process-exit', 'scenario.observationWindow.stopCondition', 256),
        },
        healthCheck: cleanText(spec.healthCheck || 'debugger-stop-and-module-loaded', 'scenario.healthCheck', 256),
        resetMethod: ['fresh-process-per-run', 'snapshot-restore', 'idempotent-input'].includes(spec.resetMethod)
          ? spec.resetMethod
          : 'fresh-process-per-run',
        isControlGroup: Boolean(spec.isControlGroup),
        baselineStatus: ['unverified', 'verified', 'failed'].includes(spec.baselineStatus) ? spec.baselineStatus : 'unverified',
        updatedAt: new Date().toISOString(),
      };
      scenario.scenarioDigest = computeScenarioDigest(scenario);
      const idx = task.scenarios.findIndex(s => s.scenarioId === scenarioId);
      if (idx >= 0) task.scenarios[idx] = scenario;
      else {
        if (task.scenarios.length >= 64) fail('SCENARIO_LIMIT', 'At most 64 scenarios per root investigation');
        task.scenarios.push(scenario);
      }
      task.planRevision += 1;
      return structuredClone(scenario);
    });
  }

  upsertQuestion(rootId, spec = {}) {
    return this._mutate(rootId, task => {
      const normalized = typeof spec === 'string' ? { question: spec } : (spec || {});
      const qIdRaw = normalized.questionId ?? normalized.id;
      const questionId = qIdRaw ? cleanText(qIdRaw, 'question.questionId', 64) : `q-${task.questions.length + 1}`;
      const qTextRaw = normalized.question ?? normalized.text ?? normalized.summary;
      const entry = {
        questionId,
        question: cleanText(qTextRaw, 'question.question', 512),
        blockerKind: cleanText(normalized.blockerKind || 'unknown-logic', 'question.blockerKind', 64),
        status: ['open', 'resolved', 'blocked'].includes(normalized.status) ? normalized.status : 'open',
        needsReassessment: Boolean(normalized.needsReassessment),
        updatedAt: new Date().toISOString(),
      };
      const idx = task.questions.findIndex(q => q.questionId === questionId);
      if (idx >= 0) task.questions[idx] = entry;
      else task.questions.push(entry);
      task.planRevision += 1;
      return structuredClone(entry);
    });
  }

  upsertRoute(rootId, spec = {}) {
    return this._mutate(rootId, task => {
      const deliverableId = spec.deliverableId
        ? cleanText(spec.deliverableId, 'route.deliverableId', 64)
        : task.deliverables[0]?.id;
      if (!task.deliverables.some(d => d.id === deliverableId)) {
        fail('DELIVERABLE_NOT_FOUND', `Deliverable "${deliverableId}" does not exist in this investigation`);
      }
      const qRaw = spec.question ?? spec.summary ?? spec.hypothesis;
      const question = cleanText(qRaw, 'route.question', 512);
      const tObsRaw = spec.targetObservation ?? spec.observation ?? spec.summary;
      const targetObservation = cleanText(tObsRaw, 'route.targetObservation', 512);
      const prepSteps = Array.isArray(spec.preparationSteps) ? spec.preparationSteps.map((s, i) => cleanText(s, `preparationSteps[${i}]`, 256)) : [];
      if (prepSteps.length > 4) {
        fail('ROUTE_PREPARATION_TOO_LONG', 'Short backward-chained routes allow at most 4 preparationSteps before a discriminating experiment');
      }
      const prepCap = spec.preparationBudgetCalls ?? 4;
      if (!Number.isSafeInteger(prepCap) || prepCap < 1 || prepCap > 8) {
        fail('INVALID_ARGUMENT', 'route.preparationBudgetCalls must be 1..8');
      }
      const objectiveKey = `${sha256(question).slice(0, 16)}:${sha256(targetObservation).slice(0, 16)}`;
      const ledger = task.preparationLedger[objectiveKey] ||= { usedCalls: 0, limit: prepCap, routeIds: [] };
      // Never enlarge an existing objective's preparation cap via route rename/recreation!
      ledger.limit = Math.min(ledger.limit, prepCap);

      const routeId = spec.routeId ? cleanText(spec.routeId, 'route.routeId', 64) : `route-${task.routes.length + 1}`;
      if (!ledger.routeIds.includes(routeId)) ledger.routeIds.push(routeId);

      const missingPrerequisites = Array.isArray(spec.missingPrerequisites)
        ? spec.missingPrerequisites.map((m, i) => cleanText(m, `missingPrerequisites[${i}]`, 128))
        : [];
      const discExpRaw = spec.discriminatingExperiment ?? spec.experiment ?? spec.targetObservation ?? spec.summary;
      const route = {
        routeId,
        deliverableId,
        question,
        targetObservation,
        methodFamily: ['dynamic-debug', 'static-analysis', 'emulation', 'trace-diff', 'hybrid'].includes(spec.methodFamily)
          ? spec.methodFamily
          : 'dynamic-debug',
        routeFeasible: spec.routeFeasible !== false,
        operationExecutableNow: spec.operationExecutableNow !== undefined ? Boolean(spec.operationExecutableNow) : missingPrerequisites.length === 0,
        missingPrerequisites,
        preparationSteps: prepSteps,
        preparationBudgetCalls: ledger.limit,
        objectiveKey,
        discriminatingExperiment: cleanText(discExpRaw, 'route.discriminatingExperiment', 512),
        exitConditions: Array.isArray(spec.exitConditions) && spec.exitConditions.length
          ? spec.exitConditions.map((c, i) => cleanText(c, `exitConditions[${i}]`, 256))
          : ['target-observation-captured-or-hypothesis-refuted'],
        status: ['active', 'blocked', 'superseded', 'completed'].includes(spec.status) ? spec.status : 'active',
        needsReassessment: false,
        updatedAt: new Date().toISOString(),
      };
      const idx = task.routes.findIndex(r => r.routeId === routeId);
      if (idx >= 0) task.routes[idx] = route;
      else task.routes.push(route);
      task.planRevision += 1;
      return structuredClone(route);
    });
  }

  submitCandidateExplanation(rootId, spec = {}, artifacts = null) {
    return this._mutate(rootId, task => {
      const deliverableId = spec.deliverableId ? cleanText(spec.deliverableId, 'deliverableId', 64) : task.deliverables[0]?.id;
      const deliv = task.deliverables.find(d => d.id === deliverableId);
      if (!deliv) fail('DELIVERABLE_NOT_FOUND', `Deliverable "${deliverableId}" not found`);
      const prev = deliv.candidateExplanation || null;
      const parsedTestVectors = Array.isArray(spec.testVectors) ? spec.testVectors.map((tv, idx) => {
        const receiptId = cleanText(tv.receiptId, `testVectors[${idx}].receiptId`, 64);
        if (!task.receipts.some(r => r.reportId === receiptId && r.outcome === 'success')) {
          fail('UNVERIFIED_RECEIPT_REFERENCE', `testVectors[${idx}].receiptId "${receiptId}" is not a successful system receipt in this investigation`);
        }
        const inputHex = tv.inputHex !== undefined ? cleanText(tv.inputHex, `testVectors[${idx}].inputHex`, 4096).toLowerCase() : null;
        const predictedHex = tv.predictedHex !== undefined ? cleanText(tv.predictedHex, `testVectors[${idx}].predictedHex`, 4096).toLowerCase() : null;
        if (inputHex !== null && (!/^[0-9a-f]+$/.test(inputHex) || inputHex.length % 2 !== 0)) {
          fail('INVALID_ARGUMENT', `testVectors[${idx}] inputHex must be an even-length hex string`);
        }
        if (predictedHex !== null && (!/^[0-9a-f]+$/.test(predictedHex) || predictedHex.length % 2 !== 0)) {
          fail('INVALID_ARGUMENT', `testVectors[${idx}] predictedHex must be an even-length hex string`);
        }
        return {
          caseId: cleanText(tv.caseId || `case-${idx + 1}`, `testVectors[${idx}].caseId`, 64),
          ...(tv.isHoldout !== undefined ? { isHoldout: Boolean(tv.isHoldout) } : {}),
          ...(inputHex !== null ? { inputHex } : {}),
          ...(predictedHex !== null ? { predictedHex } : {}),
          receiptId,
          scenarioId: tv.scenarioId ? cleanText(tv.scenarioId, `testVectors[${idx}].scenarioId`, 64) : null,
        };
      }) : null;

      const preserveCommittedRule = Boolean(
        prev
        && spec.outputSpec === undefined
        && spec.executableRule === undefined
        && spec.rule === undefined,
      );
      const outputSpec = spec.outputSpec !== undefined
        ? validateOutputSpec(spec.outputSpec)
        : (preserveCommittedRule ? prev.outputSpec : null);
      const outputSpecDigest = outputSpec ? hashOutputSpec(outputSpec) : null;
      const executableRule = spec.executableRule !== undefined
        ? validateExecutableRule(spec.executableRule, outputSpec)
        : (preserveCommittedRule ? prev.executableRule : null);
      const ruleSha256 = executableRule && outputSpec ? hashExecutableCandidate(executableRule, outputSpec) : null;
      let ruleBlobRef = preserveCommittedRule ? (prev.ruleBlobRef || null) : null;
      if (ruleSha256 && !ruleBlobRef && artifacts?.put) {
        ruleBlobRef = artifacts.put(Buffer.from(canonical({ executableRule, outputSpec }), 'utf8')).ref;
      }

      const prevSha = prev?.ruleSha256 || null;
      const prevOutDigest = prev?.outputSpecDigest || null;
      const sameCommittedRule = Boolean(ruleSha256 && ruleSha256 === prevSha && outputSpecDigest === prevOutDigest);
      if (ruleSha256 && !sameCommittedRule) {
        deliv.candidateRevision = (deliv.candidateRevision || 0) + 1;
        deliv.candidateCommittedSeq = nextSeq(task);
      }
      const explicitRuleProvided = spec.executableRule !== undefined && spec.outputSpec !== undefined && Boolean(ruleSha256);
      if (explicitRuleProvided) {
        deliv.contractRevisedRequiresUpdate = false;
      }

      const summaryRaw = spec.summary ?? spec.explanation;
      deliv.candidateExplanation = {
        summary: summaryRaw !== undefined
          ? cleanText(summaryRaw, 'candidate.summary', 2000)
          : (prev?.summary ? prev.summary : cleanText(undefined, 'candidate.summary', 2000)),
        rule: spec.rule !== undefined ? (spec.rule ? cleanText(spec.rule, 'candidate.rule', 1000) : null) : (preserveCommittedRule ? prev.rule : null),
        outputSpec,
        outputSpecDigest,
        executableRule,
        ruleSha256,
        ruleBlobRef,
        candidateRevision: deliv.candidateRevision || 0,
        candidateCommittedSeq: deliv.candidateCommittedSeq || 0,
        committedContractRevision: explicitRuleProvided
          ? (task.contractRevision || 1)
          : (prev?.committedContractRevision ?? (task.contractRevision || 1)),
        staticReceiptIds: Array.isArray(spec.staticReceiptIds)
          ? spec.staticReceiptIds.map((id, idx) => {
              const cid = cleanText(id, `staticReceiptIds[${idx}]`, 64);
              if (!task.receipts.some(r => r.reportId === cid && r.outcome === 'success')) {
                fail('UNVERIFIED_RECEIPT_REFERENCE', `staticReceiptIds[${idx}] "${cid}" is not a successful system receipt in this investigation`);
              }
              return cid;
            })
          : (prev?.staticReceiptIds ? [...prev.staticReceiptIds] : []),
        testVectors: parsedTestVectors ?? (sameCommittedRule && Array.isArray(prev?.testVectors) ? structuredClone(prev.testVectors) : []),
        needsReassessment: false,
        submittedAt: new Date().toISOString(),
      };
      task.planRevision += 1;
      return structuredClone(deliv);
    });
  }

  /**
   * Static, non-executing input preparation entrypoint confined strictly inside workspaceCwd.
   * Materializes bounded input file bytes on disk and stores an immutable content-addressed blob ref.
   */
  prepareScenarioInputs(rootId, specs = [], artifacts = null) {
    if (!Array.isArray(specs) || specs.length === 0 || specs.length > 16) {
      fail('INVALID_ARGUMENT', 'prepareInputs must be a non-empty array of 1..16 {path, hex} entries');
    }
    return this._mutate(rootId, task => {
      const allowedRoot = task.workspaceCwd
        ? canonicalPathKey(task.workspaceCwd)
        : (task.components[0]?.path ? canonicalPathKey(path.dirname(task.components[0].path)) : null);
      if (!allowedRoot) {
        fail('INVALID_ARGUMENT', 'prepareInputs requires workspaceCwd or a registered component inside the workspace');
      }
      const prepared = [];
      for (const [idx, item] of specs.entries()) {
        const relOrAbs = cleanText(item?.path, `prepareInputs[${idx}].path`, 512);
        const rawHex = cleanText(item?.hex, `prepareInputs[${idx}].hex`, 8192).toLowerCase();
        if (rawHex.length < 2 || rawHex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(rawHex)) {
          fail('INVALID_ARGUMENT', `prepareInputs[${idx}].hex must be a non-empty even-length hex string (<= 4096 bytes)`);
        }
        const base = task.workspaceCwd || path.dirname(task.components[0].path);
        const resolved = path.resolve(base, relOrAbs);
        const resolvedKey = canonicalPathKey(resolved);
        const prefix = allowedRoot.endsWith(path.sep) ? allowedRoot : allowedRoot + path.sep;
        if (resolvedKey !== allowedRoot && !resolvedKey.startsWith(prefix)) {
          fail('PATH_ESCAPE_FORBIDDEN', `prepareInputs[${idx}].path must stay strictly inside workspace "${base}"`);
        }
        if (task.components.some(c => canonicalPathKey(c.path) === resolvedKey)) {
          fail('INVALID_ARGUMENT', `prepareInputs[${idx}].path cannot overwrite registered component "${resolved}"`);
        }
        fs.mkdirSync(path.dirname(resolved), { recursive: true });
        const buf = Buffer.from(rawHex, 'hex');
        fs.writeFileSync(resolved, buf);
        const digest = sha256(buf);
        const sensitive = Boolean(item?.sensitiveInput);
        const blobRef = sensitive && typeof artifacts?.putSensitive === 'function'
          ? artifacts.putSensitive(buf).ref
          : artifacts?.put ? artifacts.put(buf).ref : null;
        const rec = {
          path: resolved,
          bytes: buf.length,
          sha256: digest,
          blobRef,
          sensitiveInput: sensitive,
          preparedAt: new Date().toISOString(),
        };
        task.preparedInputs ||= [];
        task.preparedInputs.push(rec);
        prepared.push(rec);
      }
      task.planRevision += 1;
      return prepared;
    });
  }

  /**
   * Persist verified terminal block / contract-obligation falsification evidence so multi-round
   * host stopping (`update_goal(action="blocked")` after >=3 rounds) concludes deterministically
   * without repeating redundant native or management calls.
   */
  submitTerminalFinding(rootId, spec = {}, artifacts = null) {
    return this._mutate(rootId, task => {
      if (spec === null || spec.clear === true) {
        task.terminalFinding = null;
        task.planRevision += 1;
        return null;
      }
      const allowedClasses = ['contract-obligation-falsified', 'external-environment-blocked', 'budget-insufficient'];
      const classification = cleanText(spec.classification, 'terminalFinding.classification', 64);
      if (!allowedClasses.includes(classification)) {
        fail('INVALID_ARGUMENT', `terminalFinding.classification must be one of: ${allowedClasses.join(', ')}`);
      }
      const summary = cleanText(spec.summary, 'terminalFinding.summary', 2000);
      const receiptIds = Array.isArray(spec.receiptIds) && spec.receiptIds.length > 0
        ? spec.receiptIds.map((r, i) => cleanText(r, `terminalFinding.receiptIds[${i}]`, 64))
        : task.receipts.filter(r => r.outcome === 'success').map(r => r.reportId);

      const cited = receiptIds.map(rid => {
        const found = task.receipts.find(r => r.reportId === rid);
        if (!found) fail('UNVERIFIED_RECEIPT_REFERENCE', `terminalFinding receipt "${rid}" does not belong to root investigation "${rootId}"`);
        return found;
      });

      if (classification === 'contract-obligation-falsified') {
        const STATIC_SET = new Set(['ig5_open', 'ig5_funcs', 'ig5_strings', 'ig5_decompile', 'ig5_bytes', 'ig5_cfg', 'ig5_xrefs', 'ig5_calls', 'ig5_ir', 'ig5_slice', 'ig5_struct', 'ig5_listing', 'ig5_fingerprint', 'ig5_package']);
        const DYNAMIC_SET = new Set(['ig5_dbg', 'ig5_emulate', 'ig5_capture', 'ig5_api_trace', 'ig5_app_observe']);
        const hasStatic = cited.some(r => STATIC_SET.has(r.tool) && r.outcome === 'success');
        const dynReceipts = cited.filter(r => DYNAMIC_SET.has(r.tool) && r.outcome === 'success');
        if (!hasStatic || dynReceipts.length === 0) {
          fail('UNVERIFIED_NEGATIVE_SCOPE', 'contract-obligation-falsified requires at least 1 successful static receipt and 1 successful dynamic observation receipt');
        }
        // Verify observer health on cited dynamic receipts: broken observers NEVER prove negative falsification!
        for (const dr of dynReceipts) {
          if (artifacts?.get) {
            let fullRec = null;
            try { fullRec = artifacts.get(dr.reportId); } catch { fullRec = null; }
            let out = fullRec?.result?.replayOutput;
            if (out === undefined && fullRec?.result?.replayBlobRef && artifacts?.read) {
              try { out = JSON.parse(artifacts.read(fullRec.result.replayBlobRef).data.toString('utf8')); } catch { out = null; }
            }
            if (out && typeof out === 'object') {
              if (out.observerLogIntegrity && ['missing', 'truncated', 'corrupt'].includes(out.observerLogIntegrity)) {
                fail('OBSERVER_FAILED_CANNOT_CLAIM_NEGATIVE', `Dynamic receipt "${dr.reportId}" has observerLogIntegrity="${out.observerLogIntegrity}"; observer failure cannot be claimed as contract-obligation-falsified`);
              }
              if (out.cleanup?.cleanupEnumerationStatus === 'enumeration-failed' || out.cleanup?.enumerationStatus === 'enumeration-failed' || out.cleanupEnumerationStatus === 'enumeration-failed') {
                fail('OBSERVER_FAILED_CANNOT_CLAIM_NEGATIVE', `Dynamic receipt "${dr.reportId}" suffered process enumeration failure; cannot claim negative worker falsification`);
              }
            }
          }
        }
      }

      for (const rt of task.routes) {
        if (rt.status === 'active') rt.status = 'blocked';
      }
      task.terminalFinding = {
        classification,
        summary,
        receiptIds: [...new Set(receiptIds)],
        recordedAtSeq: nextSeq(task),
        recordedAt: new Date().toISOString(),
      };
      task.planRevision += 1;
      return structuredClone(task.terminalFinding);
    });
  }

  selectExperiment(rootId, spec = {}, artifacts = null) {
    return this._mutate(rootId, task => {
      if (task.terminalFinding && spec.reopenTerminalFinding !== true) {
        fail(
          'PERSISTENT_BLOCK_ALREADY_ESTABLISHED',
          `Verified terminal finding (${task.terminalFinding.classification}) is already persisted on root investigation "${rootId}"; do not repeat business experiments without new hypothesis/reopenTerminalFinding=true — follow hostGoalRoundStatus to conclude legally`,
        );
      }
      const kind = ['static-locate', 'prepare-scenario', 'dynamic-breakpoint-read', 'trace-diff', 'control-baseline', 'holdout-verify', 'explore'].includes(spec.kind)
        ? spec.kind
        : 'dynamic-breakpoint-read';
      const isDeliverableDynamicKind = ['dynamic-breakpoint-read', 'trace-diff', 'control-baseline', 'holdout-verify'].includes(kind);
      const routeId = spec.routeId ? cleanText(spec.routeId, 'experiment.routeId', 64) : (task.routes.find(r => r.status === 'active')?.routeId || null);
      const route = routeId ? task.routes.find(r => r.routeId === routeId) : null;
      if (routeId && !route) fail('ROUTE_NOT_FOUND', `Route "${routeId}" not found`);

      const isPreparation = Boolean(spec.isPreparation || kind === 'prepare-scenario' || (route && !route.operationExecutableNow && kind === 'static-locate'));
      if (isPreparation && route) {
        const ledger = task.preparationLedger[route.objectiveKey];
        if (ledger && ledger.usedCalls >= ledger.limit) {
          fail('PREPARATION_BUDGET_EXHAUSTED', `Preparation call cap (${ledger.limit}) reached for route objective "${route.question}"; execute a discriminating experiment, adjust scenario, or mark route blocked instead of continuing static preparation`);
        }
      }

      const scenarioId = spec.scenarioId ? cleanText(spec.scenarioId, 'experiment.scenarioId', 64) : null;
      const scenario = scenarioId ? task.scenarios.find(s => s.scenarioId === scenarioId) : null;
      if (scenarioId && !scenario) fail('SCENARIO_NOT_FOUND', `Scenario "${scenarioId}" not found`);
      if (isDeliverableDynamicKind && !scenario) {
        fail('SCENARIO_REQUIRED', `Dynamic experiment kind "${kind}" requires a registered runtime scenarioId`);
      }

      const explicitComponentId = spec.componentId ? cleanText(spec.componentId, 'experiment.componentId', 64) : null;
      if (scenario && explicitComponentId && explicitComponentId !== scenario.componentId) {
        fail('SCENARIO_COMPONENT_MISMATCH', `Experiment componentId "${explicitComponentId}" does not match scenario "${scenario.scenarioId}" componentId "${scenario.componentId}"`);
      }
      const componentId = explicitComponentId || scenario?.componentId || task.components[0]?.componentId || null;
      const comp = componentId ? task.components.find(c => c.componentId === componentId) : null;
      if (componentId && !comp) fail('COMPONENT_NOT_FOUND', `Component "${componentId}" not found`);

      // Verify target file/directory bytes have not drifted on disk before selecting experiment.
      if (comp?.path && fs.existsSync(comp.path)) {
        if (computePathIdentity(comp.path).sha256 !== comp.sha256) {
          fail('COMPONENT_HASH_CHANGED', `Component "${comp.componentId}" on disk no longer matches registered SHA-256`);
        }
      }

      // Pre-freeze scenario input lifecycle validation:
      // 1. Detect post-registration disk mutation of input files BEFORE freezing snapshot.
      // 2. Reject freezing empty/broken input snapshots on deliverable-verifying experiments (unless explicit explore).
      let verifiableForDeliverable = !(['explore', 'prepare-scenario'].includes(kind) || spec.allowUnverifiedInputExplore === true);
      let snapInputHex = scenario?.inputSpec?.provenanceVerified ? scenario.inputSpec.canonicalInputHex : null;
      let snapInputSha256 = scenario?.inputSpec?.provenanceVerified ? scenario.inputSpec.canonicalInputSha256 : null;
      let snapInputBlobRef = scenario?.inputSpec?.inputBlobRef || null;
      let snapPlannedHex = scenario?.inputSpec?.plannedInputHex || null;
      let snapPlannedSha256 = scenario?.inputSpec?.plannedInputSha256 || null;
      let snapPlannedBlobRef = scenario?.inputSpec?.plannedInputBlobRef || null;
      let snapProvState = scenario?.inputSpec?.provenanceState || (scenario?.inputSpec?.provenanceVerified ? 'verified' : 'unverified');
      let snapProvVerified = Boolean(scenario?.inputSpec?.provenanceVerified);
      let snapProvReason = scenario?.inputSpec?.provenanceReason || null;

      if (scenario && scenario.inputSpec?.kind === 'file') {
        if (snapProvState === 'channel-sample-conflict' || snapProvState === 'channel-conflict') {
          fail(
            'SCENARIO_INPUT_CHANNEL_CONFLICT',
            `Scenario "${scenario.scenarioId}" file channel conflicts with declared sampleHex (${snapProvReason || 'channel-conflict'}); align sampleHex and on-disk file via root-update`,
          );
        }
        if (verifiableForDeliverable && isDeliverableDynamicKind && snapProvState === 'unbound-channel') {
          fail(
            'SCENARIO_INPUT_UNVERIFIED_FOR_EXPERIMENT',
            `Scenario "${scenario.scenarioId}" has unbound file input channel (${snapProvReason || 'unbound-channel'}); ensure scenario.args or fixedFilename binds inputSpec.filePath`,
          );
        }
        const fPath = scenario.inputSpec?.channel?.filePath
          || (scenario.inputSpec?.filePath ? path.resolve(scenario.cwd, scenario.inputSpec.filePath) : null);
        if (fPath && fs.existsSync(fPath) && fs.statSync(fPath).isFile()) {
          const diskBytes = readStableFile(fPath, 4096).data;
          const diskSha = sha256(diskBytes);
          const diskHex = diskBytes.toString('hex');
          if (snapProvState === 'verified-on-disk' && snapInputSha256 && diskSha !== snapInputSha256) {
            fail(
              'SCENARIO_INPUT_FILE_MODIFIED',
              `Input file "${fPath}" for scenario "${scenario.scenarioId}" was modified on disk after registration (expected sha256=${snapInputSha256}, actual=${diskSha}); register a new scenario via root-update or restore original bytes`,
            );
          }
          if (snapProvState === 'planned-awaiting-materialization') {
            if (snapPlannedSha256 && diskSha !== snapPlannedSha256) {
              fail(
                'SCENARIO_INPUT_CHANNEL_CONFLICT',
                `On-disk file "${fPath}" (${diskSha}) conflicts with scenario "${scenario.scenarioId}" planned sampleHex (${snapPlannedSha256})`,
              );
            }
            snapProvState = 'verified-on-disk';
            snapProvVerified = true;
            snapProvReason = 'materialized-before-select-verified';
            snapInputHex = diskHex;
            snapInputSha256 = diskSha;
            if (artifacts?.put) {
              snapInputBlobRef = (scenario.inputSpec?.sensitiveInput && typeof artifacts.putSensitive === 'function')
                ? artifacts.putSensitive(diskBytes).ref
                : artifacts.put(diskBytes).ref;
            }
          } else if (snapProvState === 'missing-unplanned-file') {
            fail(
              'SCENARIO_INPUT_NOT_FROZEN',
              `File "${fPath}" was created AFTER scenario "${scenario.scenarioId}" was registered without sampleHex; call root-update {"scenario":...} so scenarioDigest freezes the file SHA-256 before selecting an experiment`,
            );
          }
        } else if (verifiableForDeliverable && isDeliverableDynamicKind && snapProvState !== 'planned-awaiting-materialization') {
          fail(
            'SCENARIO_INPUT_UNVERIFIED_FOR_EXPERIMENT',
            `Scenario "${scenario.scenarioId}" has unverified file input (${snapProvReason || snapProvState}). Repair via root-update {"prepareInputs":[{"path":"...","hex":"..."}],"scenario":{...}} or declare inputSpec.sampleHex and materialize via ig5_app_observe input_files; for non-deliverable discovery only, pass kind="explore" or allowUnverifiedInputExplore=true`,
          );
        }
        if (!snapProvVerified && snapProvState !== 'planned-awaiting-materialization') {
          verifiableForDeliverable = false;
        }
      } else if (scenario && !snapProvVerified) {
        // Non-file broken/unobserved channels freeze explicitly as non-verifiable so deliverable verification
        // always rejects them while preserving negative provenance audit trails.
        verifiableForDeliverable = false;
      }

      const hypothesis = cleanText(spec.hypothesis, 'experiment.hypothesis', 1000);
      const observer = cleanText(spec.observer || (scenario ? 'breakpoint-regs-and-memory' : 'static-query'), 'experiment.observer', 512);
      const trigger = scenario ? scenario.trigger : (spec.trigger ? cleanText(spec.trigger, 'experiment.trigger', 512) : null);
      const ifTrue = cleanText(spec.predictions?.ifTrue || 'observation matches predicted transformation/branch', 'experiment.predictions.ifTrue', 512);
      const ifFalse = cleanText(spec.predictions?.ifFalse || 'hypothesis refuted or scenario trigger missed', 'experiment.predictions.ifFalse', 512);
      const maxSteps = spec.maxSteps ?? 8;
      if (!Number.isSafeInteger(maxSteps) || maxSteps < 1 || maxSteps > 24) {
        fail('INVALID_ARGUMENT', 'experiment.maxSteps must be 1..24');
      }

      const relevantPreconditions = {
        componentId,
        targetSha256: comp?.sha256 || null,
        scenarioId: scenario?.scenarioId || null,
        scenarioDigest: scenario?.scenarioDigest || null,
        routeId: route?.routeId || null,
        contractRevision: task.contractRevision || 1,
      };
      const preconditionDigest = sha256(relevantPreconditions);
      const semanticSignature = sha256({
        kind,
        componentId,
        scenarioDigest: scenario?.scenarioDigest || null,
        observer,
        hypothesis,
      });

      const priorIdentical = task.experiments.find(e => e.semanticSignature === semanticSignature && e.status === 'evaluated');
      if (priorIdentical && !spec.allowRepeatWithReason) {
        fail('DUPLICATE_EXPERIMENT_PREVENTED', `Experiment "${priorIdentical.expId}" already evaluated the same target/scenario/observer/hypothesis; change scenario, observer, or hypothesis`);
      }

      task.planRevision += 1;
      const expId = spec.expId ? cleanText(spec.expId, 'experiment.expId', 64) : `exp-${task.experiments.length + 1}`;
      if (task.experiments.some(e => e.expId === expId)) {
        fail('INVALID_ARGUMENT', `Experiment ID "${expId}" already exists`);
      }
      const targetDeliv = route
        ? task.deliverables.find(d => d.id === route.deliverableId)
        : task.deliverables[0];
      const scenarioSnapshot = scenario ? {
        scenarioId: scenario.scenarioId,
        scenarioDigest: scenario.scenarioDigest,
        componentId: scenario.componentId,
        targetPath: scenario.targetPath,
        targetSha256: scenario.targetSha256,
        launchMode: scenario.launchMode,
        args: [...scenario.args],
        cwd: scenario.cwd,
        verifiableForDeliverable,
        sensitiveInput: Boolean(scenario.inputSpec?.sensitiveInput),
        inputProvenanceState: snapProvState,
        plannedInputHex: snapPlannedHex,
        plannedInputSha256: snapPlannedSha256,
        plannedInputBlobRef: snapPlannedBlobRef,
        inputHex: snapInputHex,
        inputSha256: snapInputSha256,
        inputBlobRef: snapInputBlobRef,
        inputProvenanceVerified: snapProvVerified,
        inputProvenanceReason: snapProvReason,
        inputChannel: scenario.inputSpec?.channel ? structuredClone(scenario.inputSpec.channel) : null,
        claimedSampleHex: scenario.inputSpec?.claimedSampleHex || null,
        caseId: scenario.inputSpec?.caseId || null,
        isHoldout: Boolean(scenario.inputSpec?.isHoldout),
      } : null;

      const selectedSeq = nextSeq(task);
      const exp = {
        expId,
        mode: 'explicit',
        kind,
        routeId: route?.routeId || null,
        isPreparation,
        componentId,
        scenarioId: scenario?.scenarioId || null,
        scenarioSnapshot,
        boundContractRevision: task.contractRevision || 1,
        boundCandidateRuleSha256: targetDeliv?.candidateExplanation?.ruleSha256 || null,
        boundOutputSpecDigest: targetDeliv?.candidateExplanation?.outputSpecDigest || null,
        boundCandidateCommittedSeq: targetDeliv?.candidateExplanation?.candidateCommittedSeq || 0,
        selectedAtCandidateRevision: targetDeliv?.candidateRevision || 0,
        selectedSeq,
        hypothesis,
        predictions: { ifTrue, ifFalse },
        trigger,
        observer,
        relevantPreconditions,
        preconditionDigest,
        semanticSignature,
        maxSteps,
        status: 'selected',
        receiptIds: [],
        selectedAtPlanRevision: task.planRevision,
        selectedAt: new Date().toISOString(),
        evaluation: null,
      };
      task.experiments.push(exp);
      return {
        experiment: structuredClone(exp),
        researchBinding: {
          id: task.rootId,
          exp: exp.expId,
          step: 0,
          rev: task.planRevision,
          pre: exp.preconditionDigest,
        },
      };
    });
  }

  /** Validate research binding BEFORE admitting/charging a genuinely new tool call. */
  validateDispatchBinding({ research, toolName, cleanArgs, isCleanup = false }) {
    const task = this.get(research.id);
    if (!isCleanup && task.terminalFinding) {
      fail(
        'PERSISTENT_BLOCK_ALREADY_ESTABLISHED',
        `Root investigation "${research.id}" already has a persisted terminal finding (${task.terminalFinding.classification}); do not dispatch additional business tool calls — follow hostGoalRoundStatus to conclude legally`,
      );
    }
    if (!isCleanup && research.rev !== undefined && research.rev !== task.planRevision) {
      fail('STALE_RESEARCH_PLAN_REVISION', `research.rev (${research.rev}) does not match current root planRevision (${task.planRevision}); refresh brief/plan before dispatching`);
    }
    if (!research.exp) {
      // Inline low-impact explore or owner cleanup: verify component identity & hash if target is supplied.
      const inlineTarget = cleanArgs?.target || cleanArgs?.path || cleanArgs?.input?.path || null;
      if (!isCleanup && inlineTarget) {
        const inlineKey = canonicalPathKey(inlineTarget);
        if (task.components.length > 0) {
          const comp = task.components.find(c => canonicalPathKey(c.path) === inlineKey);
          if (!comp) {
            fail('EXPERIMENT_TARGET_MISMATCH', `Tool "${toolName}" target "${inlineTarget}" is not a registered component of root investigation "${research.id}"`);
          }
          if (fs.existsSync(comp.path)) {
            if (computePathIdentity(comp.path).sha256 !== comp.sha256) {
              fail('COMPONENT_HASH_CHANGED', `Target "${comp.path}" bytes changed since registration`);
            }
          }
        }
      }
      return { ok: true, mode: isCleanup ? 'cleanup' : 'inline-explore', contractRevision: task.contractRevision || 1 };
    }
    const exp = task.experiments.find(e => e.expId === research.exp);
    if (!exp) fail('EXPERIMENT_NOT_FOUND', `Experiment "${research.exp}" does not exist in root investigation "${research.id}"`);
    if (isCleanup) return { ok: true, mode: 'cleanup', expId: exp.expId };

    if (!['selected', 'running'].includes(exp.status)) {
      fail('EXPERIMENT_NOT_ACTIVE', `Experiment "${exp.expId}" is "${exp.status}" and cannot accept new business steps`);
    }
    if (exp.boundContractRevision !== undefined && exp.boundContractRevision !== (task.contractRevision || 1)) {
      fail('CONTRACT_REVISION_CHANGED', `Experiment "${exp.expId}" was selected under contractRevision ${exp.boundContractRevision}, current is ${task.contractRevision}; select a fresh experiment`);
    }
    if (research.pre !== undefined && research.pre !== exp.preconditionDigest) {
      fail('PRECONDITION_DIGEST_MISMATCH', `research.pre does not match experiment "${exp.expId}" preconditionDigest`);
    }
    if (exp.receiptIds.length >= exp.maxSteps) {
      fail('EXPERIMENT_STEP_LIMIT_EXCEEDED', `Experiment "${exp.expId}" reached maxSteps (${exp.maxSteps}); evaluate current receipts before selecting another experiment`);
    }
    if (exp.isPreparation && exp.routeId) {
      const route = task.routes.find(r => r.routeId === exp.routeId);
      const ledger = route ? task.preparationLedger[route.objectiveKey] : null;
      if (ledger && ledger.usedCalls >= ledger.limit) {
        fail('PREPARATION_BUDGET_EXHAUSTED', `Preparation call cap (${ledger.limit}) exhausted for route "${exp.routeId}"`);
      }
    }

    // Bind EVERY operation on an active experiment (not only ig5_dbg start!) to the frozen component path & SHA-256!
    const expectedComp = exp.componentId ? task.components.find(c => c.componentId === exp.componentId) : null;
    const expectedTargetPath = exp.scenarioSnapshot?.targetPath || expectedComp?.path || null;
    const expectedTargetSha = exp.scenarioSnapshot?.targetSha256 || expectedComp?.sha256 || null;
    const callTarget = cleanArgs?.target || cleanArgs?.path || cleanArgs?.input?.path || null;
    if (expectedTargetPath && callTarget && canonicalPathKey(callTarget) !== canonicalPathKey(expectedTargetPath)) {
      fail('EXPERIMENT_TARGET_MISMATCH', `${toolName} target "${callTarget}" does not match experiment "${exp.expId}" bound target "${expectedTargetPath}"`);
    }
    if (expectedTargetPath && expectedTargetSha && fs.existsSync(expectedTargetPath)) {
      if (computePathIdentity(expectedTargetPath).sha256 !== expectedTargetSha) {
        fail('COMPONENT_HASH_CHANGED', `Bound component "${expectedTargetPath}" bytes changed on disk since scenario/experiment freeze`);
      }
    }

    const scen = exp.scenarioSnapshot || (exp.scenarioId ? task.scenarios.find(s => s.scenarioId === exp.scenarioId) : null);
    let verifiedLaunchInputHex = null;

    if (scen && toolName === 'ig5_dbg' && cleanArgs?.op === 'start') {
      if (cleanArgs.target && canonicalPathKey(cleanArgs.target) !== canonicalPathKey(scen.targetPath)) {
        fail('SCENARIO_TARGET_MISMATCH', `ig5_dbg start target does not match scenario "${scen.scenarioId}" targetPath`);
      }
      const suppliedArgs = cleanArgs.args || [];
      if (JSON.stringify(suppliedArgs) !== JSON.stringify(scen.args)) {
        fail('SCENARIO_ARGS_MISMATCH', `ig5_dbg start args ${JSON.stringify(suppliedArgs)} do not match bound scenario "${scen.scenarioId}" args ${JSON.stringify(scen.args)}`);
      }
      if (cleanArgs.cwd && canonicalPathKey(cleanArgs.cwd) !== canonicalPathKey(scen.cwd)) {
        fail('SCENARIO_CWD_MISMATCH', `ig5_dbg start cwd does not match bound scenario "${scen.scenarioId}" cwd`);
      }
      if (scen.inputChannel?.kind === 'file') {
        const expectedSha = scen.inputSha256 || scen.plannedInputSha256;
        const fp = scen.inputChannel.filePath;
        if (!fp || !fs.existsSync(fp) || !fs.statSync(fp).isFile()) {
          fail('SCENARIO_INPUT_FILE_MISSING_AT_DISPATCH', `Scenario "${scen.scenarioId}" input file "${fp}" does not exist on disk before ig5_dbg start; prepare it via root-update prepareInputs first`);
        }
        const curBytes = readStableFile(fp, 4096).data;
        const curSha = sha256(curBytes);
        if (expectedSha && curSha !== expectedSha) {
          fail('SCENARIO_INPUT_FILE_MODIFIED_BEFORE_DISPATCH', `Input file "${fp}" changed on disk before ig5_dbg start (expected=${expectedSha}, actual=${curSha})`);
        }
        verifiedLaunchInputHex = curBytes.toString('hex');
      } else if (scen.inputHex) {
        verifiedLaunchInputHex = scen.inputHex;
      }
    }

    if (scen && toolName === 'ig5_app_observe' && cleanArgs?.action === 'process_chain_scenario') {
      const effectiveCwd = cleanArgs.cwd ? path.resolve(cleanArgs.cwd) : path.dirname(path.resolve(cleanArgs.target || scen.targetPath));
      if (scen.cwd && canonicalPathKey(effectiveCwd) !== canonicalPathKey(scen.cwd)) {
        fail('SCENARIO_CWD_MISMATCH', `process_chain_scenario cwd "${effectiveCwd}" does not match bound scenario "${scen.scenarioId}" cwd "${scen.cwd}"`);
      }
      if (Array.isArray(scen.args) && scen.args.length > 0) {
        const suppliedArgs = Array.isArray(cleanArgs.args) ? cleanArgs.args.map(String) : [];
        if (JSON.stringify(suppliedArgs) !== JSON.stringify(scen.args)) {
          fail('SCENARIO_ARGS_MISMATCH', `process_chain_scenario args ${JSON.stringify(suppliedArgs)} do not match bound scenario "${scen.scenarioId}" args ${JSON.stringify(scen.args)}`);
        }
      }
      const expectedSha = scen.inputSha256 || scen.plannedInputSha256 || null;
      if (scen.inputChannel?.kind === 'file' && expectedSha) {
        const expectedKey = canonicalPathKey(scen.inputChannel.filePath);
        const stagedMatch = Array.isArray(cleanArgs.input_files)
          ? cleanArgs.input_files.find(inf => inf?.path && canonicalPathKey(path.resolve(effectiveCwd, inf.path)) === expectedKey)
          : null;
        if (stagedMatch) {
          const stagedBuf = Buffer.from(String(stagedMatch.hex || '').trim(), 'hex');
          const stagedSha = sha256(stagedBuf);
          if (stagedSha !== expectedSha) {
            fail('SCENARIO_INPUT_CHANNEL_CONFLICT', `input_files entry for "${stagedMatch.path}" (sha256=${stagedSha}) conflicts with scenario "${scen.scenarioId}" bound input (sha256=${expectedSha})`);
          }
        } else {
          const fp = scen.inputChannel.filePath;
          if (!fp || !fs.existsSync(fp) || !fs.statSync(fp).isFile()) {
            fail('SCENARIO_INPUT_FILE_MISSING_AT_DISPATCH', `Bound input file "${fp}" is missing on disk and was not supplied in input_files for scenario "${scen.scenarioId}"`);
          }
          const curBytes = readStableFile(fp, 4096).data;
          const curSha = sha256(curBytes);
          if (curSha !== expectedSha) {
            fail('SCENARIO_INPUT_FILE_MODIFIED_BEFORE_DISPATCH', `Bound input file "${fp}" changed on disk before execution (expected=${expectedSha}, actual=${curSha})`);
          }
        }
      } else if (scen.inputChannel?.kind === 'stdin' && expectedSha) {
        const rawStdin = typeof cleanArgs.stdin_hex === 'string' ? cleanArgs.stdin_hex.trim() : '';
        if (!rawStdin) {
          fail('SCENARIO_INPUT_CHANNEL_CONFLICT', `Scenario "${scen.scenarioId}" requires stdin_hex matching bound stdin inputSpec`);
        }
        const stdinSha = sha256(Buffer.from(rawStdin, 'hex'));
        if (stdinSha !== expectedSha) {
          fail('SCENARIO_INPUT_CHANNEL_CONFLICT', `process_chain_scenario stdin_hex (${stdinSha}) conflicts with bound scenario "${scen.scenarioId}" (${expectedSha})`);
        }
      }
    }

    return {
      ok: true,
      mode: 'explicit',
      expId: exp.expId,
      scenarioSnapshot: scen ? structuredClone(scen) : null,
      verifiedLaunchInputHex,
      contractRevision: task.contractRevision || 1,
    };
  }

  /** System-only receipt recording called by runManagedToolExecution / recoverPendingReceipts. */
  recordSystemReceipt({ rootId, receiptRecord, operation }) {
    if (this._faultInjectLinkFailure) {
      this._faultInjectLinkFailure = false;
      fail('INJECTED_ROOT_LINK_FAILURE', 'Simulated root investigation receipt linkage failure after artifact commit');
    }
    if (!receiptRecord?.id || receiptRecord.kind !== 'managed-operation-receipt') {
      fail('INVALID_SYSTEM_RECEIPT', 'recordSystemReceipt requires a committed managed-operation-receipt artifact');
    }
    return this._mutate(rootId, task => {
      const existing = task.receipts.find(r => r.reportId === receiptRecord.id || (operation?.operationId && r.operationId === operation.operationId));
      if (existing) return structuredClone(existing);

      const body = receiptRecord.result || {};
      let expId = receiptRecord.experimentId || body.research?.exp || null;
      let exp = expId ? task.experiments.find(e => e.expId === expId) : null;

      if (!exp && !operation?.isCleanup) {
        expId = `inline-${receiptRecord.id.slice(0, 8)}`;
        exp = {
          expId,
          mode: 'inline-explore',
          kind: 'explore',
          routeId: task.routes.find(r => r.status === 'active')?.routeId || null,
          isPreparation: true,
          componentId: task.components[0]?.componentId || null,
          scenarioId: null,
          hypothesis: body.research?.note || `Inline exploration via ${receiptRecord.tool}`,
          predictions: { ifTrue: 'locate static structure', ifFalse: 'adjust query' },
          trigger: null,
          observer: receiptRecord.action || receiptRecord.tool,
          relevantPreconditions: {},
          preconditionDigest: sha256({ tool: receiptRecord.tool, note: body.research?.note || null }),
          semanticSignature: sha256({ inline: receiptRecord.id }),
          maxSteps: 1,
          status: 'running',
          receiptIds: [],
          selectedAtPlanRevision: task.planRevision,
          selectedAt: receiptRecord.createdAt,
          evaluation: null,
        };
        task.experiments.push(exp);
      }

      const summaryEntry = {
        reportId: receiptRecord.id,
        operationId: operation?.operationId || receiptRecord.operationId,
        expId: exp?.expId || expId,
        stepIndex: receiptRecord.stepIndex ?? (exp ? exp.receiptIds.length : 0),
        receiptSeq: nextSeq(task),
        isCleanup: Boolean(operation?.isCleanup),
        tool: receiptRecord.tool,
        action: receiptRecord.action,
        outcome: receiptRecord.outcome,
        cleanArgsSummary: body.cleanArgsSummary || {},
        runtimeIdentity: body.runtimeIdentity || null,
        observedMetrics: body.observedMetrics || {},
        recordedAt: receiptRecord.createdAt || new Date().toISOString(),
      };
      task.receipts.push(summaryEntry);

      if (exp) {
        if (!exp.receiptIds.includes(receiptRecord.id)) exp.receiptIds.push(receiptRecord.id);
        if (exp.status === 'selected') exp.status = 'running';
        if (exp.isPreparation && exp.routeId && !operation?.isCleanup) {
          const route = task.routes.find(r => r.routeId === exp.routeId);
          if (route && task.preparationLedger[route.objectiveKey]) {
            task.preparationLedger[route.objectiveKey].usedCalls += 1;
          }
        }
      }
      return structuredClone(summaryEntry);
    });
  }

  /** Idempotently link any `receipt-pending` operations recorded in DelegationControl without re-executing tools. */
  recoverPendingReceipts({ rootId, mgr, execution }) {
    const hasHostSession = execution?.agent?.session !== undefined;
    const ops = mgr.coordination.operationsForInvestigation(execution?.agent, rootId, {
      allowLocalFallback: !hasHostSession,
    });
    const recovered = [];
    const unknownEffects = [];
    for (const op of ops) {
      if (op.status === 'effect-unknown') {
        unknownEffects.push({ operationId: op.operationId, tool: op.tool, op: op.op, requestKey: op.requestKey });
        continue;
      }
      if (op.status === 'result-recorded' && op.researchLinkStatus === 'receipt-pending' && op.reportRef) {
        const savedReport = mgr.analysis.artifacts.get(op.reportRef);
        const linked = this.recordSystemReceipt({ rootId, receiptRecord: savedReport, operation: op });
        mgr.coordination.markOperationLinked(execution?.agent, op.slotKey, { allowLocalFallback: !hasHostSession });
        recovered.push({ operationId: op.operationId, reportId: op.reportRef, expId: linked.expId });
      }
    }
    return { rootId, recoveredCount: recovered.length, recovered, unknownEffects };
  }

  evaluateExperiment(rootId, spec = {}) {
    return this._mutate(rootId, task => {
      if (typeof spec?.expId !== 'string' || !spec.expId.trim()) {
        fail(
          'INVALID_ARGUMENT',
          'workspace.root.expId must be a non-empty string; pass {"workspace":{"action":"evaluate","id":"<rootId>","root":{"expId":"<expId>","verdict":"supports|refutes|inconclusive","observationClass":"non-empty|not-triggered|...","whyNextChanged":"...","nextAction":"..."}}}',
        );
      }
      const expId = cleanText(spec.expId, 'workspace.root.expId', 64);
      const exp = task.experiments.find(e => e.expId === expId);
      if (!exp) fail('EXPERIMENT_NOT_FOUND', `Experiment "${expId}" not found`);
      if (exp.status === 'evaluated') fail('EXPERIMENT_ALREADY_EVALUATED', `Experiment "${expId}" was already evaluated`);

      const receiptIds = Array.isArray(spec.receiptIds) && spec.receiptIds.length ? spec.receiptIds : exp.receiptIds;
      if (!receiptIds.length) {
        fail('RECEIPT_REQUIRED_FOR_EVALUATION', 'Cannot evaluate an experiment without at least one system-recorded execution receipt');
      }
      const citedReceipts = receiptIds.map(id => {
        const found = task.receipts.find(r => r.reportId === id);
        if (!found) fail('UNVERIFIED_RECEIPT_REFERENCE', `Receipt "${id}" does not belong to root investigation "${rootId}"`);
        return found;
      });

      const observationClass = spec.observationClass || 'non-empty';
      if (!VALID_OBS_CLASSES.has(observationClass)) {
        fail('INVALID_ARGUMENT', `observationClass must be one of: ${[...VALID_OBS_CLASSES].join(', ')}`);
      }
      const verdict = spec.verdict;
      if (!VALID_VERDICTS.has(verdict)) {
        fail('INVALID_ARGUMENT', `verdict must be one of: ${[...VALID_VERDICTS].join(', ')}`);
      }

      // Guard against conflating missed triggers or broken observers with valid negative results.
      if (observationClass === 'negative-within-verified-scope') {
        const anySuccess = citedReceipts.some(r => r.outcome === 'success');
        if (!anySuccess || spec.triggerConfirmed !== true || spec.observerConfirmed !== true) {
          fail('UNVERIFIED_NEGATIVE_SCOPE', 'negative-within-verified-scope requires successful receipt(s) plus explicit triggerConfirmed=true and observerConfirmed=true');
        }
        const requiresBp = /breakpoint/i.test(exp.observer || '');
        const lastBptIdx = citedReceipts.findLastIndex(r => r.action === 'ig5_dbg:bpt');
        const postBptReceipts = lastBptIdx >= 0 ? citedReceipts.slice(lastBptIdx + 1) : citedReceipts;
        const sawContWithoutBp = postBptReceipts.some(r => r.tool === 'ig5_dbg' && r.action === 'ig5_dbg:cont')
          && !postBptReceipts.some(r => r.observedMetrics?.hitBreakpoint === true && r.outcome === 'success');
        if (requiresBp && sawContWithoutBp) {
          fail('UNVERIFIED_NEGATIVE_SCOPE', 'Breakpoint observer never hit after ig5_dbg:bpt; classify as not-triggered or window-insufficient instead of negative-within-verified-scope');
        }
      }

      if (['not-triggered', 'observer-failed', 'window-insufficient'].includes(observationClass) && verdict === 'supports') {
        fail('INVALID_EVALUATION_VERDICT', `Observation class "${observationClass}" cannot claim verdict="supports" for a target hypothesis`);
      }

      const prerequisiteChanges = Array.isArray(spec.prerequisiteChanges)
        ? spec.prerequisiteChanges.map((p, idx) => ({
            prerequisite: cleanText(p.prerequisite, `prerequisiteChanges[${idx}].prerequisite`, 128),
            status: ['established', 'invalidated'].includes(p.status) ? p.status : 'established',
          }))
        : [];

      const evalRecord = {
        evalId: `eval-${task.evaluations.length + 1}`,
        expId,
        receiptIds: [...receiptIds],
        observationClass,
        verdict,
        newObservations: Array.isArray(spec.newObservations)
          ? spec.newObservations.map((o, i) => cleanText(o, `newObservations[${i}]`, 512))
          : [],
        coverageChange: cleanText(spec.coverageChange || 'recorded step observations', 'evaluate.coverageChange', 512),
        prerequisiteChanges,
        candidateChanges: cleanText(spec.candidateChanges || 'retained current candidate set', 'evaluate.candidateChanges', 512),
        whyNextChanged: cleanText(spec.whyNextChanged, 'evaluate.whyNextChanged', 512),
        nextAction: cleanText(spec.nextAction, 'evaluate.nextAction', 512),
        evaluatedAt: new Date().toISOString(),
      };

      exp.status = 'evaluated';
      exp.evaluation = evalRecord;
      task.evaluations.push(evalRecord);

      if (exp.scenarioId && observationClass === 'non-empty' && citedReceipts.some(r => r.outcome === 'success')) {
        const scen = task.scenarios.find(s => s.scenarioId === exp.scenarioId);
        if (scen && scen.baselineStatus === 'unverified') scen.baselineStatus = 'verified';
      }

      if (exp.routeId) {
        const route = task.routes.find(r => r.routeId === exp.routeId);
        if (route && prerequisiteChanges.length) {
          const established = new Set(prerequisiteChanges.filter(p => p.status === 'established').map(p => p.prerequisite));
          const invalidated = prerequisiteChanges.filter(p => p.status === 'invalidated').map(p => p.prerequisite);
          route.missingPrerequisites = [
            ...route.missingPrerequisites.filter(p => !established.has(p)),
            ...invalidated.filter(p => !route.missingPrerequisites.includes(p)),
          ];
          route.operationExecutableNow = route.missingPrerequisites.length === 0;
        }
      }

      let counterexample = null;
      if (verdict === 'refutes') {
        counterexample = {
          counterexampleId: `cx-${task.counterexamples.length + 1}`,
          expId,
          routeId: exp.routeId,
          hypothesis: exp.hypothesis,
          receiptIds: [...receiptIds],
          reason: evalRecord.whyNextChanged,
          status: 'unresolved',
          supersededByExpId: null,
          recordedAt: evalRecord.evaluatedAt,
        };
        task.counterexamples.push(counterexample);
        if (exp.routeId) {
          const route = task.routes.find(r => r.routeId === exp.routeId);
          if (route) route.needsReassessment = true;
        }
        for (const d of task.deliverables) {
          if (d.candidateExplanation) d.candidateExplanation.needsReassessment = true;
        }
      }

      if (spec.resolveCounterexampleId) {
        const cx = task.counterexamples.find(c => c.counterexampleId === spec.resolveCounterexampleId);
        if (!cx) fail('COUNTEREXAMPLE_NOT_FOUND', `Counterexample "${spec.resolveCounterexampleId}" not found`);
        if (verdict !== 'supports' || observationClass !== 'non-empty') {
          fail('INVALID_COUNTEREXAMPLE_RESOLUTION', 'Resolving a retained counterexample requires a non-empty supporting experiment receipt');
        }
        cx.status = 'addressed';
        cx.supersededByExpId = expId;
      }

      task.planRevision += 1;
      return { evaluation: structuredClone(evalRecord), counterexample: structuredClone(counterexample), planRevision: task.planRevision };
    });
  }

  issueDelegationBrief(rootId, { parentAgentId, childRole, componentId, scenarioId = null, objective }) {
    return this._mutate(rootId, task => {
      task.delegationBriefs ||= [];
      if (task.delegationBriefs.length >= 64) fail('DELEGATION_BRIEF_LIMIT', 'Maximum 64 delegation briefs per root investigation');
      const brief = createChildResearchBrief({
        rootTask: task,
        parentAgentId,
        childRole,
        componentId,
        scenarioId,
        objective,
      });
      task.delegationBriefs.push(brief);
      return structuredClone(brief);
    });
  }

  acceptChildFinding(rootId, { briefId, childReport, artifacts = null }) {
    return this._mutate(rootId, task => {
      task.delegationBriefs ||= [];
      task.childFindings ||= [];
      const brief = task.delegationBriefs.find(b => b.briefId === briefId);
      if (!brief) fail('DELEGATION_BRIEF_NOT_FOUND', `Delegation brief "${briefId}" not found in root investigation "${rootId}"`);
      const accepted = verifyAndAcceptChildFinding({
        rootTask: task,
        brief,
        childReport,
        artifacts,
      });
      task.childFindings.push(accepted);
      task.planRevision += 1;
      return structuredClone(accepted);
    });
  }
}

/**
 * Render strictly deterministic pre-step brief text over committed investigation state.
 * Contains zero timestamps or volatile tokens so DSH RuntimeContextProjection only emits
 * a snapshot update when investigation state genuinely advances.
 */
export function renderDeterministicRootBrief(rootTask, assessment) {
  if (!rootTask) return '';
  const activeRoute = rootTask.routes.find(r => r.status === 'active') || null;
  const activeExp = rootTask.experiments.find(e => ['selected', 'running'].includes(e.status)) || null;
  const unresolvedCx = rootTask.counterexamples.filter(c => c.status === 'unresolved');
  const lines = [
    `[IG5 Root Investigation ${rootTask.rootId}]`,
    `rev=${rootTask.revision} planRev=${rootTask.planRevision} workState=${assessment.workState}${assessment.stopReason ? '(' + assessment.stopReason + ')' : ''} assessment=${assessment.assessment} cleanup=${assessment.cleanup}`,
    `goal: ${rootTask.goal}`,
    `components=${rootTask.components.length} scenarios=${rootTask.scenarios.length} receipts=${rootTask.receipts.length} unresolvedCounterexamples=${unresolvedCx.length}`,
  ];
  if (activeRoute) {
    lines.push(`route[${activeRoute.routeId}]: method=${activeRoute.methodFamily} executableNow=${activeRoute.operationExecutableNow} missing=[${activeRoute.missingPrerequisites.join(',')}] targetObs=${activeRoute.targetObservation}`);
  }
  if (activeExp) {
    lines.push(`activeExperiment[${activeExp.expId}]: kind=${activeExp.kind} steps=${activeExp.receiptIds.length}/${activeExp.maxSteps} pre=${activeExp.preconditionDigest.slice(0, 12)}`);
  }
  if (assessment.pendingCleanup?.length) {
    lines.push(`pendingCleanup: ${assessment.pendingCleanup.map(c => `${c.resourceKey}(${c.status})`).join(', ')}`);
  }
  if (assessment.budget) {
    const rem = Math.max(0, assessment.budget.limit - assessment.budget.used - (assessment.budget.reserved || 0));
    lines.push(`budget: used=${assessment.budget.used}/${assessment.budget.limit} reservedCleanup=${assessment.budget.reserved || 0} remainingOrdinary=${rem}`);
    if (rem <= 6) {
      lines.push('budgetHeadroomWarning: <=6 ordinary calls remaining; prioritize resource cleanup, attaching verified testVectors, running assess, and clean goal completion/block transition instead of starting new exploration.');
    }
  }
  if (assessment.goalAssessmentAligned === false) {
    lines.push(`hostGoalWarning: hostGoalState=${assessment.hostGoalState} diverges from investigationAssessment=${assessment.assessment}`);
  }
  if (rootTask.terminalFinding || assessment.assessment === 'blocked') {
    const tf = rootTask.terminalFinding;
    const rs = assessment.hostGoalRoundStatus;
    if (tf) {
      lines.push(`persistedTerminalFinding: classification=${tf.classification} receipts=${tf.receiptIds.length}`);
    }
    if (rs && rs.currentRound !== null) {
      if (rs.canCallHostBlockedNow) {
        lines.push(`hostStopProtocol: round=${rs.currentRound}/${rs.minRoundsForHostBlocked} (>=3 satisfied) -> stop any owned resources, call get_goal (if id/revision unknown), and call update_goal(action="blocked", goal_id, revision, blocked_reason) now.`);
      } else {
        lines.push(`hostStopProtocol: round=${rs.currentRound}/${rs.minRoundsForHostBlocked} -> DSH rejects action="blocked" before round 3. Do NOT call more tools in this round; output a concise factual summary now to end round ${rs.currentRound} cleanly so DSH advances to round ${rs.currentRound + 1}.`);
      }
    }
  }
  lines.push(
    `resumeHint: if context was compacted, reload skill "ig5-reverse-agent", confirm ig5_profile {"toolset":"full"}, and read ig5_workspace {"workspace":{"action":"root-resume","id":"${rootTask.rootId}"}}`,
    `workspaceSyntax: pass all root parameters inside args.workspace (never top-level args): {"workspace":{"action":"root-update|select|evaluate|assess","id":"${rootTask.rootId}","root":{...}}}`,
  );
  return lines.join('\n');
}
