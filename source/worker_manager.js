import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { engineId, terminateTree } from '../engine_runtime.js';
import { spawnWorker, attachWorker, doctorWorker } from './worker_transport.js';
import { ProjectStore } from './project_store.js';
import { ResultArtifacts } from './result_artifacts.js';
import { FunctionBatches } from './function_batches.js';
import { saveDebugTrace } from './debug_trace.js';
import { saveApiTrace } from './api_trace.js';
import { RemoteExecutionStore } from './remote_execution_store.js';
import { loadGuestProfile, guestTarget } from './guest_debug_profile.js';
import { recoverGuestExecution } from './guest_recovery.js';
import { diagAppend } from './diag_log.js';
import { publicEngineError } from './engine_error.js';
import { IMPLEMENTATION_REVISION, IMPLEMENTATION_LOADED_AT } from './implementation_info.js';

// 插件根目录(原 index.js 的 HERE)
const HERE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// ── Worker 池（小样：1 目标 = 1 Python 进程，JSON-RPC over stdio） ──────────
export class WorkerManager {
  constructor(cfg) {
    this.cfg = cfg;
    let functionResults;
    Object.defineProperty(this, 'functionResults', { get: () => functionResults ||= new ResultArtifacts(path.join(cfg.projectRoot, 'function-results')) });
    let functionBatches;
    Object.defineProperty(this, 'functionBatches', { get: () => functionBatches ||= new FunctionBatches(cfg.projectRoot) });
    this.sessions = new Map(); // key: lower(abs target path)
    this.launching = new Map(); // serialize concurrent opens of the same target
    this.jobs = new Map(); // 后台分析作业的进度投影（工作台轮询 /ig5-jobs）
    this.seq = 0;
    this.scope = new AsyncLocalStorage();
    this.projects = new ProjectStore({ root: cfg.projectRoot });
    this.debugOwners = new Map();
    this.debugQueues = new Map();
    this.admissions = Promise.resolve();
    // A lease is recoverable only after both recorded owners are proven dead.
    const retained = this.remoteExecutionStatus();
    this.attachmentRecovery = this.projects.recoverAttachments({ retainDebugArtifacts: retained.map(row => 'artifact_' + row.targetSha256) });
  }

  sessionKey(target, engine = this.scope.getStore()?.engine || this.cfg.defaultEngine || 'reverse') {
    const absolute = path.resolve(String(target));
    const base = (this.cfg.host?.platform || process.platform) === 'win32' ? absolute.toLowerCase() : absolute;
    return engine === 'reverse' ? base : `${base}::${engineId(engine)}`;
  }

  get(target, engine) {
    const exact = this.sessions.get(this.sessionKey(target, engine));
    if (exact) return exact;
    if (!engine && !this.scope.getStore()?.engine) {
      const ghidraSession = this.sessions.get(this.sessionKey(target, 'ghidra'));
      if (ghidraSession) return ghidraSession;
    }
    return undefined;
  }

  selectedTarget() {
    const engine = this.scope.getStore()?.engine || this.cfg.defaultEngine;
    const live = [...this.sessions.values()].filter((s) => this.alive(s) && s.engine === engine && s.engine !== 'x64dbg');
    if (live.length !== 1) throw new Error('Specify target when there are zero or multiple active targets in the selected engine');
    return live[0].target;
  }

  alive(session) {
    return !!session && !!session.proc && session.proc.exitCode === null && session.ready;
  }

  checkCancelled() {
    if (this.scope.getStore()?.signal?.aborted) throw Object.assign(new Error('IG5 operation cancelled before execution'), { code: 'ABORT_ERR' });
  }

  remoteStore() {
    return this.guestExecutions ||= new RemoteExecutionStore({ root: this.cfg.remoteExecutionRoot || path.join(this.cfg.home || this.cfg.projectRoot, 'remote-executions') });
  }

  remoteExecutionStatus() {
    const root = this.cfg.remoteExecutionRoot || path.join(this.cfg.home || this.cfg.projectRoot, 'remote-executions');
    if (!this.guestExecutions && !fs.existsSync(path.join(root, 'projects.json'))) return [];
    return this.remoteStore().list().filter(row => row.state !== 'cleaned').map(row => ({ key: row.key, nonce: row.nonce,
      state: row.state, target: row.binding.target, targetSha256: row.binding.targetSha256, guestCID: row.binding.guestCID,
      profile: row.binding.profileName, profileSha256: row.binding.profileSha256, remote: row.remote, agentId: row.agentId,
      observedNativeRoots: row.observedRoots.length, scope: 'Retained guest execution custody; host/bridge liveness is not guest cleanup proof' }));
  }

  remoteCleanupEvidence() {
    const root = this.cfg.remoteExecutionRoot || path.join(this.cfg.home || this.cfg.projectRoot, 'remote-executions');
    if (!this.guestExecutions && !fs.existsSync(path.join(root, 'projects.json')))
      return { entries: [], totalStoredCleanedGenerations: 0, omitted: 0, partial: false,
        scope: 'No stored cleanup metadata; not proof of remote process termination' };
    return this.remoteStore().cleanupEvidence();
  }

  retainRemoteExecution(session, reason = 'transport-lost') {
    if (!session.remoteLease) return false;
    const current = this.remoteStore().current(session.remoteLease.key);
    if (current?.nonce === session.remoteLease.nonce && current.state === 'cleaned') return false;
    session.ready = false;
    session.runtime = { state: 'unknown', stateCode: null, guestExecutionRetained: true, cleanupRequired: true };
    if (!current || current.nonce !== session.remoteLease.nonce) return true;
    this.debugOwners.set(path.resolve(session.target).toLowerCase(), 'x64dbg');
    if (current.state === 'reserved') {
      const releaseUnarmed = () => {
        try {
          session.remoteLease = this.remoteStore().abandonUnarmed(current, true);
          const currentSession = this.sessions.get(session.key);
          if (currentSession === session) this.sessions.delete(session.key);
          this.releaseAttachmentAfterExit(session);
          if (!currentSession || currentSession === session) this.debugOwners.delete(path.resolve(session.target).toLowerCase());
        } catch (error) { session.remoteLeaseError = publicEngineError(error, this.cfg); }
      };
      if (!session.proc?.pid || session.proc.exitCode !== null || session.proc.signalCode) releaseUnarmed();
      else if (!session.remoteUnarmedExitWait) { session.remoteUnarmedExitWait = true; session.proc.once('exit', releaseUnarmed); }
      return true;
    }
    session.remoteLease = this.remoteStore().uncertain(current, reason);
    return true;
  }

  acceptRemoteResult(session, method, value) {
    const location = value?.executionLocation, expected = session.executionLocation;
    if (value?.authenticatedGuestResponse !== true || !location || !expected || ['kind', 'profileSha256', 'guestCID', 'bundleSha256', 'serverInstanceId', 'sessionId'].some(key => location[key] !== expected[key]))
      throw new Error('Guest response identity differs from the bound worker');
    const roots = value.guestProvenance?.nativeRootsObserved;
    if (Array.isArray(roots) && roots.some(root => !session.remoteLease.observedRoots.some(known => known.rootId === root.rootId && known.pid === root.pid)))
      session.remoteLease = this.remoteStore().observeRoots(session.remoteLease, roots);
    if (value.guestCleanup !== undefined) {
      if (method !== 'close' || value.guestCleanupHMACVerified !== true) throw new Error('Guest cleanup requires the authenticated terminal close response');
      session.remoteLease = this.remoteStore().complete(session.remoteLease, value.guestCleanup);
    }
  }

  withSessions(sessions, perform) {
    const unique = [...new Set(sessions)].filter(Boolean);
    for (const session of unique) if (session.closing) throw new Error('Target is closing; wait for it to finish');
    const predecessors = unique.map((s) => Promise.resolve(s.operationQueue).catch(() => {}));
    for (const session of unique) session.queuedOperations = (session.queuedOperations || 0) + 1;
    const pending = Promise.all(predecessors).then(() => { this.checkCancelled(); return perform(); }).finally(() => {
      for (const session of unique) session.queuedOperations--;
    });
    for (const session of unique) session.operationQueue = pending;
    return pending;
  }

  async admitSession(key, target, engine, options = {}) {
    const pending = this.admissions.catch(() => {}).then(async () => {
      this.checkCancelled();
      if (engine !== 'x64dbg' && [...this.sessions.values()].filter((s) => s.engine !== 'x64dbg').length >= this.cfg.maxSessions) await this.closeOldest();
      const session = { key, engine, target: path.resolve(String(target)), proc: null, ready: false,
        pending: new Map(), seq: 0, startedAt: Date.now(), info: null, lastOp: 'launching', lastStage: null,
        progress: null, stderrTail: '', cache: new Map(), dbRevision: 0, queuedOperations: 0, state: 'opening' };
      const identity = this.projects.open(session.target);
      Object.assign(session, { projectId: identity.projectId, artifactId: identity.artifactId, sha256: identity.sha256 });
      if ((engine === 'ghidra' || engine === 'reverse' && this.cfg.reverseProvider === 'bundled') && [...this.sessions.values()].some((s) => s.engine === engine && s.artifactId === identity.artifactId)) {
        throw new Error('This artifact already has an active database in this analysis lane at another path; close that session before reopening its moved alias');
      }
      if (options.guestProfile) {
        const snapshot = options.guestProfile, registered = guestTarget(snapshot, identity.sha256);
        session.guestProfile = snapshot;
        session.remoteLease = this.remoteStore().reserve({ guestCID: snapshot.profile.guestCID, profileName: snapshot.name,
          profileSha256: snapshot.sha256, bundleSha256: snapshot.profile.bundleSha256, targetSha256: identity.sha256,
          targetId: registered.id, target: session.target, projectRoot: path.resolve(this.cfg.projectRoot) }, this.scope.getStore()?.agentId || 'local');
      }
      let proc;
      try { proc = this.spawnWorker(engine, options.guestProfile); }
      catch (error) { if (session.remoteLease) this.remoteStore().abandonUnarmed(session.remoteLease, true); throw error; }
      session.proc = proc; proc.__ig5 = session;
      this.sessions.set(key, session);
      return session;
    });
    this.admissions = pending.catch(() => {});
    return pending;
  }

  spawnWorker(engine = this.scope.getStore()?.engine || this.cfg.defaultEngine || 'reverse', guestProfile) {
    return spawnWorker(guestProfile ? { ...this.cfg, guestExecutionProfile: { path: guestProfile.path, sha256: guestProfile.sha256 } } : this.cfg, engineId(engine), HERE, {
      formatError: error => this.rpcError(error), timers: { setTimeout, clearTimeout },
    });
  }

  async open(target, autoAnalysis = true, options = {}) {
    const engine = engineId(options.engine || this.scope.getStore()?.engine || this.cfg.defaultEngine || 'reverse');
    if (engine === 'x64dbg' && !options.internal) throw new Error('Use ig5_dbg backend=x64dbg for runtime execution');
    const fresh = options.fresh === true;
    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
    const key = this.sessionKey(target, engine);
    const inflight = this.launching.get(key);
    if (inflight) {
      await inflight;
      return this.open(target, autoAnalysis, options);
    }
    const existing = this.sessions.get(key);
    if (existing && (Boolean(existing.guestProfile) !== Boolean(options.guestProfile)
        || existing.guestProfile && (existing.guestProfile.name !== options.guestProfile?.name || existing.guestProfile.sha256 !== options.guestProfile?.sha256)))
      throw new Error('Debugger execution destination changed; close the original session before switching local/guest profiles');
    if (existing?.remoteLease && !this.alive(existing)) throw new Error('Guest execution is retained; use approved op=recover with its original guest binding');
    if (this.alive(existing)) {
      if (fresh || options.analysisProfile && existing.info?.analysisProfile !== options.analysisProfile) {
        throw new Error('Target is already open with different analysis settings; close it before requesting fresh or another profile');
      }
      return { ...existing.info, alreadyOpen: true };
    }
    if (existing) this.killSession(key);

    const p = (async () => {
      const session = await this.admitSession(key, target, engine, options);
      const proc = session.proc;

      const onLine = (obj) => {
        if (obj.ig5 === 'ready') {
          if (session.guestProfile) {
            const location = obj.executionLocation, snapshot = session.guestProfile;
            if (location?.kind !== 'vmci-guest' || location.profileSha256 !== snapshot.sha256
                || location.guestCID !== snapshot.profile.guestCID || location.bundleSha256 !== snapshot.profile.bundleSha256)
              throw new Error('Guest worker startup identity differs from the selected profile');
            session.remoteLease = this.remoteStore().bind(session.remoteLease, { guestCID: location.guestCID,
              bundleSha256: location.bundleSha256, serverInstanceId: location.serverInstanceId, sessionId: location.sessionId });
            session.executionLocation = location;
          } else if (obj.executionLocation) throw new Error('Local debugger unexpectedly reported a remote execution destination');
          session.ready = true;
          session.capabilities = obj.capabilities || null;
          return;
        }
        if (obj.ig5 === 'progress') {
          session.progress = obj.payload;
          session.lastStage = obj.payload?.stage ?? session.lastStage;
          const pend = obj.id !== undefined ? session.pending.get(obj.id) : undefined;
          try {
            pend?.onProgress?.(obj.payload);
          } catch {
            // a progress listener must never break the stdout pump
          }
          return;
        }
        if (obj.id !== undefined && session.pending.has(obj.id)) {
          const pend = session.pending.get(obj.id);
          if (session.remoteLease) {
            if (!obj.error || obj.error.authenticatedGuestResponse === true) this.acceptRemoteResult(session, pend.method, obj.error || obj.result);
            else if (obj.error.code === 'ETRANSPORT') {
              // Reject below, then recycle the local bridge while keeping remote custody.
              this.retainRemoteExecution(session, 'transport-lost');
            }
          }
          session.pending.delete(obj.id);
          clearTimeout(pend.timer);
          pend.removeAbort?.();
          if (obj.error) {
            if (this.isMutation(pend.method, pend.params)) {
              try { this.invalidate(session, `${pend.method}: failed or partial attempt`); }
              catch (error) {
                // 保留 worker 的原始回执（committed/partial_commit/recoveryRequired/journalId/revision…），元数据失败另附。
                const failure = this.rpcError(obj.error);
                failure.message = `Engine operation failed and revision metadata is unavailable; session recycled: ${publicEngineError(error, this.cfg)} | original: ${failure.message}`;
                failure.metadataFailure = { code: error?.code ?? 'UNKNOWN', message: publicEngineError(error, this.cfg) };
                pend.reject(failure);
                this.killSession(key); return;
              }
            }
            pend.reject(this.rpcError(obj.error));
            if (session.remoteLease && obj.error.code === 'ETRANSPORT') this.killSession(key);
          }
          else {
            // A false result can follow a partial write. It is never evidence of a rollback.
            if (this.isMutation(pend.method, pend.params)) {
              try { this.invalidate(session, pend.method); }
              catch (error) {
                const failure = new Error(`Engine operation completed but revision metadata could not be committed; inspect the saved database before retrying. Session recycled: ${publicEngineError(error, this.cfg)}`);
                this.copyReceipt(failure, obj.result);
                failure.code = failure.code ?? 'REVISION_COMMIT_FAILED';
                failure.operationCompleted = true;
                failure.operationResult = obj.result;
                failure.metadataFailure = { code: error?.code ?? 'UNKNOWN', message: publicEngineError(error, this.cfg) };
                pend.reject(failure);
                this.killSession(key); return;
              }
            }
            if (pend.method === 'analyze' && session.info && obj.result && typeof obj.result === 'object') {
              for (const field of ['partial', 'analysisComplete', 'analysisProfile', 'skippedAnalyzers', 'n_funcs']) {
                if (Object.hasOwn(obj.result, field)) session.info[field] = obj.result[field];
              }
            }
            const result = obj.result && typeof obj.result === 'object' && !Array.isArray(obj.result) && session.attachmentId
              ? { ...obj.result, _ig5: this.evidence(session) } : obj.result;
            if (pend.cancelled && result && typeof result === 'object') result.cancellationRequested = true;
            pend.resolve(result);
          }
        }
      };
      session.client = attachWorker(proc, {
        session, onMessage: onLine, formatError: error => this.rpcError(error),
        timers: { setTimeout, clearTimeout },
        onExit: () => {
          // Includes pipe/protocol failures as well as actual exit; never leave an untracked worker alive.
          if (!proc.__ig5TransportTerminated) terminateTree(proc);
          if (session.remoteLease && this.retainRemoteExecution(session)) return;
          this.releaseAttachmentAfterExit(session);
          const current = this.sessions.get(key);
          if (current === session) this.sessions.delete(key);
          if (session.engine === 'x64dbg' && (!current || current === session)) this.debugOwners.delete(path.resolve(session.target).toLowerCase());
          session.runtime = null; session.controlOwner = null;
        },
      });
      try { await session.client.waitReady(60_000); }
      catch (error) { this.killSession(key); throw error; }

      session.lastOp = 'open';
      session.progress = null;
      try { session.info = await this.rpc(
        session,
        'open',
        { path: session.target, auto: !!autoAnalysis, fresh, progress: true, database_key: `${engine === 'reverse' && this.cfg.reverseProvider === 'bundled' ? 'reverse-' : ''}${session.projectId}-${session.artifactId}`,
          ...(options.analysisTimeout !== undefined ? { timeout: options.analysisTimeout } : {}),
          ...(options.analysisProfile !== undefined ? { analysis_profile: options.analysisProfile } : {}) },
        this.cfg.openTimeoutMs,
        onProgress,
      ); } catch (error) { this.killSession(key); throw error; }
      let attachment;
      try { attachment = this.projects.attachEngine({ projectId: session.projectId, artifactId: session.artifactId,
        engine, sessionId: `${process.pid}-${proc.pid}-${session.startedAt}`, workerPid: proc.pid,
        databasePath: session.info?.databasePath || session.info?.idb_path });
      } catch (error) { this.killSession(key); throw error; }
      session.attachmentId = attachment.attachmentId;
      session.dbRevision = attachment.dbRevision;
      try { if (session.remoteLease) session.remoteLease = this.remoteStore().attach(session.remoteLease, attachment); }
      catch (error) { this.killSession(key); throw error; }
      session.info = { ...session.info, backendEngine: session.info?.engine, ...this.evidence(session), target: session.target, engine };
      session.state = 'open';
      session.lastOp = 'idle';
      session.lastStage = null;
      if (engine === 'reverse' && this.cfg.reverseProvider === 'bundled') Object.assign(this.cfg.reverseRuntime, {
        readiness: 'verified', runtimeReady: true, startupVerified: true, verifiedBy: 'open',
        reason: '五代内置 Reverse 核心已启动并打开分析数据库。',
      });
      return { ...session.info, alreadyOpen: false };
    })();

    this.launching.set(key, p);
    try {
      return await p;
    } finally {
      this.launching.delete(key);
    }
  }

  rpc(session, method, params, timeoutMs = this.cfg.requestTimeoutMs, onProgress = null) {
    if (session?.state === 'opening' && method !== 'open') {
      return Promise.resolve(this.launching.get(session.key)).then(() => {
        if (session.state !== 'open' || this.sessions.get(session.key) !== session) throw new Error('Target did not finish opening');
        return this.rpc(session, method, params, timeoutMs, onProgress);
      });
    }
    if (method === 'dbg-native') method = 'dbg';
    else if (method === 'dbg' && session?.engine !== 'x64dbg') return this.debug(session, params, timeoutMs);
    if (!this.alive(session)) throw new Error(publicEngineError(`worker 不在运行（目标：${session?.target ?? '?'}），请先 ig5_open`, this.cfg));
    if (Array.isArray(session.capabilities) && !session.capabilities.includes(method)) {
      throw Object.assign(new Error(`${session.engine} does not support ${method}; select an engine that advertises this capability`), { code: 'UNSUPPORTED_CAPABILITY', phase: 'provider-admission', retryable: false });
    }
    if (session.pending.size >= 64) throw new Error('Worker queue is full; wait for current operations to finish');
    this.checkCancelled();
    const signal = this.scope.getStore()?.signal;
    const client = session.client || attachWorker(session.proc, { session, formatError: error => this.rpcError(error) });
    return client.request(session, method, params, {
      timeoutMs, signal, onProgress, mutation: this.isMutation(method, params),
      onTimeout: () => this.killSession(session.key),
    }).catch((error) => { throw this.rpcError(error); });
  }

  rpcError(value) {
    const error = new Error(publicEngineError(value, this.cfg).split('\n').slice(-3).join(' | '));
    this.copyReceipt(error, value);
    return error;
  }

  /** 把 worker 回执（committed/partial_commit/journalId/revision 等）复制到 error 上；不覆盖已有字段。 */
  copyReceipt(error, value) {
    if (value && typeof value === 'object') for (const field of ['metadataFailure', 'operationCompleted', 'operationResult', 'code', 'committed', 'saved', 'partial_commit', 'recoveryRequired', 'stage', 'journalId', 'revision', 'durableRevision', 'cleanedUp', 'state', 'stateCode', 'runId', 'stopSeq', 'cancelledBeforeExecution', 'transactionRolledBack', 'stdout', 'stderr', 'compatibility', 'exceptionType', 'budget', 'source', 'compatibilityWrites', 'limitations', 'target_executed', 'executionLocation', 'authenticatedGuestResponse', 'guestCleanupConfirmed', 'cleanupConfirmed', 'analysisFailure', 'runtimePolicyBlock', 'policyStateError', 'nativeLaunchAttempted', 'nativeTargetExecuted', 'metadataPublished', 'metadataStage', 'metadataCleanupConfirmed', 'metadataCleanupError']) {
      if (value[field] !== undefined && error[field] === undefined) error[field] = value[field];
    }
    return error;
  }

  evidence(session) {
    return { target: session.target, engine: session.engine, projectId: session.projectId, artifactId: session.artifactId,
      provider: session.engine === 'reverse' ? this.cfg.reverseProvider === 'bundled' ? 'ghidra' : 'commercial' : session.engine,
      sha256: session.sha256, dbRevision: session.dbRevision, attachmentId: session.attachmentId };
  }

  isMutation(method, params) {
    return ['rename', 'patch', 'comment', 'analyze', 'set_type', 'idapython'].includes(method)
      || method === 'undo' && params?.action !== 'list'
      || method === 'struct' && !['get', 'list'].includes(params?.action)
      || method === 'switch_repair' && params?.apply === true;
  }

  invalidate(session, reason) {
    session.cache.clear();
    if (session.attachmentId) {
      const next = this.projects.bumpRevision(session.attachmentId, { reason });
      session.dbRevision = next.dbRevision;
    } else session.dbRevision++;
    if (session.info) session.info.dbRevision = session.dbRevision;
  }

  async debug(session, params, timeoutMs) {
    if (!this.alive(session)) throw new Error('Target is not open; call ig5_open first');
    const key = path.resolve(session.target).toLowerCase();
    const run = () => { this.checkCancelled(); return this.performDebug(session, params, timeoutMs); };
    // Control requests must reach the adapter while a run is waiting for an event.
    if (['suspend', 'stop'].includes(params.op)) return run();
    const queued = Promise.resolve(this.debugQueues.get(key)).catch(() => {}).then(run);
    this.debugQueues.set(key, queued);
    try { return await queued; }
    finally { if (this.debugQueues.get(key) === queued) this.debugQueues.delete(key); }
  }

  async performDebug(session, params, timeoutMs) {
    if (!this.alive(session)) throw new Error('Target is not open; call ig5_open first');
    const targetKey = path.resolve(session.target).toLowerCase();
    const previous = this.sessions.get(this.sessionKey(session.target, 'x64dbg'));
    let guestProfile;
    if (params.guest_profile !== undefined || params.guest_binding_sha256 !== undefined) {
      if (params.backend !== 'x64dbg' || typeof params.guest_profile !== 'string' || !/^[a-f0-9]{64}$/.test(params.guest_binding_sha256 || ''))
        throw new Error('Guest debugging requires explicit backend=x64dbg, guest_profile and inspected guest_binding_sha256');
      if (previous?.guestProfile) {
        guestProfile = previous.guestProfile;
        if (guestProfile.name !== params.guest_profile || guestProfile.sha256 !== params.guest_binding_sha256)
          throw new Error('Guest binding differs from the existing debugger; close it before switching profiles');
      } else guestProfile = loadGuestProfile(this.cfg, params.guest_profile, params.guest_binding_sha256);
    } else if (previous?.guestProfile) throw new Error('Every guest debugger call requires its explicit guest_profile and guest_binding_sha256');
    if (!guestProfile && this.remoteExecutionStatus().some(row => row.targetSha256 === session.sha256))
      throw new Error('This artifact has retained guest execution; close or recover that guest session before local execution');
    const owner = this.debugOwners.get(targetKey);
    const backend = params.backend && params.backend !== 'auto' ? params.backend : owner === 'reverse' ? 'auto' : owner || this.cfg.defaultDebugger;
    if (owner && backend !== owner && !(owner === 'reverse' && ['auto', 'bochs', 'win32'].includes(backend))) {
      throw new Error(`Target already has a ${owner} debug session; stop it before switching debugger`);
    }
    const debuggerEngine = backend === 'x64dbg' ? 'x64dbg' : 'reverse';
    if (params.op === 'apitrace' && debuggerEngine !== 'x64dbg') throw new Error('API tracing requires backend=x64dbg');
    if (params.record_trace && debuggerEngine !== 'x64dbg') throw new Error('Recorded traces require backend=x64dbg');
    if (params.record_image && (!params.record_trace || debuggerEngine !== 'x64dbg')) throw new Error('record_image requires an approved native recorded trace');
    if (params.record_events && (!params.record_trace || debuggerEngine !== 'x64dbg')) throw new Error('record_events requires an approved native recorded trace');
    if (params.interrupt_method && debuggerEngine !== 'x64dbg') throw new Error('interrupt_method requires backend=x64dbg');
    if (params.thread_id !== undefined && debuggerEngine !== 'x64dbg') throw new Error('thread_id requires backend=x64dbg');
    if (params.anti_debug_profile && params.anti_debug_profile !== 'none' && debuggerEngine !== 'x64dbg') throw new Error('anti_debug_profile requires backend=x64dbg');
    if (params.exception_disposition && params.exception_disposition !== 'preserve' && debuggerEngine !== 'x64dbg') throw new Error('exception_disposition requires backend=x64dbg');
    if (debuggerEngine !== 'x64dbg' && (['threads', 'callstack'].includes(params.op)
        || ['bpt', 'unbpt'].includes(params.op) && params.kind === 'hardware')) {
      throw Object.assign(new Error('Threads, callstack and hardware breakpoints require backend=x64dbg; this Reverse debugger does not advertise them'), { code: 'unsupported' });
    }
    if (['load', 'start'].includes(params.op)) {
      const executedPath = params.path || session.target;
      if (createHash('sha256').update(fs.readFileSync(executedPath)).digest('hex') !== session.sha256) {
        throw new Error('Debug target differs from the opened artifact; open that target explicitly before execution');
      }
    }
    if (debuggerEngine === 'x64dbg' && params.addressSpace === 'database' && params.ea) {
      const value = BigInt(params.ea);
      if (!session.info?.imageBase || !session.info.segments?.some((s) => value >= BigInt(s.start) && value < BigInt(s.end))) throw new Error('Database address is outside the selected loaded image');
      params = { ...params, rva: '0x' + (value - BigInt(session.info.imageBase)).toString(16), addressSpace: 'runtime' };
    }
    if (params.op === 'bpt' && (params.kind || 'software') === 'software' && session?.engine === 'ghidra' && session?.info?.imageBase) {
      let staticEa = null;
      try {
        const imgBase = BigInt(session.info.imageBase);
        if (params.rva) staticEa = imgBase + BigInt(params.rva);
        else if (params.ea && params.addressSpace === 'rva') staticEa = imgBase + BigInt(params.ea);
        else if (params.ea && params.addressSpace === 'database') staticEa = BigInt(params.ea);
      } catch { staticEa = null; }
      if (staticEa !== null) {
        const dis = await this.rpc(session, 'disasm', { ea: '0x' + staticEa.toString(16), limit: 4, size: 32 }).catch(() => null);
        if (dis && dis.isInstructionBoundary === false && dis.containingInstruction) {
          const ci = dis.containingInstruction;
          const nearby = (dis.rows || []).map(r => `${r.rva || r.ea} (${r.text})`).join(', ');
          throw Object.assign(
            new Error(`MID_INSTRUCTION_BREAKPOINT: Software breakpoint at ${params.rva || params.ea} lands inside multi-byte instruction at ${ci.ea} (RVA ${ci.rva}: "${ci.text}", ${ci.size} bytes). Setting INT3 (0xCC) mid-instruction corrupts instruction operands/registers. Use an exact instruction boundary RVA such as: ${nearby}`),
            { code: 'MID_INSTRUCTION_BREAKPOINT' },
          );
        }
      }
    }
    let debugSession = session;
    if (debuggerEngine === 'x64dbg') {
      await this.open(session.target, false, { engine: 'x64dbg', internal: true, guestProfile });
      debugSession = this.sessions.get(this.sessionKey(session.target, 'x64dbg'));
    } else if (session.engine !== 'reverse' || this.cfg.reverseProvider === 'bundled') {
      throw new Error('This debugger requires the optional commercial provider; select backend=x64dbg for the bundled core');
    }
    const caller = this.scope.getStore()?.agentId || 'local';
    const readOnly = ['regs', 'readmem', 'state', 'event', 'modules', 'threads', 'callstack'].includes(params.op);
    if (!readOnly && debugSession.controlOwner && debugSession.controlOwner !== caller && params.control !== 'takeover') {
      throw new Error('Debugger is controlled by another agent; explicitly request approved control=takeover before changing its state');
    }
    if (params.expected_stop_seq !== undefined && debugSession.runtime?.stopSeq !== params.expected_stop_seq) {
      throw new Error('Debugger pause changed; refresh the current stop context before execution');
    }
    if (params.expected_run_id !== undefined && debugSession.runtime?.runId !== params.expected_run_id) throw new Error('Debugger run changed');
    if (debugSession.remoteLease) {
      // Persist before sending even load: it launches an owned native debugger.
      debugSession.remoteLease = this.remoteStore().arm(debugSession.remoteLease);
      this.debugOwners.set(targetKey, 'x64dbg');
    }
    if (!readOnly) debugSession.controlOwner = caller;
    if (['load', 'start'].includes(params.op)) this.debugOwners.set(targetKey, debuggerEngine);
    if (['cont', 'step', 'stepover', 'trace', 'apitrace'].includes(params.op)) {
      debugSession.runtime = { ...debugSession.runtime, state: 'running', regs: undefined, operation: params.op };
    }
    // The lower RPC must bypass routing only for the Reverse implementation.
    let result;
    try {
      result = debuggerEngine === 'x64dbg'
        ? await this.rpc(debugSession, 'dbg', { ...params, backend }, timeoutMs)
        : await this.rawDebug(session, { ...params, backend }, timeoutMs);
    } catch (error) {
      if (debugSession.remoteLease) {
        if (!this.alive(debugSession) || error.code === 'ETRANSPORT') this.killSession(debugSession.key);
      } else if (error.cleanedUp || !this.alive(debugSession)) {
        this.debugOwners.delete(targetKey);
        debugSession.controlOwner = null;
        debugSession.runtime = { state: 'no-task', stateCode: -1, cleanedUp: true, runId: error.runId, stopSeq: error.stopSeq };
      }
      throw error;
    }
    if (params.record_trace && result?.recording) {
      try { result = await saveDebugTrace(this.cfg, session, result, params); }
      catch (error) { result = { ...result, traceSaved: false, traceArtifactError: error.message, executionAlreadyAttempted: true }; }
    }
    if (params.op === 'apitrace' && result?.schema === 'ig5.apiTrace.v1' && result?.ok === true) {
      try { result = await saveApiTrace(this.cfg, session, result, params); }
      catch (error) { result = { ...result, apiTraceSaved: false, apiTraceArtifactError: error.message, executionAlreadyAttempted: true }; }
    }
    if (result?.ok !== false && ['load', 'start'].includes(params.op)) this.debugOwners.set(targetKey, debuggerEngine);
    if (!debugSession.remoteLease && params.op === 'stop' && result?.ok !== false) this.debugOwners.delete(targetKey);
    if (result?.cacheInvalidated || result?.historyGap) debugSession.runtime = null;
    if (result?.context || result?.runId || result?.state) debugSession.runtime = { ...debugSession.runtime, ...result };
    if (result?.state === 'no-task') { if (!debugSession.remoteLease) this.debugOwners.delete(targetKey); debugSession.controlOwner = null; }
    if (!readOnly && result?.ok !== false) debugSession.controlOwner = params.op === 'stop' || params.control === 'release' || result?.state === 'no-task' ? null : caller;
    return { ...result, engine: debuggerEngine, projectId: session.projectId, artifactId: session.artifactId };
  }

  async rawDebug(session, params, timeoutMs) {
    const result = await this.rpc(session, 'dbg-native', params, timeoutMs);
    if (['start', 'regs', 'stop'].includes(params.op)) {
      const info = await this.rpc(session, 'stats', {});
      if (info.imageBase && info.imageBase !== session.info.imageBase) this.invalidate(session, 'debugger database rebase');
      session.info = { ...session.info, ...info, ...this.evidence(session) };
    }
    return result;
  }

  async doctor(engine = this.scope.getStore()?.engine || this.cfg.defaultEngine) {
    engine = engineId(engine);
    if (engine === 'reverse' && !this.cfg.reverseAvailable) {
      const runtime = this.cfg.reverseRuntime;
      throw Object.assign(new Error(runtime?.reason || 'Reverse 本机运行环境不可用；可选择 engine=ghidra。'), { code: runtime?.code || 'REVERSE_UNAVAILABLE' });
    }
    let child;
    try {
      child = this.spawnWorker(engine);
      const result = await doctorWorker(child, { formatError: error => this.rpcError(error) });
      if (engine === 'x64dbg' && result?.engine === 'x64dbg' && result.ok === false && result.launchVerified === false
        && result.targetExecuted === false && Object.values(result.launchReadiness || {}).some(row => row?.nativeLaunchAttempted === false
          && ['blocked-by-application-control', 'unknown-policy-state'].includes(row.state)))
        return { ...result, runtimeReady: false, startupVerified: false, nativeTargetExecuted: false, scope: 'metadata-and-recorded-launch-blocks-only' };
      if (result?.ok !== true && !(engine === 'reverse' && this.cfg.reverseProvider !== 'bundled' && result?.idalib === 'loaded')) throw new Error('Analysis core did not confirm a successful startup');
      if (engine === 'x64dbg') return { ...result, provider: engine, engine, runtimeReady: false, startupVerified: false,
        nativeTargetExecuted: false, scope: 'metadata-only-native-launch-not-probed' };
      if (engine === 'reverse' && this.cfg.reverseProvider !== 'bundled') {
        if (result?.idalib !== 'loaded') throw new Error('Reverse 原生内核没有确认启动完成。');
        if (this.cfg.reverseRuntime) Object.assign(this.cfg.reverseRuntime, { readiness: 'verified', runtimeReady: true, startupVerified: true,
          reason: 'Reverse 原生启动检查通过；具体目标架构的反编译能力仍需打开样本验证。' });
        return { ok: true, engine: 'Reverse', python: result?.python, startupVerified: true,
          runtimeReady: result?.idalib === 'loaded', caps: {
            planAndWait: result?.caps?.['ida_auto.plan_and_wait'] === true,
            wait: result?.caps?.['ida_auto.auto_wait'] === true,
            makeCode: result?.caps?.['ida_auto.auto_make_code'] === true } };
      }
      if (engine === 'reverse') Object.assign(this.cfg.reverseRuntime, { readiness: 'verified', runtimeReady: true, startupVerified: true, verifiedBy: 'doctor',
        reason: '五代内置 Reverse 核心启动检查通过。' });
      return { ...result, provider: engine === 'reverse' ? this.cfg.reverseProvider === 'bundled' ? 'ghidra' : 'commercial' : engine,
        engine, runtimeReady: true, startupVerified: true };
    } catch (error) {
      if (engine === 'reverse' && this.cfg.reverseRuntime) Object.assign(this.cfg.reverseRuntime, { readiness: 'startup-failed', runtimeReady: false,
        startupVerified: false, reason: 'Reverse 原生启动检查失败：' + publicEngineError(error, this.cfg) });
      throw error;
    } finally { terminateTree(child); }
  }

  engines() {
    return [{ id: 'reverse', label: this.cfg.reverseProvider === 'bundled' ? 'Reverse · 内置' : 'Reverse · 本机扩展', available: this.cfg.reverseAvailable, default: this.cfg.defaultEngine === 'reverse',
      provider: this.cfg.reverseProvider === 'bundled' ? 'ghidra' : 'commercial', portable: this.cfg.reverseProvider === 'bundled' && this.cfg.ghidra?.portable,
      source: this.cfg.reverseRuntime?.source || 'local-installation', distribution: this.cfg.reverseProvider === 'bundled' ? 'bundled' : 'local-installation',
      readiness: this.cfg.reverseRuntime?.readiness || 'detected', runtimeReady: this.cfg.reverseRuntime?.runtimeReady ?? null,
      startupVerified: this.cfg.reverseRuntime?.startupVerified === true, validation: this.cfg.reverseRuntime?.validation || 'files-only',
      reason: this.cfg.reverseRuntime?.reason, code: this.cfg.reverseRuntime?.code, discoveryPartial: this.cfg.reverseRuntime?.discoveryPartial === true },
      ...['ghidra', 'x64dbg'].map((id) => ({ id, label: id === 'ghidra' ? 'Ghidra' : 'x64dbg',
        available: !!this.cfg[id]?.available, platform: this.cfg[id]?.platform, mode: this.cfg[id]?.mode || 'headless',
        default: this.cfg.defaultEngine === id, source: this.cfg[id]?.source, portable: this.cfg[id]?.portable,
        reason: this.cfg[id]?.reason }))];
  }

  async closeOldest() {
    let oldest = null;
    for (const s of this.sessions.values()) {
      if (s.engine === 'x64dbg' || this.debugOwners.has(path.resolve(s.target).toLowerCase())) continue;
      if (!s.info || s.pending.size || s.queuedOperations || s.closing) continue;
      if (!oldest || s.startedAt < oldest.startedAt) oldest = s;
    }
    if (!oldest) throw new Error('All static sessions are busy; close a target or wait before opening another');
    await this.close(oldest.target, true, oldest.engine);
  }

  releaseAttachmentAfterExit(session) {
    if (session.remoteLease && this.remoteStore().current(session.remoteLease.key)?.state !== 'cleaned') return;
    if (!session.attachmentId || session.attachmentReleased || session.attachmentExitWait) return;
    const release = () => {
      session.attachmentExitWait = false;
      if (session.attachmentReleased) return;
      try { this.projects.closeAttachment(session.attachmentId); session.attachmentReleased = true; }
      catch (error) { diagAppend(this.cfg, `host: attachment release deferred: ${publicEngineError(error, this.cfg)}`); }
    };
    // A kill request and a broken pipe do not prove that the database owner exited.
    if (session.databaseClosed || session.proc?.exitCode != null || session.proc?.signalCode != null) release();
    else if (typeof session.proc?.once === 'function') {
      session.attachmentExitWait = true;
      session.proc.once('exit', release);
    }
  }

  killSession(key) {
    const s = this.sessions.get(key);
    if (!s) return;
    for (const [, pend] of s.pending) {
      clearTimeout(pend.timer);
      pend.removeAbort?.();
      pend.reject(new Error('worker 已被关闭'));
    }
    s.pending.clear();
    s.client?.dispose();
    try {
      if (!s.proc.__ig5TransportTerminated) terminateTree(s.proc);
    } catch {
      // already dead
    }
    if (s.remoteLease) {
      try { if (this.retainRemoteExecution(s, 'shutdown')) return false; }
      catch (error) { s.ready = false; s.remoteLeaseError = publicEngineError(error, this.cfg); return false; }
    }
    this.sessions.delete(key);
    this.releaseAttachmentAfterExit(s);
    if (s.engine === 'x64dbg') this.debugOwners.delete(path.resolve(s.target).toLowerCase());
    s.runtime = null; s.controlOwner = null;
    return true;
  }

  async recoverGuest(target, params) {
    const snapshot = loadGuestProfile(this.cfg, params.guest_profile, params.guest_binding_sha256);
    const absolute = path.resolve(target), caller = this.scope.getStore()?.agentId || 'local';
    const matching = this.remoteStore().list().filter(row => row.state !== 'cleaned'
      && row.binding.guestCID === snapshot.profile.guestCID && path.resolve(row.binding.target).toLowerCase() === absolute.toLowerCase());
    if (matching.length !== 1) throw Object.assign(new Error(matching.length === 0
      ? 'No retained execution matches the original target path and guest. This does not confirm remote cleanup. Inspect ig5_status remoteExecutions and the original target/profile; do not restart, change bindings, or repeat this unchanged request to manufacture a receipt.'
      : 'Multiple retained executions match the original target path and guest. Cleanup ownership is ambiguous; inspect ig5_status remoteExecutions. No execution was released.'),
      { code: matching.length === 0 ? 'GUEST_RECOVERY_NOT_FOUND' : 'GUEST_RECOVERY_AMBIGUOUS' });
    const lease = matching[0];
    if (lease.binding.profileName !== snapshot.name || lease.binding.profileSha256 !== snapshot.sha256 || lease.binding.bundleSha256 !== snapshot.profile.bundleSha256
        || guestTarget(snapshot, lease.binding.targetSha256).id !== lease.binding.targetId)
      throw new Error('Recovery profile differs from the original immutable guest binding');
    if (lease.agentId !== caller && params.control !== 'takeover') throw new Error('Guest execution is controlled by another agent; recovery requires approved control=takeover');
    const key = this.sessionKey(absolute, 'x64dbg'), original = this.sessions.get(key);
    if (original && original.remoteLease?.nonce !== lease.nonce) throw new Error('Recovery cannot affect a different debugger generation');
    if (original) {
      this.killSession(key);
      const proc = original.proc;
      if (proc?.pid && proc.exitCode === null && proc.signalCode == null) {
        const exited = await new Promise(resolve => {
          const onExit = () => { clearTimeout(timer); resolve(true); };
          const timer = setTimeout(() => { proc.removeListener('exit', onExit); resolve(false); }, 5000);
          proc.once('exit', onExit);
        });
        if (!exited) throw new Error('Original bridge exit is unconfirmed; guest custody is retained');
      }
    }
    const proof = await recoverGuestExecution(this.cfg, HERE, snapshot, lease, { signal: this.scope.getStore()?.signal });
    const completed = this.remoteStore().complete(lease, proof);
    if (lease.attachment) {
      const projects = new ProjectStore({ root: lease.binding.projectRoot });
      const attachment = projects.getAttachment(lease.attachment.attachmentId);
      if (attachment.projectId !== lease.attachment.projectId || attachment.artifactId !== lease.attachment.artifactId || attachment.engine !== 'x64dbg')
        throw new Error('Original guest attachment identity differs; cleanup proof was saved but attachment requires inspection');
      projects.closeAttachment(attachment.attachmentId);
    }
    if (original && this.sessions.get(key) === original) { original.remoteLease = completed; this.sessions.delete(key); }
    if (!this.sessions.has(key)) this.debugOwners.delete(absolute.toLowerCase());
    return { ok: true, recovered: true, guestExecutionCleaned: true, target: absolute,
      guestCID: lease.binding.guestCID, originalSessionId: lease.remote.sessionId, cleanup: completed.cleanup, nativeTargetExecuted: false };
  }

  async close(target, save = false, engine, { force = false } = {}) {
    const key = this.sessionKey(target, engine);
    const s = this.sessions.get(key);
    if (!s) return false;
    const debugKey = this.sessionKey(target, 'x64dbg');
    const debug = this.sessions.get(debugKey) || (s.engine === 'reverse' && this.debugOwners.has(path.resolve(s.target).toLowerCase()) ? s : null);
    const caller = this.scope.getStore()?.agentId || 'local';
    if (!force && debug?.controlOwner && debug.controlOwner !== caller) throw new Error('Active debugger is controlled by another agent; stop it with an approved takeover before closing');
    if (s.closing) return s.closePromise;
    s.closing = true;
    s.closePromise = (async () => {
      try {
        await Promise.resolve(s.operationQueue).catch(() => {});
        if (debug && this.alive(debug) && this.debugOwners.has(path.resolve(s.target).toLowerCase())) {
          try { await this.performDebug(s, { op: 'stop', backend: debug.engine === 'x64dbg' ? 'x64dbg' : 'auto',
            ...(debug.guestProfile ? { guest_profile: debug.guestProfile.name, guest_binding_sha256: debug.guestProfile.sha256 } : {}),
            ...(force ? { control: 'takeover' } : {}) }, 10_000); }
          catch (error) { if (!force) throw error; diagAppend(this.cfg, `host: debugger stop during shutdown: ${publicEngineError(error, this.cfg)}`); }
        }
        if (debug?.remoteLease) {
          if (!this.alive(debug)) throw new Error('Guest bridge is disconnected; approved op=recover must confirm original cleanup before closing');
          const terminal = await this.rpc(debug, 'close', {}, 10_000);
          if (terminal?.ok === false || this.remoteStore().current(debug.remoteLease.key)?.state !== 'cleaned')
            throw new Error('Guest terminal cleanup is unconfirmed; custody is retained');
        }
        if (!s.remoteLease && this.alive(s) && s.lastOp !== 'open') {
          const result = await this.rpc(s, 'close', {}, 10_000);
          if (result?.ok === false) throw new Error('Engine refused to checkpoint and close; session was retained');
          s.databaseClosed = true;
        }
      } catch (error) {
        if (!force) { s.closing = false; throw error; }
        diagAppend(this.cfg, `host: forced shutdown after checkpoint failure: ${publicEngineError(error, this.cfg)}`);
      }
      const closed = this.killSession(key);
      const debugClosed = debugKey === key ? closed : this.killSession(debugKey);
      return closed !== false && debugClosed !== false;
    })();
    return s.closePromise;
  }

  status() {
    return [...this.sessions.values()].map((s) => ({
      target: s.target,
      key: s.key,
      ...this.evidence(s),
      capabilities: s.capabilities,
      ...(s.executionLocation ? { executionLocation: s.executionLocation, guestExecutionState: s.remoteLease?.state } : {}),
      runtime: s.runtime ? { state: s.runtime.state, runId: s.runtime.runId, stopSeq: s.runtime.stopSeq } : null,
      alive: this.alive(s),
      ready: s.ready,
      pid: s.proc?.pid ?? null,
      uptimeMs: Date.now() - s.startedAt,
      lastOp: s.lastOp,
      lastStage: s.lastStage ?? null,
      progress: s.progress ?? null,
      n_funcs: s.info?.n_funcs ?? null,
      bits: s.info?.bits ?? null,
      partial: s.info?.partial === true,
    }));
  }

  // ── 后台作业（M1-A）：工作台面板轮询 /ig5-jobs 读这份快照 ──────────────
  trackJob(jobId, target, label) {
    const rec = {
      id: String(jobId),
      target,
      label,
      state: 'running',
      stage: null,
      pct: 0,
      functions: null,
      detail: null,
      startedAt: Date.now(),
      endedAt: null,
    };
    this.jobs.set(rec.id, rec);
    this.trimJobs();
    return rec;
  }

  noteProgress(target, payload, jobId) {
    const resolved = path.resolve(String(target));
    for (const rec of this.jobs.values()) {
      if (rec.state !== 'running') continue;
      if (jobId && rec.id !== String(jobId)) continue;
      if (!jobId && path.resolve(rec.target) !== resolved) continue;
      rec.stage = payload?.stage ?? rec.stage;
      if (typeof payload?.pct === 'number') rec.pct = payload.pct;
      if (typeof payload?.functions === 'number') rec.functions = payload.functions;
      if (payload?.detail) rec.detail = String(payload.detail).slice(0, 120);
    }
  }

  finishJob(jobId, state, detail) {
    const rec = this.jobs.get(String(jobId));
    if (!rec) return;
    rec.state = state;
    rec.detail = detail ?? rec.detail;
    rec.endedAt = Date.now();
    if (state === 'completed') rec.pct = 100;
  }

  trimJobs() {
    const settled = [...this.jobs.values()].filter((r) => r.state !== 'running').sort((a, b) => (a.endedAt ?? 0) - (b.endedAt ?? 0));
    while (this.jobs.size > 12 && settled.length) {
      this.jobs.delete(settled.shift().id);
    }
  }

  snapshot() {
    return {
      implementation: { revision: IMPLEMENTATION_REVISION, loadedAt: IMPLEMENTATION_LOADED_AT },
      now: Date.now(),
      sessions: this.status(),
      jobs: [...this.jobs.values()].sort((a, b) => (b.startedAt ?? 0) - (a.startedAt ?? 0)),
      config: { host: this.cfg.host, runtimeSource: Object.fromEntries(['ghidra', 'x64dbg'].map(id => [id, this.cfg[id]?.source || null])), engine: this.cfg.defaultEngine, engines: this.engines(), maxSessions: this.cfg.maxSessions, openTimeoutMs: this.cfg.openTimeoutMs,
        ...(this.workflow?.snapshot() || { toolset: this.cfg.toolset }) },
    };
  }
}
