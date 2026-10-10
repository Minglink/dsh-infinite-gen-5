import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { installWorkflow } from './workflow.js';
import { defineAdvancedTools } from './advanced_tools.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { runtimeConfiguration, engineId, terminateTree } from './engine_runtime.js';
import { spawnWorker, attachWorker, doctorWorker } from './source/worker_transport.js';
import { ProjectStore } from './source/project_store.js';
import { defineIntegrationTools } from './integration_tools.js';
import { defineAnalysisTools } from './analysis_tools.js';
import { exportPatchDiff } from './source/patch_export.js';
import { readAuditPage, targetIdentity } from './source/audit_history.js';
import { jsonToolOutput } from './source/json_output.js';
import { resolveReverseRuntime } from './source/reverse_runtime.js';

// ── 无限五代（IG5）v1.0.0 ──────────────────────────────────────────────────
// DeepSeek Harness 逆向插件：隔离多引擎 Worker 池 + ig5_* 工具面 + ig5dash 投影。
// 零提示词注入；指导载体 = 工具描述 + 会话流卡片。

const PLUGIN_ID = 'dsh-infinite-gen-5';
const PLUGIN_VERSION = '1.0.0';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKER = path.join(HERE, 'worker', 'ig5_worker.py');

// ── Config（cordis.yml 插件行可覆盖；misconfiguration fails loud） ──────────
function resolveConfig(cfg = {}) {
  const runtime = runtimeConfiguration(cfg);
  const reverseRuntime = resolveReverseRuntime(cfg, { host: runtime.host });
  const { idaDir, pythonExe, available: reverseAvailable } = reverseRuntime;
  return {
    ...runtime,
    idaDir,
    reverseAvailable,
    reverseRuntime,
    pythonExe,
    defaultEngine: cfg.defaultEngine ? engineId(cfg.defaultEngine) : runtime.ghidra.available ? 'ghidra' : reverseAvailable ? 'reverse' : 'ghidra',
    defaultDebugger: cfg.defaultDebugger || (runtime.x64dbg.available ? 'x64dbg' : 'auto'),
    projectRoot: cfg.projectRoot || (cfg.artifactDir ? path.join(cfg.artifactDir, 'projects') : runtime.projectRoot),
    stateRoot: cfg.stateRoot || (cfg.artifactDir ? path.join(cfg.artifactDir, 'runtime-state') : path.join(runtime.home, 'state')),
    requestTimeoutMs: Number(cfg.requestTimeoutMs ?? 240_000),
    // 后台分析是长任务：单独一档超时，别让 240s 的短超时杀掉大二进制
    openTimeoutMs: Number(cfg.openTimeoutMs ?? 1_800_000),
    maxSessions: Number(cfg.maxSessions ?? 3),
    artifactDir: cfg.artifactDir || path.join(runtime.home, 'artifacts'),
    autoOpenHint: cfg.autoOpenHint !== false,
    backgroundOpen: cfg.backgroundOpen !== false,
    toolset: cfg.toolset || 'core',
  };
}

// Keep the failure reason while hiding runtime install paths and engine versions.
function publicEngineError(error, cfg) {
  let message = String(error?.message ?? error);
  for (const configuredPath of [cfg?.pythonExe, cfg?.idaDir]) {
    if (!configuredPath || !/[\\/]/.test(configuredPath)) continue;
    const variants = new Set([
      configuredPath,
      configuredPath.replace(/\\/g, '/'),
      configuredPath.replace(/\//g, '\\'),
      configuredPath.replace(/\\/g, '\\\\'),
    ]);
    for (const variant of variants) {
      const escaped = variant.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      message = message.replace(new RegExp(escaped, 'gi'), '[Reverse runtime]');
    }
  }
  return message
    .replace(/\b(?:IDA(?:\s+(?:Professional|Pro))?|idalib|idapro|Hex[- ]?Rays)(?:\s+(?:SDK|Decompiler))?\s*(?:v(?:ersion)?[ .:=]*)?(?:\d+(?:\.[\dx]+)*(?:[a-z][\w.-]*)?|\(\s*\d+\s*(?:,\s*\d+\s*)+\))/gi, 'Reverse')
    .replace(/\b(?:IDA(?:\s+(?:Professional|Pro))?|idalib|idapro|Hex[- ]?Rays)\b/gi, 'Reverse');
}

// ── Worker 池（小样：1 目标 = 1 Python 进程，JSON-RPC over stdio） ──────────
class WorkerManager {
  constructor(cfg) {
    this.cfg = cfg;
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
    this.attachmentRecovery = this.projects.recoverAttachments();
  }

  sessionKey(target, engine = this.scope.getStore()?.engine || this.cfg.defaultEngine || 'reverse') {
    const absolute = path.resolve(String(target));
    const base = (this.cfg.host?.platform || process.platform) === 'win32' ? absolute.toLowerCase() : absolute;
    return engine === 'reverse' ? base : `${base}::${engineId(engine)}`;
  }

  get(target, engine) {
    return this.sessions.get(this.sessionKey(target, engine));
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

  async admitSession(key, target, engine) {
    const pending = this.admissions.catch(() => {}).then(async () => {
      this.checkCancelled();
      if (engine !== 'x64dbg' && [...this.sessions.values()].filter((s) => s.engine !== 'x64dbg').length >= this.cfg.maxSessions) await this.closeOldest();
      const session = { key, engine, target: path.resolve(String(target)), proc: null, ready: false,
        pending: new Map(), seq: 0, startedAt: Date.now(), info: null, lastOp: 'launching', lastStage: null,
        progress: null, stderrTail: '', cache: new Map(), dbRevision: 0, queuedOperations: 0, state: 'opening' };
      const identity = this.projects.open(session.target);
      Object.assign(session, { projectId: identity.projectId, artifactId: identity.artifactId, sha256: identity.sha256 });
      if (engine === 'ghidra' && [...this.sessions.values()].some((s) => s.engine === engine && s.artifactId === identity.artifactId)) {
        throw new Error('This artifact already has an active Ghidra database at another path; close that session before reopening its moved alias');
      }
      const proc = this.spawnWorker(engine);
      session.proc = proc; proc.__ig5 = session;
      this.sessions.set(key, session);
      return session;
    });
    this.admissions = pending.catch(() => {});
    return pending;
  }

  spawnWorker(engine = this.scope.getStore()?.engine || this.cfg.defaultEngine || 'reverse') {
    return spawnWorker(this.cfg, engineId(engine), HERE, {
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
    if (this.alive(existing)) {
      if (fresh || options.analysisProfile && existing.info?.analysisProfile !== options.analysisProfile) {
        throw new Error('Target is already open with different analysis settings; close it before requesting fresh or another profile');
      }
      return { ...existing.info, alreadyOpen: true };
    }
    if (existing) this.killSession(key);

    const p = (async () => {
      const session = await this.admitSession(key, target, engine);
      const proc = session.proc;

      const onLine = (obj) => {
        if (obj.ig5 === 'ready') {
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
          session.pending.delete(obj.id);
          clearTimeout(pend.timer);
          pend.removeAbort?.();
          if (obj.error) {
            if (this.isMutation(pend.method, pend.params)) {
              try { this.invalidate(session, `${pend.method}: failed or partial attempt`); }
              catch (error) {
                pend.reject(new Error(`Engine operation failed and revision metadata is unavailable; session recycled: ${publicEngineError(error, this.cfg)}`));
                this.killSession(key); return;
              }
            }
            pend.reject(this.rpcError(obj.error));
          }
          else {
            // A false result can follow a partial write. It is never evidence of a rollback.
            if (this.isMutation(pend.method, pend.params)) {
              try { this.invalidate(session, pend.method); }
              catch (error) {
                pend.reject(new Error(`Engine operation completed but revision metadata could not be committed; inspect the saved database before retrying. Session recycled: ${publicEngineError(error, this.cfg)}`));
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
          this.releaseAttachmentAfterExit(session);
          if (this.sessions.get(key) === session) this.sessions.delete(key);
          if (session.engine === 'x64dbg') this.debugOwners.delete(path.resolve(session.target).toLowerCase());
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
        { path: session.target, auto: !!autoAnalysis, fresh, progress: true, database_key: `${session.projectId}-${session.artifactId}`,
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
      session.info = { ...session.info, ...this.evidence(session), target: session.target, engine };
      session.state = 'open';
      session.lastOp = 'idle';
      session.lastStage = null;
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
      throw new Error(`${session.engine} does not support ${method}; select an engine that advertises this capability`);
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
    for (const field of ['code', 'committed', 'saved', 'partial_commit', 'recoveryRequired', 'stage', 'journalId', 'revision', 'durableRevision', 'cleanedUp', 'state', 'stateCode', 'runId', 'stopSeq', 'cancelledBeforeExecution']) {
      if (value && typeof value === 'object' && value[field] !== undefined) error[field] = value[field];
    }
    return error;
  }

  evidence(session) {
    return { target: session.target, engine: session.engine, projectId: session.projectId, artifactId: session.artifactId,
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
    const owner = this.debugOwners.get(targetKey);
    const backend = params.backend && params.backend !== 'auto' ? params.backend : owner === 'reverse' ? 'auto' : owner || this.cfg.defaultDebugger;
    if (owner && backend !== owner && !(owner === 'reverse' && ['auto', 'bochs', 'win32'].includes(backend))) {
      throw new Error(`Target already has a ${owner} debug session; stop it before switching debugger`);
    }
    const debuggerEngine = backend === 'x64dbg' ? 'x64dbg' : 'reverse';
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
    let debugSession = session;
    if (debuggerEngine === 'x64dbg') {
      await this.open(session.target, false, { engine: 'x64dbg', internal: true });
      debugSession = this.sessions.get(this.sessionKey(session.target, 'x64dbg'));
    } else if (session.engine !== 'reverse') {
      throw new Error('This debugger requires a Reverse session; select backend=x64dbg for Ghidra targets');
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
    if (!readOnly) debugSession.controlOwner = caller;
    if (['load', 'start'].includes(params.op)) this.debugOwners.set(targetKey, debuggerEngine);
    if (['cont', 'step', 'stepover', 'trace'].includes(params.op)) {
      debugSession.runtime = { ...debugSession.runtime, state: 'running', regs: undefined, operation: params.op };
    }
    // The lower RPC must bypass routing only for the Reverse implementation.
    let result;
    try {
      result = debuggerEngine === 'x64dbg'
        ? await this.rpc(debugSession, 'dbg', { ...params, backend }, timeoutMs)
        : await this.rawDebug(session, { ...params, backend }, timeoutMs);
    } catch (error) {
      if (error.cleanedUp || !this.alive(debugSession)) {
        this.debugOwners.delete(targetKey);
        debugSession.controlOwner = null;
        debugSession.runtime = { state: 'no-task', stateCode: -1, cleanedUp: true, runId: error.runId, stopSeq: error.stopSeq };
      }
      throw error;
    }
    if (result?.ok !== false && ['load', 'start'].includes(params.op)) this.debugOwners.set(targetKey, debuggerEngine);
    if (params.op === 'stop' && result?.ok !== false) this.debugOwners.delete(targetKey);
    if (result?.cacheInvalidated || result?.historyGap) debugSession.runtime = null;
    if (result?.context || result?.runId || result?.state) debugSession.runtime = { ...debugSession.runtime, ...result };
    if (result?.state === 'no-task') { this.debugOwners.delete(targetKey); debugSession.controlOwner = null; }
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
      if (engine === 'reverse') {
        if (result?.idalib !== 'loaded') throw new Error('Reverse 原生内核没有确认启动完成。');
        if (this.cfg.reverseRuntime) Object.assign(this.cfg.reverseRuntime, { readiness: 'verified', runtimeReady: true, startupVerified: true,
          reason: 'Reverse 原生启动检查通过；具体目标架构的反编译能力仍需打开样本验证。' });
        return { ok: true, engine: 'Reverse', python: result?.python, startupVerified: true,
          runtimeReady: result?.idalib === 'loaded', caps: {
            planAndWait: result?.caps?.['ida_auto.plan_and_wait'] === true,
            wait: result?.caps?.['ida_auto.auto_wait'] === true,
            makeCode: result?.caps?.['ida_auto.auto_make_code'] === true } };
      }
      return { ...result, engine, runtimeReady: true };
    } catch (error) {
      if (engine === 'reverse' && this.cfg.reverseRuntime) Object.assign(this.cfg.reverseRuntime, { readiness: 'startup-failed', runtimeReady: false,
        startupVerified: false, reason: 'Reverse 原生启动检查失败：' + publicEngineError(error, this.cfg) });
      throw error;
    } finally { terminateTree(child); }
  }

  engines() {
    return [{ id: 'reverse', label: 'Reverse', available: this.cfg.reverseAvailable, default: this.cfg.defaultEngine === 'reverse',
      source: this.cfg.reverseRuntime?.source || 'local-installation', distribution: 'local-installation',
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
    this.sessions.delete(key);
    this.releaseAttachmentAfterExit(s);
    if (s.engine === 'x64dbg') this.debugOwners.delete(path.resolve(s.target).toLowerCase());
    s.runtime = null; s.controlOwner = null;
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
          try { await this.performDebug(s, { op: 'stop', backend: debug.engine === 'x64dbg' ? 'x64dbg' : 'auto', ...(force ? { control: 'takeover' } : {}) }, 10_000); }
          catch (error) { if (!force) throw error; diagAppend(this.cfg, `host: debugger stop during shutdown: ${publicEngineError(error, this.cfg)}`); }
        }
        if (this.alive(s) && s.lastOp !== 'open') {
          const result = await this.rpc(s, 'close', {}, 10_000);
          if (result?.ok === false) throw new Error('Engine refused to checkpoint and close; session was retained');
          s.databaseClosed = true;
        }
      } catch (error) {
        if (!force) { s.closing = false; throw error; }
        diagAppend(this.cfg, `host: forced shutdown after checkpoint failure: ${publicEngineError(error, this.cfg)}`);
      }
      this.killSession(key);
      if (debugKey !== key) this.killSession(debugKey);
      return true;
    })();
    return s.closePromise;
  }

  status() {
    return [...this.sessions.values()].map((s) => ({
      target: s.target,
      key: s.key,
      ...this.evidence(s),
      capabilities: s.capabilities,
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
      now: Date.now(),
      sessions: this.status(),
      jobs: [...this.jobs.values()].sort((a, b) => (b.startedAt ?? 0) - (a.startedAt ?? 0)),
      config: { host: this.cfg.host, runtimeSource: Object.fromEntries(['ghidra', 'x64dbg'].map(id => [id, this.cfg[id]?.source || null])), engine: this.cfg.defaultEngine, engines: this.engines(), maxSessions: this.cfg.maxSessions, openTimeoutMs: this.cfg.openTimeoutMs,
        ...(this.workflow?.snapshot() || { toolset: this.cfg.toolset }) },
    };
  }
}

// ── 诊断回路：client POST /ig5-diag → 落盘 artifacts/ig5-diag.log ───────────
function installDiagRoute(ctx, cfg) {
  ctx.inject(['webServer'], (subCtx) => {
    let ws = null;
    try {
      ws = subCtx.webServer ?? (typeof subCtx.get === 'function' ? subCtx.get('webServer') : undefined);
    } catch {
      ws = undefined;
    }
    if (!ws || typeof ws.register !== 'function') {
      diagAppend(cfg, 'host: webServer 不可用（诊断回路未挂载）');
      return;
    }
    try {
      const dispose = ws.register({
        kind: 'prefix',
        path: '/ig5-diag',
        handler: (req, res) => {
          const isPost = req.method === 'POST';
          const isPoll = !isPost && /poll=1/.test(String(req.url || ''));
          if (req.method !== 'POST' && req.method !== 'GET') {
            res.writeHead(405);
            res.end();
            return;
          }
          if (isPoll) {
            // 命令通道：读 ig5-cmd.json（一次性），返回后删除
            const cmdFile = path.join(cfg.artifactDir, 'ig5-cmd.json');
            let payload = 'ok';
            try {
              if (fs.existsSync(cmdFile)) {
                payload = fs.readFileSync(cmdFile, 'utf8');
                fs.unlinkSync(cmdFile);
              }
            } catch {
              payload = 'ok';
            }
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(payload);
            return;
          }
          const chunks = [];
          req.on('data', (c) => {
            if (chunks.length < 64) chunks.push(c);
          });
          req.on('end', () => {
            try {
              const body = Buffer.concat(chunks).toString('utf8').slice(0, 200_000);
              diagAppend(cfg, `[client ${req.method}] ${body || '(empty)'}`);
            } catch {
              diagAppend(cfg, 'host: diag body 读取失败');
            }
            res.writeHead(200, { 'content-type': 'text/plain' });
            res.end('ok');
          });
          req.on('error', () => {
            try { res.end(); } catch { /* already gone */ }
          });
        },
      });
      diagAppend(cfg, 'host: /ig5-diag 路由已挂载');
      return () => {
        try {
          if (typeof dispose === 'function') dispose();
        } catch {
          // route already gone
        }
      };
    } catch (e) {
      diagAppend(cfg, `host: 挂载失败 ${e && e.message}`);
    }
  });
}

function diagAppend(cfg, line) {
  try {
    fs.mkdirSync(cfg.artifactDir, { recursive: true });
    const stamp = new Date().toISOString();
    fs.appendFileSync(path.join(cfg.artifactDir, 'ig5-diag.log'), `[${stamp}] ${line}\n`, 'utf8');
  } catch {
    // diagnostics must never break the plugin
  }
}

// ── 作业进度回路：client 轮询 GET /ig5-jobs → 工作台渲染进度条 ──────────────
function installJobsRoute(ctx, mgr, cfg) {
  ctx.inject(['webServer'], (subCtx) => {
    let ws = null;
    try {
      ws = subCtx.webServer ?? (typeof subCtx.get === 'function' ? subCtx.get('webServer') : undefined);
    } catch {
      ws = undefined;
    }
    if (!ws || typeof ws.register !== 'function') {
      diagAppend(cfg, 'host: webServer 不可用（/ig5-jobs 未挂载）');
      return;
    }
    try {
      const dispose = ws.register({
        kind: 'prefix',
        path: '/ig5-jobs',
        handler: (req, res) => {
          let body;
          try {
            body = JSON.stringify(mgr.snapshot());
          } catch (e) {
            body = JSON.stringify({ error: publicEngineError(e, cfg) });
          }
          res.writeHead(200, {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
          });
          res.end(body);
        },
      });
      diagAppend(cfg, 'host: /ig5-jobs 路由已挂载');
      return () => {
        try {
          if (typeof dispose === 'function') dispose();
        } catch {
          // route already gone
        }
      };
    } catch (e) {
      diagAppend(cfg, `host: /ig5-jobs 挂载失败 ${e && e.message}`);
    }
  });
}

// ── M1-B 审批门：写工具 pre-execute 弹 ui-approval；post-execute 留痕 ────────
const IG5_WRITE_TOOLS = new Set([
  'ig5_rename', 'ig5_patch_bytes', 'ig5_comment', 'ig5_analyze', 'ig5_set_type',
  'ig5_undo', 'ig5_run_idapython', 'ig5_dbg', 'ig5_struct',
  'ig5_switch_repair', 'ig5_emulate',
  'ig5_sync',
]);

function installApprovalGate(ctx, cfg) {
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (!IG5_WRITE_TOOLS.has(exec?.name)) return next();
    const args = exec?.arguments ?? {};
    const what = args?.plan_id ?? args?.ea ?? args?.name ?? args?.target ?? '';
    const request = {
      reason: `IG5 写操作待批准: ${exec.name} @ ${what}`,
      displayReason: {
        en: `IG5 operation "${exec.name}" needs one-time approval before mutation or execution.`,
        zh: `IG5 操作「${exec.name}」（${what}）涉及修改或执行，需要你批准一次。`,
      },
    };
    // Resolve the public approval seam here. Some host builds turn a rejected
    // `ask` into an allow; a plugin-owned deny must remain a deny.
    if (exec?.signal?.aborted) return { kind: 'cancel' };
    let approval;
    try { approval = ctx.get('approval'); } catch { /* uncomposed host */ }
    if (!exec?.agent || typeof approval?.request !== 'function')
      return { kind: 'deny', reason: `IG5 ${exec.name} requires an active agent and an available approval service.` };
    let outcome;
    try {
      outcome = await approval.request({ agent: exec.agent, toolName: exec.name,
        callId: exec.callId, ...request, signal: exec.signal });
    } catch {
      if (exec?.signal?.aborted) return { kind: 'cancel' };
      return { kind: 'deny', reason: `IG5 ${exec.name} approval could not be confirmed; operation was not dispatched.` };
    }
    if (exec?.signal?.aborted || outcome === 'cancelled') return { kind: 'cancel' };
    if (outcome !== 'allowed-once')
      return { kind: 'deny', reason: `IG5 ${exec.name} approval was ${outcome === 'rejected' ? 'rejected' : 'unavailable'}; operation was not dispatched.` };
    return next();
  });
  ctx.on('tools/post-execute', async (exec, result, next) => {
    if (!IG5_WRITE_TOOLS.has(exec?.name)) return next();
    try {
      fs.mkdirSync(cfg.artifactDir, { recursive: true });
      const rec = {
        ts: new Date().toISOString(),
        tool: exec.name,
        args: exec.arguments,
        isError: result?.isError === true,
        detail: result?.isError ? result?.error?.message : result?.value,
      };
      fs.appendFileSync(path.join(cfg.artifactDir, 'approvals.jsonl'), JSON.stringify(rec) + '\n', 'utf8');
    } catch {
      // audit must never break the result path
    }
    return next();
  });
  diagAppend(cfg, `host: 审批门已挂载（${[...IG5_WRITE_TOOLS].join(', ')}）`);
}

// ── M1-C 数据回路：client 工作台 GET /ig5-data（funcs/decompile 只读代理） ──
function installDataRoute(ctx, mgr, cfg) {
  const readTypes = new Set([
    'funcs', 'decompile', 'xrefs', 'strings', 'listing', 'calls', 'bytes',
    'search', 'scan', 'struct', 'cfg', 'slice', 'fingerprint', 'approvals',
    'disasm', 'stack', 'switches', 'vtables', 'microcode',
    'ir', 'debug_state', 'analyses', 'analysis_result',
  ]);
  ctx.inject(['webServer'], (subCtx) => {
    let ws = null;
    try {
      ws = subCtx.webServer ?? (typeof subCtx.get === 'function' ? subCtx.get('webServer') : undefined);
    } catch {
      ws = undefined;
    }
    if (!ws || typeof ws.register !== 'function') {
      diagAppend(cfg, 'host: webServer 不可用（/ig5-data 未挂载）');
      return;
    }
    try {
      const dispose = ws.register({
        kind: 'prefix',
        path: '/ig5-data',
        handler: (req, res) => {
          const url = new URL(String(req.url || '/ig5-data'), 'http://local');
          const type = url.searchParams.get('type') || 'funcs';
          const target = url.searchParams.get('target') || '';
          const engine = url.searchParams.get('engine') || undefined;
          const send = (code, obj) => {
            res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
            res.end(JSON.stringify(obj));
          };
          if (req.method !== 'GET') {
            send(405, { error: 'Only GET is supported' });
            return;
          }
          if (!readTypes.has(type)) {
            send(400, { error: 'Unsupported read-only data type' });
            return;
          }
          if (type === 'analyses' || type === 'analysis_result') {
            try {
              if (!mgr.analysis) throw new Error('Data analysis service is unavailable');
              const data = type === 'analyses'
                ? mgr.analysis.list({ target: target || undefined, engine, archived: url.searchParams.get('archived') === 'true', offset: Number(url.searchParams.get('offset') || 0), limit: Number(url.searchParams.get('limit') || 20) })
                : mgr.analysis.result(url.searchParams.get('id'), url.searchParams.get('select') || undefined);
              if (type === 'analyses') {
                Promise.resolve(data).then(value => send(200, { target, engine, type, data: value }), error => send(200, { error: publicEngineError(error, cfg) }));
                return;
              }
              if (type === 'analysis_result' && target && (!data.association?.target || mgr.sessionKey(data.association.target, engine) !== mgr.sessionKey(target, engine))) throw new Error('Analysis result belongs to another target');
              if (type === 'analysis_result' && engine && data.association?.engine && data.association.engine !== engine) throw new Error('Analysis result belongs to another engine');
              send(200, { target, engine, type, data });
            } catch (error) { send(200, { error: publicEngineError(error, cfg) }); }
            return;
          }
          if (type === 'debug_state') {
            if (engine && engine !== 'x64dbg') { send(400, { error: 'debug_state requires engine=x64dbg' }); return; }
            const debug = target ? mgr.sessions.get(mgr.sessionKey(target, 'x64dbg')) : [...mgr.sessions.values()].find((s) => s.engine === 'x64dbg');
            send(200, { target: target || debug?.target || '', engine: 'x64dbg', type,
              data: debug?.runtime || { state: 'idle', note: 'Use the approved debug tool to execute a target' } });
            return;
          }
          if (engine && !['reverse', 'ghidra'].includes(engine)) { send(400, { error: 'Unsupported static engine' }); return; }
          const structAction = url.searchParams.get('action') || 'list';
          if (type === 'struct' && !['list', 'get'].includes(structAction)) {
            send(400, { error: 'Only struct list/get is supported by this read-only route' });
            return;
          }
          const session = target ? mgr.sessions.get(mgr.sessionKey(target, engine)) : [...mgr.sessions.values()].find((s) => mgr.alive(s) && s.engine !== 'x64dbg' && (!engine || s.engine === engine));
          if (!session || !mgr.alive(session)) {
            send(200, { error: 'no open target' });
            return;
          }
          const params = { offset: Number(url.searchParams.get('offset') || 0), limit: Number(url.searchParams.get('limit') || 30) };
          if (type === 'approvals') {
            const auditFile = path.join(cfg.artifactDir, 'approvals.jsonl');
            if (!fs.existsSync(auditFile)) {
              send(200, { target: session.target, type, data: { rows: [], total: 0, offset: params.offset, limit: params.limit } });
              return;
            }
            const scope = mgr.sessionKey(session.target, session.engine);
            readAuditPage(auditFile, { offset: params.offset || 0, limit: params.limit || 30,
              cursor: url.searchParams.get('cursor') || undefined, scope,
              predicate: item => {
                const auditTarget = item?.detail?.destination?.target || item?.detail?._ig5?.target || item?.args?.target;
                const auditEngine = item?.detail?.destination?.engine || item?.detail?._ig5?.engine || item?.args?.engine || 'reverse';
                return auditTarget && mgr.sessionKey(auditTarget, session.engine) === scope
                  && (!session.engine || auditEngine === session.engine);
              } })
              .then(data => send(200, { target: session.target, type, data }), err => send(200, { error: publicEngineError(err, cfg) }));
            return;
          }
          if (type === 'funcs') {
            params.filter = url.searchParams.get('filter') || '';
            params.user_only = url.searchParams.get('user_only') === 'true';
          }
          if (type === 'decompile') {
            params.ea = url.searchParams.get('ea') || '';
            params.name = url.searchParams.get('name') || '';
          }
          if (type === 'xrefs') {
            params.ea = url.searchParams.get('ea') || '';
            params.str = url.searchParams.get('str') || '';
          }
          if (type === 'strings') {
            params.offset = Number(url.searchParams.get('offset') || 0);
            params.limit = Number(url.searchParams.get('limit') || 50);
          }
          if (type === 'listing') {
            params.kind = url.searchParams.get('kind') || 'segments';
            params.offset = Number(url.searchParams.get('offset') || 0);
            params.limit = Number(url.searchParams.get('limit') || 100);
          }
          if (type === 'calls') {
            params.ea = url.searchParams.get('ea') || '';
            params.name = url.searchParams.get('name') || '';
            params.direction = url.searchParams.get('direction') || 'callees';
          }
          if (type === 'bytes') {
            params.ea = url.searchParams.get('ea') || '';
            params.size = Number(url.searchParams.get('size') || 64);
          }
          if (type === 'search') {
            params.pattern = url.searchParams.get('pattern') || '';
          }
          if (type === 'scan') {
            // static recon sweep
          }
          if (type === 'struct') {
            params.action = structAction;
            params.name = url.searchParams.get('name') || '';
            params.filter = url.searchParams.get('filter') || '';
          }
          if (type === 'cfg') {
            params.ea = url.searchParams.get('ea') || '';
            params.name = url.searchParams.get('name') || '';
          }
          if (type === 'slice') {
            params.ea = url.searchParams.get('ea') || '';
            params.var = url.searchParams.get('var') || '';
          }
          if (type === 'fingerprint') {
            // full sweep
          }
          if (['disasm', 'stack', 'switches', 'vtables', 'microcode', 'ir'].includes(type)) {
            params.ea = url.searchParams.get('ea') || '';
            params.name = url.searchParams.get('name') || '';
          }
          if (type === 'disasm') params.size = Number(url.searchParams.get('size') || 1024);
          if (type === 'microcode') {
            params.action = 'inspect'; // UI route cannot request an optimization or repair.
            params.maturity = url.searchParams.get('maturity') || 'generated';
          }
          if (type === 'ir') {
            params.level = url.searchParams.get('level') || 'high';
            params.max_instructions = Math.max(1, Math.min(params.limit || 120, 1000));
          }
          Promise.resolve()
            .then(() => mgr.rpc(session, type, params, 60_000))
            .then((data) => send(200, { target: session.target, engine: session.engine, projectId: session.projectId,
              artifactId: session.artifactId, dbRevision: session.dbRevision, type, data }))
            .catch((e) => send(200, { error: publicEngineError(e, cfg) }));
        },
      });
      diagAppend(cfg, 'host: /ig5-data 路由已挂载');
      return () => {
        try {
          if (typeof dispose === 'function') dispose();
        } catch {
          // route already gone
        }
      };
    } catch (e) {
      diagAppend(cfg, `host: /ig5-data 挂载失败 ${e && e.message}`);
    }
  });
}

function formatProgress(payload) {
  const pct = typeof payload?.pct === 'number' ? payload.pct : 0;
  const stage = payload?.stage ?? 'working';
  const parts = [`${stage} ${pct}%`];
  if (payload?.segment) parts.push(`段 ${payload.segment}`);
  if (typeof payload?.functions === 'number') parts.push(`${payload.functions} 函数`);
  if (typeof payload?.bytes === 'number' && typeof payload?.totalBytes === 'number') {
    parts.push(`${(payload.bytes / 1048576).toFixed(1)}/${(payload.totalBytes / 1048576).toFixed(1)} MB`);
  }
  if (payload?.detail) parts.push(String(payload.detail));
  return parts.join(' · ');
}

function dimsOf(info) {
  return {
    engine: info.engine,
    projectId: info.projectId,
    artifactId: info.artifactId,
    dbRevision: info.dbRevision,
    partial: info.partial === true,
    ...(info.analysis ? { analysis: info.analysis } : {}),
    ...(info.analysisProfile ? { analysisProfile: info.analysisProfile, analysisComplete: info.analysisComplete,
      skippedAnalyzers: info.skippedAnalyzers || [] } : {}),
    target: info.target,
    bits: info.bits,
    proc: info.proc,
    n_funcs: info.n_funcs,
    segments: info.segments,
    entries: info.entries,
    elapsedMs: info.elapsedMs ?? null,
    alreadyOpen: !!info.alreadyOpen,
  };
}

// ── 工具面（ig5_*，模型视角描述 + 手工参数校验 + canonical JSON 返回） ────────
function textRender(_args, value) {
  return [{ type: 'text', text: JSON.stringify(value, null, 1) }];
}

function requireString(args, field) {
  const v = args?.[field];
  if (typeof v !== 'string' || !v.trim()) {
    throw new Error(`参数 ${field} 缺失或非法（需要非空字符串）`);
  }
  return v.trim();
}

function defineIg5Tools(ctx, mgr, cfg) {
  const spill = (session, ea, code) => {
    const dir = path.join(cfg.artifactDir, 'decompile', session.artifactId, session.engine);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `func_${String(ea).replace(/[^\w.-]/g, '_')}-r${session.dbRevision}.c`);
    fs.writeFileSync(file, code, 'utf8');
    return file;
  };

  return [
    {
      name: 'ig5_profile',
      description:
        'Return IG5 engines, projects, active tools and skills. Optionally switch core (8 frequent tools) or full (38 tools) for the calling agent on hosts supporting agent scopes; older hosts explicitly report plugin-instance scope. History stats/archive/restore manage saved analysis reports without changing engine databases; archive retains result IDs and data refs.',
      parameters: { type: 'object', properties: { toolset: { type: 'string', enum: ['core', 'full'] }, history: { type: 'object', properties: { action: { type: 'string', enum: ['stats', 'archive', 'restore'] }, ids: { type: 'array', minItems: 1, maxItems: 1000, items: { type: 'string' } } }, required: ['action'], additionalProperties: false } }, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args = {}, execution) {
        if (args.toolset !== undefined) {
          if (!mgr.workflow) throw new Error('IG5 workflow is not ready');
          mgr.workflow.setToolset(args.toolset, execution);
        }
        return {
          plugin: PLUGIN_ID,
          version: PLUGIN_VERSION,
          engine: cfg.defaultEngine || 'reverse',
          host: cfg.host,
          runtimeSource: Object.fromEntries(['ghidra', 'x64dbg'].map(id => [id, cfg[id]?.source || null])),
          engines: mgr.engines?.() || [],
          projects: mgr.projects?.listProjects?.() || [],
          ...(mgr.workflow?.snapshot(execution) || { toolset: cfg.toolset || 'core' }),
          ...(args.history ? { history: await mgr.analysis.history(args.history) } : {}),
          engineConfigured: !cfg.defaultEngine || cfg.defaultEngine === 'reverse' ? !!cfg.idaDir : !!cfg[cfg.defaultEngine]?.available,
          pythonConfigured: !cfg.defaultEngine || cfg.defaultEngine === 'reverse' ? !!cfg.pythonExe : !!cfg[cfg.defaultEngine]?.pythonExe,
          requestTimeoutMs: cfg.requestTimeoutMs,
          maxSessions: cfg.maxSessions,
          tools: [
            'ig5_doctor', 'ig5_open', 'ig5_status', 'ig5_funcs', 'ig5_strings',
            'ig5_decompile', 'ig5_xrefs', 'ig5_calls', 'ig5_bytes', 'ig5_search',
            'ig5_listing', 'ig5_scan', 'ig5_export_diff', 'ig5_cfg', 'ig5_slice', 'ig5_fingerprint',
            'ig5_rename*', 'ig5_patch_bytes*', 'ig5_comment*', 'ig5_analyze*', 'ig5_set_type*',
            'ig5_undo*', 'ig5_run_idapython*', 'ig5_dbg*', 'ig5_struct*', 'ig5_close', 'ig5_profile',
            'ig5_stack', 'ig5_switches', 'ig5_switch_repair*', 'ig5_vtables', 'ig5_microcode', 'ig5_bindiff', 'ig5_emulate*',
            'ig5_ir', 'ig5_sync*',
            'ig5_crypto', 'ig5_protocol',
          ],
          writeGated: [...IG5_WRITE_TOOLS],
          lineage: 'dsh-infinite-gen-4 (提示词层) -> dsh-infinite-gen-5 (纯逆向工具面, 零提示词注入)',
        };
      },
    },
    {
      name: 'ig5_doctor',
      description:
        'Self-check the selected IG5 engine. Ghidra and x64dbg use the complete runtimes included in the plugin; Reverse uses the configured licensed installation. Verify startup, runtime dependencies and capabilities before analysis.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args = {}) {
        if (typeof mgr.doctor === 'function') return mgr.doctor(args.engine || cfg.defaultEngine || 'reverse');
        let child;
        try {
          child = mgr.spawnWorker();
          const result = await doctorWorker(child, { timeoutMs: 60_000,
            formatError: error => new Error(publicEngineError(error, cfg)) });
          return { ok: true, engine: 'Reverse (headless)', python: result.python,
            runtimeReady: result.idalib === 'loaded', caps: {
              planAndWait: result.caps?.['ida_auto.plan_and_wait'] === true,
              wait: result.caps?.['ida_auto.auto_wait'] === true,
              makeCode: result.caps?.['ida_auto.auto_make_code'] === true }, artifactDir: cfg.artifactDir };
        } catch (error) { throw new Error(publicEngineError(error, cfg)); }
        finally { try { child?.kill(); } catch {} }
      },
    },
    {
      name: 'ig5_open',
      description:
        'Open a binary in the selected static engine and run auto-analysis. Returns project/artifact identity, engine, database revision, architecture, segments, function count and entries. One worker per target and engine. Analysis defaults to a native background job; pass background:false for inline results. A runtime pack is required for the selected engine.',
      parameters: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Absolute path of the target binary' },
          auto_analysis: { type: 'boolean', description: 'Run automatic analysis using the selected profile (default true)' },
          analysis_timeout: { type: 'number', description: 'Ghidra analysis budget in seconds, 1..600; returns explicitly partial evidence if exhausted' },
          analysis_profile: { type: 'string', enum: ['interactive', 'full'], description: 'Ghidra: interactive (default) skips batch Decompiler Parameter ID; full enables that batch analyzer. Function decompilation is available in both.' },
          background: {
            type: 'boolean',
            description: 'Run the analysis as a background job (default true). false = block this call until analysis finishes.',
          },
          fresh: {
            type: 'boolean',
            description: 'Ignore and back up an adjacent existing .i64/.idb so the database is re-analyzed from scratch (default false = reuse)',
          },
        },
        required: ['path'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args, exec) {
        const target = requireString(args, 'path');
        if (!fs.existsSync(target)) throw new Error(`文件不存在: ${target}`);
        const auto = args?.auto_analysis !== false;
        const fresh = args?.fresh === true;
        if (args.analysis_timeout !== undefined && (!Number.isSafeInteger(args.analysis_timeout) || args.analysis_timeout < 1 || args.analysis_timeout > 600)) throw new Error('analysis_timeout must be an integer from 1 to 600');
        if (args.analysis_profile !== undefined && !['interactive', 'full'].includes(args.analysis_profile)) throw new Error('analysis_profile must be interactive or full');

        const runInline = async () => {
          const info = await mgr.open(target, auto, {
            fresh,
            engine: args.engine,
            analysisTimeout: args.analysis_timeout,
            analysisProfile: args.analysis_profile,
            onProgress: (p) => mgr.noteProgress(target, p),
          });
          return { ...dimsOf(info), background: false };
        };

        const wantsInline = args?.background === false || !cfg.backgroundOpen;
        if (wantsInline) return runInline();

        const jobs = ctx.get('jobs');
        if (!jobs || typeof jobs.start !== 'function') {
          // 部署里没有作业控制器时降级为同步，而不是失败
          return { ...(await runInline()), background: false, backgroundUnavailable: true };
        }

        // Agent 身份就是 SessionId（Agent.id），作业归属以它为准
        const owner = exec?.agent?.id ?? exec?.agent?.sessionId;
        const label = `IG5 分析 ${path.basename(target)}`;
        const jobId = jobs.start({
          kind: 'ig5-open',
          label,
          ...(owner ? { owner } : {}),
          run: (job) => {
            mgr.trackJob(job.id, target, label);
            const done = (async () => {
              try {
                const info = await mgr.open(target, auto, {
                  fresh,
                  engine: args.engine,
                  analysisTimeout: args.analysis_timeout,
                  analysisProfile: args.analysis_profile,
                  onProgress: (p) => {
                    job.updateProgress(formatProgress(p));
                    mgr.noteProgress(target, p, job.id);
                  },
                });
                const summary = `IG5 ${info.partial ? '分析预算到期，返回部分结果' : '分析完成'}: ${path.basename(info.target ?? target)} · ${info.n_funcs} 函数 · ${info.bits} 位 · ${((info.elapsedMs ?? 0) / 1000).toFixed(1)}s`;
                job.append(summary + '\n', { channel: 'stdout' });
                mgr.finishJob(job.id, 'completed', `${info.partial ? '部分分析 · ' : ''}${info.n_funcs} 函数`);
                return { status: 'completed', detail: `${info.partial ? '部分分析 · ' : ''}${info.n_funcs} 函数`, result: JSON.stringify(dimsOf(info)) };
              } catch (e) {
                const msg = publicEngineError(e, cfg);
                job.append(`IG5 分析失败: ${msg}\n`, { channel: 'stderr' });
                mgr.finishJob(job.id, 'failed', msg.slice(0, 200));
                return { status: 'failed', detail: msg.slice(0, 200) };
              }
            })();
            return {
              cancel: (reason) => {
                mgr.close(target, false, args.engine);
                mgr.finishJob(job.id, 'killed', reason ?? 'cancelled');
              },
              done,
            };
          },
        });

        return {
          kind: 'background',
          jobId,
          target,
          hint: '分析在后台运行：右栏 IG5 工作台实时显示进度；用 job_output 取结果，job_kill 取消。',
        };
      },
    },
    {
      name: 'ig5_status',
      description:
        'List all open IG5 worker sessions: target path, worker pid, uptime, last operation, function count. Use it to check what is loaded before running analysis tools.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      execute() {
        const sessions = mgr.status();
        return { sessions, count: sessions.length, config: { engine: cfg.defaultEngine || 'reverse', engines: mgr.engines?.() || [], maxSessions: cfg.maxSessions } };
      },
    },
    {
      name: 'ig5_funcs',
      description:
        'List functions of an open target, paged: address (EA), name, size. Use filter for a name substring. EA is the stable handle for every other ig5 tool.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          offset: { type: 'number', description: 'Skip first N functions (cursor paging)' },
          limit: { type: 'number', description: 'Max rows (default 30, max 200)' },
          filter: { type: 'string', description: 'Case-insensitive name substring filter' },
          user_only: { type: 'boolean', description: 'Filter out library / FLIRT detected functions to focus strictly on user logic' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const session = mgr.get(target);
        const result = await mgr.rpc(session, 'funcs', {
          offset: Number(args?.offset ?? 0),
          limit: Number(args?.limit ?? 30),
          filter: typeof args?.filter === 'string' ? args.filter : '',
          user_only: args?.user_only === true,
        });
        return { target: session.target, ...result };
      },
    },
    {
      name: 'ig5_strings',
      description:
        'List strings of an open target with addresses, paged. First hop for locating license checks, messages, URLs, and crypto constants.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          offset: { type: 'number' },
          limit: { type: 'number', description: 'Max rows (default 30, max 200)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const session = mgr.get(target);
        const result = await mgr.rpc(session, 'strings', {
          offset: Number(args?.offset ?? 0),
          limit: Number(args?.limit ?? 30),
        });
        return { target: session.target, ...result };
      },
    },
    {
      name: 'ig5_decompile',
      description:
        'Decompile one function in the selected static engine to C-like pseudocode. Address by EA or exact name. style=llm adds supporting references when available. Returns engine and database revision. Results over ~12KB spill to an artifact file with a preview.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Function address, hex string like 0x140001070' },
          name: { type: 'string', description: 'Exact function name (used when ea is absent)' },
          style: { type: 'string', description: '"llm" adds meta.callees + meta.strings for model consumption' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const session = mgr.get(target);
        const style = args?.style === 'llm' ? 'llm' : '';
        const key = `${session.dbRevision}|${args?.ea ?? ''}|${args?.name ?? ''}|${style}`;
        let result = session.cache.get(key);
        if (!result) {
          result = await mgr.rpc(session, 'decompile', { ea: args?.ea, name: args?.name, style });
          session.cache.set(key, result);
          if (session.cache.size > 256) session.cache.delete(session.cache.keys().next().value);
        }
        const code = String(result.code ?? '');
        const base = {
          ea: result.ea,
          name: result.name,
          size: result.size,
          lines: result.lines,
          target: session.target,
          ...(result._ig5 || mgr.evidence?.(session) || {}),
          ...(result._ig5 ? { _ig5: result._ig5 } : {}),
          ...(result.meta ? { meta: result.meta } : {}),
        };
        if (code.length > 12_000) {
          const file = spill(session, result.ea, code);
          return {
            ...base,
            spilled: true,
            path: file,
            preview: code.slice(0, 2_000),
            note: '伪代码超过 12KB，已落盘为工件；用 read 工具按 offset/limit 分页细读该文件',
          };
        }
        return { ...base, code };
      },
    },
    {
      name: 'ig5_close',
      description:
        'Close one open target and recycle its worker process. The analysis database stays on disk next to the target; reopening with ig5_open reuses it.',
      parameters: {
        type: 'object',
        properties: { target: { type: 'string', description: 'Target path to close' } },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const existed = await mgr.close(target);
        return { target, closed: existed };
      },
    },
    {
      name: 'ig5_xrefs',
      description:
        'Cross-references of an open target: references to an address/function, from it, or to strings matching a substring (str). Rows carry the other side EA and its containing function. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address, e.g. 0x140001070' },
          name: { type: 'string', description: 'Exact function name (alternative to ea)' },
          str: { type: 'string', description: 'String substring — lists xrefs to every matching string literal' },
          direction: { type: 'string', description: '"to" (default) or "from"' },
          limit: { type: 'number', description: 'Max rows (default 30, max 200)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        return mgr.rpc(mgr.get(target), 'xrefs', {
          ea: args?.ea || '',
          name: args?.name || '',
          str: args?.str || '',
          direction: args?.direction === 'from' ? 'from' : 'to',
          limit: args?.limit,
        });
      },
    },
    {
      name: 'ig5_rename',
      description:
        'Rename a function or label. WRITE OPERATION: gated behind one-time human approval and recorded in approvals.jsonl. Provide ea or name plus new_name.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address' },
          name: { type: 'string', description: 'Current function name (alternative to ea)' },
          new_name: { type: 'string', description: 'New name' },
        },
        required: ['target', 'new_name'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        if (!args?.new_name || !String(args.new_name).trim()) throw new Error('new_name is required');
        return mgr.rpc(mgr.get(target), 'rename', {
          ea: args?.ea || '',
          name: args?.name || '',
          new_name: String(args.new_name).trim(),
        });
      },
    },
    {
      name: 'ig5_patch_bytes',
      description:
        'Patch raw bytes at an address, e.g. hex "74 05" or "74E8". WRITE OPERATION: gated behind one-time human approval; the result carries before/after hex for the diff and everything is recorded in approvals.jsonl.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address to patch' },
          hex: { type: 'string', description: 'Byte payload as hex, spaces optional' },
          expected: { type: 'string', description: 'Expected original hex bytes; mismatch rejects before mutation' },
        },
        required: ['target', 'ea', 'hex'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        requireString(args, 'ea');
        requireString(args, 'hex');
        return mgr.rpc(mgr.get(target), 'patch', { ea: args.ea, hex: args.hex, expected: args.expected });
      },
    },
    {
      name: 'ig5_comment',
      description:
        'Set a disassembly comment at an address. WRITE OPERATION: gated behind one-time human approval and recorded.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address' },
          name: { type: 'string', description: 'Function name (alternative to ea)' },
          text: { type: 'string', description: 'Comment text' },
          repeatable: { type: 'boolean', description: 'Repeatable comment (default false)' },
        },
        required: ['target', 'text'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        if (!args?.text) throw new Error('text is required');
        return mgr.rpc(mgr.get(target), 'comment', {
          ea: args?.ea || '',
          name: args?.name || '',
          text: String(args.text),
          repeatable: args?.repeatable === true,
        });
      },
    },
    {
      name: 'ig5_calls',
      description:
        'Call graph of a function: callees (who it calls, with reference counts) or callers (who calls it). Read-only; pairs well with ig5_decompile style=llm.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address' },
          name: { type: 'string', description: 'Function name (alternative to ea)' },
          direction: { type: 'string', description: '"callees" (default) or "callers"' },
          limit: { type: 'number', description: 'Max rows (default 30, max 200)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        return mgr.rpc(mgr.get(target), 'calls', {
          ea: args?.ea || '',
          name: args?.name || '',
          direction: args?.direction === 'callers' ? 'callers' : 'callees',
          limit: args?.limit,
        });
      },
    },
    {
      name: 'ig5_analyze',
      description:
        'Explicit static analysis-engine control: create_function, delete_function, undefine, mark_code, reanalyze. Range analysis does not certify completion of the whole program. WRITE OPERATION: approval-gated and recorded.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          action: {
            type: 'string',
            description: 'One of: create_function, delete_function, undefine, mark_code, reanalyze',
          },
          ea: { type: 'string', description: 'Hex address' },
          end: { type: 'string', description: 'Hex end address (create_function / mark_code ranges)' },
          size: { type: 'number', description: 'Byte count (undefine default 16; range fallback 4096)' },
        },
        required: ['target', 'action'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const action = requireString(args, 'action');
        if (!['create_function', 'delete_function', 'undefine', 'mark_code', 'reanalyze'].includes(action)) {
          throw new Error(`unknown action: ${action}`);
        }
        return mgr.rpc(mgr.get(target), 'analyze', {
          action,
          ea: args?.ea || '',
          end: args?.end || '',
          size: args?.size,
        });
      },
    },
    {
      name: 'ig5_set_type',
      description:
        'Apply a type to an address/function: either a local-types name (typename) or a C declaration (decl, e.g. "int check_serial(int a, int b)"). WRITE OPERATION: approval-gated; uses parse_decl + apply_tinfo.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address' },
          name: { type: 'string', description: 'Function name (alternative to ea)' },
          decl: { type: 'string', description: 'C declaration snippet' },
          typename: { type: 'string', description: 'Existing local-type name' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        if (!args?.decl && !args?.typename) throw new Error('decl or typename is required');
        return mgr.rpc(mgr.get(target), 'set_type', {
          ea: args?.ea || '',
          name: args?.name || '',
          decl: args?.decl || '',
          typename: args?.typename || '',
        });
      },
    },
    {
      name: 'ig5_bytes',
      description:
        'Read raw bytes currently in the analysis database at an address (static view). Returns hex.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address' },
          name: { type: 'string', description: 'Function name (alternative to ea)' },
          size: { type: 'number', description: 'Byte count (default 64, max 4096)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        return mgr.rpc(mgr.get(target), 'bytes', {
          ea: args?.ea || '',
          name: args?.name || '',
          size: args?.size,
        });
      },
    },
    {
      name: 'ig5_search',
      description:
        'Byte-pattern search across the analysis database with ?? wildcards, e.g. "48 8B ?? 90" or "637C777B" for the AES sbox. Returns hit EAs. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          pattern: { type: 'string', description: 'Hex pattern, space-separated, ?? = wildcard byte' },
          start: { type: 'string', description: 'Hex start address (default first segment)' },
          end: { type: 'string', description: 'Hex end address' },
          limit: { type: 'number', description: 'Max hits (default 30, max 200)' },
        },
        required: ['target', 'pattern'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        requireString(args, 'pattern');
        return mgr.rpc(mgr.get(target), 'search', {
          pattern: args.pattern,
          start: args?.start || '',
          end: args?.end || '',
          limit: args?.limit,
        });
      },
    },
    {
      name: 'ig5_listing',
      description:
        'Enumerate static structures: kind=segments (name/class/perm), imports (module + function), exports (ordinal/name/ea). Paged. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          kind: { type: 'string', description: 'segments | imports | exports' },
          offset: { type: 'number', description: 'Skip first N rows' },
          limit: { type: 'number', description: 'Max rows (default 100, max 500)' },
        },
        required: ['target', 'kind'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const kind = requireString(args, 'kind');
        if (!['segments', 'imports', 'exports'].includes(kind)) throw new Error(`unknown kind: ${kind}`);
        return mgr.rpc(mgr.get(target), 'listing', { kind, offset: args?.offset, limit: args?.limit });
      },
    },
    {
      name: 'ig5_undo',
      description:
        'Roll back the most recent IG5 write operation via the in-worker operation journal (bytes/rename/comment/set_type/create_function/delete_function). action=list lists the journal without undoing. WRITE OPERATION: approval-gated.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          action: { type: 'string', description: '"list" to inspect the journal (default: undo one step)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        return mgr.rpc(mgr.get(target), 'undo', { action: args?.action === 'list' ? 'list' : 'undo' });
      },
    },
    {
      name: 'ig5_scan',
      description:
        'Bounded static sweep in Reverse/Ghidra: AES, MD5/shared initial-state, SHA-256/SHA-512 and CRC constants; communication/crypto imports; sampled segment entropy and string families. Returns addresses, evidence, coverage and truncation. Hits and high entropy are clues, not proof of an algorithm or encryption. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          max_bytes: { type: 'number', description: 'Global sampled bytes: default 8 MiB, maximum 64 MiB' },
          max_segment_bytes: { type: 'number', description: 'Per-segment sampled bytes: default 1 MiB, maximum 16 MiB' },
          max_matches: { type: 'number' }, max_imports: { type: 'number' }, max_strings: { type: 'number' },
          max_segments: { type: 'number' }, max_api_matches: { type: 'number' }, max_string_chars: { type: 'number' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const params = {};
        for (const key of ['max_bytes', 'max_segment_bytes', 'max_matches', 'max_imports', 'max_strings', 'max_segments', 'max_api_matches', 'max_string_chars']) if (args[key] !== undefined) params[key] = args[key];
        return mgr.rpc(mgr.get(target), 'scan', params);
      },
    },
    {
      name: 'ig5_run_idapython',
      description:
        'Escape hatch: execute arbitrary Reverse Python API code in the worker and capture stdout. WRITE OPERATION: approval-gated; a hanging script is killed with the worker by the RPC timeout.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          code: { type: 'string', description: 'Reverse Python API source' },
        },
        required: ['target', 'code'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const code = requireString(args, 'code');
        return mgr.rpc(mgr.get(target), 'idapython', { code }, cfg.requestTimeoutMs);
      },
    },
    {
      name: 'ig5_dbg',
      description:
        'Debug lane over x64dbg or Reverse debuggers. Choose backend explicitly for load. Reports bounded debug events, process state and exception context. Approval-gated; start executes the debuggee. Runtime addresses must not be confused with static database addresses.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          op: {
            type: 'string',
            description: 'load | start | bpt | unbpt | regs | setreg | threads | callstack | modules | state | event | step | stepover | trace | cont | suspend | readmem | writemem | stop',
          },
          kind: { type: 'string', enum: ['software', 'hardware'], default: 'software', description: 'Breakpoint kind for bpt/unbpt' },
          access: { type: 'string', enum: ['execute', 'write', 'readwrite'], default: 'execute', description: 'Hardware breakpoint access' },
          backend: { type: 'string', enum: ['auto', 'x64dbg', 'bochs', 'win32'], description: 'Explicit debugger selection; auto resumes the selected debugger, otherwise prefers the configured default' },
          control: { type: 'string', enum: ['claim', 'takeover', 'release'], description: 'Explicit approval-gated debugger ownership change' },
          expected_stop_seq: { type: 'number', description: 'Reject a plan made for a previous debugger pause' },
          expected_run_id: { type: 'string' },
          reg: { type: 'string', description: 'Register name for setreg' },
          value: { type: 'string', description: 'Integer register value for setreg, decimal or hex' },
          ea: { type: 'string', description: 'Hex address (bpt/unbpt/readmem/writemem)' },
          rva: { type: 'string', description: 'Explicit main-module RVA for x64dbg; mapped against the current loaded module' },
          address_space: { type: 'string', enum: ['runtime', 'database', 'rva'], description: 'Explicit address interpretation for x64dbg ea; default runtime' },
          max_steps: { type: 'number', description: 'Bounded x64dbg single-step trace budget' },
          expected: { type: 'string', description: 'Optional original register or memory value checked before modification' },
          size: { type: 'number', description: 'Memory byte count (default 64); hardware bpt size 1|2|4|8, execute requires 1' },
          hex: { type: 'string', description: 'Byte payload (writemem)' },
          path: { type: 'string', description: 'Debuggee path override (start)' },
          timeout: { type: 'number', description: 'Event wait seconds (default 15; cont 30)' },
        },
        required: ['target', 'op'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const op = requireString(args, 'op');
        if (!['load', 'start', 'bpt', 'unbpt', 'regs', 'setreg', 'threads', 'callstack', 'step', 'stepover', 'cont', 'suspend', 'readmem', 'writemem', 'stop', 'state', 'event', 'modules', 'trace'].includes(op)) {
          throw new Error(`unknown dbg op: ${op}`);
        }
        if (op === 'bpt' && args.kind === 'hardware' && args.size !== undefined && ![1, 2, 4, 8].includes(args.size)) throw new Error('Hardware breakpoint size must be 1, 2, 4 or 8');
        return mgr.rpc(mgr.get(target), 'dbg', {
          op,
          backend: args?.backend || 'auto',
          kind: args.kind || 'software', access: args.access || 'execute',
          reg: args?.reg,
          value: args?.value,
          ea: args?.ea || '',
          size: args?.size,
          hex: args?.hex || '',
          path: args?.path || '',
          timeout: args?.timeout,
          rva: args.rva, count: args.max_steps, addressSpace: args.address_space, expected: args.expected,
          control: args.control, expected_stop_seq: args.expected_stop_seq, expected_run_id: args.expected_run_id,
        }, Math.min(cfg.requestTimeoutMs, 75_000));
      },
    },
    {
      name: 'ig5_export_diff',
      description:
        'Export a patched copy and changes report for audited byte regions, reading their current bytes from the open database so undone patches are excluded. Read-only to the analysis database; writes deliverable files.',
      parameters: {
        type: 'object',
        properties: { target: { type: 'string', description: 'Target path previously opened with ig5_open' } },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        return exportPatchDiff({ target: requireString(args, 'target'), mgr, cfg });
      },
    },
    {
      name: 'ig5_struct',
      description:
        'Type system & Struct synthesizer (Local Types / Til). Define C struct declarations, inspect struct fields and offsets, list all user-defined types, or apply struct types to memory addresses. WRITE OPERATION (action=define/apply): approval-gated.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target binary path (omit for active session)' },
          action: {
            type: 'string',
            enum: ['define', 'get', 'list', 'apply'],
            description: "Action to perform: 'define' (compile C struct decl), 'get' (inspect struct fields), 'list' (list local types), 'apply' (apply struct to EA)",
          },
          decl: { type: 'string', description: "C language struct or typedef declaration (required for action='define'). E.g., 'struct Context { int id; char name[32]; void *buf; };'" },
          name: { type: 'string', description: "Type/struct name (required for action='get' or 'apply')" },
          ea: { type: 'string', description: "Target address (hex string, required for action='apply')" },
          filter: { type: 'string', description: "Filter string for action='list'" },
          limit: { type: 'number', description: "Max results for action='list' (default 100)" },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = args?.target || mgr.selectedTarget();
        if (!target) throw new Error('No open target found');
        return mgr.rpc(mgr.get(target), 'struct', {
          action: args.action,
          decl: args.decl,
          name: args.name,
          ea: args.ea,
          filter: args.filter,
          limit: args.limit,
        });
      },
    },
    {
      name: 'ig5_cfg',
      description:
        'Control Flow Graph (CFG) extraction. Generates a basic block topology map and standard Mermaid flowchart diagram (flowchart TD) for a function, revealing decision branches, loop cycles, and basic blocks. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target binary path (omit for active session)' },
          ea: { type: 'string', description: 'Function entry EA (e.g. 0x140001000)' },
          name: { type: 'string', description: 'Function name (alternative to ea)' },
        },
        required: [],
        additionalProperties: false,
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = args?.target || mgr.selectedTarget();
        if (!target) throw new Error('No open target found');
        return mgr.rpc(mgr.get(target), 'cfg', { ea: args.ea, name: args.name });
      },
    },
    {
      name: 'ig5_slice',
      description:
        'Microcode & Variable Semantic Slicing. Inspects all function arguments and local variables (with types, registers, and widths), and extracts focused code slices matching a specific variable without dumping redundant boilerplate code. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target binary path (omit for active session)' },
          ea: { type: 'string', description: 'Function EA (e.g. 0x140001000)' },
          var: { type: 'string', description: 'Variable name to focus and slice (optional, returns focused code lines if provided)' },
        },
        required: ['ea'],
        additionalProperties: false,
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = args?.target || mgr.selectedTarget();
        if (!target) throw new Error('No open target found');
        return mgr.rpc(mgr.get(target), 'slice', { ea: args.ea, var: args.var });
      },
    },
    {
      name: 'ig5_fingerprint',
      description:
        'Compiler fingerprint and FLIRT standard library function identification. Distinguishes user code from static library boilerplate (e.g. CRT, OpenSSL, zlib), helping avoid wasting context on standard functions. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target binary path (omit for active session)' },
        },
        required: [],
        additionalProperties: false,
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = args?.target || [...mgr.sessions.values()].find((s) => mgr.alive(s))?.target;
        if (!target) throw new Error('No open target found');
        return mgr.rpc(mgr.get(target), 'fingerprint', {});
      },
    },
    ...defineAdvancedTools(mgr, cfg, textRender),
    ...defineIntegrationTools(mgr, cfg, textRender),
    ...defineAnalysisTools(mgr, cfg, textRender),
  ];
}

// ── ig5dash 会话投影（只折叠已提交的 tool 事件，model-visible ⟺ logged） ────
function ig5DashDefinition() {
  const anySchema = { parse: (value) => value };
  return {
    key: 'ig5dash',
    stateVersion: 1,
    stateSchema: anySchema,
    init: () => ({ running: null, tool: null, calls: 0, errors: 0, last: null, lastSummary: null, pending: {} }),
    apply(state, event) {
      if (!event || typeof event !== 'object') return state;
      const d = event.data;
      if (event.type === 'tool/call') {
        if (typeof d?.name !== 'string' || !d.name.startsWith('ig5_')) return state;
        const pending = { ...state.pending, [d.callId]: d.name };
        const ids = Object.keys(pending);
        while (ids.length > 32) delete pending[ids.shift()];
        return { ...state, running: d.name, tool: d.name, calls: state.calls + 1, pending };
      }
      if (event.type === 'tool/result') {
        const msg = d?.message ?? {};
        const cid = msg?.callId ?? d?.callId;
        const name = (typeof msg?.name === 'string' && msg.name) || (cid && state.pending[cid]) || null;
        if (!name || !String(name).startsWith('ig5_')) return state;
        const pending = { ...state.pending };
        if (cid) delete pending[cid];
        const isError = !!msg?.isError;
        let summary = null;
        const blocks = Array.isArray(msg?.content) ? msg.content : [];
        for (const b of blocks) {
          if (b && b.type === 'text' && typeof b.text === 'string') {
            summary = b.text.slice(0, 120);
            break;
          }
        }
        return {
          ...state,
          running: null,
          last: name,
          errors: state.errors + (isError ? 1 : 0),
          lastSummary: summary,
          pending,
        };
      }
      return state;
    },
    wire: { viewSchema: anySchema, view: (state) => state },
  };
}

// ── 插件入口（具名导出，无 default export） ─────────────────────────────────
export const name = PLUGIN_ID;
export const inject = ['tools', 'sessionProjections'];

export function apply(ctx, config = {}) {
  const cfg = resolveConfig(config);
  const mgr = new WorkerManager(cfg);
  installDiagRoute(ctx, cfg);
  installJobsRoute(ctx, mgr, cfg);
  installDataRoute(ctx, mgr, cfg);
  installApprovalGate(ctx, cfg);

  ctx.effect(() => {
    const definitions = defineIg5Tools(ctx, mgr, cfg).map((definition) => {
      const execute = definition.execute;
      const isGlobal = ['ig5_profile', 'ig5_status', 'ig5_crypto', 'ig5_protocol'].includes(definition.name);
      const isData = ['ig5_crypto', 'ig5_protocol'].includes(definition.name);
      definition.parameters.properties.engine = { type: 'string', enum: definition.name === 'ig5_doctor'
        ? ['reverse', 'ghidra', 'x64dbg'] : ['reverse', 'ghidra'],
        description: isData ? 'Optional result association or static source backend; standalone byte/file/ref analysis does not require an engine.' : 'Explicit backend. Omit to use the configured primary static engine; results identify their source.' };
      if (IG5_WRITE_TOOLS.has(definition.name) && definition.name !== 'ig5_sync') definition.parameters.properties.expected_revision = {
        type: 'number', description: 'Reject this operation if the selected database revision has changed since planning' };
      definition.execute = (args = {}, execution) => mgr.scope.run({ engine: args.engine || (definition.name === 'ig5_ir' ? 'ghidra' : cfg.defaultEngine), agentId: execution?.agent?.id || execution?.agent?.sessionId, signal: execution?.signal }, async () => {
        if (execution?.signal?.aborted) throw new Error('IG5 operation cancelled');
        if (args.engine) engineId(args.engine);
        const selected = !args.target && !isGlobal && !['ig5_open', 'ig5_doctor', 'ig5_bindiff', 'ig5_sync'].includes(definition.name)
          && !definition.parameters.required?.includes('target') ? mgr.selectedTarget() : args.target;
        if (selected) args = { ...args, target: selected };
        const session = selected && !isData ? mgr.get(selected) : null;
        const perform = async () => {
        if (session?.state === 'opening') {
          await mgr.launching.get(session.key);
          if (session.state !== 'open' || mgr.get(session.target, session.engine) !== session) throw new Error('Target did not finish opening');
        }
        mgr.checkCancelled();
        if (session?.closing) throw new Error('Target is closing; wait for it to finish');
        if (args.expected_revision !== undefined && (!session || session.dbRevision !== args.expected_revision)) {
          throw new Error('Database revision changed; read current evidence and review the operation again');
        }
        const result = await execute(args, execution);
        return jsonToolOutput(result && typeof result === 'object' && !Array.isArray(result) && session && !isGlobal
          ? { ...result, _ig5: result._ig5 || mgr.evidence(session) } : result);
        };
        if (!session || !(IG5_WRITE_TOOLS.has(definition.name) || definition.name === 'ig5_export_diff') || ['ig5_sync', 'ig5_dbg'].includes(definition.name)) return perform();
        return mgr.withSessions([session], perform);
      });
      return definition;
    });
    const workflow = installWorkflow(ctx, { cfg, mgr, definitions, formatError: publicEngineError });
    mgr.workflow = workflow;
    return async () => {
      await workflow.dispose();
      await mgr.analysis?.dispose();
      await Promise.all([...mgr.sessions.values()].filter((s) => s.engine !== 'x64dbg').map((s) => mgr.close(s.target, true, s.engine, { force: true })));
      await Promise.all([...mgr.sessions.values()].map((s) => mgr.close(s.target, true, s.engine, { force: true })));
    };
  }, `${PLUGIN_ID}: ig5 tool surface`);

  const projections = ctx.get('sessionProjections');
  if (projections !== undefined && typeof projections.register === 'function') {
    ctx.effect(() => projections.register(ig5DashDefinition(), `${PLUGIN_ID}: ig5dash projection`));
  }
}
