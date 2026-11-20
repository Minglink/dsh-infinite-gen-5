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
import { defineCaptureTools } from './capture_tools.js';
import { exportPatchDiff } from './source/patch_export.js';
import { targetIdentity } from './source/audit_history.js';
import { jsonToolOutput } from './source/json_output.js';
import { resolveReverseRuntime } from './source/reverse_runtime.js';
import { collectFunctionDossier } from './source/function_dossier.js';
import { ResultArtifacts } from './source/result_artifacts.js';
import { FunctionBatches } from './source/function_batches.js';
import { workspaceSchema, runWorkspace, captureDossier } from './source/investigation_workflow.js';
import { installReadOnlyDataRoute } from './source/read_only_data_route.js';
import { autonomyStatus } from './source/autonomy_status.js';
import { recoveryProfileSchema, runRecoveryProfile } from './source/vm_recovery_profile.js';
import { saveDebugTrace } from './source/debug_trace.js';
import { debugTimeout } from './source/debug_timeout.js';
import { RemoteExecutionStore, remoteExecutionKey } from './source/remote_execution_store.js';
import { guestProfileConfiguration, loadGuestProfile, publicGuestProfile, guestTarget } from './source/guest_debug_profile.js';
import { recoverGuestExecution, validateGuestRecoveryArgs } from './source/guest_recovery.js';
import { ig5DashDefinition } from './source/dashboard_projection.js';
import { installLcmBridge, memorySchema } from './source/lcm_bridge.js';
import { runKnowledge, knowledgeSchema } from './source/knowledge_catalog.js';
import { installDelegationControl } from './source/delegation_control.js';
import { diagAppend } from './source/diag_log.js';
import { publicEngineError } from './source/engine_error.js';
import { WorkerManager } from './source/worker_manager.js';
import { IMPLEMENTATION_REVISION, IMPLEMENTATION_LOADED_AT } from './source/implementation_info.js';
import { installApprovalGate, IG5_WRITE_TOOLS } from './source/approval_gate.js';
import { capabilityCatalog } from './source/capability_catalog.js';
import { FailureRecords } from './source/failure_record.js';
import { failureBinding } from './source/failure_adapters.js';
import { planningRequestKey } from './source/planning_identity.js';
import { planningImplementationDigest } from './source/planning_runtime.js';
import { CapabilityAcceptance, runtimeIdentity } from './source/capability_acceptance.js';
import { runManagedToolExecution, parseAndStripResearch, RESEARCH_BINDING_SCHEMA } from './source/delegation_execution.js';
import { installAutonomyHost } from './source/autonomy_host.js';
import { RootInvestigationStore } from './source/investigation_root.js';


// ── 无限五代（IG5）v1.0.0 ──────────────────────────────────────────────────
// DeepSeek Harness 逆向插件：隔离多引擎 Worker 池 + ig5_* 工具面 + ig5dash 投影。
// 零提示词注入；指导载体 = 工具描述 + 会话流卡片。

const PLUGIN_ID = 'dsh-infinite-gen-5';
const PLUGIN_VERSION = '1.4.0';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKER = path.join(HERE, 'worker', 'ig5_worker.py');

// ── Config（cordis.yml 插件行可覆盖；misconfiguration fails loud） ──────────
function resolveConfig(cfg = {}) {
  const runtime = runtimeConfiguration(cfg);
  const reverseProvider = cfg.reverseProvider || 'bundled';
  if (!['bundled', 'commercial'].includes(reverseProvider)) throw new Error('reverseProvider must be bundled or commercial');
  const reverseRuntime = reverseProvider === 'commercial' ? resolveReverseRuntime(cfg, { host: runtime.host }) : {
    available: runtime.ghidra.available, source: runtime.ghidra.source, distribution: 'bundled', provider: 'ghidra',
    readiness: runtime.ghidra.available ? 'ready-to-start' : 'missing-runtime', runtimeReady: null,
    startupVerified: false, validation: 'runtime-metadata-and-files',
    reason: runtime.ghidra.available ? '五代内置 Reverse 核心已就绪；首次检查会验证实际启动。' : runtime.ghidra.reason,
    pythonExe: runtime.ghidra.pythonExe,
  };
  const { idaDir, pythonExe, available: reverseAvailable } = reverseRuntime;
  return {
    ...runtime,
    idaDir,
    reverseAvailable,
    reverseRuntime,
    reverseProvider,
    pythonExe,
    defaultEngine: cfg.defaultEngine ? engineId(cfg.defaultEngine) : 'reverse',
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
    memory: cfg.memory !== false,
    knowledge: cfg.knowledge !== false,
    capture: cfg.capture ?? {},
    guestDebugProfiles: guestProfileConfiguration(cfg.guestDebugProfiles),
    remoteExecutionRoot: path.resolve(cfg.remoteExecutionRoot || path.join(runtime.home, 'remote-executions')),
  };
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


// ── M1-C 数据回路：client 工作台 GET /ig5-data（funcs/decompile 只读代理） ──
function installDataRoute(ctx, mgr, cfg) {
  return installReadOnlyDataRoute(ctx, mgr, cfg, { diagAppend, publicEngineError });
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
    provider: info.provider,
    projectId: info.projectId,
    artifactId: info.artifactId,
    sha256: info.sha256,
    attachmentId: info.attachmentId,
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
    entriesMeaning: 'Provider analysis entrypoints; may include program entry and TLS callbacks. Not the PE export table. Use ig5_listing kind=exports for exports.',
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

function formatWindowsCommandLineArgs(argv) {
  return argv.map((arg) => {
    if (arg === '') return '""';
    if (!/[ \t"]/.test(arg)) return arg;
    let out = '"';
    let backslashes = 0;
    for (const ch of arg) {
      if (ch === '\\') {
        backslashes += 1;
      } else if (ch === '"') {
        out += '\\'.repeat(backslashes * 2 + 1) + '"';
        backslashes = 0;
      } else {
        out += '\\'.repeat(backslashes) + ch;
        backslashes = 0;
      }
    }
    out += '\\'.repeat(backslashes * 2) + '"';
    return out;
  }).join(' ');
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
        'IG5 status/toolset(core|full) or standalone op: guest_debug, history, address, capabilities, memory, knowledge, collaboration.',
      parameters: { type: 'object', properties: { target: { type: 'string' }, guest_debug: { type: 'string' }, toolset: { type: 'string', enum: ['core', 'full'] }, history: { type: 'object', properties: { action: { type: 'string', enum: ['stats', 'archive', 'restore'] }, ids: { type: 'array', minItems: 1, maxItems: 1000, items: { type: 'string' } } }, required: ['action'], additionalProperties: false } }, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args = {}, execution) {
        if (args.knowledge !== undefined) {
          if (Object.keys(args).some(k => k !== 'knowledge')) throw new Error('Use knowledge separately from other profile operations');
          return { knowledge: runKnowledge(cfg, args.knowledge) };
        }
        if (args.address !== undefined) {
          if (Object.keys(args).some(k => !['address','target','engine'].includes(k))) throw new Error('Use address conversion separately');
          const session = mgr.get(requireString(args, 'target'));
          return mgr.rpc(session, 'address_convert', args.address);
        }
        if (args.capabilities !== undefined) {
          if (args.capabilities !== true || Object.keys(args).some(k => !['capabilities', 'engine'].includes(k))) throw Object.assign(new Error('Use capabilities=true separately from other profile operations'), { code: 'INVALID_ARGUMENT' });
          return { capabilities: capabilityCatalog(mgr, cfg, { engine: args.engine }) };
        }
        if (args.memory !== undefined) {
          if (Object.keys(args).some(k => !['memory', 'engine'].includes(k))) throw new Error('Use memory separately from other profile operations');
          return { memory: await mgr.memory.handle(execution?.agent, args.memory) };
        }
        if (args.collaboration !== undefined) {
          if (Object.keys(args).some(k => !['collaboration', 'engine'].includes(k))) throw new Error('Use collaboration separately from other profile operations');
          return { collaboration: mgr.coordination.budget(execution?.agent, args.collaboration) };
        }
        if (args.recovery !== undefined) throw new Error('Use ig5_recovery for recovery and failure-planning operations');
        if (args.workspace !== undefined) throw new Error('Use ig5_workspace for investigation task operations');
        if (args.toolset !== undefined) {
          if (!mgr.workflow) throw new Error('IG5 workflow is not ready');
          mgr.workflow.setToolset(args.toolset, execution);
        }
        return {
          plugin: PLUGIN_ID,
          version: PLUGIN_VERSION,
          implementationRevision: IMPLEMENTATION_REVISION,
          engine: cfg.defaultEngine || 'reverse',
          host: cfg.host,
          runtimeSource: Object.fromEntries(['ghidra', 'x64dbg'].map(id => [id, cfg[id]?.source || null])),
          engines: mgr.engines?.() || [],
          projects: mgr.projects?.listProjects?.() || [],
          ...(mgr.workflow?.snapshot(execution) || { toolset: cfg.toolset || 'core' }),
          autonomy: autonomyStatus(ctx, execution, mgr),
          ...(args.history ? { history: await mgr.analysis.history(args.history) } : {}),
          engineConfigured: cfg.defaultEngine === 'reverse' ? cfg.reverseAvailable : !!cfg[cfg.defaultEngine]?.available,
          pythonConfigured: cfg.defaultEngine === 'reverse' ? !!cfg.pythonExe : !!cfg[cfg.defaultEngine]?.pythonExe,
          requestTimeoutMs: cfg.requestTimeoutMs,
          maxSessions: cfg.maxSessions,
          capture: mgr.capture?.status() || { state: 'idle' },
          guestDebugProfiles: Object.keys(cfg.guestDebugProfiles || {}),
          ...(args.guest_debug !== undefined ? { guestDebug: publicGuestProfile(loadGuestProfile(cfg, args.guest_debug)) } : {}),
          tools: [
            'ig5_doctor', 'ig5_open', 'ig5_status', 'ig5_funcs', 'ig5_strings',
            'ig5_decompile', 'ig5_xrefs', 'ig5_calls', 'ig5_bytes', 'ig5_search',
            'ig5_listing', 'ig5_scan', 'ig5_export_diff', 'ig5_cfg', 'ig5_slice', 'ig5_fingerprint',
            'ig5_rename*', 'ig5_patch_bytes*', 'ig5_comment*', 'ig5_analyze*', 'ig5_set_type*',
            'ig5_undo*', 'ig5_run_idapython*', 'ig5_dbg*', 'ig5_struct*', 'ig5_close', 'ig5_profile',
            'ig5_workspace', 'ig5_recovery',
            'ig5_stack', 'ig5_switches', 'ig5_switch_repair*', 'ig5_vtables', 'ig5_microcode', 'ig5_bindiff', 'ig5_emulate*',
            'ig5_ir', 'ig5_sync*',
            'ig5_crypto', 'ig5_protocol', 'ig5_package',
            'ig5_capture', 'ig5_capture_control*',
          ],
          writeGated: [...IG5_WRITE_TOOLS],
          lineage: 'dsh-infinite-gen-4 (提示词层) -> dsh-infinite-gen-5 (逆向工具面、按需 Skill 与宿主持久 Goal；无全局 persona 注入)',
        };
      },
    },
    {
      name: 'ig5_workspace',
      description: 'Investigation workspace: notes, evidence, research CAS, handoffs, and root lifecycle (root-*/select/evaluate/assess).',
      parameters: { type: 'object', properties: { workspace: workspaceSchema, target: { type: 'string' } }, required: ['workspace'], additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args = {}, execution) { return runWorkspace(mgr, cfg, args, execution); },
    },
    {
      name: 'ig5_recovery',
      description: 'Static VM recovery planning and recorded-trace analysis (case_ref/observations/roles/flow/recurrences/handlers/context/instances).',
      parameters: { type: 'object', properties: { recovery: recoveryProfileSchema }, required: ['recovery'], additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args = {}) { return runRecoveryProfile(mgr, args, cfg); },
    },
    {
      name: 'ig5_doctor',
      description: 'Check IG5 engine/provider readiness or session metadata (operation=session).',
      parameters: { type: 'object', properties: { operation: { type: 'string', enum: ['engine', 'session'] } }, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args = {}, execution) {
        if (args.operation === 'session') return mgr.coordination.diagnose(execution?.agent, args);
        if (args.operation !== undefined && args.operation !== 'engine') throw new Error('doctor operation must be engine or session');
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
      description: 'Open binary in static engine (default background=true; background=false inline).',
      parameters: {
        type: 'object',
        properties: {
          path: { type: 'string' },
          auto_analysis: { type: 'boolean' },
          analysis_timeout: { type: 'number' },
          analysis_profile: { type: 'string', enum: ['interactive', 'full'] },
          background: { type: 'boolean' },
          fresh: { type: 'boolean' },
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
        'List open IG5 sessions, pending remoteExecutions, and stored remoteCleanupEvidence.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      execute() {
        const sessions = mgr.status();
        return { sessions, count: sessions.length, remoteExecutions: mgr.remoteExecutionStatus?.() || [], remoteCleanupEvidence: mgr.remoteCleanupEvidence(), config: { engine: cfg.defaultEngine || 'reverse', engines: mgr.engines?.() || [], maxSessions: cfg.maxSessions } };
      },
    },
    {
      name: 'ig5_funcs',
      description: 'List functions of an open target (EA, name, size), paged.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          offset: { type: 'number' },
          limit: { type: 'number', description: 'Max rows (default 30, max 200)' },
          filter: { type: 'string' },
          user_only: { type: 'boolean' },
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
        const out = { target: session.target, ...result };
        if (session._clrMetadata === undefined) {
          session._clrMetadata = null;
          try {
            if (session.target && fs.existsSync(session.target)) {
              const st = fs.statSync(session.target);
              if (st.isFile() && st.size > 64 && st.size <= 16 * 1024 * 1024 && fs.readFileSync(session.target).includes(Buffer.from('BSJB'))) {
                session._clrMetadata = (await mgr.rpc(session, 'scan', { max_bytes: 524288, max_matches: 4, max_strings: 4, max_imports: 4 }))?.clrMetadata || null;
              }
            }
          } catch { session._clrMetadata = null; }
        }
        return session._clrMetadata ? { ...out, clrMetadata: session._clrMetadata } : out;
      },
    },
    {
      name: 'ig5_strings',
      description: 'List strings with addresses, paged.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
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
        const out = { target: session.target, ...result };
        if (session._clrMetadata === undefined) {
          session._clrMetadata = null;
          try {
            if (session.target && fs.existsSync(session.target)) {
              const st = fs.statSync(session.target);
              if (st.isFile() && st.size > 64 && st.size <= 16 * 1024 * 1024 && fs.readFileSync(session.target).includes(Buffer.from('BSJB'))) {
                session._clrMetadata = (await mgr.rpc(session, 'scan', { max_bytes: 524288, max_matches: 4, max_strings: 4, max_imports: 4 }))?.clrMetadata || null;
              }
            }
          } catch { session._clrMetadata = null; }
        }
        return session._clrMetadata ? { ...out, clrMetadata: session._clrMetadata } : out;
      },
    },
    {
      name: 'ig5_decompile',
      description: 'Read-only decompilation by EA/name (plain, style=dossier, operation=read paged dossier, or operation=batch).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          ea: { type: 'string' },
          name: { type: 'string' },
          style: { type: 'string', enum: ['', 'llm', 'dossier'] },
          operation: { type: 'string', enum: ['collect', 'read', 'batch'] },
          batch: { type: 'object', properties: { action: { type: 'string', enum: ['create','status','run','cancel'] }, id: { type: 'string' }, functions: { type: 'array', minItems: 1, maxItems: 72, items: { type: 'string' } }, max_items: { type: 'integer', minimum: 1, maximum: 8 } }, required: ['action'], additionalProperties: false },
          result_ref: { type: 'object', properties: { id: { type: 'string' }, sha256: { type: 'string' }, expiresAt: { type: 'string' } }, required: ['id', 'sha256'], additionalProperties: false },
          section: { type: 'string', enum: ['decompile', 'cfg', 'callers', 'callees', 'stack'] },
          format: { type: 'string', enum: ['text', 'records', 'json-text'] },
          cursor: { type: 'string' },
          page_max_bytes: { type: 'integer', minimum: 4000, maximum: 64000 },
          dossier_max_bytes: { type: 'number' },
          dossier_max_rows: { type: 'number' },
          refresh: { type: 'boolean' },
          task_id: { type: 'string' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args, execution) {
        const target = requireString(args, 'target');
        const session = mgr.get(target);
        if (args.operation === 'batch') {
          if (Object.keys(args).some(k => !['operation','target','engine','batch'].includes(k))) throw new Error('Use batch parameters separately');
          return mgr.functionBatches.execute(mgr, session, args, execution);
        }
        if (args.batch !== undefined) throw new Error('batch requires operation=batch');
        if (args.operation === 'read') {
          if (Object.keys(args).some(k => !['operation','target','engine','result_ref','section','format','cursor','page_max_bytes'].includes(k))) throw new Error('Use saved result read parameters separately from collection');
          mgr.checkCancelled();
          return mgr.functionResults.read(args.result_ref, mgr.evidence(session), args);
        }
        if (args.operation !== undefined && args.operation !== 'collect') throw new Error('decompile operation must be collect or read');
        if (['result_ref','section','format','cursor','page_max_bytes'].some(k => args[k] !== undefined)) throw new Error('Saved-result parameters require operation=read');
        if (args.style !== undefined && !['', 'llm', 'dossier'].includes(args.style)) throw new Error('style must be empty, llm or dossier');
        if (args.style === 'dossier') {
          const dossier = await collectFunctionDossier(mgr, session, args);
          return args.task_id === undefined ? dossier : { ...dossier, investigation: captureDossier(mgr, cfg, dossier, args.task_id, execution) };
        }
        if (['task_id', 'dossier_max_bytes', 'dossier_max_rows', 'refresh'].some(key => args[key] !== undefined)) throw new Error('Dossier parameters require style=dossier');
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
          ...(result.addresses ? { addresses: result.addresses } : {}),
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
      description: 'Close an open target and stop its worker; analysis DB remains on disk.',
      parameters: {
        type: 'object',
        properties: { target: { type: 'string' } },
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
      description: 'Read-only cross-references to/from EA, function name, or string substring (str).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          ea: { type: 'string' },
          name: { type: 'string' },
          str: { type: 'string', description: 'String substring' },
          direction: { type: 'string', description: 'to|from' },
          limit: { type: 'number' },
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
      description: 'Rename function/label by ea or name. WRITE OPERATION (approval-gated).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          ea: { type: 'string' },
          name: { type: 'string' },
          new_name: { type: 'string' },
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
      description: 'Patch hex bytes at ea (optional expected pre-check). WRITE OPERATION (approval-gated).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          ea: { type: 'string' },
          hex: { type: 'string' },
          expected: { type: 'string', description: 'Expected original hex' },
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
      description: 'Set disassembly comment at ea/name. WRITE OPERATION (approval-gated).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          ea: { type: 'string' },
          name: { type: 'string' },
          text: { type: 'string' },
          repeatable: { type: 'boolean' },
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
      description: 'Read-only function call graph (callees or callers).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          ea: { type: 'string' },
          name: { type: 'string' },
          direction: { type: 'string', description: 'callees|callers' },
          limit: { type: 'number' },
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
      description: 'Static analysis control (create_function|delete_function|undefine|mark_code|reanalyze). WRITE OPERATION (approval-gated).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          action: { type: 'string' },
          ea: { type: 'string' },
          end: { type: 'string' },
          size: { type: 'number' },
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
      description: 'Apply local typename or C decl to ea/name. WRITE OPERATION (approval-gated).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          ea: { type: 'string' },
          name: { type: 'string' },
          decl: { type: 'string' },
          typename: { type: 'string' },
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
      description: 'Read raw hex bytes from static analysis DB at ea/name.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          ea: { type: 'string' },
          name: { type: 'string' },
          size: { type: 'number', description: 'Bytes (default 64, max 4096)' },
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
      description: 'Read-only hex byte-pattern search with ?? wildcards across DB.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          pattern: { type: 'string' },
          start: { type: 'string' },
          end: { type: 'string' },
          limit: { type: 'number' },
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
      description: 'Read-only paged static listing: segments, imports, exports (export dir), or entries (entrypoints/TLS).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          kind: { type: 'string', enum: ['segments', 'imports', 'exports', 'entries'] },
          offset: { type: 'number' },
          limit: { type: 'number' },
        },
        required: ['target', 'kind'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const kind = requireString(args, 'kind');
        if (!['segments', 'imports', 'exports', 'entries'].includes(kind)) throw new Error(`unknown kind: ${kind}`);
        return mgr.rpc(mgr.get(target), 'listing', { kind, offset: args?.offset, limit: args?.limit });
      },
    },
    {
      name: 'ig5_undo',
      description: 'Roll back last IG5 DB write (action=list inspects journal). WRITE OPERATION (approval-gated).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          action: { type: 'string', description: 'list or undo (default)' },
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
      description: 'Read-only static sweep: crypto/CRC constants, API behaviors, entropy, packing/CLR metadata, and YARA-style ruleMatches.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          max_bytes: { type: 'number' },
          max_segment_bytes: { type: 'number' },
          max_matches: { type: 'number' }, max_imports: { type: 'number' }, max_strings: { type: 'number' },
          max_segments: { type: 'number' }, max_api_matches: { type: 'number' }, max_string_chars: { type: 'number' },
          max_rule_matches: { type: 'number' },
          rules: { type: 'string', maxLength: 65536, description: 'Restricted YARA-style rules (<=64)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const params = {};
        for (const key of ['max_bytes', 'max_segment_bytes', 'max_matches', 'max_imports', 'max_strings', 'max_segments', 'max_api_matches', 'max_string_chars', 'max_rule_matches']) if (args[key] !== undefined) params[key] = args[key];
        if (args.rules !== undefined) {
          if (typeof args.rules !== 'string' || !args.rules.trim()) throw new Error('rules must be a non-empty restricted YARA-style source string');
          if (Buffer.byteLength(args.rules, 'utf8') > 65536) throw new Error('rules is longer than 65536 bytes');
          params.rules = args.rules;
        }
        return mgr.rpc(mgr.get(target), 'scan', params);
      },
    },
    {
      name: 'ig5_run_idapython',
      description: 'APPROVAL REQUIRED. Run Python (currentProgram/flat_api or legacy Reverse API subset, <=64 KiB) inside the active worker; not a sandbox.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          code: { type: 'string' },
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
      description: 'APPROVAL REQUIRED. Bundled x64dbg debug lane (or VMCI guest with backend=x64dbg + guest_profile + guest_binding_sha256).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          op: {
            type: 'string',
            description: 'load|start|bpt|unbpt|regs|setreg|threads|callstack|modules|state|event|step|stepover|trace|apitrace|cont|suspend|readmem|writemem|stop|recover',
          },
          kind: { type: 'string', enum: ['software', 'hardware'], default: 'software' },
          access: { type: 'string', enum: ['execute', 'write', 'readwrite'], default: 'execute' },
          backend: { type: 'string', enum: ['auto', 'x64dbg', 'bochs', 'win32'] },
          guest_profile: { type: 'string' },
          guest_binding_sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' },
          control: { type: 'string', enum: ['claim', 'takeover', 'release'] },
          expected_stop_seq: { type: 'number' },
          expected_run_id: { type: 'string' },
          reg: { type: 'string' },
          value: { type: 'string' },
          ea: { type: 'string' },
          rva: { type: 'string' },
          address_space: { type: 'string', enum: ['runtime', 'database', 'rva'] },
          max_steps: { type: 'number' },
          api_names: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 64 },
          max_api_calls: { type: 'number' },
          max_apis: { type: 'number' },
          record_trace: { type: 'boolean' },
          record_image: { type: 'boolean' },
          record_events: { type: 'boolean' },
          until: { type: 'string' },
          interrupt_method: { type: 'string', enum: ['native-pause', 'break-process'] },
          thread_id: { type: 'number' },
          anti_debug_profile: { type: 'string', enum: ['none', 'scyllahide-thread-context'] },
          exception_disposition: { type: 'string', enum: ['preserve', 'handled'] },
          trace_inputs: { type: 'array', minItems: 2, maxItems: 2, items: { type: 'string', enum: ['dil', 'sil', 'di', 'si', 'edi', 'esi', 'rdi', 'rsi', 'cl', 'dl', 'cx', 'dx', 'ecx', 'edx', 'rcx', 'rdx'] } },
          trace_output: { type: 'string', enum: ['al', 'ax', 'eax', 'rax'] },
          expected: { type: 'string' },
          size: { type: 'number' },
          hex: { type: 'string' },
          path: { type: 'string' },
          args: { type: 'array', maxItems: 32, items: { type: 'string' } },
          cwd: { type: 'string' },
          timeout: { type: 'number' },
        },
        required: ['target', 'op'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const op = requireString(args, 'op');
        if (!['load', 'start', 'bpt', 'unbpt', 'regs', 'setreg', 'threads', 'callstack', 'step', 'stepover', 'cont', 'suspend', 'readmem', 'writemem', 'stop', 'state', 'event', 'modules', 'trace', 'apitrace', 'recover'].includes(op)) {
          throw new Error(`unknown dbg op: ${op}`);
        }
        if (args.guest_profile !== undefined || args.guest_binding_sha256 !== undefined || op === 'recover') {
          if (args.backend !== 'x64dbg' || typeof args.guest_profile !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(args.guest_profile)
              || !/^[a-f0-9]{64}$/.test(args.guest_binding_sha256 || '')) throw new Error('Guest debugging requires backend=x64dbg, guest_profile and its inspected guest_binding_sha256');
        }
        if (op === 'recover') {
          validateGuestRecoveryArgs(args);
          return mgr.recoverGuest(target, args);
        }
        if (op === 'bpt' && args.kind === 'hardware' && args.size !== undefined && ![1, 2, 4, 8].includes(args.size)) throw new Error('Hardware breakpoint size must be 1, 2, 4 or 8');
        if (args.record_trace !== undefined && typeof args.record_trace !== 'boolean') throw new Error('record_trace must be boolean');
        if (args.record_trace && op !== 'trace') throw new Error('record_trace requires op=trace');
        if (args.record_image !== undefined && typeof args.record_image !== 'boolean') throw new Error('record_image must be boolean');
        if (args.record_image && !args.record_trace) throw new Error('record_image requires record_trace=true');
        if (args.record_events !== undefined && typeof args.record_events !== 'boolean') throw new Error('record_events must be boolean');
        if (args.record_events && !args.record_trace) throw new Error('record_events requires record_trace=true');
        if ((args.trace_inputs || args.trace_output) && !args.record_trace) throw new Error('Trace recovery registers require record_trace=true');
        if (args.until !== undefined && op !== 'trace') throw new Error('until requires op=trace');
        if (args.api_names !== undefined) {
          if (op !== 'apitrace') throw new Error('api_names requires op=apitrace');
          if (!Array.isArray(args.api_names) || args.api_names.length < 1 || args.api_names.length > 64
              || args.api_names.some(name => typeof name !== 'string' || !name || name.length > 64 || /[\x00-\x1f\x7f]/.test(name))) {
            throw new Error('api_names requires 1..64 printable names of at most 64 characters');
          }
        }
        if (args.max_api_calls !== undefined && (op !== 'apitrace' || !Number.isSafeInteger(args.max_api_calls) || args.max_api_calls < 1 || args.max_api_calls > 1024)) throw new Error('max_api_calls requires op=apitrace and an integer in 1..1024');
        if (args.max_apis !== undefined && (op !== 'apitrace' || !Number.isSafeInteger(args.max_apis) || args.max_apis < 1 || args.max_apis > 256)) throw new Error('max_apis requires op=apitrace and an integer in 1..256');
        if (args.interrupt_method !== undefined && (op !== 'suspend' || !['native-pause', 'break-process'].includes(args.interrupt_method))) throw new Error('interrupt_method requires a typed op=suspend choice');
        if (args.thread_id !== undefined && (op !== 'regs' || !Number.isSafeInteger(args.thread_id) || args.thread_id <= 0 || args.thread_id >= 2 ** 32)) throw new Error('thread_id requires op=regs and a positive DWORD thread ID');
        if (args.anti_debug_profile !== undefined && (!['none', 'scyllahide-thread-context'].includes(args.anti_debug_profile) || args.anti_debug_profile !== 'none' && (op !== 'start' || args.backend !== 'x64dbg'))) throw new Error('anti_debug_profile requires an explicit typed x64dbg start');
        if (args.exception_disposition !== undefined && (!['preserve', 'handled'].includes(args.exception_disposition) || args.exception_disposition !== 'preserve' && (op !== 'cont' || args.backend !== 'x64dbg'))) throw new Error('exception_disposition requires an explicit typed x64dbg continuation');
        if (args.record_trace && args.max_steps !== undefined && (!Number.isSafeInteger(args.max_steps) || args.max_steps < 1 || args.max_steps > 512)) throw new Error('Recorded trace max_steps must be 1..512');
        if (args.trace_inputs && !['dil,sil', 'di,si', 'edi,esi', 'rdi,rsi', 'cl,dl', 'cx,dx', 'ecx,edx', 'rcx,rdx'].includes(args.trace_inputs.join(','))) throw new Error('Trace inputs must be an explicit equal-width RDI/RSI or RCX/RDX pair');
        let launchCmdArgs;
        let launchArgv;
        let launchDir;
        if (args.args !== undefined || args.cwd !== undefined) {
          if (op !== 'start' || args.guest_profile !== undefined || (args.backend !== undefined && !['auto', 'x64dbg'].includes(args.backend))) {
            throw Object.assign(new Error('args and cwd require local x64dbg op=start'), { code: 'INVALID_ARGUMENT' });
          }
          if (args.args !== undefined) {
            if (!Array.isArray(args.args) || args.args.length > 32 || args.args.some(a => typeof a !== 'string' || a.length > 512 || /[\x00\r\n]/.test(a))) {
              throw Object.assign(new Error('args must be an array of 0..32 single-line strings (<= 512 chars each)'), { code: 'INVALID_ARGUMENT' });
            }
            launchArgv = [...args.args];
            launchCmdArgs = formatWindowsCommandLineArgs(launchArgv);
          }
          if (args.cwd !== undefined) {
            if (typeof args.cwd !== 'string' || !args.cwd.trim() || args.cwd.includes('\0')) {
              throw Object.assign(new Error('cwd must be a non-empty directory path'), { code: 'INVALID_ARGUMENT' });
            }
            const resolvedCwd = path.resolve(args.cwd.trim());
            let st = null;
            try { st = fs.lstatSync(resolvedCwd); } catch { st = null; }
            if (!st || st.isSymbolicLink() || !st.isDirectory()) {
              throw Object.assign(new Error('cwd must be an existing regular non-symlink directory'), { code: 'INVALID_ARGUMENT' });
            }
            launchDir = resolvedCwd;
          }
        }
        const timeout = debugTimeout(args, cfg);
        return mgr.rpc(mgr.get(target), 'dbg', {
          op,
          backend: args?.backend || 'auto',
          guest_profile: args.guest_profile, guest_binding_sha256: args.guest_binding_sha256,
          kind: args.kind || 'software', access: args.access || 'execute',
          reg: args?.reg,
          value: args?.value,
          ea: args?.ea || '',
          size: args?.size,
          hex: args?.hex || '',
          path: args?.path || '',
          ...(launchArgv !== undefined ? { args: launchCmdArgs, argv: launchArgv } : {}),
          ...(launchDir !== undefined ? { dir: launchDir } : {}),
          timeout: timeout.seconds,
          rva: args.rva, count: args.max_steps, addressSpace: args.address_space, expected: args.expected,
          api_names: args.api_names, max_api_calls: args.max_api_calls, max_apis: args.max_apis,
          record_trace: args.record_trace, record_image: args.record_image, record_events: args.record_events, until: args.until, trace_inputs: args.trace_inputs, trace_output: args.trace_output,
          interrupt_method: args.interrupt_method,
          thread_id: args.thread_id,
          anti_debug_profile: args.anti_debug_profile,
          exception_disposition: args.exception_disposition,
          control: args.control, expected_stop_seq: args.expected_stop_seq, expected_run_id: args.expected_run_id,
        }, timeout.rpcTimeoutMs);
      },
    },
    {
      name: 'ig5_export_diff',
      description: 'Export patched binary copy and changes report from current DB bytes.',
      parameters: {
        type: 'object',
        properties: { target: { type: 'string' } },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        return exportPatchDiff({ target: requireString(args, 'target'), mgr, cfg });
      },
    },
    {
      name: 'ig5_struct',
      description: 'Define, inspect, list, or apply local C structs (define/apply WRITE OPERATION, approval-gated).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          action: { type: 'string', enum: ['define', 'get', 'list', 'apply'] },
          decl: { type: 'string' },
          name: { type: 'string' },
          ea: { type: 'string' },
          filter: { type: 'string' },
          limit: { type: 'number' },
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
      description: 'Read-only function basic-block CFG and Mermaid flowchart.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          ea: { type: 'string' },
          name: { type: 'string' },
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
      description: 'Read-only decompiler variable metadata and optional lexical line filter (not full taint/def-use slice).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          ea: { type: 'string' },
          var: { type: 'string' },
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
      description: 'Read-only compiler/ABI info and provider function classifications.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string' },
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
    ...defineCaptureTools(ctx, mgr, cfg, textRender),
  ];
}

// ── ig5dash 会话投影（只折叠已提交的 tool 事件，model-visible ⟺ logged） ────
// ── 插件入口（具名导出，无 default export） ─────────────────────────────────
export const name = PLUGIN_ID;
export const inject = ['tools', 'sessionProjections'];

export function apply(ctx, config = {}) {
  const cfg = resolveConfig(config);
  diagAppend(cfg, `host: implementation=${IMPLEMENTATION_REVISION} module=${fileURLToPath(import.meta.url)}`);
  const mgr = new WorkerManager(cfg);
  // AnalysisArtifacts is installed by defineAnalysisTools later in registration.
  let failureRecords, capabilityAcceptance, rootInvestigations;
  Object.defineProperties(mgr, {
    failures: { get: () => failureRecords ||= new FailureRecords({ root: cfg.projectRoot, artifacts: mgr.analysis.artifacts }) },
    capabilityAcceptance: { get: () => capabilityAcceptance ||= new CapabilityAcceptance({ root: cfg.projectRoot, artifacts: mgr.analysis.artifacts, cfg }) },
    rootInvestigations: {
      get: () => rootInvestigations ||= new RootInvestigationStore({ projectRoot: cfg.projectRoot }),
      set: (value) => { rootInvestigations = value; },
      configurable: true,
    },
  });
  mgr.coordination = installDelegationControl(ctx, cfg);
  mgr.memory = installLcmBridge(ctx, cfg);
  const autonomyHost = installAutonomyHost(ctx, { cfg, getManager: () => mgr });
  mgr.autonomyHost = autonomyHost;
  ctx.effect(() => () => {
    autonomyHost.dispose();
    mgr.memory.dispose();
  });
  installDiagRoute(ctx, cfg);
  installJobsRoute(ctx, mgr, cfg);
  installDataRoute(ctx, mgr, cfg);
  installApprovalGate(ctx, cfg, {
    beforePreExecute: autonomyHost.beforePreExecute,
    isAuthorizedOwnerCleanup: (exec) => {
      const { cleanArgs } = parseAndStripResearch(exec?.arguments);
      return mgr.coordination.hasActiveOwnerCleanup(exec?.agent, exec?.name, cleanArgs, {
        allowLocalFallback: exec?.agent?.session === undefined,
      });
    },
  });

  ctx.effect(() => {
    const definitions = defineIg5Tools(ctx, mgr, cfg).map((definition) => {
      const execute = definition.execute;
      if (definition.name === 'ig5_profile') {
        definition.parameters.properties.address = { type: 'object', properties: {
          value: { type: 'string' }, space: { type: 'string', enum: ['ghidra_va','elf_vaddr','file_offset','module_offset','runtime_va'] },
          to_space: { type: 'string', enum: ['ghidra_va','elf_vaddr','file_offset','module_offset','runtime_va'] } },
          required: ['value','space','to_space'], additionalProperties: false };
        definition.parameters.properties.capabilities = { type: 'boolean', const: true };
        definition.parameters.properties.memory = memorySchema;
        definition.parameters.properties.knowledge = knowledgeSchema;
      }
      const isCapture = ['ig5_capture', 'ig5_capture_control', 'ig5_app_observe'].includes(definition.name);
      const isGlobal = isCapture || ['ig5_profile', 'ig5_workspace', 'ig5_recovery', 'ig5_status', 'ig5_crypto', 'ig5_protocol', 'ig5_package'].includes(definition.name);
      const isData = isCapture || ['ig5_crypto', 'ig5_protocol', 'ig5_package'].includes(definition.name);
      if (!isCapture) definition.parameters.properties.engine = { type: 'string', enum: definition.name === 'ig5_doctor'
        ? ['reverse', 'ghidra', 'x64dbg'] : ['reverse', 'ghidra'] };
      if (definition.name === 'ig5_profile') definition.parameters.properties.collaboration = {
        type: 'object', properties: { action: { type: 'string', enum: ['start', 'status'] },
          max_calls: { type: 'integer', minimum: 1, maximum: 1000 } },
        required: ['action'], additionalProperties: false };
      if (!isCapture && IG5_WRITE_TOOLS.has(definition.name) && definition.name !== 'ig5_sync') definition.parameters.properties.expected_revision = {
        type: 'number' };
      if (!['ig5_profile', 'ig5_workspace', 'ig5_doctor', 'ig5_status'].includes(definition.name)) {
        definition.parameters.properties.research = RESEARCH_BINDING_SCHEMA;
      }
      definition.execute = (rawArgs = {}, execution) => runManagedToolExecution({
        mgr,
        toolName: definition.name,
        rawArgs,
        execution,
        runCore: (cleanArgs, effectiveSignal, dispatchContext) => mgr.scope.run({
          engine: cleanArgs.engine || (definition.name === 'ig5_ir' && cfg.reverseProvider !== 'bundled' ? 'ghidra' : cfg.defaultEngine),
          agentId: execution?.agent?.id || execution?.agent?.sessionId,
          signal: effectiveSignal,
        }, async () => {
          let args = cleanArgs;
          try {
          if (effectiveSignal?.aborted) throw new Error('IG5 operation cancelled');
          await mgr.memory.activate(execution?.agent);
          if (args.engine) engineId(args.engine);
          const selected = !args.target && !isGlobal && !['ig5_open', 'ig5_doctor', 'ig5_bindiff', 'ig5_sync'].includes(definition.name)
            && !definition.parameters.required?.includes('target') ? mgr.selectedTarget() : args.target;
          if (selected) args = { ...args, target: selected };
          const standaloneKernel = definition.name === 'ig5_ir' && ['kernel', 'trace', 'lift', 'project'].includes(args.level);
          const session = selected && !isData && !standaloneKernel ? mgr.get(selected) : null;
          const selectedAttachment = session?.attachmentId;
          const perform = async () => {
          if (session?.state === 'opening') {
            await mgr.launching.get(session.key);
            if (session.state !== 'open' || mgr.get(session.target, session.engine) !== session) throw new Error('Target did not finish opening');
          }
          // A failed predecessor can recycle its worker while this operation is
          // queued. execute() resolves target again; never let old planning and
          // expected_revision checks transfer to a newly opened attachment.
          if (session && (mgr.get(session.target, session.engine) !== session
            || selectedAttachment !== undefined && session.attachmentId !== selectedAttachment)) {
            throw Object.assign(new Error('Target session changed while this operation was queued; reopen its context and review the operation again'), { code: 'STALE_SESSION_CONTEXT' });
          }
          mgr.checkCancelled();
          if (session?.closing) throw new Error('Target is closing; wait for it to finish');
          if (args.expected_revision !== undefined && (!session || session.dbRevision !== args.expected_revision)) {
            throw new Error('Database revision changed; read current evidence and review the operation again');
          }
          const nextExec = execution
            ? { ...execution, signal: effectiveSignal, _boundScenarioSnapshot: dispatchContext?.boundScenarioSnapshot || null }
            : (dispatchContext?.boundScenarioSnapshot ? { signal: effectiveSignal, _boundScenarioSnapshot: dispatchContext.boundScenarioSnapshot } : execution);
          let result = await execute(args, nextExec);
          if (['ig5_xrefs','ig5_calls','ig5_cfg'].includes(definition.name) && result && typeof result === 'object') {
            const rows = result.hits || result.calls || result.blocks || [];
            const total = result.total ?? result.total_blocks;
            const truncated = result.truncated === true || Number.isSafeInteger(total) && total > rows.length;
            const incomplete = session?.info?.analysisComplete === false || session?.info?.partial === true;
            result = { ...result, queryState: { status: result.error ? 'error' : truncated ? 'truncated' : incomplete ? 'analysis_incomplete' : rows.length ? 'observed' : 'empty',
              empty: rows.length === 0, returned: rows.length, total: Number.isSafeInteger(total) ? total : null,
              analysisComplete: typeof session?.info?.analysisComplete === 'boolean' ? session.info.analysisComplete : null,
              coverage: 'provider-observations-only', unresolvedIndirectCalls: 'unknown' } };
          }
          if (definition.name === 'ig5_decompile' && args.style === 'dossier' && args.operation !== 'read') {
            try { mgr.capabilityAcceptance.registerDossier(result); }
            catch (error) { diagAppend(cfg, `host: capability acceptance not indexed: ${error.code || 'ACCEPTANCE_RECORD_FAILED'}`); }
          }
          return jsonToolOutput(result && typeof result === 'object' && !Array.isArray(result) && session && !isGlobal
            ? { ...result, _ig5: result._ig5 || mgr.evidence(session) } : result);
          };
          const batchControl = definition.name === 'ig5_decompile' && args.operation === 'batch' && ['cancel','status'].includes(args.batch?.action);
          const queuedRead = definition.name === 'ig5_decompile' && !batchControl || definition.name === 'ig5_workspace' || definition.name === 'ig5_profile' && args.address !== undefined;
          if (!session || !(IG5_WRITE_TOOLS.has(definition.name) || definition.name === 'ig5_export_diff' || queuedRead) || ['ig5_sync', 'ig5_dbg'].includes(definition.name)) return await perform();
          return await mgr.withSessions([session], perform);
          } catch (error) {
            // Keep the original Error/receipt and rejection semantics. Diagnostics are advisory.
            try {
              const current = args.target ? mgr.get(args.target) : null;
              const scope = current && mgr.alive(current) ? mgr.evidence(current) : null;
              const failure = mgr.failures.add({ operation: definition.name, scope, ...failureBinding(definition.name, args, mgr, error), error,
                planningKey: planningRequestKey({ tool: definition.name, ...args }, scope, planningImplementationDigest),
                runtimeDigest: runtimeIdentity(cfg, definition.name==='ig5_dbg'?'x64dbg':current?.engine||args.engine||cfg.defaultEngine),
                ...(error.analysisFailure?.failedStage || error.stage ? { failedStage: error.analysisFailure?.failedStage || error.stage } : {}) });
              if (error && typeof error === 'object' && Object.isExtensible(error)) error.investigationFailure = failure;
            } catch (diagnosticError) {
              if(error&&typeof error==='object'&&Object.isExtensible(error))error.investigationFailureStatus={persisted:false,code:diagnosticError.code||'FAILURE_RECORD_UNAVAILABLE'};
            }
            throw error;
          }
        }),
      });
      return definition;
    });
    const workflow = installWorkflow(ctx, { cfg, mgr, definitions, formatError: publicEngineError });
    mgr.workflow = workflow;
    return async () => {
      await workflow.dispose();
      await mgr.capture?.dispose();
      await mgr.appObserver?.dispose();
      await mgr.androidProvider?.dispose();
      await mgr.analysis?.dispose();
      await mgr.kernel?.dispose();
      await mgr.trace?.dispose();
      await mgr.lifter?.dispose();
      await Promise.all([...mgr.sessions.values()].filter((s) => s.engine !== 'x64dbg').map((s) => mgr.close(s.target, true, s.engine, { force: true })));
      await Promise.all([...mgr.sessions.values()].map((s) => mgr.close(s.target, true, s.engine, { force: true })));
    };
  }, `${PLUGIN_ID}: ig5 tool surface`);

  const projections = ctx.get('sessionProjections');
  if (projections !== undefined && typeof projections.register === 'function') {
    ctx.effect(() => projections.register(ig5DashDefinition(), `${PLUGIN_ID}: ig5dash projection`));
  }
}
