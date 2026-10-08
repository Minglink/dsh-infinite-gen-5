import { spawn } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { installWorkflow } from './workflow.js';
import { defineAdvancedTools } from './advanced_tools.js';

// ── 无限五代（IG5）v0.9.0 ──────────────────────────────────────────────────
// DeepSeek Harness 纯逆向插件：Reverse 无头引擎 Worker 池 + ig5_* 工具面 + ig5dash 投影。
// 零提示词注入；指导载体 = 工具描述 + 会话流卡片。

const PLUGIN_ID = 'dsh-infinite-gen-5';
const PLUGIN_VERSION = '0.9.0';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKER = path.join(HERE, 'worker', 'ig5_worker.py');

// ── Config（cordis.yml 插件行可覆盖；misconfiguration fails loud） ──────────
function resolveConfig(cfg = {}) {
  const idaDir = cfg.idaDir || process.env.IG5_IDA_DIR || findIdaDir();
  if (!idaDir) {
    throw new Error(
      `[${PLUGIN_ID}] Reverse 安装目录未找到。请在 cordis.yml 的插件行 config 里设置 idaDir，` +
      `或设置环境变量 IG5_IDA_DIR。`,
    );
  }
  if (!fs.existsSync(path.join(idaDir, 'idalib'))) {
    throw new Error(`[${PLUGIN_ID}] Reverse 安装目录中缺少引擎库，请检查 idaDir 配置。`);
  }
  const pythonCandidates = [
    cfg.pythonExe,
    path.join(idaDir, 'python311', 'python.exe'),
    'python',
  ].filter(Boolean);
  const pythonExe = pythonCandidates.find((p) => p === 'python' || fs.existsSync(p)) || 'python';
  return {
    idaDir,
    pythonExe,
    requestTimeoutMs: Number(cfg.requestTimeoutMs ?? 240_000),
    // 后台分析是长任务：单独一档超时，别让 240s 的短超时杀掉大二进制
    openTimeoutMs: Number(cfg.openTimeoutMs ?? 1_800_000),
    maxSessions: Number(cfg.maxSessions ?? 3),
    artifactDir: cfg.artifactDir || path.join(os.homedir(), '.dsh', 'ig5', 'artifacts'),
    autoOpenHint: cfg.autoOpenHint !== false,
    backgroundOpen: cfg.backgroundOpen !== false,
    toolset: cfg.toolset || 'core',
  };
}

function findIdaDir() {
  const roots = [
    path.join(os.homedir(), 'Desktop'),
    'C:\\Program Files',
    'C:\\Program Files (x86)',
  ];
  for (const root of roots) {
    try {
      for (const entry of fs.readdirSync(root)) {
        if (/^IDA\b/i.test(entry)) {
          const candidate = path.join(root, entry);
          if (fs.existsSync(path.join(candidate, 'idalib', 'python'))) return candidate;
        }
      }
    } catch {
      // unreadable root — skip
    }
  }
  return null;
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
  }

  sessionKey(target) {
    return path.resolve(String(target)).toLowerCase();
  }

  get(target) {
    return this.sessions.get(this.sessionKey(target));
  }

  alive(session) {
    return !!session && !!session.proc && session.proc.exitCode === null && session.ready;
  }

  spawnWorker() {
    let child;
    try {
      child = spawn(
        this.cfg.pythonExe,
        ['-X', 'utf8', WORKER, '--ida-dir', this.cfg.idaDir],
        {
          stdio: ['pipe', 'pipe', 'pipe'],
          windowsHide: true,
          // Windows Python otherwise decodes stdio with the ANSI code page and a
          // non-ASCII target path arrives as mojibake.
          env: { ...process.env, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' },
        },
      );
    } catch (error) {
      throw new Error(publicEngineError(error, this.cfg));
    }
    child.stderr?.on('data', (d) => {
      const tail = String(d);
      const s = child.__ig5;
      if (s) s.stderrTail = (s.stderrTail + tail).slice(-4000);
    });
    return child;
  }

  async open(target, autoAnalysis = true, options = {}) {
    const fresh = options.fresh === true;
    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
    const key = this.sessionKey(target);
    const existing = this.sessions.get(key);
    if (this.alive(existing)) {
      return { ...existing.info, alreadyOpen: true };
    }
    if (existing) this.killSession(key);
    const inflight = this.launching.get(key);
    if (inflight) return inflight;

    const p = (async () => {
      if (this.sessions.size >= this.cfg.maxSessions) this.closeOldest();
      const session = {
        key,
        target: path.resolve(String(target)),
        proc: null,
        ready: false,
        pending: new Map(),
        seq: 0,
        startedAt: Date.now(),
        info: null,
        lastOp: 'launching',
        lastStage: null,
        progress: null,
        stderrTail: '',
        cache: new Map(),
      };
      const proc = this.spawnWorker();
      session.proc = proc;
      proc.__ig5 = session;
      this.sessions.set(key, session);

      let buf = '';
      const onLine = (line) => {
        line = line.trim();
        if (!line) return;
        let obj = null;
        try {
          obj = JSON.parse(line);
        } catch {
          return; // IDA 插件横幅噪音，忽略
        }
        if (obj.ig5 === 'ready') {
          session.ready = true;
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
          if (obj.error) pend.reject(new Error(publicEngineError(obj.error, this.cfg).split('\n').slice(-3).join(' | ')));
          else pend.resolve(obj.result);
        }
      };
      proc.stdout.on('data', (d) => {
        buf += d.toString('utf8');
        let idx;
        while ((idx = buf.indexOf('\n')) >= 0) {
          onLine(buf.slice(0, idx));
          buf = buf.slice(idx + 1);
        }
      });

      const readyOrExit = new Promise((resolve, reject) => {
        const t = setTimeout(
          () => reject(new Error(`worker 未在 60s 内就绪\n${publicEngineError(session.stderrTail, this.cfg).slice(-600)}`)),
          60_000,
        );
        proc.once('exit', (code) => {
          clearTimeout(t);
          reject(new Error(`worker 提前退出 code=${code}\n${publicEngineError(session.stderrTail, this.cfg).slice(-600)}`));
        });
        proc.once('error', (error) => {
          clearTimeout(t);
          reject(new Error(publicEngineError(error, this.cfg)));
        });
        proc.stdout.on('data', function poll() {
          if (session.ready) {
            clearTimeout(t);
            proc.stdout.removeListener('data', poll);
            resolve();
          }
        });
      });
      await readyOrExit;
      proc.removeAllListeners('exit');
      proc.on('exit', (code) => {
        session.ready = false;
        for (const pending of session.pending.values()) {
          clearTimeout(pending.timer);
          pending.reject(new Error(publicEngineError(`worker exited code=${code}: ${session.stderrTail.slice(-600)}`, this.cfg)));
        }
        session.pending.clear();
        if (this.sessions.get(key) === session) this.sessions.delete(key);
      });

      session.lastOp = 'open';
      session.progress = null;
      session.info = await this.rpc(
        session,
        'open',
        { path: session.target, auto: !!autoAnalysis, fresh, progress: true },
        this.cfg.openTimeoutMs,
        onProgress,
      );
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
    if (!this.alive(session)) throw new Error(publicEngineError(`worker 不在运行（目标：${session?.target ?? '?'}），请先 ig5_open`, this.cfg));
    const id = ++session.seq;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        session.pending.delete(id);
        this.killSession(session.key); // 超时 = 进程级回收，守护逻辑的最小集
        reject(new Error(`worker rpc 超时（${method}，${timeoutMs}ms），已回收该 worker，可重新 ig5_open`));
      }, timeoutMs);
      session.pending.set(id, {
        resolve,
        reject,
        timer,
        onProgress: typeof onProgress === 'function' ? onProgress : undefined,
      });
      session.lastOp = method;
      session.proc.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    }).catch((error) => { throw new Error(publicEngineError(error, this.cfg)); });
  }

  closeOldest() {
    let oldest = null;
    for (const s of this.sessions.values()) {
      if (!oldest || s.startedAt < oldest.startedAt) oldest = s;
    }
    if (oldest) this.killSession(oldest.key);
  }

  killSession(key) {
    const s = this.sessions.get(key);
    if (!s) return;
    for (const [, pend] of s.pending) {
      clearTimeout(pend.timer);
      pend.reject(new Error('worker 已被关闭'));
    }
    s.pending.clear();
    try {
      s.proc?.kill();
    } catch {
      // already dead
    }
    this.sessions.delete(key);
  }

  close(target, save = false) {
    const key = this.sessionKey(target);
    const s = this.sessions.get(key);
    if (!s) return false;
    if (save && this.alive(s)) {
      try {
        this.rpc(s, 'ping', {}, 5000);
      } catch {
        // best effort
      }
    }
    this.killSession(key);
    return true;
  }

  status() {
    return [...this.sessions.values()].map((s) => ({
      target: s.target,
      alive: this.alive(s),
      ready: s.ready,
      pid: s.proc?.pid ?? null,
      uptimeMs: Date.now() - s.startedAt,
      lastOp: s.lastOp,
      lastStage: s.lastStage ?? null,
      progress: s.progress ?? null,
      n_funcs: s.info?.n_funcs ?? null,
      bits: s.info?.bits ?? null,
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
      config: { engine: 'Reverse (headless)', maxSessions: this.cfg.maxSessions, openTimeoutMs: this.cfg.openTimeoutMs,
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
]);

function installApprovalGate(ctx, cfg) {
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (!IG5_WRITE_TOOLS.has(exec?.name)) return next();
    const args = exec?.arguments ?? {};
    const what = args?.ea ?? args?.name ?? args?.target ?? '';
    return {
      kind: 'ask',
      reason: `IG5 写操作待批准: ${exec.name} @ ${what}`,
      displayReason: {
        en: `IG5 operation "${exec.name}" needs one-time approval before mutation or execution.`,
        zh: `IG5 操作「${exec.name}」（${what}）涉及修改或执行，需要你批准一次。`,
      },
    };
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
          const structAction = url.searchParams.get('action') || 'list';
          if (type === 'struct' && !['list', 'get'].includes(structAction)) {
            send(400, { error: 'Only struct list/get is supported by this read-only route' });
            return;
          }
          const session = target ? mgr.sessions.get(mgr.sessionKey(target)) : [...mgr.sessions.values()].find((s) => mgr.alive(s));
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
            try {
              const rawLines = fs.readFileSync(auditFile, 'utf8').split('\n').filter(Boolean);
              const items = rawLines.map((l) => { try { return JSON.parse(l); } catch { return null; } })
                .filter((item) => item?.args?.target && mgr.sessionKey(item.args.target) === mgr.sessionKey(session.target)).reverse();
              const offset = Math.max(0, params.offset || 0), limit = Math.max(1, Math.min(params.limit || 30, 200));
              send(200, { target: session.target, type, data: { rows: items.slice(offset, offset + limit), total: items.length, offset, limit } });
            } catch (err) {
              send(200, { error: publicEngineError(err, cfg) });
            }
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
          if (['disasm', 'stack', 'switches', 'vtables', 'microcode'].includes(type)) {
            params.ea = url.searchParams.get('ea') || '';
            params.name = url.searchParams.get('name') || '';
          }
          if (type === 'disasm') params.size = Number(url.searchParams.get('size') || 1024);
          if (type === 'microcode') {
            params.action = 'inspect'; // UI route cannot request an optimization or repair.
            params.maturity = url.searchParams.get('maturity') || 'generated';
          }
          Promise.resolve()
            .then(() => mgr.rpc(session, type, params, 60_000))
            .then((data) => send(200, { target: session.target, type, data }))
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
  const spill = (target, ea, code) => {
    const slug = path.basename(target).replace(/[^\w.-]+/g, '_');
    const dir = path.join(cfg.artifactDir, slug);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `func_${ea}.c`);
    fs.writeFileSync(file, code, 'utf8');
    return file;
  };

  return [
    {
      name: 'ig5_profile',
      description:
        'Return runtime metadata, active tools and skills for the 无限五代 Reverse plugin. Optionally switch toolset to core (8 frequent tools) or full (all 34 tools) for this plugin instance. Switching is immediate across sessions and is not persisted.',
      parameters: { type: 'object', properties: { toolset: { type: 'string', enum: ['core', 'full'] } }, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      execute(args = {}) {
        if (args.toolset !== undefined) {
          if (!mgr.workflow) throw new Error('IG5 workflow is not ready');
          mgr.workflow.setToolset(args.toolset);
        }
        return {
          plugin: PLUGIN_ID,
          version: PLUGIN_VERSION,
          engine: 'Reverse (headless)',
          ...(mgr.workflow?.snapshot() || { toolset: cfg.toolset || 'core' }),
          engineConfigured: !!cfg.idaDir,
          pythonConfigured: !!cfg.pythonExe,
          requestTimeoutMs: cfg.requestTimeoutMs,
          maxSessions: cfg.maxSessions,
          tools: [
            'ig5_doctor', 'ig5_open', 'ig5_status', 'ig5_funcs', 'ig5_strings',
            'ig5_decompile', 'ig5_xrefs', 'ig5_calls', 'ig5_bytes', 'ig5_search',
            'ig5_listing', 'ig5_scan', 'ig5_export_diff', 'ig5_cfg', 'ig5_slice', 'ig5_fingerprint',
            'ig5_rename*', 'ig5_patch_bytes*', 'ig5_comment*', 'ig5_analyze*', 'ig5_set_type*',
            'ig5_undo*', 'ig5_run_idapython*', 'ig5_dbg*', 'ig5_struct*', 'ig5_close', 'ig5_profile',
            'ig5_stack', 'ig5_switches', 'ig5_switch_repair*', 'ig5_vtables', 'ig5_microcode', 'ig5_bindiff', 'ig5_emulate*',
          ],
          writeGated: [...IG5_WRITE_TOOLS],
          lineage: 'dsh-infinite-gen-4 (提示词层) -> dsh-infinite-gen-5 (纯逆向工具面, 零提示词注入)',
        };
      },
    },
    {
      name: 'ig5_doctor',
      description:
        'Bootstrap self-check for the IG5 headless Reverse engine: verifies the engine install dir, the bundled Python runtime, and that the Reverse library loads. Run this first if any other ig5 tool fails.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute() {
        let child;
        try {
          child = mgr.spawnWorker();
          const result = await new Promise((resolve, reject) => {
            let buf = '';
            const t = setTimeout(() => reject(new Error('doctor 超时')), 60_000);
            child.stdout.on('data', (d) => {
              buf += d.toString('utf8');
              let idx;
              while ((idx = buf.indexOf('\n')) >= 0) {
                const line = buf.slice(0, idx).trim();
                buf = buf.slice(idx + 1);
                if (!line) continue;
                try {
                  const obj = JSON.parse(line);
                  if (obj.id === 0) {
                    clearTimeout(t);
                    if (obj.error) reject(new Error(obj.error));
                    else resolve(obj.result);
                    return;
                  }
                } catch {
                  // noise
                }
              }
            });
            child.once('exit', (code) => {
              clearTimeout(t);
              reject(new Error(`doctor worker exit code=${code}`));
            });
            child.once('error', (error) => {
              clearTimeout(t);
              reject(error);
            });
            child.stdin.write(JSON.stringify({ id: 0, method: 'doctor', params: {} }) + '\n');
          });
          return {
            ok: true,
            engine: 'Reverse (headless)',
            python: result.python,
            runtimeReady: result.idalib === 'loaded',
            caps: {
              planAndWait: result.caps?.['ida_auto.plan_and_wait'] === true,
              wait: result.caps?.['ida_auto.auto_wait'] === true,
              makeCode: result.caps?.['ida_auto.auto_make_code'] === true,
            },
            artifactDir: cfg.artifactDir,
          };
        } catch (error) {
          throw new Error(publicEngineError(error, cfg));
        } finally {
          try {
            child?.kill();
          } catch {
            // already dead
          }
        }
      },
    },
    {
      name: 'ig5_open',
      description:
        'Open a binary (PE/ELF/Mach-O/dex/so) in a headless Reverse worker and run auto-analysis. Returns target info: architecture, bitness, segments, function count, entries. One worker process per target; call this before ig5_funcs / ig5_strings / ig5_decompile. By default the analysis runs as a background job (progress is visible in the IG5 workbench; collect the result with job_output) — pass background:false only for a small binary you want inline.',
      parameters: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Absolute path of the target binary' },
          auto_analysis: { type: 'boolean', description: 'Run full auto-analysis (default true)' },
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

        const runInline = async () => {
          const info = await mgr.open(target, auto, {
            fresh,
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
                  onProgress: (p) => {
                    job.updateProgress(formatProgress(p));
                    mgr.noteProgress(target, p, job.id);
                  },
                });
                const summary = `IG5 分析完成: ${path.basename(info.target ?? target)} · ${info.n_funcs} 函数 · ${info.bits} 位 · ${((info.elapsedMs ?? 0) / 1000).toFixed(1)}s`;
                job.append(summary + '\n', { channel: 'stdout' });
                mgr.finishJob(job.id, 'completed', `${info.n_funcs} 函数`);
                return { status: 'completed', detail: `${info.n_funcs} 函数`, result: JSON.stringify(dimsOf(info)) };
              } catch (e) {
                const msg = publicEngineError(e, cfg);
                job.append(`IG5 分析失败: ${msg}\n`, { channel: 'stderr' });
                mgr.finishJob(job.id, 'failed', msg.slice(0, 200));
                return { status: 'failed', detail: msg.slice(0, 200) };
              }
            })();
            return {
              cancel: (reason) => {
                mgr.close(target);
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
        return { sessions, count: sessions.length, config: { engine: 'Reverse (headless)', maxSessions: cfg.maxSessions } };
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
        'Decompile one function to C-like pseudocode with Reverse. Address the function by EA (hex, e.g. "0x140001070") or exact name. style=llm also returns meta: callees with ref counts and referenced strings (cheaper for model consumption). Results over ~12KB spill to an artifacts .c file and the tool returns its path plus a preview.',
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
        const key = `${args?.ea ?? ''}|${args?.name ?? ''}|${style}`;
        let result = session.cache.get(key);
        if (!result) {
          result = await mgr.rpc(session, 'decompile', { ea: args?.ea, name: args?.name, style });
          session.cache.set(key, result);
        }
        const code = String(result.code ?? '');
        const base = {
          ea: result.ea,
          name: result.name,
          size: result.size,
          lines: result.lines,
          target: session.target,
          ...(result.meta ? { meta: result.meta } : {}),
        };
        if (code.length > 12_000) {
          const file = spill(session.target, result.ea, code);
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
      execute(args) {
        const target = requireString(args, 'target');
        const existed = mgr.close(target);
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
        'Explicit Reverse analysis-engine control: create_function, delete_function, undefine, mark_code, reanalyze. WRITE OPERATION: approval-gated and recorded.',
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
        'Static intelligence sweep: crypto constants (AES/MD5/SHA-256/CRC32 markers), suspicious imported APIs, per-segment entropy (>7.2 flagged as packed/encrypted), string families. Returns a structured recon report. Read-only.',
      parameters: {
        type: 'object',
        properties: { target: { type: 'string', description: 'Target path previously opened with ig5_open' } },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        return mgr.rpc(mgr.get(target), 'scan', {});
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
        'Debug lane over Reverse debuggers; backend auto, bochs, or win32. op: load | start | bpt | unbpt | regs | setreg | step | stepover | cont | suspend | readmem | writemem | stop. Reports bounded debug events, process state and exception context. Approval-gated (start executes the debuggee).',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          op: {
            type: 'string',
            description: 'load | start | bpt | unbpt | regs | setreg | step | stepover | cont | suspend | readmem | writemem | stop',
          },
          backend: { type: 'string', enum: ['auto', 'bochs', 'win32'], description: 'Explicit debugger selection for load; default auto prefers bochs' },
          reg: { type: 'string', description: 'Register name for setreg' },
          value: { type: 'string', description: 'Integer register value for setreg, decimal or hex' },
          ea: { type: 'string', description: 'Hex address (bpt/unbpt/readmem/writemem)' },
          size: { type: 'number', description: 'Byte count (readmem, default 64)' },
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
        if (!['load', 'start', 'bpt', 'unbpt', 'regs', 'setreg', 'step', 'stepover', 'cont', 'suspend', 'readmem', 'writemem', 'stop'].includes(op)) {
          throw new Error(`unknown dbg op: ${op}`);
        }
        return mgr.rpc(mgr.get(target), 'dbg', {
          op,
          backend: args?.backend || 'auto',
          reg: args?.reg,
          value: args?.value,
          ea: args?.ea || '',
          size: args?.size,
          hex: args?.hex || '',
          path: args?.path || '',
          timeout: args?.timeout,
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
        const target = requireString(args, 'target');
        const auditFile = path.join(cfg.artifactDir, 'approvals.jsonl');
        if (!fs.existsSync(auditFile)) return { target, patches: 0, note: '无审计记录' };
        const patches = [];
        for (const line of fs.readFileSync(auditFile, 'utf8').split('\n')) {
          if (!line.trim()) continue;
          let rec;
          try {
            rec = JSON.parse(line);
          } catch {
            continue;
          }
          if (rec.tool !== 'ig5_patch_bytes' || rec.isError) continue;
          if (path.resolve(rec.args?.target ?? '') !== path.resolve(target)) continue;
          const d = rec.detail ?? {};
          if (typeof d.fileOffset !== 'number' || !d.after || !d.applied) continue;
          patches.push(d);
        }
        if (!patches.length) return { target, patches: 0, note: '该目标没有已应用的字节补丁记录' };
        const original = fs.readFileSync(target);
        const patched = Buffer.from(original);
        const lines = ['# IG5 补丁报告', '', `目标: ${target}`, '', '| EA | 文件偏移 | before | after |', '|---|---|---|---|'];
        const ranges = [];
        for (const p of patches) {
          if (p.fileOffset < 0 || p.fileOffset + p.size > patched.length) {
            lines.push(`| ${p.ea} | ${p.fileOffset} | ${p.before} | (越界，跳过) |`);
            continue;
          }
          const current = await mgr.rpc(mgr.get(target), 'bytes', { ea: p.ea, size: p.size });
          const bytes = Buffer.from(current.hex || '', 'hex');
          if (bytes.length !== p.size) throw new Error('Could not read a complete audited patch region');
          bytes.copy(patched, p.fileOffset);
          ranges.push(p);
        }
        let applied = 0;
        const seen = new Set();
        for (const p of ranges) {
          const key = `${p.fileOffset}:${p.size}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const before = original.subarray(p.fileOffset, p.fileOffset + p.size).toString('hex');
          const after = patched.subarray(p.fileOffset, p.fileOffset + p.size).toString('hex');
          if (before === after) continue;
          applied++;
          lines.push(`| ${p.ea} | ${p.fileOffset} | ${before} | ${after} |`);
        }
        const slug = path.basename(target).replace(/[^\w.-]+/g, '_');
        const outBin = path.join(cfg.artifactDir, `${slug}.ig5-patched`);
        const outMd = path.join(cfg.artifactDir, `${slug}.changes.md`);
        fs.writeFileSync(outBin, patched);
        fs.writeFileSync(outMd, lines.join('\n') + '\n', 'utf8');
        return { target, patches: applied, auditedRegions: ranges.length, patchedBinary: outBin, report: outMd };
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
        const target = args?.target || [...mgr.sessions.values()].find((s) => mgr.alive(s))?.target;
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
        const target = args?.target || [...mgr.sessions.values()].find((s) => mgr.alive(s))?.target;
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
        const target = args?.target || [...mgr.sessions.values()].find((s) => mgr.alive(s))?.target;
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
    const workflow = installWorkflow(ctx, { cfg, mgr, definitions: defineIg5Tools(ctx, mgr, cfg), formatError: publicEngineError });
    mgr.workflow = workflow;
    return () => {
      workflow.dispose();
      for (const s of [...mgr.sessions.keys()]) mgr.killSession(s);
    };
  }, `${PLUGIN_ID}: ig5 tool surface`);

  const projections = ctx.get('sessionProjections');
  if (projections !== undefined && typeof projections.register === 'function') {
    ctx.effect(() => projections.register(ig5DashDefinition(), `${PLUGIN_ID}: ig5dash projection`));
  }
}
