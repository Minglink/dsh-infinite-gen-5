import { spawn } from 'node:child_process';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';

/** Engine-specific paths/environment; the JSONL transport below is engine neutral. */
export function workerLaunch(cfg, engine, pluginRoot) {
  const paths = cfg.host?.platform === 'linux' ? path.posix : path;
  const env = { ...process.env, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' };
  let executable, args;
  if (engine === 'reverse') {
    if (!cfg.reverseAvailable) throw new Error('Reverse runtime is unavailable; configure it or use engine=ghidra');
    executable = cfg.pythonExe;
    args = ['-X', 'utf8', paths.join(pluginRoot, 'worker', 'ig5_worker.py'), '--ida-dir', cfg.idaDir];
  } else {
    const pack = cfg[engine];
    if (!pack?.available) throw new Error(`${engine} runtime is unavailable: ${pack?.reason || 'not configured'}`);
    executable = pack.pythonExe;
    args = ['-I', '-B', paths.join(pluginRoot, 'adapters', engine, engine === 'ghidra' ? 'worker.py' : 'adapter.py')];
    if (engine === 'ghidra') Object.assign(env, {
      IG5_GHIDRA_HOME: pack.ghidraHome, IG5_JAVA_HOME: pack.javaHome,
      IG5_GHIDRA_PROJECT_ROOT: paths.join(cfg.projectRoot, 'ghidra-databases'),
    });
    else Object.assign(env, {
      IG5_X64DBG_RUNTIME: pack.manifest,
      IG5_X64DBG_STATE_ROOT: paths.join(cfg.stateRoot || paths.join(cfg.home || cfg.artifactDir || cfg.projectRoot, 'state'), 'x64dbg'),
    });
  }
  return { executable, args, options: {
    stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env,
    // A new POSIX process group lets timeout cleanup include native decompiler children.
    ...(cfg.host?.platform === 'linux' ? { detached: true } : {}),
  } };
}

export function spawnWorker(cfg, engine, pluginRoot, { spawnProcess = spawn, formatError = error => error, timers } = {}) {
  const launch = workerLaunch(cfg, engine, pluginRoot);
  let child;
  try { child = spawnProcess(launch.executable, launch.args, launch.options); }
  catch (error) { throw formatError(error); }
  child.__ig5ProcessGroup = !!launch.options.detached;
  // Install listeners before the caller's first await: ENOENT and ready can arrive immediately.
  child.__ig5Client = new WorkerClient(child, { formatError, ...(timers ? { timers } : {}) });
  return child;
}

/** JSONL framing and subprocess/request lifetime. Queues, approvals and revisions stay in the host. */
export class WorkerClient {
  constructor(proc, { formatError = error => error, timers = { setTimeout, clearTimeout } } = {}) {
    this.proc = proc;
    this.formatError = formatError;
    this.timers = timers;
    this.decoder = new StringDecoder('utf8');
    this.buffer = '';
    this.stderrTail = '';
    this.backlog = [];
    this.waiters = new Set();
    this.ready = false;
    this.failure = null;
    this.disposed = false;
    this.dataListener = data => {
      this.buffer += Buffer.isBuffer(data) ? this.decoder.write(data) : String(data);
      let end;
      while ((end = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, end).trim(); this.buffer = this.buffer.slice(end + 1);
        if (!line) continue;
        let message; try { message = JSON.parse(line); } catch { continue; }
        if (!message || typeof message !== 'object' || Array.isArray(message)) continue;
        if (message.ig5 === 'ready') {
          this.ready = true; this.readyMessage = message;
          for (const waiter of this.waiters) { this.timers.clearTimeout(waiter.timer); waiter.resolve(); }
          this.waiters.clear();
        }
        if (this.onMessage) this.deliver(message);
        else this.backlog.push(message);
      }
    };
    this.stderrListener = data => {
      this.stderrTail = (this.stderrTail + String(data)).slice(-4000);
      if (this.session) this.session.stderrTail = this.stderrTail;
    };
    this.errorListener = error => { proc.__ig5SpawnError = error; this.fail(error); };
    this.exitListener = code => this.fail(new Error(`worker exited code=${code}: ${this.stderrTail.slice(-600)}`));
    this.stdinListener = error => this.fail(error);
    proc.stdout?.on('data', this.dataListener);
    proc.stderr?.on('data', this.stderrListener);
    proc.on('error', this.errorListener);
    proc.on('exit', this.exitListener);
    proc.stdin?.on?.('error', this.stdinListener);
  }

  configure({ session, onMessage, onExit, formatError } = {}) {
    if (session) { this.session = session; session.stderrTail = this.stderrTail; }
    if (formatError) this.formatError = formatError;
    if (onMessage !== undefined) this.onMessage = onMessage;
    if (onExit !== undefined) this.onExit = onExit;
    for (const message of this.backlog.splice(0)) this.deliver(message);
    if (this.failure) this.onExit?.(this.failure);
    return this;
  }

  deliver(message) {
    try { this.onMessage?.(message); }
    catch (error) { this.fail(error); }
  }

  waitReady(timeoutMs = 60000) {
    if (this.failure) return Promise.reject(this.failure);
    if (this.ready) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject };
      waiter.timer = this.timers.setTimeout(() => {
        this.waiters.delete(waiter);
        reject(this.formatError(new Error(`worker 未在 ${timeoutMs / 1000}s 内就绪\n${this.stderrTail.slice(-600)}`)));
      }, timeoutMs);
      this.waiters.add(waiter);
    });
  }

  fail(value) {
    if (this.failure || this.disposed) return;
    this.failure = this.formatError(value);
    this.ready = false;
    if (this.session) this.session.ready = false;
    for (const waiter of this.waiters) { this.timers.clearTimeout(waiter.timer); waiter.reject(this.failure); }
    this.waiters.clear();
    this.rejectPending(this.failure);
    this.onExit?.(this.failure);
  }

  rejectPending(error) {
    for (const pending of this.session?.pending?.values() || []) {
      this.timers.clearTimeout(pending.timer); pending.removeAbort?.(); pending.reject(error);
    }
    this.session?.pending?.clear();
  }

  write(value) {
    if (this.failure || this.disposed) throw this.failure || new Error('worker 已被关闭');
    this.proc.stdin.write(JSON.stringify(value) + '\n');
  }

  request(session, method, params, { timeoutMs, signal, onProgress, mutation = false, onTimeout } = {}) {
    if (signal?.aborted) return Promise.reject(Object.assign(new Error('IG5 operation cancelled before execution'), { code: 'ABORT_ERR' }));
    const id = ++session.seq;
    return new Promise((resolve, reject) => {
      const pending = { method, params, resolve, reject, onProgress: typeof onProgress === 'function' ? onProgress : undefined };
      const cleanup = () => { this.timers.clearTimeout(pending.timer); pending.removeAbort?.(); session.pending.delete(id); };
      pending.timer = this.timers.setTimeout(() => {
        cleanup();
        try { onTimeout?.(); }
        catch (error) { reject(error); return; }
        reject(new Error(`worker rpc 超时（${method}，${timeoutMs}ms），已回收该 worker，可重新 ig5_open`));
      }, timeoutMs);
      if (signal) {
        const abort = () => {
          pending.cancelled = true;
          if (session.engine === 'x64dbg') {
            try { this.write({ id: ++session.seq, method: 'cancel', params: { requestId: id } }); }
            catch (error) { this.fail(error); }
          } else if (!mutation) {
            reject(Object.assign(new Error('IG5 read cancelled; engine result will be discarded'), { code: 'ABORT_ERR' }));
          }
          // A running static write still settles and updates revision: cancellation is not rollback.
        };
        signal.addEventListener('abort', abort, { once: true });
        pending.removeAbort = () => signal.removeEventListener('abort', abort);
      }
      session.pending.set(id, pending);
      session.lastOp = method;
      try { this.write({ id, method, params }); }
      catch (error) { cleanup(); reject(error); }
    });
  }

  dispose(error = new Error('worker 已被关闭')) {
    if (this.disposed) return;
    this.disposed = true; this.ready = false;
    for (const waiter of this.waiters) { this.timers.clearTimeout(waiter.timer); waiter.reject(error); }
    this.waiters.clear(); this.rejectPending(error);
    this.proc.stdout?.removeListener('data', this.dataListener);
    this.proc.stderr?.removeListener('data', this.stderrListener);
    // Retain error listeners through subprocess exit to avoid late unhandled EPIPE/ENOENT.
    this.backlog.length = 0; this.onMessage = this.onExit = null;
  }
}

export function attachWorker(proc, options = {}) {
  const client = proc.__ig5Client || new WorkerClient(proc, options);
  proc.__ig5Client = client;
  return client.configure(options);
}

export async function doctorWorker(proc, { timeoutMs = 90000, formatError = error => error } = {}) {
  const session = { seq: -1, engine: 'doctor', pending: new Map() };
  const client = attachWorker(proc, { session, formatError, onMessage(message) {
    const pending = session.pending.get(message.id);
    if (!pending) return;
    session.pending.delete(message.id);
    clearTimeout(pending.timer);
    message.error ? pending.reject(formatError(message.error)) : pending.resolve(message.result);
  } });
  try { return await client.request(session, 'doctor', {}, { timeoutMs }); }
  finally { client.dispose(); }
}
