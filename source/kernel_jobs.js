import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WorkerClient } from './worker_transport.js';
import { terminateTree } from '../engine_runtime.js';

const root = fs.realpathSync(path.dirname(fileURLToPath(import.meta.url)) + '/..');

/** Isolated, read-only requests; cancellation/disposal terminates only our child. */
export class KernelJobs {
  constructor(cfg, { spawnProcess = spawn, terminate = terminateTree, stopTimeoutMs = 5000 } = {}) {
    if (!Number.isSafeInteger(stopTimeoutMs) || stopTimeoutMs < 1 || stopTimeoutMs > 10000) throw new Error('Invalid kernel cleanup timeout');
    this.cfg = cfg; this.active = new Set(); this.closed = false;
    this.spawnProcess = spawnProcess; this.terminate = terminate; this.stopTimeoutMs = stopTimeoutMs;
  }
  async run(args, signal) {
    if (this.closed) throw new Error('IG5 kernel service disposed');
    if (signal?.aborted) throw new Error('IG5 kernel request cancelled');
    if (this.active.size >= 2) throw new Error('IG5 kernel is busy; maximum two independent requests');
    const pack = this.cfg.ghidra;
    if (!pack?.available || this.cfg.host?.id !== 'win32-x64') throw new Error('IG5 native kernel requires the bundled Windows x64 runtime');
    const runtimeRoot = fs.realpathSync(path.dirname(pack.manifest));
    const child = this.spawnProcess(pack.pythonExe, ['-I', '-B', path.join(root, 'worker', 'ig5_kernel.py'),
      '--runtime-root', runtimeRoot, '--ghidra-home', pack.ghidraHome, '--java-home', pack.javaHome],
    { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, cwd: root,
      env: { ...process.env, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' } });
    const item = { child, stopIssued: false, exited: false };
    item.stopped = new Promise(resolve => {
      const done = () => { item.exited = true; this.active.delete(item); resolve(); };
      child.once('exit', done);
      child.once('error', () => { if (!child.pid) done(); });
    });
    item.stop = () => {
      if (item.stopIssued || item.exited) return;
      item.stopIssued = true;
      try { this.terminate(child); } catch (error) { item.stopError = error; }
    };
    const session = { seq: 0, engine: 'kernel', pending: new Map() };
    const client = new WorkerClient(child, { terminate: item.stop });
    item.client = client;
    client.configure({ session, onMessage(message) {
      const pending = session.pending.get(message.id);
      if (!pending) return;
      session.pending.delete(message.id);
      clearTimeout(pending.timer); pending.removeAbort?.();
      message.error ? pending.reject(Object.assign(new Error(message.error.message || 'IG5 kernel failed'), { code: message.error.code })) : pending.resolve(message.result);
    } });
    this.active.add(item);
    const abort = () => { client.dispose(new Error('IG5 kernel request cancelled')); item.stop(); };
    signal?.addEventListener('abort', abort, { once: true });
    try {
      if (signal?.aborted) abort();
      await client.waitReady(10000);
      return await client.request(session, 'kernel', args,
        { timeoutMs: Math.min(60000, this.cfg.requestTimeoutMs || 30000), signal });
    } finally {
      signal?.removeEventListener('abort', abort);
      client.dispose();
      item.stop();
      // Keep capacity occupied until confirmed exit, including timeout teardown.
      // The exit listener releases capacity. A failed kill retains ownership.
    }
  }
  async dispose() {
    this.closed = true;
    const active = [...this.active];
    for (const item of active) { item.client.dispose(); item.stop(); }
    let timer;
    try {
      await Promise.race([Promise.all(active.map(item => item.stopped)), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('IG5 kernel cleanup timed out; owned worker exit was not confirmed')), this.stopTimeoutMs);
      })]);
    } finally { clearTimeout(timer); }
  }
}
