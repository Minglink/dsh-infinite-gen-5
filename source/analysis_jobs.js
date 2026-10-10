import { Worker } from 'node:worker_threads';

const error = (code, message) => Object.assign(new Error(message), { code });
/** One bounded data worker per plugin instance; cancellation never kills an engine. */
export class AnalysisJobs {
  constructor({ timeoutMs = 15000 } = {}) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw error('INVALID_INPUT', 'Invalid data worker timeout');
    this.timeoutMs = timeoutMs; this.active = null; this.queue = []; this.closed = false;
  }
  run(kind, request, signal) {
    if (this.closed) return Promise.reject(error('DISPOSED', 'Analysis service has been disposed'));
    if (signal?.aborted) return Promise.reject(error('ABORT_ERR', 'Analysis cancelled'));
    if (this.queue.length >= 4) return Promise.reject(error('BUSY', 'Data analysis queue is full'));
    return new Promise((resolve, reject) => {
      const task = { kind, request, signal, resolve, reject };
      task.abort = () => {
        if (this.active === task) task.finish(error('ABORT_ERR', 'Analysis cancelled'));
        else { this.queue = this.queue.filter(item => item !== task); signal?.removeEventListener('abort', task.abort); reject(error('ABORT_ERR', 'Queued analysis cancelled')); }
      };
      signal?.addEventListener('abort', task.abort, { once: true });
      this.queue.push(task); this.pump();
    });
  }
  pump() {
    if (this.active || this.closed || !this.queue.length) return;
    const task = this.active = this.queue.shift();
    let settled = false, worker, timer;
    task.finish = (failure, value) => {
      if (settled) return; settled = true;
      clearTimeout(timer); task.signal?.removeEventListener('abort', task.abort);
      const stopped = worker ? worker.terminate() : Promise.resolve();
      task.stopped = Promise.resolve(stopped);
      if (failure) task.reject(failure); else task.resolve(value);
      // Start only after the old worker's memory and event loop have been released.
      const next = () => { this.active = null; this.pump(); };
      task.stopped.then(next, next);
    };
    try {
      worker = new Worker(new URL('./analysis_worker.js', import.meta.url), { workerData: { kind: task.kind, request: task.request }, resourceLimits: { maxOldGenerationSizeMb: 64 } });
      timer = setTimeout(() => task.finish(error('TIMEOUT', 'Data analysis exceeded its execution budget')), this.timeoutMs);
      worker.once('message', message => message.ok ? task.finish(null, message.value) : task.finish(error(message.error?.code || 'ANALYSIS_FAILED', message.error?.message || 'Analysis failed')));
      worker.once('error', () => task.finish(error('ANALYSIS_FAILED', 'Data analysis worker failed; no output was committed')));
      worker.once('exit', () => task.finish(error('WORKER_EXIT', 'Data analysis worker exited before a result')));
    } catch (failure) { task.finish(failure); }
  }
  async dispose() {
    this.closed = true;
    for (const task of this.queue.splice(0)) { task.signal?.removeEventListener('abort', task.abort); task.reject(error('DISPOSED', 'Analysis service disposed')); }
    const active = this.active;
    active?.finish(error('DISPOSED', 'Analysis service disposed'));
    await active?.stopped;
  }
}
