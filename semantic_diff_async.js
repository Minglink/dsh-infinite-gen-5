import { Worker } from 'node:worker_threads';

/** CPU-heavy matching never runs on the DSH event loop. Cancellation is local. */
export function compareSemanticsAsync(left, right, options = {}, signal) {
  if (signal?.aborted) return Promise.reject(Object.assign(new Error('Version comparison cancelled'), { code: 'ABORT_ERR' }));
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./semantic_diff_worker.js', import.meta.url), {
      workerData: { left, right, options }, resourceLimits: { maxOldGenerationSizeMb: 384 },
    });
    let settled = false;
    const finish = (error, value) => {
      if (settled) return; settled = true;
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      void worker.terminate(); error ? reject(error) : resolve(value);
    };
    const abort = () => finish(Object.assign(new Error('Version comparison cancelled'), { code: 'ABORT_ERR' }));
    const timer = setTimeout(() => finish(new Error('Version comparison exceeded its 60 second budget')), 60_000);
    signal?.addEventListener('abort', abort, { once: true });
    worker.once('message', (reply) => finish(reply.error ? new Error(reply.error) : null, reply.result));
    worker.once('error', (error) => finish(error));
    worker.once('exit', (code) => { if (!settled) finish(new Error(`Version comparison worker exited (${code})`)); });
  });
}
