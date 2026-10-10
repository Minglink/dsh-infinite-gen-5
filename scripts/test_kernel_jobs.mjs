import assert from 'node:assert/strict';
import { EventEmitter, getEventListeners } from 'node:events';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { KernelJobs } from '../source/kernel_jobs.js';

// Real WorkerClient framing/request/abort logic, fake owned subprocesses only.
// No Python, JVM, DLL, sample execution or real process termination is started.
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const tick = () => new Promise(resolve => setImmediate(resolve));
const pass = label => console.log('PASS', label);
let nextPid = 70000;

async function within(promise, milliseconds = 300) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Fixture deadline exceeded')), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

function harness({ ready = true, onWrite, spawnError, terminateError, spawnThrow,
                   requestTimeoutMs = 25, stopTimeoutMs = 25 } = {}) {
  const children = [], calls = [], launch = [];
  const cfg = {
    host: { id: 'win32-x64' }, requestTimeoutMs,
    ghidra: { available: true, manifest: path.join(root, 'fixture-runtime.json'),
      pythonExe: 'fixture-no-process.exe', ghidraHome: root, javaHome: root },
  };
  const spawnProcess = (file, args, options) => {
    launch.push({ file, args, options });
    if (spawnThrow) throw spawnThrow;
    const child = new EventEmitter();
    child.pid = spawnError ? undefined : ++nextPid;
    child.exitCode = null; child.signalCode = null;
    child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = new EventEmitter();
    child.sent = [];
    child.frame = value => child.stdout.emit('data', Buffer.from(JSON.stringify(value) + '\n'));
    child.finish = (code = 0) => {
      if (child.exitCode !== null || child.signalCode) return;
      child.exitCode = code;
      child.emit('exit', code);
    };
    child.stdin.write = line => {
      const request = JSON.parse(line);
      child.sent.push(request);
      onWrite?.(child, request);
      return true;
    };
    children.push(child);
    queueMicrotask(() => {
      if (spawnError) child.emit('error', spawnError);
      else if (ready) child.frame({ ig5: 'ready', engine: 'IG5 Kernel', capabilities: ['kernel'] });
    });
    return child;
  };
  const jobs = new KernelJobs(cfg, {
    spawnProcess, stopTimeoutMs,
    terminate(child) {
      assert.ok(children.includes(child), 'cleanup must target this harness\'s owned subprocess');
      calls.push(child);
      if (terminateError) throw terminateError;
    },
  });
  return { jobs, children, calls, launch, cfg,
    killed: child => calls.filter(value => value === child).length,
    async cleanup() {
      for (const child of children) child.finish();
      await jobs.dispose();
    },
  };
}

async function check(label, options, run) {
  const h = harness(options);
  try { await within(run(h), 1000); }
  finally { await h.cleanup(); }
  pass(label);
}

await check('successful JSONL/Unicode response stops once and retains capacity until actual exit', {
  onWrite(child, request) {
    queueMicrotask(() => child.frame({ id: request.id, result: { ok: true, text: '中文🧪' } }));
  },
}, async h => {
  const result = await h.jobs.run({ action: 'info', target: 'fixture' });
  assert.deepEqual(result, { ok: true, text: '中文🧪' });
  assert.equal(h.children[0].sent[0].method, 'kernel');
  assert.deepEqual(h.launch[0].args.slice(0, 2), ['-I', '-B']);
  assert.equal(h.launch[0].options.windowsHide, true);
  assert.equal(h.launch[0].options.env.PYTHONIOENCODING, 'utf-8');
  assert.equal(h.jobs.active.size, 1);
  const item = [...h.jobs.active][0];
  assert.equal(item.exited, false);
  assert.equal(item.client.disposed, true);
  assert.equal(item.client.session.pending.size, 0);
  item.stop(); item.stop();
  assert.equal(h.killed(h.children[0]), 1);
  h.children[0].finish();
  assert.equal(item.exited, true);
  assert.equal(h.jobs.active.size, 0);
});

await check('abort during ready handshake rejects without sending a request', { ready: false }, async h => {
  const controller = new AbortController();
  const pending = h.jobs.run({ action: 'info' }, controller.signal);
  const rejected = assert.rejects(pending, /kernel request cancelled/);
  controller.abort(); await rejected;
  assert.equal(h.children[0].sent.length, 0);
  assert.equal(h.killed(h.children[0]), 1);
  assert.equal(h.jobs.active.size, 1);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

await check('abort of in-flight RPC ignores late response and removes abort hooks', {}, async h => {
  const controller = new AbortController();
  const pending = h.jobs.run({ action: 'analyze' }, controller.signal);
  const rejected = assert.rejects(pending, /kernel request cancelled/);
  await tick();
  assert.equal(h.children[0].sent.length, 1);
  assert.ok(getEventListeners(controller.signal, 'abort').length >= 1);
  controller.abort(); await rejected;
  h.children[0].frame({ id: 1, result: { ok: true, shouldBeDiscarded: true } });
  const item = [...h.jobs.active][0];
  assert.equal(item.client.session.pending.size, 0);
  assert.equal(item.client.waiters.size, 0);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  item.stop();
  assert.equal(h.killed(h.children[0]), 1);
  assert.equal(h.jobs.active.size, 1);
});

await check('already aborted operation creates no subprocess', {}, async h => {
  const controller = new AbortController(); controller.abort();
  await assert.rejects(h.jobs.run({}, controller.signal), /cancelled/);
  assert.equal(h.children.length, 0); assert.equal(h.jobs.active.size, 0);
});

await check('request timeout clears transport state and stops its owned child once', {}, async h => {
  const controller = new AbortController();
  await assert.rejects(h.jobs.run({}, controller.signal), /worker rpc/);
  const item = [...h.jobs.active][0];
  assert.equal(item.client.session.pending.size, 0);
  assert.equal(item.client.waiters.size, 0);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  assert.equal(item.exited, false);
  assert.equal(h.killed(item.child), 1);
});

for (const [label, frame, limit] of [
  ['oversized stdout', () => Buffer.alloc(16 * 1024 * 1024 + 1, 0x61), 'lineBytes'],
  ['invalid UTF-8 stdout', () => Buffer.from([0xff, 0x0a]), 'invalidUtf8'],
]) {
  await check(label + ' transport failure shares the same single termination', {}, async h => {
    const pending = h.jobs.run({});
    const rejected = assert.rejects(pending, { code: 'WORKER_PROTOCOL_LIMIT', limit });
    await tick();
    h.children[0].stdout.emit('data', frame());
    await rejected;
    const item = [...h.jobs.active][0];
    assert.equal(item.client.transportTerminated, true);
    assert.equal(item.client.buffer.length, 0);
    assert.equal(item.client.session.pending.size, 0);
    item.stop();
    assert.equal(h.killed(item.child), 1);
    assert.equal(item.exited, false);
  });
}

for (const channel of ['child', 'stdin']) {
  await check(channel + ' error rejects RPC but does not claim confirmed process exit', {}, async h => {
    const pending = h.jobs.run({});
    const rejected = assert.rejects(pending, /fixture transport failure/);
    await tick();
    (channel === 'child' ? h.children[0] : h.children[0].stdin).emit('error', new Error('fixture transport failure'));
    await rejected;
    const item = [...h.jobs.active][0];
    assert.equal(item.exited, false); assert.equal(h.jobs.active.size, 1);
    assert.equal(h.killed(item.child), 1);
    // Late errors remain handled after dispose; no unhandled EventEmitter error.
    item.child.emit('error', new Error('late handled child error'));
    item.child.stdin.emit('error', new Error('late handled stdin error'));
    assert.equal(item.exited, false);
  });
}

await check('confirmed child exit rejects pending RPC and needs no later termination', {}, async h => {
  const pending = h.jobs.run({});
  const rejected = assert.rejects(pending, /exited code=3.*fixture stderr/);
  await tick();
  h.children[0].stderr.emit('data', Buffer.from('fixture stderr'));
  h.children[0].finish(3); await rejected;
  assert.equal(h.jobs.active.size, 0);
  assert.equal(h.killed(h.children[0]), 0);
});

await check('ENOENT before spawn confirmation releases capacity without targeting a PID', {
  ready: false, spawnError: Object.assign(new Error('fixture missing executable'), { code: 'ENOENT' }),
}, async h => {
  await assert.rejects(h.jobs.run({}), { code: 'ENOENT' });
  assert.equal(h.children[0].pid, undefined);
  assert.equal(h.jobs.active.size, 0); assert.equal(h.calls.length, 0);
});

await check('synchronous spawn failure leaves no owner or termination action', {
  spawnThrow: new Error('fixture synchronous spawn failure'),
}, async h => {
  await assert.rejects(h.jobs.run({}), /synchronous spawn failure/);
  assert.equal(h.children.length, 0); assert.equal(h.jobs.active.size, 0); assert.equal(h.calls.length, 0);
});

await check('maximum two requests remains occupied after response until matching children exit', {
  onWrite(child, request) { queueMicrotask(() => child.frame({ id: request.id, result: { ok: true } })); },
}, async h => {
  await Promise.all([h.jobs.run({}), h.jobs.run({})]);
  assert.equal(h.jobs.active.size, 2);
  await assert.rejects(h.jobs.run({}), /maximum two/);
  assert.equal(h.children.length, 2);
  h.children[0].emit('error', new Error('not an exit'));
  assert.equal(h.jobs.active.size, 2);
  await assert.rejects(h.jobs.run({}), /maximum two/);
  h.children[0].finish(); assert.equal(h.jobs.active.size, 1);
  await h.jobs.run({}); assert.equal(h.children.length, 3); assert.equal(h.jobs.active.size, 2);
  for (const child of h.children) assert.equal(h.killed(child), 1);
});

await check('dispose times out explicitly, retains unconfirmed owners and never repeats stop', {}, async h => {
  const first = h.jobs.run({}), second = h.jobs.run({});
  const firstRejected = assert.rejects(first, /worker/), secondRejected = assert.rejects(second, /worker/);
  await tick();
  const items = [...h.jobs.active];
  await assert.rejects(h.jobs.dispose(), /cleanup timed out.*exit was not confirmed/);
  await Promise.all([firstRejected, secondRejected]);
  assert.equal(h.jobs.closed, true); assert.equal(h.jobs.active.size, 2);
  for (const item of items) {
    assert.equal(item.exited, false); assert.equal(item.child.exitCode, null);
    item.stop(); item.stop(); assert.equal(h.killed(item.child), 1);
  }
  await assert.rejects(h.jobs.dispose(), /cleanup timed out/);
  assert.equal(h.jobs.active.size, 2);
  await assert.rejects(h.jobs.run({}), /service disposed/);
  assert.equal(h.children.length, 2);
  h.children[0].finish(); assert.equal(h.jobs.active.size, 1);
  h.children[1].finish(); assert.equal(h.jobs.active.size, 0);
  await h.jobs.dispose(); await h.jobs.dispose();
  assert.equal(h.calls.length, 2);
});

await check('termination exception is recorded without pretending the child exited', {
  terminateError: new Error('fixture termination denied'),
}, async h => {
  await assert.rejects(h.jobs.run({}), /worker rpc/);
  const item = [...h.jobs.active][0];
  assert.equal(item.stopError.message, 'fixture termination denied');
  assert.equal(item.exited, false); assert.equal(h.jobs.active.size, 1);
  await assert.rejects(h.jobs.dispose(), /cleanup timed out/);
  item.stop(); assert.equal(h.killed(item.child), 1);
});

for (const invalid of [0, -1, 10001, true, 1.5]) {
  assert.throws(() => new KernelJobs({}, { stopTimeoutMs: invalid }), /Invalid kernel cleanup timeout/);
}
pass('cleanup deadline configuration rejects invalid/unbounded values');
console.log('Kernel jobs regression tests passed; no native process or engine was started.');
