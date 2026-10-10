// Pure approval-hook acceptance. Reads the actual product gate into an isolated
// VM; no worker, sample, database, profile, artifact or network operation runs.
// Complete host SDK dispatch is covered separately by test_host_sdk.mjs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(process.env.IG5_PLUGIN_UNDER_TEST || fileURLToPath(new URL('..', import.meta.url)));
const source = fs.readFileSync(path.join(root, 'index.js'), 'utf8');
const start = source.indexOf('const IG5_WRITE_TOOLS =');
const end = source.indexOf('function installDataRoute', start);
assert(start >= 0 && end > start, 'Actual product approval gate must be present');
const install = vm.runInNewContext(source.slice(start, end) + '\ninstallApprovalGate;', {
  diagAppend() {}, fs: new Proxy({}, { get() { throw new Error('Approval gate test must not access writable file APIs'); } }),
}, { filename: 'actual-product-approval-gate.js' });
const gated = ['rename', 'patch_bytes', 'comment', 'analyze', 'set_type', 'undo', 'run_idapython', 'dbg', 'struct', 'switch_repair', 'emulate', 'sync'].map(name => 'ig5_' + name);
const results = []; let sequence = 0;
function host(outcome, seam = 'service') {
  if (arguments.length === 0) outcome = 'allowed-once';
  const handlers = new Map(), requests = [];
  const service = { async request(request) { requests.push(request); return typeof outcome === 'function' ? outcome(request) : outcome; } };
  const ctx = {
    on(name, handler) { assert(!handlers.has(name)); handlers.set(name, handler); },
    get(name) {
      assert.equal(name, 'approval');
      if (seam === 'throw-get') throw new Error('Public service lookup failed');
      if (seam === 'missing') return undefined;
      if (seam === 'no-request') return {};
      return service;
    },
  };
  install(ctx, {});
  const pre = handlers.get('tools/pre-execute'); assert.equal(typeof pre, 'function');
  return { pre, requests };
}
function execution(name = 'ig5_patch_bytes', overrides = {}) {
  return { name, arguments: { ea: '0x140001000', hex: '90' }, agent: { id: 'approval-gate-test' },
    callId: 'approval-call-' + (++sequence), signal: new AbortController().signal, ...overrides };
}
async function test(name, run) {
  try { await run(); results.push({ name, ok: true }); console.log('PASS', name); }
  catch (error) { results.push({ name, ok: false, error: error.message }); console.error('FAIL', name, error.stack); }
}
async function blocked(h, exec, expectedKind = 'deny') {
  let delegates = 0;
  const decision = await h.pre(exec, async () => { delegates++; return { kind: 'allow' }; });
  assert.equal(decision.kind, expectedKind); assert.equal(delegates, 0, 'Blocked gate must never delegate dispatch');
  return decision;
}

for (const name of gated) {
  await test(name + ': allowed-once uses exact public request then delegates once', async () => {
    const h = host(), exec = execution(name); let delegates = 0;
    const result = await h.pre(exec, async () => { delegates++; return { kind: 'allow', marker: exec.callId }; });
    assert.equal(result.kind, 'allow'); assert.equal(result.marker, exec.callId); assert.equal(delegates, 1); assert.equal(h.requests.length, 1);
    const request = h.requests[0]; assert.equal(request.agent, exec.agent); assert.equal(request.signal, exec.signal);
    assert.equal(request.callId, exec.callId); assert.equal(request.toolName, name); assert.match(request.reason, new RegExp(name));
    assert(request.displayReason.en && request.displayReason.zh);
  });
  await test(name + ': rejected/unavailable/unknown never dispatch', async () => {
    for (const outcome of ['rejected', 'unavailable', undefined, null, false, true, 'allowed', 'allow', 'allowed-always', {}, []]) {
      const h = host(outcome); await blocked(h, execution(name)); assert.equal(h.requests.length, 1);
    }
  });
  await test(name + ': missing agent or public service deny without requesting', async () => {
    for (const agent of [undefined, null]) { const h = host(); await blocked(h, execution(name, { agent })); assert.equal(h.requests.length, 0); }
    for (const seam of ['missing', 'no-request', 'throw-get']) { const h = host('allowed-once', seam); await blocked(h, execution(name)); assert.equal(h.requests.length, 0); }
  });
}
await test('cancelled public approval returns terminal cancel without dispatch', async () => {
  const h = host('cancelled'); await blocked(h, execution(), 'cancel'); assert.equal(h.requests.length, 1);
});
await test('pre-aborted execution cancels before public approval request', async () => {
  const abort = new AbortController(); abort.abort(); const h = host();
  await blocked(h, execution('ig5_emulate', { signal: abort.signal }), 'cancel'); assert.equal(h.requests.length, 0);
});
await test('abort while approval is pending takes priority over allowed-once', async () => {
  const abort = new AbortController(); let resolve;
  const h = host(() => new Promise(done => { resolve = done; })); let delegates = 0;
  const pending = h.pre(execution('ig5_dbg', { signal: abort.signal }), async () => { delegates++; return { kind: 'allow' }; });
  await Promise.resolve(); assert.equal(h.requests.length, 1); assert.equal(delegates, 0);
  abort.abort(); resolve('allowed-once'); const result = await pending; assert.equal(result.kind, 'cancel'); assert.equal(delegates, 0);
});
await test('public approval throw fails closed without dispatch', async () => {
  const h = host(() => { throw new Error('Approval service unavailable'); }); await blocked(h, execution()); assert.equal(h.requests.length, 1);
});
await test('abort followed by approval throw remains a cancellation', async () => {
  const abort = new AbortController(); const h = host(() => { abort.abort(); throw new Error('Request aborted'); });
  await blocked(h, execution('ig5_sync', { signal: abort.signal }), 'cancel'); assert.equal(h.requests.length, 1);
});
await test('allowed-once preserves downstream deny instead of overriding it', async () => {
  const h = host(); let delegates = 0, executions = 0;
  const result = await h.pre(execution(), async () => { delegates++; return { kind: 'deny', reason: 'another policy' }; });
  if (result.kind === 'allow') executions++;
  assert.equal(result.kind, 'deny'); assert.equal(result.reason, 'another policy'); assert.equal(delegates, 1); assert.equal(executions, 0);
});
await test('downstream dispatch errors are propagated after approval', async () => {
  const h = host(); const failure = new Error('Downstream failure');
  await assert.rejects(h.pre(execution(), async () => { throw failure; }), error => error === failure);
});
await test('every call requests independently; one-time approval is never cached', async () => {
  let request = 0; const h = host(() => ++request === 1 ? 'allowed-once' : 'rejected'); let delegates = 0;
  const first = execution(), second = execution();
  assert.equal((await h.pre(first, async () => { delegates++; return { kind: 'allow' }; })).kind, 'allow');
  await blocked(h, second); assert.equal(delegates, 1); assert.equal(h.requests.length, 2); assert.notEqual(h.requests[0].callId, h.requests[1].callId);
});
await test('read-only tools delegate without public approval service', async () => {
  const h = host('allowed-once', 'missing');
  for (const name of ['ig5_funcs', 'ig5_stack', 'ig5_switches', 'ig5_vtables', 'ig5_microcode', 'ig5_bindiff', 'ig5_crypto', 'ig5_protocol']) {
    let delegates = 0; const result = await h.pre(execution(name, { agent: undefined }), async () => { delegates++; return { kind: 'allow' }; });
    assert.equal(result.kind, 'allow'); assert.equal(delegates, 1);
  }
  assert.equal(h.requests.length, 0);
});
const report = { ok: results.every(row => row.ok), pluginRoot: root, gatedTools: gated.length, checks: results,
  sideEffects: { workersStarted: 0, targetsExecuted: 0, databaseWrites: 0, profileWrites: 0, artifactWrites: 0, networkRequests: 0 },
  boundary: 'The exact product pre-execute gate and public approval.request contract are tested. Full real SDK dispatch belongs to test_host_sdk.mjs.' };
console.log(JSON.stringify(report));
if (!report.ok) process.exitCode = 1;
