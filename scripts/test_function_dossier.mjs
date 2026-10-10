// Host aggregation contract fixtures only: no native engine, target execution,
// real database or user artifacts are opened by this regression.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { collectFunctionDossier } from '../source/function_dossier.js';
import { jsonToolOutput } from '../source/json_output.js';

const EA = '0xfedcba9876543210';
const passes = [];
function fixture(options = {}) {
  const session = {
    target: 'C:\\fixtures\\dossier.exe', engine: 'reverse', provider: 'ghidra',
    projectId: 'project-fixture', artifactId: 'artifact-fixture', sha256: 'a'.repeat(64),
    attachmentId: 'attachment-fixture', dbRevision: 7, alive: true, cache: new Map(),
    capabilities: ['decompile', 'cfg', 'calls', 'stack'],
    info: { partial: true, analysisComplete: false, analysisProfile: 'interactive' },
    ...options.session,
  };
  const calls = [], controller = new AbortController();
  let active = session;
  const mgr = {
    cfg: { requestTimeoutMs: 240000 },
    alive(value) { return value?.alive === true; },
    checkCancelled() { if (controller.signal.aborted) throw Object.assign(new Error('IG5 operation cancelled'), { code: 'ABORT_ERR' }); },
    get() { return active; },
    evidence(value) {
      return Object.fromEntries(['target', 'projectId', 'artifactId', 'sha256', 'engine', 'provider', 'attachmentId', 'dbRevision'].map(key => [key, value[key]]));
    },
    async rpc(value, method, params, timeout) {
      calls.push({ method, params: structuredClone(params), timeout });
      await options.beforeRPC?.({ value, method, params, calls, controller, mgr });
      if (options.error?.(method, params)) throw options.error(method, params);
      const address = params.ea || EA;
      let result;
      if (method === 'decompile') result = { ea: address, name: 'check_input', size: 32, lines: 3, code: 'int check_input(int x) {\n  return x + 1;\n}', engine: 'Ghidra', revision: 0 };
      if (method === 'cfg') result = { ea: address, start_ea: address, name: 'check_input', func: 'check_input', blocks: [
        { id: 0, start: address, end: '0xfedcba9876543220', insns: 4, succs: [1], preds: [], first: 'CMP EAX,0', last: 'JZ done' },
        { id: 1, start: '0xfedcba9876543220', end: '0xfedcba9876543230', insns: 2, succs: [], preds: [0], first: 'ADD EAX,1', last: 'RET' },
      ], edges: [{ from: 0, to: 1 }], total_blocks: 2, total_edges: 1, mermaid: 'flowchart TD\n B0 --> B1' };
      if (method === 'calls') result = { ea: address, name: 'check_input', direction: params.direction, total: 2, refsMeaning: 'unique function relationship', calls: [
        { ea: '0xfedcba9876543300', name: params.direction === 'callers' ? 'main' : 'helper', refs: 1 },
        { ea: '0xfedcba9876543400', name: 'other', refs: 1 },
      ] };
      if (method === 'stack') result = { ok: true, ea: address, has_frame: true, frame_size: 32, local_size: 16, total_members: 1,
        members: [{ name: 'value', offset: -8, size: 8, type: 'longlong', kind: 'locals' }], engine: 'Ghidra' };
      result = options.result?.(method, params, result) ?? result;
      await options.afterRPC?.({ value, method, params, calls, controller, mgr, result });
      return result;
    },
  };
  return { mgr, session, calls, controller, replace(value) { active = value; }, collect(args = {}) { return collectFunctionDossier(mgr, active, { ea: EA, ...args }); } };
}
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  return value;
}
function digest(value) {
  const { cache, snapshotDigest, ...content } = value;
  return createHash('sha256').update(JSON.stringify(stable(content)), 'utf8').digest('hex');
}
function pass(text) { passes.push(text); console.log('PASS ' + text); }

{
  const state = fixture(), first = await state.collect();
  assert.deepEqual(state.calls.map(call => [call.method, call.params.direction ?? null]), [
    ['decompile', null], ['cfg', null], ['calls', 'callers'], ['calls', 'callees'], ['stack', null],
  ]);
  assert(state.calls.every(call => call.timeout === 60000));
  assert(state.calls.slice(1).every(call => call.params.limit === 32));
  assert(state.calls.every(call => call.params.ea === EA));
  assert.equal(first.kind, 'function-dossier'); assert.equal(first.function.ea, EA);
  assert.equal(first.functionAddress.value, EA); assert.equal(first.functionAddress.kind, 'va'); assert.equal(first.functionAddress.space, 'static');
  assert.equal(first.functionAddress.dbRevision, 7); assert.equal(first.provenance.provider, 'ghidra');
  assert.equal(first.analysis.partial, true); assert.equal(first.analysis.analysisComplete, false);
  assert.equal(first.sections.stack.data.members[0].offset, -8); assert.equal(first.sections.cfg.data.mermaid, undefined);
  assert(Object.values(first.sections).every(section => section.status === 'ok'));
  assert.equal(first.snapshotDigest, digest(first)); assert.deepEqual(jsonToolOutput(first), first);
  assert.equal(first.cache.hit, false);
  first.sections.decompile.data.code = 'caller mutation'; first.provenance.dbRevision = 88;
  const cached = await state.collect();
  assert.equal(cached.cache.hit, true); assert.equal(state.calls.length, 5); assert.equal(cached.provenance.dbRevision, 7);
  assert.match(cached.sections.decompile.data.code, /return x \+ 1/); assert.equal(cached.snapshotDigest, digest(cached));
  cached.sections.stack.data.members[0].offset = 123;
  assert.equal((await state.collect()).sections.stack.data.members[0].offset, -8);
  pass('five static RPC contracts, precise 64-bit VA, partial analysis, digest and defensive cache copies');
}
{
  const state = fixture();
  await state.collect(); state.session.dbRevision++; state.session.cache.clear();
  const revised = await state.collect(); assert.equal(revised.cache.hit, false); assert.equal(state.calls.length, 10); assert.equal(revised.provenance.dbRevision, 8);
  state.session.dbRevision++; // Key identity protects even if a caller forgets invalidation.
  assert.equal((await state.collect()).cache.hit, false); assert.equal(state.calls.length, 15);
  const replacement = { ...state.session, attachmentId: 'attachment-reopened', cache: state.session.cache };
  state.replace(replacement);
  await assert.rejects(collectFunctionDossier(state.mgr, state.session, { ea: EA }), { code: 'DOSSIER_CONTEXT_CHANGED' });
  assert.equal((await state.collect()).cache.hit, false); assert.equal(state.calls.length, 20);
  replacement.engine = 'ghidra';
  assert.equal((await state.collect()).cache.hit, false); assert.equal(state.calls.length, 25);
  pass('revision, reopened attachment and analysis lane separate cache identities');
}
{
  const state = fixture({ afterRPC({ value, method }) { if (method === 'cfg') value.dbRevision++; } });
  await assert.rejects(state.collect(), { code: 'DOSSIER_CONTEXT_CHANGED' }); assert.equal(state.calls.length, 2); assert.equal(state.session.cache.size, 0);
  const stale = fixture({ result(method, params, value) { return method === 'stack' ? { ...value, _ig5: { dbRevision: 6 } } : value; } });
  await assert.rejects(stale.collect(), { code: 'DOSSIER_CONTEXT_CHANGED' }); assert.equal(stale.session.cache.size, 0);
  const different = fixture({ result(method, params, value) { return method === 'calls' ? { ...value, ea: '0xfedcba9876549999' } : value; } });
  await assert.rejects(different.collect(), { code: 'DOSSIER_FUNCTION_CHANGED' }); assert.equal(different.calls.length, 3);
  const ghidraCodeCFG = fixture({ result(method, params, value) {
    return method === 'cfg' ? { ...value, ea: '0xfedcba9876549999', start_ea: '0xfedcba9876549999' } : value;
  } });
  await assert.rejects(ghidraCodeCFG.collect(), { code: 'DOSSIER_FUNCTION_CHANGED' });
  assert.equal(ghidraCodeCFG.calls.length, 2); assert.equal(ghidraCodeCFG.session.cache.size, 0);
  const inside = '0x' + (BigInt(EA) + 8n).toString(16);
  const commercialInterior = fixture({ session: { provider: 'commercial' }, result(method, params, value) {
    return method === 'cfg' ? { ...value, ea: EA, start_ea: EA } : value;
  } });
  const canonical = await commercialInterior.collect({ ea: inside });
  assert.equal(canonical.sections.decompile.data.ea, inside);
  assert.equal(canonical.sections.cfg.data.start_ea, EA);
  assert.equal(canonical.function.ea, EA); assert.equal(canonical.function.requestedEA, inside);
  assert.equal(canonical.functionAddress.value, EA); assert.equal(canonical.function.resolved, true);
  assert.equal(commercialInterior.calls[2].params.ea, EA); assert.equal(canonical.cache.hit, false);
  assert.equal((await commercialInterior.collect({ ea: inside })).cache.hit, true);
  pass('snapshot drift and Ghidra code/CFG entry mismatch reject; commercial interior requests resolve compatibly');
}
{
  const early = fixture(); early.controller.abort();
  await assert.rejects(early.collect(), { code: 'ABORT_ERR' }); assert.equal(early.calls.length, 0);
  const during = fixture({ afterRPC({ method, controller }) { if (method === 'cfg') controller.abort(); } });
  await assert.rejects(during.collect(), { code: 'ABORT_ERR' }); assert.equal(during.calls.length, 2); assert.equal(during.session.cache.size, 0);
  const death = fixture({ afterRPC({ method, value }) { if (method === 'decompile') value.alive = false; } });
  await assert.rejects(death.collect(), { code: 'DOSSIER_SESSION_STOPPED' }); assert.equal(death.calls.length, 1);
  const transport = fixture({ error() { return Object.assign(new Error('pipe closed'), { code: 'EPIPE' }); } });
  await assert.rejects(transport.collect(), { code: 'EPIPE' }); assert.equal(transport.calls.length, 1);
  const limit = fixture({ error() { return Object.assign(new Error('receive limit'), { code: 'WORKER_PROTOCOL_LIMIT' }); } });
  await assert.rejects(limit.collect(), { code: 'WORKER_PROTOCOL_LIMIT' }); assert.equal(limit.calls.length, 1);
  pass('preflight/in-flight cancellation, worker death and transport failures never become section success');
}
{
  const state = fixture({ error(method) { return method === 'decompile' ? new Error('Ghidra decompile failed: unknown stack effect') : null; } });
  const result = await state.collect(); assert.equal(result.sections.decompile.status, 'error'); assert.equal(result.sections.cfg.status, 'ok');
  assert.equal(result.function.resolved, true); assert.equal(state.session.cache.size, 0);
  await state.collect(); assert.equal(state.calls.length, 10, 'failed sections must be retried only on an explicit new collection');
  const named = fixture({ error() { return new Error('Exact name does not identify a function'); } });
  await assert.rejects(named.collect({ ea: undefined, name: 'missing_name' }), { code: 'DOSSIER_FUNCTION_UNRESOLVED' });
  assert.equal(named.calls.length, 5); assert.equal(named.session.cache.size, 0);
  const resolved = fixture({ error(method) { return method === 'decompile' ? new Error('decompiler unavailable') : null; } });
  const byName = await resolved.collect({ ea: undefined, name: 'check_input' });
  assert.equal(byName.function.ea, EA); assert.equal(resolved.calls[0].params.name, 'check_input');
  assert.equal(resolved.calls[1].params.name, 'check_input'); assert.equal(resolved.calls[2].params.ea, EA);
  const unresolvedAddress = fixture({ error() { return new Error('No function analysis available'); } });
  const explicit = await unresolvedAddress.collect(); assert.equal(explicit.function.resolved, false); assert.equal(explicit.function.addressRole, 'requested-address');
  pass('decompiler failure retains assembly evidence; unresolved names fail and explicit unresolved addresses stay unconfirmed');
}
{
  const state = fixture({ session: { capabilities: ['decompile', 'cfg', 'stack'] } });
  const result = await state.collect(); assert.equal(state.calls.length, 3);
  assert.equal(result.sections.callers.status, 'unsupported'); assert.equal(result.sections.callees.status, 'unsupported');
  assert.equal((await state.collect()).cache.hit, true); assert.equal(state.calls.length, 3);
  const unsupported = fixture({ error(method) { return method === 'stack' ? Object.assign(new Error('unsupported capability'), { code: 'UNSUPPORTED_CAPABILITY' }) : null; } });
  assert.equal((await unsupported.collect()).sections.stack.status, 'unsupported');
  pass('advertised and actual provider capability gaps remain explicit without changing engines');
}
{
  const rows = Array.from({ length: 200 }, (_, index) => ({ ea: '0x' + (BigInt(EA) + BigInt(index)).toString(16), name: '候选函数🙂'.repeat(30), refs: index + 1 }));
  const state = fixture({ result(method, params, value) {
    if (method === 'decompile') return { ...value, code: '密钥🔑协议🙂\\\"'.repeat(10000), lines: 10000 };
    if (method === 'calls') return { ...value, calls: rows.slice(0, params.limit), total: 200 };
    if (method === 'stack') return { ...value, total_members: 200, members: rows.map(row => ({ name: row.name, offset: -8, type: '类型🙂'.repeat(20), size: 8 })) };
    return value;
  } });
  const result = await state.collect({ dossier_max_bytes: 4000, dossier_max_rows: 3 });
  assert(Buffer.byteLength(JSON.stringify(result), 'utf8') <= 4000); assert.equal(result.responseBudgetBytes, 4000); assert.equal(result.responseTruncated, true);
  assert.equal(result.sections.decompile.status, 'truncated'); assert.equal(result.sections.callers.status, 'truncated');
  assert(result.sections.callers.truncation.provider.some(record => record.available === 200 && record.omitted === 197));
  for (const section of Object.values(result.sections)) for (const child of Object.values(section.data || {})) if (Array.isArray(child)) assert(child.length <= 3);
  function wholeUnicode(value) {
    if (typeof value === 'string') assert.doesNotMatch(value, /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/);
    if (value && typeof value === 'object') Object.values(value).forEach(wholeUnicode);
  }
  wholeUnicode(result); assert.equal(result.snapshotDigest, digest(result));
  function preciseAddresses(value) {
    if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
      if (['ea', 'start', 'end', 'value'].includes(key) && typeof child === 'string' && child.startsWith('0x'))
        assert(BigInt(child) >= BigInt(EA), 'a bounded view must not turn a long address into a shorter valid address');
      preciseAddresses(child);
    }
  }
  preciseAddresses(result);
  const cached = await state.collect({ dossier_max_bytes: 4000, dossier_max_rows: 3 });
  assert.equal(cached.cache.hit, true); assert.equal(cached.snapshotDigest, result.snapshotDigest); assert(Buffer.byteLength(JSON.stringify(cached), 'utf8') <= 4000);
  const otherBudget = await state.collect({ dossier_max_bytes: 6000, dossier_max_rows: 3 }); assert.equal(otherBudget.cache.hit, false);
  pass('escaped Unicode, UTF-8 whole-response bytes, row limits and producer totals disclose truncation');
}
{
  const state = fixture(); state.session.cache.set('ordinary-decompile-key', { code: 'untouched' });
  for (let index = 0; index < 18; index++) await state.collect({ ea: '0x' + (BigInt(EA) + BigInt(index)).toString(16) });
  const stored = [...state.session.cache.entries()].filter(([key]) => key.startsWith('dossier:v1:'));
  assert.equal(stored.length, 16); assert(stored.reduce((sum, [, entry]) => sum + entry.bytes, 0) <= 1024 * 1024);
  assert.deepEqual(state.session.cache.get('ordinary-decompile-key'), { code: 'untouched' });
  assert.equal((await state.collect()).cache.hit, false);
  pass('bounded dossier cache evicts its own oldest entries and leaves ordinary decompile cache intact');
}
{
  const state = fixture();
  for (const args of [
    { ea: undefined, name: undefined }, { ea: 123 }, { ea: '0x10000000000000000' },
    { dossier_max_bytes: 3999 }, { dossier_max_bytes: 64001 }, { dossier_max_bytes: NaN },
    { dossier_max_rows: 0 }, { dossier_max_rows: 129 }, { dossier_max_rows: 1.5 }, { name: {} },
  ]) await assert.rejects(state.collect(args));
  assert.equal(state.calls.length, 0);
  const invalid = fixture({ result(method, params, value) { return method === 'decompile' ? { ...value, size: 1n } : value; } });
  await assert.rejects(invalid.collect(), { code: 'INVALID_IG5_OUTPUT' }); assert.equal(invalid.calls.length, 1);
  const enormousIdentity = fixture({ session: { target: 'C:\\' + '很长'.repeat(5000) } });
  await assert.rejects(enormousIdentity.collect({ dossier_max_bytes: 4000 }), { code: 'DOSSIER_RESPONSE_LIMIT' });
  assert.equal(enormousIdentity.session.cache.size, 0);
  pass('invalid input, unsafe provider JSON and metadata too large for the chosen budget reject explicitly');
}
console.log(`IG5 function dossier: ${passes.length} host fixture groups passed; no native execution was performed.`);
