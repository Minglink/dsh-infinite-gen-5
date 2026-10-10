// Public tool regressions against generated PE files and a disposable notepad copy.
// The mock supplies native DSH service lifecycles; it does not replace any engine.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { apply } from '../index.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const source = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-host-reliability-'));
const fixture = buildPE64Fixture(1);
const reverseTarget = path.join(scratch, 'Reverse隔离样本.exe');
const ghidraTarget = path.join(scratch, 'Ghidra隔离样本.exe');
const otherTarget = path.join(scratch, '容量淘汰样本.exe');
fs.writeFileSync(reverseTarget, fixture.image);
fs.writeFileSync(ghidraTarget, fixture.image);
fs.writeFileSync(otherTarget, buildPE64Fixture(2).image);
const harnesses = [];

function harness(label, config = {}) {
  const tools = new Map(), effects = [], events = new Map(), routes = new Map();
  const services = {
    webServer: { register(spec) { routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } },
  };
  const ctx = {
    tools: { register(definition) {
      assert(!tools.has(definition.name), 'duplicate tool registration: ' + definition.name);
      tools.set(definition.name, definition); return () => tools.delete(definition.name);
    } },
    get(name) { return services[name]; },
    on(name, handler) { events.set(name, handler); return () => events.delete(name); },
    inject(names, callback) {
      let remove = names.every(name => services[name]) ? callback({ get: ctx.get, ...services }) : null;
      return { async dispose() { if (typeof remove === 'function') { const once = remove; remove = null; await once(); } } };
    },
    effect(body) { const remove = body(); if (typeof remove === 'function') effects.push(remove); },
  };
  apply(ctx, { toolset: 'full', backgroundOpen: false, artifactDir: path.join(scratch, label),
    requestTimeoutMs: 120000, openTimeoutMs: 180000,
    ...(process.env.IG5_IDA_DIR ? { idaDir: process.env.IG5_IDA_DIR } : {}),
    ...(process.env.IG5_PYTHON ? { pythonExe: process.env.IG5_PYTHON } : {}), ...config });
  const result = {
    tools, events, routes,
    call(name, args = {}, execution = {}) {
      const definition = tools.get(name);
      assert(definition, name + ' must be registered');
      return definition.execute(args, { agent: { id: 'host-reliability' }, ...execution });
    },
    async gated(name, args) {
      let dispatched = false;
      const before = (await result.call('ig5_status')).sessions.map(session => [session.key, session.dbRevision]);
      const decision = await events.get('tools/pre-execute')({ name, arguments: args }, async () => { dispatched = true; return { kind: 'allow' }; });
      assert.equal(decision.kind, 'deny', 'Missing agent/approval service must deny ' + name);
      assert.equal(dispatched, false);
      assert.deepEqual((await result.call('ig5_status')).sessions.map(session => [session.key, session.dbRevision]), before);
    },
    async dispose() { for (const remove of effects.splice(0).reverse()) await remove(); },
  };
  harnesses.push(result); return result;
}

const pass = (label, details = {}) => console.log('PASS', label, JSON.stringify(details));
async function status(harness, target, engine) {
  const result = await harness.call('ig5_status');
  return result.sessions.find(item => item.target === target && item.engine === engine);
}
async function waitFor(label, condition, timeout = 5000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { const result = await condition(); if (result) return result; await delay(10); }
  throw new Error('Timed out waiting for ' + label);
}

try {
  const reverse = harness('reverse', { reverseProvider: 'commercial', defaultEngine: 'reverse', maxSessions: 2 });
  const call = (name, args = {}, execution = {}) => reverse.call(name, { target: reverseTarget, engine: 'reverse', ...args }, execution);
  const opened = await call('ig5_open', { path: reverseTarget, background: false });
  assert.equal(opened.bits, 64); assert(opened.n_funcs >= 16);
  const ea = fixture.addresses.constant;
  const before = await call('ig5_decompile', { ea });
  assert.match(before.code, /\b17\b|0x11/i);
  assert.equal((await call('ig5_bytes', { ea, size: 6 })).hex, 'b811000000c3');
  // Populate the exact public decompile cache before the partial mutation.
  assert.equal((await call('ig5_decompile', { ea })).code, before.code);
  const partialArgs = { target: reverseTarget, engine: 'reverse', code:
    `import ida_bytes\nassert ida_bytes.patch_dword(${BigInt(ea) + 1n}, 42)\nraise RuntimeError('intentional exception after patch')` };
  await reverse.gated('ig5_run_idapython', partialArgs);
  const partial = await reverse.call('ig5_run_idapython', partialArgs);
  assert.equal(partial.ok, false); assert.match(partial.error, /intentional exception after patch/);
  assert.equal(partial._ig5.dbRevision, before._ig5.dbRevision + 1);
  const after = await call('ig5_decompile', { ea });
  assert.match(after.code, /\b42\b|0x2a/i);
  assert.notEqual(after.code, before.code); assert.equal(after._ig5.dbRevision, partial._ig5.dbRevision);
  assert.equal((await call('ig5_bytes', { ea, size: 6 })).hex, 'b82a000000c3');
  pass('Reverse partial script failure advances revision and refreshes cached 17 to 42', { revision: after._ig5.dbRevision });

  const marker = path.join(scratch, 'blocking-script-running.txt');
  const blocker = call('ig5_run_idapython', { code:
    `import time\nfrom pathlib import Path\nPath(${JSON.stringify(marker)}).write_text('running', encoding='utf-8')\ntime.sleep(1.25)\nprint('released')` });
  await waitFor('the first native script to enter its blocking section', () => fs.existsSync(marker));
  const controller = new AbortController();
  const cancelledText = 'QUEUED_COMMENT_MUST_NOT_EXECUTE';
  const queued = call('ig5_comment', { ea: fixture.addresses.add, text: cancelledText }, { signal: controller.signal })
    .then(value => ({ value }), error => ({ error }));
  await delay(30); controller.abort();
  const firstResult = await blocker;
  assert.equal(firstResult.ok, true);
  const cancelled = await queued;
  assert(cancelled.error, 'the queued write must reject'); assert.match(cancelled.error.message, /cancelled/i);
  assert.equal(cancelled.error.code, 'ABORT_ERR');
  assert.equal((await status(reverse, reverseTarget, 'reverse')).dbRevision, firstResult._ig5.dbRevision,
    'a cancelled queued write must not reach the worker or increment revision');
  const commentProbe = await call('ig5_run_idapython', { code:
    `import json, ida_bytes\nprint(json.dumps(ida_bytes.get_cmt(${BigInt(fixture.addresses.add)}, False)))` });
  assert.equal(commentProbe.ok, true); assert.equal(JSON.parse(commentProbe.output), null);
  pass('AbortSignal cancels a queued static write before native execution');

  const currentRevision = (await status(reverse, reverseTarget, 'reverse')).dbRevision;
  const implicitArgs = { engine: 'reverse', action: 'define', expected_revision: currentRevision - 1,
    decl: 'struct ImplicitGuardedType { int first; int second; };' };
  await reverse.gated('ig5_struct', implicitArgs);
  await assert.rejects(reverse.call('ig5_struct', implicitArgs), /revision changed/);
  const missing = await reverse.call('ig5_struct', { engine: 'reverse', action: 'list', filter: 'ImplicitGuardedType' });
  assert(!missing.items.some(item => item.name === 'ImplicitGuardedType'));
  assert.equal((await status(reverse, reverseTarget, 'reverse')).dbRevision, currentRevision);
  const implicit = await reverse.call('ig5_struct', { ...implicitArgs, expected_revision: currentRevision });
  assert.equal(implicit.status, 'ok'); assert.equal(implicit._ig5.dbRevision, currentRevision + 1);
  assert.equal((await reverse.call('ig5_struct', { engine: 'reverse', action: 'get', name: 'ImplicitGuardedType' })).size, 8);
  pass('implicit target struct writes enforce expected_revision in the public execution queue');
  await reverse.dispose();

  const ghidra = harness('ghidra', { reverse: false, defaultEngine: 'ghidra', maxSessions: 1 });
  let firstFinished = false;
  const firstOpen = ghidra.call('ig5_open', { path: ghidraTarget, engine: 'ghidra', background: false, analysis_profile: 'interactive' });
  firstOpen.then(() => { firstFinished = true; }, () => { firstFinished = true; });
  // Exercise the original failure window, after protocol ready but before sample info.
  const window = await waitFor('ready-but-opening Ghidra session', async () => {
    const session = await status(ghidra, ghidraTarget, 'ghidra');
    if (session?.ready && session.n_funcs === null) return session;
    if (firstFinished) throw new Error('Ghidra open finished before the concurrent-open window was observed');
    return false;
  }, 120000);
  assert.equal(window.n_funcs, null); assert.equal(firstFinished, false);
  const secondOpen = ghidra.call('ig5_open', { path: ghidraTarget, engine: 'ghidra', background: false, analysis_profile: 'interactive' });
  const [firstInfo, secondInfo] = await Promise.all([firstOpen, secondOpen]);
  for (const info of [firstInfo, secondInfo]) {
    assert.equal(info.bits, 64); assert(info.n_funcs >= 16); assert(info.projectId); assert(info.artifactId);
    assert.equal(info.analysisProfile, 'interactive'); assert.equal(info.analysisComplete, true);
  }
  assert.equal(firstInfo.alreadyOpen, false); assert.equal(secondInfo.alreadyOpen, true);
  assert.equal(firstInfo.artifactId, secondInfo.artifactId);
  await assert.rejects(ghidra.call('ig5_open', { path: ghidraTarget, engine: 'ghidra', background: false, fresh: true }), /already open.*different analysis settings/);
  await assert.rejects(ghidra.call('ig5_open', { path: ghidraTarget, engine: 'ghidra', background: false, analysis_profile: 'full' }), /already open.*different analysis settings/);
  pass('concurrent open waits for full sample info; active fresh/profile changes reject explicitly');

  const defined = await ghidra.call('ig5_struct', { target: ghidraTarget, engine: 'ghidra', action: 'define',
    decl: 'struct CapacityDurableType { int first; int second; };', expected_revision: firstInfo.dbRevision });
  assert.equal(defined.ok, true); assert.equal(defined.saved, false); assert.equal(defined.persistence, 'session-only');
  await ghidra.call('ig5_open', { path: otherTarget, engine: 'ghidra', background: false });
  assert.equal(await status(ghidra, ghidraTarget, 'ghidra'), undefined);
  const reopened = await ghidra.call('ig5_open', { path: ghidraTarget, engine: 'ghidra', background: false });
  assert.equal(reopened.dbRevision, defined._ig5.dbRevision);
  const durableType = await ghidra.call('ig5_struct', { target: ghidraTarget, engine: 'ghidra', action: 'get', name: 'CapacityDurableType' });
  assert.equal(durableType.size, 8); assert.equal(durableType.fields[1].offset, 4);
  pass('normal capacity eviction checkpoints advanced Ghidra writes before closing', { revision: reopened.dbRevision, size: durableType.size });
  await ghidra.dispose();

  const notepadSource = process.env.IG5_TEST_TARGET || path.join(source, '..', '_research', 'fixtures', 'notepad.exe');
  const notepadBytes = fs.readFileSync(notepadSource);
  const notepadTarget = path.join(scratch, '记事本导入回归.exe');
  fs.writeFileSync(notepadTarget, notepadBytes);
  const imports = harness('imports', { reverseProvider: 'commercial', defaultEngine: 'reverse', maxSessions: 1 });
  const importCall = (name, args = {}) => imports.call(name, { target: notepadTarget, engine: 'reverse', ...args });
  await importCall('ig5_open', { path: notepadTarget, background: false });
  const truth = await importCall('ig5_run_idapython', { code: [
    'import json, ida_nalt', 'rows = []',
    'for index in range(ida_nalt.get_import_module_qty()):',
    '    module = ida_nalt.get_import_module_name(index) or ("#" + str(index))',
    '    def collect(ea, name, ordinal):',
    '        rows.append({"module": module, "ea": hex(ea), "name": name or ("#" + str(ordinal)), "ordinal": int(ordinal)})',
    '        return True',
    '    ida_nalt.enum_import_names(index, collect)',
    'counts = {}', 'for row in rows:', '    counts[row["module"]] = counts.get(row["module"], 0) + 1',
    'print(json.dumps({"total": len(rows), "byModule": counts, "getProcAddress": [row for row in rows if row["name"] == "GetProcAddress"]}))',
  ].join('\n') });
  assert.equal(truth.ok, true); const expected = JSON.parse(truth.output);
  assert(expected.total > 100); assert(expected.getProcAddress.length > 0);
  const rows = [];
  for (let offset = 0; offset < expected.total; offset += 100) {
    const page = await importCall('ig5_listing', { kind: 'imports', offset, limit: 100 });
    assert.equal(page.total, expected.total); assert.equal(page.items.length, Math.min(100, expected.total - offset));
    rows.push(...page.items);
  }
  assert.equal(rows.length, expected.total);
  assert.equal(new Set(rows.map(row => JSON.stringify(row))).size, expected.total);
  const byModule = Object.fromEntries(Object.keys(expected.byModule).map(module => [module, rows.filter(row => row.module === module).length]));
  assert.deepEqual(byModule, expected.byModule);
  for (const expectedRow of expected.getProcAddress) {
    assert(rows.some(row => row.module === expectedRow.module && row.ea === expectedRow.ea && row.name === expectedRow.name));
  }
  const scan = await importCall('ig5_scan');
  for (const expectedRow of expected.getProcAddress) {
    assert(scan.suspiciousApis.some(row => row.module === expectedRow.module && row.api === expectedRow.name));
  }
  pass('notepad imports pagination and GetProcAddress scan match a complete native enumeration',
    { imports: expected.total, modules: Object.keys(expected.byModule).length, getProcAddress: expected.getProcAddress });
  await imports.dispose();
  assert.deepEqual(fs.readFileSync(notepadSource), notepadBytes);
  assert.deepEqual(fs.readFileSync(notepadTarget), notepadBytes);
  assert.deepEqual(fs.readFileSync(reverseTarget), fixture.image);
  assert.deepEqual(fs.readFileSync(ghidraTarget), fixture.image);
  console.log('Host reliability passed; artifacts retained:', scratch);
} catch (error) {
  console.error(error.stack, '\nArtifacts retained:', scratch);
  process.exitCode = 1;
} finally {
  for (const instance of harnesses.reverse()) await instance.dispose();
}
