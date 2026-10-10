// Public tool acceptance on generated, disposable binaries. A controlled public
// approval service exercises the actual plugin gate; native engines are real.
// Set IG5_PLUGIN_UNDER_TEST to a downloaded/installed plugin root. This script
// never modifies that root, a real DSH profile, or an existing user database.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pluginRoot = fs.realpathSync(process.env.IG5_PLUGIN_UNDER_TEST || sourceRoot);
const requestedEngines = (process.env.IG5_PUBLIC_CATALOG_ENGINES || 'reverse,ghidra').split(',').map(v => v.trim()).filter(Boolean);
assert(requestedEngines.length && requestedEngines.every(v => ['reverse', 'ghidra'].includes(v)));
assert.equal(new Set(requestedEngines).size, requestedEngines.length);
const executeDebugger = process.env.IG5_PUBLIC_CATALOG_DEBUG !== '0';
const reportDirectory = path.resolve(process.env.IG5_PUBLIC_CATALOG_REPORT_DIR || path.join(os.homedir(), '.dsh', 'ig5', 'artifacts', 'github-consumer-validation-20261010'));
assert(!isChild(reportDirectory, pluginRoot), 'Reports must be outside the tested plugin');
const reportFile = path.join(reportDirectory, 'public-tool-catalog-' + randomUUID() + '.json');
const temporaryRoot = fs.realpathSync(os.tmpdir());
const scratch = fs.mkdtempSync(path.join(temporaryRoot, 'ig5-public-catalog-中文 '));
const originalEnvironment = { ...process.env };
const configuredReverse = { idaDir: process.env.IG5_IDA_DIR, pythonExe: process.env.IG5_PYTHON };
const tools = new Map(), events = new Map(), routes = new Map(), effects = [], checks = [];
const approvalChecks = [], fixtures = [], targets = [], opened = [];
const expectedNames = [
  'doctor', 'open', 'status', 'funcs', 'strings', 'decompile', 'xrefs', 'calls', 'bytes', 'search', 'listing', 'scan',
  'export_diff', 'cfg', 'slice', 'fingerprint', 'rename', 'patch_bytes', 'comment', 'analyze', 'set_type', 'undo',
  'run_idapython', 'dbg', 'struct', 'close', 'profile', 'stack', 'switches', 'switch_repair', 'vtables', 'microcode',
  'bindiff', 'emulate', 'ir', 'sync', 'crypto', 'protocol',
].map(v => 'ig5_' + v);
const writeNames = ['rename', 'patch_bytes', 'comment', 'analyze', 'set_type', 'undo', 'run_idapython', 'dbg', 'struct', 'switch_repair', 'emulate', 'sync'].map(v => 'ig5_' + v);
let failure, cleanupSucceeded = false, engineReports = [], approvalSequence = 0;
const executionAgent = { id: 'public-catalog-acceptance' };
const approvalState = { outcome: 'allowed-once', requests: [] };
const approvalService = {
  async request(request) { approvalState.requests.push(request); return approvalState.outcome; },
};
function isChild(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const listingRows = value => value.items || value.rows || [];
const stringText = row => row.text ?? row.str ?? row.value ?? '';
const inline = bytes => ({ encoding: 'hex', data: bytes.toString('hex') });
function publicError(error) {
  let message = String(error?.message || error);
  for (const value of [configuredReverse.idaDir, configuredReverse.pythonExe]) if (value) message = message.split(value).join('Reverse runtime');
  message = message.replace(/IDA(?: Professional)?\s+\d+(?:\.\d+)*[^|\n]*/gi, 'Reverse runtime');
  return { name: error?.name || 'Error', code: error?.code ?? null, message };
}
const context = {
  tools: { register(definition) { assert(!tools.has(definition.name)); tools.set(definition.name, definition); return () => tools.delete(definition.name); } },
  get(name) { return name === 'webServer' ? context.webServer : name === 'approval' ? approvalService : undefined; },
  webServer: { register(spec) { assert(!routes.has(spec.path)); routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } },
  on(name, handler) { assert(!events.has(name)); events.set(name, handler); return () => events.delete(name); },
  inject(names, callback) {
    const remove = names.every(name => context.get(name)) ? callback({ get: context.get, webServer: context.webServer }) : undefined;
    const dispose = async () => { if (typeof remove === 'function') await remove(); };
    effects.push(dispose); return { dispose };
  },
  effect(body) { const remove = body(); if (typeof remove === 'function') effects.push(remove); },
};
async function call(name, args = {}, engine, target = targets[0]) {
  const definition = tools.get(name); assert(definition, name + ' must be registered');
  const parameters = { ...(target ? { target } : {}), ...(engine ? { engine } : {}), ...args };
  const execution = { agent: executionAgent, callId: 'catalog-call-' + (++approvalSequence), signal: new AbortController().signal };
  if (writeNames.includes(name)) {
    let dispatchAllowed = false;
    const decision = await events.get('tools/pre-execute')({ name, arguments: parameters, ...execution }, async () => { dispatchAllowed = true; return { kind: 'allow' }; });
    assert.equal(decision.kind, 'allow'); assert.equal(dispatchAllowed, true, 'Allowed-once must delegate ' + name);
  }
  const value = await definition.execute(parameters, execution);
  if (writeNames.includes(name)) await events.get('tools/post-execute')({ name, arguments: parameters }, { isError: false, value }, async () => ({ kind: 'accept' }));
  return value;
}
async function check(tool, engine, label, run) {
  const start = Date.now();
  try {
    const evidence = await run(); checks.push({ tool, engine, label, status: 'passed', durationMs: Date.now() - start, evidence });
    console.log('PASS', engine || 'host', tool, label);
  } catch (error) {
    checks.push({ tool, engine, label, status: 'failed', durationMs: Date.now() - start, error: publicError(error) }); throw error;
  }
}
async function unsupported(tool, engine, args, method) {
  const before = (await call('ig5_status')).sessions.map(s => [s.key, s.dbRevision]);
  let rejected;
  await assert.rejects(call(tool, args, engine), error => {
    assert.match(error.message, new RegExp('does not support ' + method + '|requires engine=ghidra'));
    rejected = publicError(error); return true;
  });
  assert.deepEqual((await call('ig5_status')).sessions.map(s => [s.key, s.dbRevision]), before);
  // Preserve the actual error shape: the current host capability guard has no
  // code field. This evidence must not be advertised as a coded worker error.
  checks.push({ tool, engine, label: 'explicit capability rejection, revisions unchanged', status: 'unsupported', error: rejected });
}
async function data(query) {
  let status;
  const value = await new Promise((resolve, reject) => {
    try { routes.get('/ig5-data')({ method: 'GET', url: '/ig5-data?' + new URLSearchParams(query) }, {
      writeHead(code) { status = code; }, end(body) { resolve(JSON.parse(body)); },
    }); } catch (error) { reject(error); }
  });
  assert.equal(status, 200); assert.equal(value.error, undefined); return value.data;
}
async function revision(engine) {
  const session = (await call('ig5_status')).sessions.find(s => s.engine === engine && s.target === targets[0]);
  assert(session); return session.dbRevision;
}
function assertInsideScratch(filename) { assert(isChild(fs.realpathSync(filename), scratch), 'Output must belong to this test'); }

try {
  for (const key of Object.keys(process.env)) if (/^IG5_|^JAVA_HOME$|^JDK_HOME$|^PYTHON|^GHIDRA/i.test(key)) delete process.env[key];
  process.env.IG5_HOME = path.join(scratch, 'home');
  const { buildPE64Fixture } = await import(pathToFileURL(path.join(pluginRoot, 'scripts/fixtures/pe64.mjs')).href);
  const { apply } = await import(pathToFileURL(path.join(pluginRoot, 'index.js')).href);
  for (const version of [1, 2]) {
    const fixture = buildPE64Fixture(version);
    // Deterministic direct caller and explicit string/constant evidence.
    fixture.image.set(Buffer.from('e87bffffffc3', 'hex'), 0x480);
    fixture.image.write('https://ig5.invalid/crypto AES fixture\0', 0x1300, 'ascii');
    const aesSource = fs.readFileSync(path.join(pluginRoot, 'worker/scan_analysis.py'), 'utf8');
    const aesMatch = /AES_SBOX\s*=\s*bytes\.fromhex\(\s*([\s\S]*?)\)/.exec(aesSource);
    assert(aesMatch, 'Fixture needs the shipped canonical AES S-box vector');
    const aesHex = [...aesMatch[1].matchAll(/['"]([0-9a-fA-F\s]+)['"]/g)].map(m => m[1]).join('').replace(/\s/g, '');
    const aes = Buffer.from(aesHex, 'hex'); assert.equal(aes.length, 256); aes.copy(fixture.image, 0x1200);
    const target = path.join(scratch, '生成版本 ' + version + '.exe'); fs.writeFileSync(target, fixture.image, { flag: 'wx' });
    fixtures.push(fixture); targets.push(target);
  }
  apply(context, { toolset: 'full', defaultEngine: requestedEngines[0], reverse: requestedEngines.includes('reverse'),
    artifactDir: path.join(scratch, 'artifacts'), projectRoot: path.join(scratch, 'home', 'projects'),
    requestTimeoutMs: 120000, openTimeoutMs: 180000, maxSessions: 8,
    ...(configuredReverse.idaDir ? { idaDir: configuredReverse.idaDir } : {}),
    ...(configuredReverse.pythonExe ? { pythonExe: configuredReverse.pythonExe } : {}),
  });
  assert.deepEqual([...tools.keys()].sort(), [...expectedNames].sort());
  for (const name of writeNames) {
    const execution = { agent: executionAgent, callId: 'catalog-denial-' + (++approvalSequence), signal: new AbortController().signal };
    const exec = { name, arguments: { target: targets[0] }, ...execution };
    approvalState.outcome = 'rejected'; let deniedDispatchCalls = 0;
    const rejected = await events.get('tools/pre-execute')(exec, async () => { deniedDispatchCalls++; return { kind: 'allow' }; });
    assert.equal(rejected.kind, 'deny'); assert.equal(deniedDispatchCalls, 0);
    const request = approvalState.requests.at(-1); assert.equal(request.toolName, name);
    assert.equal(request.agent, execution.agent); assert.equal(request.callId, execution.callId); assert.equal(request.signal, execution.signal);
    approvalState.outcome = 'allowed-once'; let allowedDelegations = 0;
    const allowedExec = { ...exec, callId: 'catalog-allowed-' + (++approvalSequence), signal: new AbortController().signal };
    const allowed = await events.get('tools/pre-execute')(allowedExec, async () => { allowedDelegations++; return { kind: 'allow' }; });
    assert.equal(allowed.kind, 'allow'); assert.equal(allowedDelegations, 1);
    approvalChecks.push({ tool: name, publicServiceRequested: true, rejectedDecision: 'deny', deniedDispatchCalls, allowedOnceDelegations: allowedDelegations });
  }
  await check('ig5_profile', 'host', 'Full38 / Core8 / Full38 schemas', async () => {
    assert.equal((await call('ig5_profile', { toolset: 'core' })).activeTools.length, 8); assert.equal(tools.size, 8);
    const full = await call('ig5_profile', { toolset: 'full' }); assert.equal(full.activeTools.length, 38); assert.equal(tools.size, 38);
    for (const engine of requestedEngines) assert.equal(full.engines.find(e => e.id === engine)?.available, true, engine + ' must actually be available');
    return { core: 8, full: 38, approvalTools: approvalChecks.length };
  });
  for (const engine of requestedEngines) {
    await check('ig5_doctor', engine, 'actual worker bootstrap', async () => { const value = await call('ig5_doctor', {}, engine); assert.equal(value.ok, true); return { ok: value.ok }; });
    for (const [index, target] of targets.entries()) await check('ig5_open', engine, 'generated version ' + (index + 1), async () => {
      const value = await call('ig5_open', { path: target, background: false, analysis_timeout: 60 }, engine, target);
      assert.equal(value.engine, engine); assert.equal(value.bits, 64); assert(value.n_funcs >= 16); assert.equal(value.partial, false);
      opened.push({ engine, target }); return { functions: value.n_funcs, artifactId: value.artifactId };
    });
  }
  const fixture = fixtures[0], ea = fixture.addresses.add;
  for (const engine of requestedEngines) {
    await check('ig5_status', engine, 'live scoped native database', async () => {
      const value = await call('ig5_status'); const session = value.sessions.find(s => s.engine === engine && s.target === targets[0]);
      assert(session?.alive); assert.equal(session.sha256, hash(fixture.image)); assert.equal(session.dbRevision, 0); return { sha256: session.sha256, revision: 0 };
    });
    await check('ig5_funcs', engine, 'known exported function and library filtering', async () => {
      const value = await call('ig5_funcs', { limit: 100 }, engine); assert(value.funcs.some(f => f.ea === ea && f.name === 'ig5_fixture_add'));
      const user = await call('ig5_funcs', { user_only: true, limit: 100 }, engine); assert(user.funcs.every(f => !f.is_lib)); return { total: value.total, user: user.total };
    });
    await check('ig5_strings', engine, 'exact generated string', async () => {
      const value = await call('ig5_strings', { limit: 200 }, engine); assert(value.strings.some(row => stringText(row).includes('https://ig5.invalid/crypto AES fixture'))); return { total: value.total };
    });
    await check('ig5_decompile', engine, 'native integer function pseudocode', async () => {
      const value = await call('ig5_decompile', { ea }, engine); assert.equal(value.ea, ea); assert.match(value.code, /return/); assert(value.code.length > 20); return { characters: value.code.length };
    });
    await check('ig5_bytes', engine, 'exact known machine bytes', async () => { const value = await call('ig5_bytes', { ea, size: 5 }, engine); assert.equal(value.hex, '488d0411c3'); assert.equal(value.size, 5); return { hex: value.hex }; });
    await check('ig5_search', engine, 'exact and wildcard hit address', async () => {
      for (const pattern of ['48 8d 04 11 c3', '48 8d ?? 11 c3']) assert((await call('ig5_search', { pattern, limit: 50 }, engine)).hits.includes(ea)); return { address: ea };
    });
    await check('ig5_calls', engine, 'real caller/callee link', async () => {
      const callers = await call('ig5_calls', { ea, direction: 'callers' }, engine);
      const callees = await call('ig5_calls', { ea: fixture.addresses.spin, direction: 'callees' }, engine);
      assert(callers.calls.some(row => row.ea === fixture.addresses.spin)); assert(callees.calls.some(row => row.ea === ea)); return { caller: fixture.addresses.spin, callee: ea };
    });
    await check('ig5_xrefs', engine, 'direct-call native reference', async () => {
      const value = await call('ig5_xrefs', { ea }, engine); assert(value.hits.some(row => [row.other, row.from, row.func_ea].includes(fixture.addresses.spin))); return { total: value.total };
    });
    await check('ig5_listing', engine, 'segments / exports / correctly empty imports', async () => {
      const segments = await call('ig5_listing', { kind: 'segments', limit: 100 }, engine); assert(listingRows(segments).some(row => row.name === '.text'));
      const exports = await call('ig5_listing', { kind: 'exports', limit: 100 }, engine); assert(listingRows(exports).some(row => row.name === 'ig5_fixture_add' && row.ea === ea));
      const imports = await call('ig5_listing', { kind: 'imports', limit: 100 }, engine); assert.equal(imports.total, 0); assert.equal(listingRows(imports).length, 0);
      return { segments: segments.total, exports: exports.total, imports: imports.total };
    });
    await check('ig5_scan', engine, 'canonical AES marker at exact generated address; bounded reads', async () => {
      const value = await call('ig5_scan', { max_bytes: 65536 }, engine); assert.equal(value.schemaVersion, 2); assert.equal(value.sourceEngine, engine);
      assert.equal(value.idb_modified, false); assert(value.crypto_markers.some(row => row.name === 'AES S-box' && row.ea === '0x140003400'));
      const bounded = await call('ig5_scan', { max_bytes: 128, max_segment_bytes: 64 }, engine); assert(bounded.truncated); assert(bounded.coverage.bytesAttempted <= 128);
      return { markers: value.crypto_markers.length, boundedBytes: bounded.coverage.bytesAttempted };
    });
    await check('ig5_cfg', engine, 'branch topology consistency', async () => {
      const value = await call('ig5_cfg', { ea: fixture.addresses.branch }, engine); assert(value.blocks.length > 1); assert(value.edges.length > 0);
      assert.equal(value.total_blocks, value.blocks.length); assert.equal(value.total_edges, value.edges.length); assert.match(value.mermaid, /flowchart TD/); return { blocks: value.blocks.length, edges: value.edges.length };
    });
    await check('ig5_slice', engine, 'symbols and focused variable lines', async () => {
      const value = await call('ig5_slice', { ea }, engine); assert(value.variables.length > 0); const name = value.variables[0].name;
      const focused = await call('ig5_slice', { ea, var: name }, engine); assert.equal(focused.slice_variable, name); assert(focused.slice_lines.length > 0); return { variables: value.variables.length, focusedLines: focused.slice_lines.length };
    });
    await check('ig5_fingerprint', engine, 'architecture and function counts', async () => {
      const value = await call('ig5_fingerprint', {}, engine); if (engine === 'ghidra') assert.equal(value.bits, 64); assert.equal(typeof value.abi, 'string');
      const functions = await call('ig5_funcs', { limit: 100 }, engine); assert.equal(value.total_functions, functions.total);
      assert.equal(value.library_functions_count + value.user_functions_count, value.total_functions); return { abi: value.abi, functions: value.total_functions };
    });
    await check('ig5_stack', engine, 'assembly frame with concrete local member', async () => { const value = await call('ig5_stack', { ea: fixture.addresses.frame }, engine); assert(value.members.length > 0); assert(value.members.some(row => row.size === 8)); return { members: value.members.length }; });
    await check('ig5_bindiff', engine, 'changed constants and unchanged add function', async () => {
      const value = await call('ig5_bindiff', { left: targets[0], right: targets[1], threshold: 0.4, limit: 100 }, engine);
      const changed = value.matches.find(row => row.old.name === 'ig5_fixture_constant'); assert(changed?.changed); assert(changed.changedBlocks.old.length && changed.changedBlocks.new.length);
      assert.equal(value.matches.find(row => row.old.name === 'ig5_fixture_add')?.changed, false); return { matches: value.matches.length, changed: changed.old.name };
    });
    await check('ig5_emulate', engine, 'real Unicorn exact integer return', async () => {
      const before = await call('ig5_bytes', { ea, size: 5 }, engine), beforeRevision = await revision(engine);
      const value = await call('ig5_emulate', { ea, abi: 'win64', args: ['19', '23'] }, engine);
      assert.equal(value.ok, true); assert.equal(value.reason, 'returned'); assert.equal(value.return_value, '0x2a'); assert.equal(value.idb_modified, false);
      assert.equal((await call('ig5_bytes', { ea, size: 5 }, engine)).hex, before.hex); assert.equal(await revision(engine), beforeRevision);
      return { returnValue: value.return_value, databaseUnchanged: true };
    });
    await check('ig5_rename', engine, 'rename reflected in native decompilation', async () => {
      const name = 'IG5Catalog_' + engine + '_add'; const value = await call('ig5_rename', { ea, new_name: name }, engine); assert.equal(value.ok, true); assert.equal(value.new, name);
      assert.equal((await call('ig5_decompile', { ea }, engine)).name, name); return { name };
    });
    await check('ig5_comment', engine, 'native comment response and journal inverse', async () => {
      const text = 'IG5 catalog comment ' + engine; const value = await call('ig5_comment', { ea, text }, engine); assert.equal(value.ok, true); assert.equal(value.text, text);
      const undone = await call('ig5_undo', {}, engine); assert.equal(undone.ok, true); assert.equal(undone.kind, 'comment'); return { text, undone: true };
    });
    await check('ig5_set_type', engine, 'prototype changes actual pseudocode and can undo', async () => {
      // A pre-existing explicit type gives Reverse a concrete inverse, instead
      // of relying on its documented inability to undo an absent old type.
      const baseline = await call('ig5_set_type', { ea, decl: 'long long IG5Catalog_' + engine + '_add(long long baseline_left, long long baseline_right);' }, engine);
      assert.equal(baseline.ok, true);
      const value = await call('ig5_set_type', { ea, decl: 'long long IG5Catalog_' + engine + '_add(long long catalog_left, long long catalog_right);' }, engine);
      assert.equal(value.ok, true); assert.match(value.type, /long\s*long|__int64/); const code = (await call('ig5_decompile', { ea }, engine)).code;
      assert(code.includes('catalog_left') && code.includes('catalog_right'));
      const undone = await call('ig5_undo', {}, engine); assert.equal(undone.ok, true); assert.equal(undone.kind, 'set_type');
      const restored = (await call('ig5_decompile', { ea }, engine)).code; assert(restored.includes('baseline_left') && restored.includes('baseline_right'));
      return { type: value.type, pseudocodeParametersVerified: true, existingTypeInverseVerified: true };
    });
    await check('ig5_analyze', engine, 'delete/create function changes enumerated database', async () => {
      const address = fixture.addresses.case2; const before = await call('ig5_funcs', { limit: 100 }, engine); assert(before.funcs.some(row => row.ea === address));
      assert.equal((await call('ig5_analyze', { action: 'delete_function', ea: address }, engine)).ok, true);
      const deleted = await call('ig5_funcs', { limit: 100 }, engine); assert.equal(deleted.total, before.total - 1); assert(!deleted.funcs.some(row => row.ea === address));
      assert.equal((await call('ig5_analyze', { action: 'create_function', ea: address, size: 6 }, engine)).ok, true);
      assert((await call('ig5_funcs', { limit: 100 }, engine)).funcs.some(row => row.ea === address)); assert.equal((await call('ig5_undo', {}, engine)).ok, true); assert.equal((await call('ig5_undo', {}, engine)).ok, true);
      assert.equal((await call('ig5_funcs', { limit: 100 }, engine)).total, before.total); return { before: before.total, deleted: deleted.total, restored: before.total };
    });
    await check('ig5_struct', engine, 'define/get/list/apply concrete field layout', async () => {
      const name = 'IG5CatalogHeader_' + engine; const value = await call('ig5_struct', { action: 'define', decl: 'struct ' + name + ' { int magic; int version; char tag[8]; };' }, engine);
      assert.equal(value.name, name); const layout = await call('ig5_struct', { action: 'get', name }, engine); assert.equal(layout.size, 16);
      assert.deepEqual(layout.fields.map(({ name, offset, size }) => ({ name, offset, size })), [{ name: 'magic', offset: 0, size: 4 }, { name: 'version', offset: 4, size: 4 }, { name: 'tag', offset: 8, size: 8 }]);
      assert((await call('ig5_struct', { action: 'list', filter: name }, engine)).items.some(row => row.name === name));
      const before = await revision(engine);
      const applied = await call('ig5_struct', { action: 'apply', name, ea: '0x140003e00' }, engine);
      if (engine === 'reverse') assert.equal(applied.applied, true);
      else { assert.equal(applied.ok, true); assert.equal(applied.ea, '0x140003e00'); }
      assert.equal(await revision(engine), before + 1); return { name, size: layout.size, applicationRevisionAdvanced: true };
    });
    await check('ig5_patch_bytes', engine, 'expected mismatch rejects, real patch reads back', async () => {
      await assert.rejects(call('ig5_patch_bytes', { ea, hex: '90', expected: 'ff' }, engine), /expected|match/);
      assert.equal((await call('ig5_bytes', { ea, size: 1 }, engine)).hex, '48');
      const value = await call('ig5_patch_bytes', { ea, hex: '90', expected: '48' }, engine); assert.equal(value.ok, true); assert.equal(value.applied, true);
      assert.equal((await call('ig5_bytes', { ea, size: 1 }, engine)).hex, '90'); return { before: value.before, after: value.after };
    });
    await check('ig5_export_diff', engine, 'exported binary reflects current patch', async () => {
      const value = await call('ig5_export_diff', {}, engine); assert.equal(value.patches, 1); assertInsideScratch(value.patchedBinary); assertInsideScratch(value.report);
      const bytes = fs.readFileSync(value.patchedBinary); assert.equal(bytes[0x400], 0x90); const expected = Buffer.from(fixture.image); expected[0x400] = 0x90; assert.deepEqual(bytes, expected);
      return { patches: value.patches, bytes: bytes.length };
    });
    await check('ig5_undo', engine, 'byte inverse and undo-aware export', async () => {
      const journal = await call('ig5_undo', { action: 'list' }, engine); assert(journal.journal.length > 0);
      const undone = await call('ig5_undo', {}, engine); assert.equal(undone.ok, true); assert(['bytes', 'patch'].includes(undone.kind));
      assert.equal((await call('ig5_bytes', { ea, size: 5 }, engine)).hex, '488d0411c3'); const value = await call('ig5_export_diff', {}, engine); assert.equal(value.patches, 0);
      assert.deepEqual(fs.readFileSync(value.patchedBinary), fixture.image); return { patchesAfterUndo: 0 };
    });
    if (engine === 'reverse') {
      await check('ig5_run_idapython', engine, 'native API byte/name result exactly matches public tools', async () => {
        const value = await call('ig5_run_idapython', { code: 'import json, ida_bytes, ida_name\nprint(json.dumps({"hex": ida_bytes.get_bytes(' + BigInt(ea) + ', 5).hex(), "name": ida_name.get_name(' + BigInt(ea) + ')}))' }, engine);
        assert.equal(value.ok, true); const result = JSON.parse(value.output); assert.equal(result.hex, '488d0411c3'); assert.equal(result.name, 'IG5Catalog_reverse_add'); return result;
      });
      await check('ig5_vtables', engine, 'RTTI class plus explicit virtual slot', async () => {
        const value = await call('ig5_vtables', { ea: fixture.vtable, abi: 'msvc', offset: 8 }, engine); assert.equal(value.total, 1); const table = value.tables[0];
        assert.equal(table.slots.length, 2); assert.equal(table.selected_slot.target, fixture.addresses.buffer); assert.equal(table.rtti.type.raw_name, '.?AVIG5Derived@@'); return { class: table.rtti.type.raw_name, slots: table.slots.length };
      });
      await check('ig5_microcode', engine, 'real bounded generated IR', async () => {
        const value = await call('ig5_microcode', { ea, maturity: 'generated', max_blocks: 30, max_instructions: 200 }, engine); assert.equal(value.ok, true); assert.equal(value.graph_built, true);
        assert(value.returned_instructions > 0); assert(value.blocks.some(block => block.instructions.some(row => row.text.length > 0))); return { blocks: value.total_blocks, instructions: value.returned_instructions };
      });
      await check('ig5_switch_repair', engine, 'preview leaves database unchanged and explicit apply', async () => {
        const args = { ea: fixture.switchJump, action: 'define', table: fixture.switchTable, ncases: 3, element_size: 8, lowcase: 0, default: fixture.switchDefault };
        const before = await revision(engine); const preview = await call('ig5_switch_repair', { ...args, apply: false }, engine); assert.equal(preview.ok, true); assert.equal(preview.applied, false); assert.equal(await revision(engine), before);
        const value = await call('ig5_switch_repair', { ...args, apply: true }, engine); assert.equal(value.ok, true); return { cases: 3, previewUnchanged: true };
      });
      await check('ig5_switches', engine, 'exact case values and native target set', async () => {
        const value = await call('ig5_switches', { ea: fixture.switchJump, exact: true }, engine); assert.equal(value.total, 1);
        assert.deepEqual(value.switches[0].cases.flatMap(row => row.values).sort(), [0, 1, 2]);
        assert.deepEqual(value.switches[0].cases.map(row => row.target).sort(), ['case0', 'case1', 'case2'].map(name => fixture.addresses[name]).sort()); return { cases: 3 };
      });
      if (requestedEngines.includes('ghidra')) await unsupported('ig5_ir', engine, { ea }, 'ir');
    } else {
      for (const [tool, method] of [['ig5_run_idapython', 'idapython'], ['ig5_microcode', 'microcode']])
        await unsupported(tool, engine, tool === 'ig5_run_idapython' ? { code: 'pass' } : { ea }, method);
      await check('ig5_vtables', engine, 'IG5 kernel RTTI over real Ghidra memory', async () => {
        const value = await call('ig5_vtables', { ea: fixture.vtable, abi: 'msvc', offset: 8 }, engine);
        assert.equal(value.total, 1); const table = value.tables[0];
        assert.equal(table.slots.length, 2); assert.equal(table.selected_slot.target, fixture.addresses.buffer);
        assert.equal(table.rtti.type.raw_name, '.?AVIG5Derived@@'); assert.equal(value.implementation, 'ig5-kernel');
        return { class: table.rtti.type.raw_name, slots: 2 };
      });
      await check('ig5_switch_repair', engine, 'validated target override, unchanged preview and transaction', async () => {
        const args = { ea: fixture.switchJump, action: 'define', table: fixture.switchTable, ncases: 3, element_size: 8,
          lowcase: 0, default: fixture.switchDefault };
        const before = await revision(engine), preview = await call('ig5_switch_repair', { ...args, apply: false }, engine);
        assert.equal(preview.applied, false); assert.equal(await revision(engine), before);
        assert.equal(preview.labelsPersisted, false); assert.equal(preview.defaultMetadataPersisted, false);
        assert.deepEqual(preview.targets.slice(0, 3), ['case0', 'case1', 'case2'].map(name => fixture.addresses[name]));
        const applied = await call('ig5_switch_repair', { ...args, apply: true }, engine);
        assert.equal(applied.applied, true); assert.equal(applied.committed, true); assert.equal(applied.saved, false);
        assert.equal(await revision(engine), before + 1); return { targets: applied.targets, journalId: applied.journalId };
      });
      await check('ig5_switches', engine, 'real branch destinations with explicit unknown default', async () => {
        const value = await call('ig5_switches', { ea: fixture.switchJump, exact: true }, engine);
        assert.equal(value.total, 1); const table = value.switches[0]; assert.equal(table.defaultUnknown, true);
        const targets = new Set(table.cases.map(row => row.target));
        for (const name of ['case0', 'case1', 'case2']) assert(targets.has(fixture.addresses[name]));
        return { targets: [...targets], labelsMapped: table.labelsMapped, defaultUnknown: true };
      });
      await check('ig5_ir', engine, 'typed raw/high p-code with native provenance', async () => {
        const evidence = {};
        for (const level of ['raw', 'high']) { const value = await call('ig5_ir', { ea, level, max_instructions: 200 }, engine); assert(value.instructions.length > 0); assert.equal(value.idb_modified, false); assert.equal(value.source.engine, 'Ghidra'); evidence[level] = value.instructions.length; }
        return evidence;
      });
    }
    engineReports.push({ engine, sampleSHA256: hash(fixture.image), revision: await revision(engine) });
  }
  if (requestedEngines.length === 2) await check('ig5_sync', 'reverse→ghidra', 'reviewed name/comment plan, digest rejection, exact apply and replay rejection', async () => {
    const text = 'IG5 cross-engine catalog evidence'; await call('ig5_comment', { ea, text }, 'reverse');
    const args = { action: 'preview', source_engine: 'reverse', destination_engine: 'ghidra', selections: [{ kind: 'rename', rva: '0x1000' }, { kind: 'comment', rva: '0x1000' }] };
    const plan = await call('ig5_sync', args, 'ghidra'); assert.equal(plan.rows.length, 2); assert(plan.rows.some(row => row.kind === 'comment' && row.after === text));
    await assert.rejects(call('ig5_sync', { action: 'apply', plan_id: plan.plan_id, plan_digest: 'wrong' }, 'ghidra'), /digest/);
    const value = await call('ig5_sync', { action: 'apply', plan_id: plan.plan_id, plan_digest: plan.plan_digest }, 'ghidra'); assert.equal(value.ok, true); assert.equal(value.applied.length, 2);
    assert.equal((await call('ig5_decompile', { ea }, 'ghidra')).name, 'IG5Catalog_reverse_add');
    const empty = await call('ig5_sync', args, 'ghidra'); assert.equal(empty.rows.length, 0);
    await assert.rejects(call('ig5_sync', { action: 'apply', plan_id: plan.plan_id, plan_digest: plan.plan_digest }, 'ghidra'), /already been attempted/); return { applied: value.applied.length, verifiedEmptyFollowup: true };
  });
  const plain = Buffer.from('IG5 public tool catalog verified text'), encrypted = Buffer.from(plain.map(value => value ^ 0x5a));
  await check('ig5_crypto', 'data', 'bounded XOR decrypt, exact verification and reusable result', async () => {
    const value = await call('ig5_crypto', { action: 'transform', input: inline(encrypted), recipe: { kind: 'xor', key: inline(Buffer.from([0x5a])) }, expected: inline(plain) });
    assert.equal(value.output.sha256, hash(plain)); assert.equal(value.value.verification.matched, true);
    const historical = await call('ig5_crypto', { action: 'result', result_id: value.result_id }); assert.equal(historical.output.ref, value.output.ref); return { outputSHA256: value.output.sha256 };
  });
  await check('ig5_protocol', 'data', 'length prefix and exact typed UTF8 field decoding', async () => {
    const bytes = Buffer.from('000548656c6c6f', 'hex');
    const value = await call('ig5_protocol', { action: 'decode', input: inline(bytes), framing: { type: 'length-prefix', size: 2, offset: 0, endian: 'big', headerLength: 2, lengthIncludesHeader: false }, schema: { fields: [{ name: 'length', offset: 0, type: 'u16', endian: 'big' }, { name: 'text', offset: 2, type: 'utf8', length: 5 }] } });
    assert.equal(value.value.complete, true); assert.equal(value.value.frames.length, 1); const fields = value.value.frames[0].fields;
    assert.equal(fields.find(row => row.name === 'length').value, 5); assert.equal(fields.find(row => row.name === 'text').value, 'Hello'); return { frames: 1, text: 'Hello' };
  });
  if (executeDebugger) await check('ig5_dbg', 'x64dbg', 'generated PE headless breakpoint / registers / memory / step / stop', async () => {
    const engine = requestedEngines.includes('ghidra') ? 'ghidra' : requestedEngines[0];
    const debug = (op, args = {}) => call('ig5_dbg', { backend: 'x64dbg', op, timeout: 15, ...args }, engine);
    const loaded = await debug('load'); assert.equal(loaded.targetExecuted, false);
    let started;
    try {
      started = await debug('start'); assert.equal(started.ok, true); assert.equal(started.mode, 'headless'); assert.equal(started.state, 'suspended');
      await debug('bpt', { rva: '0x1000' }); const runtimeEntry = '0x' + (BigInt(started.context.mainModuleBase) + 0x1000n).toString(16);
      let regs = await debug('regs'); for (let i = 0; regs.regs.rip !== runtimeEntry && i < 4; i++) { await debug('cont'); regs = await debug('regs'); }
      assert.equal(regs.regs.rip, runtimeEntry); assert.equal((await debug('readmem', { rva: '0x1000', size: 5 })).hex, '488d0411c3');
      await debug('setreg', { reg: 'rax', value: '0x1234', expected: regs.regs.rax }); assert.equal((await debug('regs')).regs.rax, '0x1234');
      const step = await debug('step', { expected_run_id: regs.runId, expected_stop_seq: regs.stopSeq }); assert.equal(step.state, 'suspended'); assert(step.stopSeq > regs.stopSeq);
      assert.notEqual((await debug('regs')).regs.rip, runtimeEntry);
      const cached = await data({ type: 'debug_state', engine: 'x64dbg', target: targets[0] }); assert.equal(cached.runId, started.runId); assert.equal(cached.state, 'suspended');
      assert.equal((await debug('stop')).state, 'no-task'); return { headless: true, breakpointHit: true, stepAdvanced: true, stopped: true };
    } finally { if (started) await debug('stop').catch(() => {}); }
  });
  else checks.push({ tool: 'ig5_dbg', engine: 'x64dbg', label: 'explicitly disabled by test operator', status: 'skipped' });
  for (const session of opened.splice(0).reverse()) await check('ig5_close', session.engine, 'close generated native database', async () => {
    const value = await call('ig5_close', {}, session.engine, session.target); assert.equal(value.closed, true);
    assert(!(await call('ig5_status')).sessions.some(s => s.target === session.target && s.engine === session.engine)); return { closed: true };
  });
  for (const [index, target] of targets.entries()) assert.deepEqual(fs.readFileSync(target), fixtures[index].image, 'Generated input must remain byte-identical');
} catch (error) { failure = publicError(error); process.exitCode = 1; console.error('FAIL public catalog:', failure.message); }
finally {
  const cleanupErrors = [];
  for (const session of opened.splice(0).reverse()) {
    try { await call('ig5_close', {}, session.engine, session.target); }
    catch (error) { cleanupErrors.push(publicError(error)); }
  }
  for (const remove of effects.splice(0).reverse()) {
    try { await remove(); }
    catch (error) { cleanupErrors.push(publicError(error)); }
  }
  try {
    for (const [index, target] of targets.entries()) assert.deepEqual(fs.readFileSync(target), fixtures[index].image);
    assert(isChild(fs.realpathSync(scratch), temporaryRoot)); assert.notEqual(fs.realpathSync(scratch), temporaryRoot);
    assert(path.basename(scratch).startsWith('ig5-public-catalog-'));
    await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 30, retryDelay: 100 });
    cleanupSucceeded = cleanupErrors.length === 0;
    if (cleanupErrors.length) { failure ||= { name: 'CleanupError', code: null, message: cleanupErrors.map(row => row.message).join(' | ') }; process.exitCode = 1; }
  } catch (error) { failure ||= publicError(error); process.exitCode = 1; }
  for (const key of Object.keys(process.env)) if (!(key in originalEnvironment)) delete process.env[key];
  Object.assign(process.env, originalEnvironment);
  const coverage = expectedNames.map(tool => ({ tool, passed: checks.some(row => row.tool === tool && row.status === 'passed'),
    checks: checks.filter(row => row.tool === tool), approval: approvalChecks.find(row => row.tool === tool) }));
  const covered = coverage.filter(row => row.passed).length;
  const report = { schemaVersion: 1, ok: !failure && cleanupSucceeded && covered === 38, pluginRoot, sourceRoot,
    requestedEngines, executeDebugger, toolCount: expectedNames.length, passedToolCount: covered, approvalToolCount: approvalChecks.length,
    engineReports, coverage, checks, cleanupSucceeded, ...(failure ? { error: failure } : {}),
    execution: 'Real public definition.execute → native Reverse/Ghidra workers; real bundled Unicorn; x64dbg executes only a generated PE64.',
    hostBoundary: 'A controlled public approval.request service exercises the real plugin gate with agent/callId/signal. Rejected decisions must not call next; allowed-once delegates once. The actual DSH SDK dispatch is exercised separately in isolation by test_host_sdk.mjs. The desktop consent dialog is not verified by either suite.',
    boundaries: ['One generated PE64 pair; no arbitrary-binary guarantee.', 'Unsupported engine/tool pairs are recorded separately and do not count as successful execution.', 'No Android/iOS native runtime claim.', 'Full38 success requires both licensed Reverse and bundled Ghidra plus enabled x64dbg.'],
  };
  fs.mkdirSync(reportDirectory, { recursive: true }); fs.writeFileSync(reportFile, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ ok: report.ok, passedToolCount: covered, approvalToolCount: approvalChecks.length, report: reportFile }));
  if (!report.ok) process.exitCode = 1;
}
