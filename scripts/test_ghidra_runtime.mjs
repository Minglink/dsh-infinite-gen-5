import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, copyFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
import { runtimeConfiguration } from '../engine_runtime.js';

const source = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = runtimeConfiguration().ghidra;
assert(manifest.available, manifest.reason);
const resolveRuntime = value => value;
const temp = await mkdtemp(path.join(os.tmpdir(), 'ig5-ghidra-'));
const fixture = buildPE64Fixture();
// A real direct call in a test-only copy, to verify callers/callees and xrefs.
fixture.image.set(Buffer.from('e87bffffffc3', 'hex'), 0x480);
const target = path.join(temp, '真实样本.exe');
await writeFile(target, fixture.image);
const child = spawn(resolveRuntime(manifest.pythonExe), ['-I', '-B', path.join(source, 'adapters', 'ghidra', 'worker.py')], {
  env: { ...process.env, IG5_GHIDRA_HOME: resolveRuntime(manifest.ghidraHome),
    IG5_JAVA_HOME: resolveRuntime(manifest.javaHome), IG5_GHIDRA_PROJECT_ROOT: path.join(temp, 'projects') },
  windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
});
let sequence = 0, stderr = '', protocolError;
const pending = new Map();
const ready = new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('Ghidra ready timed out\n' + stderr)), 120000);
  child.once('error', reject);
  child.once('exit', code => { clearTimeout(timer); reject(new Error(`worker exited ${code}\n${stderr}`)); });
  readline.createInterface({ input: child.stdout }).on('line', line => {
    let value;
    try { value = JSON.parse(line); }
    catch { protocolError = new Error('non-JSON stdout: ' + line); reject(protocolError); return; }
    if (value.ig5 === 'ready') { clearTimeout(timer); resolve(value); return; }
    if (value.ig5 === 'progress') return;
    const slot = pending.get(value.id);
    if (!slot) { protocolError = new Error('unknown response: ' + line); return; }
    clearTimeout(slot.timer); pending.delete(value.id);
    if (value.error) slot.reject(Object.assign(new Error(value.error.message), { code: value.error.code }));
    else slot.resolve(value.result);
  });
});
child.stderr.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-50000); });
function rpc(method, params = {}, timeout = 120000) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out\n${stderr}`)); }, timeout);
    pending.set(id, { resolve, reject, timer });
    child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
  });
}
function check(label, value) { console.log('PASS', label, JSON.stringify(value ?? '')); }
try {
  const greeting = await ready;
  assert.equal(greeting.engine, 'Ghidra');
  assert(greeting.capabilities.includes('ir'));
  const doctor = await rpc('doctor');
  assert.equal(doctor.version, '12.1.4'); assert.equal(doctor.ok, true);
  if (/[^\x00-\x7f]/.test(manifest.pythonExe)) assert.equal(doctor.jvmBootstrap, 'relative-classpath');
  assert(doctor.analysisProfileScope.includes('batch Decompiler Parameter ID'));
  assert.equal((await rpc('stats')).open, false);
  check('independent runtime', doctor);
  const opened = await rpc('open', { path: target, fresh: true });
  assert(opened.n_funcs >= 16); assert.equal(opened.imageBase, '0x140000000'); assert.equal(opened.partial, false);
  assert.equal(opened.analysisProfile, 'interactive'); assert.deepEqual(opened.skippedAnalyzers, ['Decompiler Parameter ID']);
  check('import and analysis', { n_funcs: opened.n_funcs, language: opened.languageId, project: opened.project });
  const functions = await rpc('funcs', { limit: 100 });
  assert(functions.funcs.some(row => row.ea === fixture.addresses.add));
  check('functions', functions.total);
  const strings = await rpc('strings', { limit: 100 });
  assert(strings.strings.length > 0); check('defined strings', strings.total);
  const decompiled = await rpc('decompile', { ea: fixture.addresses.add });
  assert(decompiled.code.includes('return')); check('native decompiler', decompiled.code);
  assert.equal((await rpc('decompile', { ea: '', name: 'ig5_fixture_add' })).ea, fixture.addresses.add);
  const bytes = await rpc('bytes', { ea: fixture.addresses.add, size: 5 });
  assert.equal(bytes.hex, '488d0411c3');
  const disasm = await rpc('disasm', { ea: fixture.addresses.add, size: 5 });
  assert(disasm.rows.length >= 2); assert(disasm.rows.some(row => row.mnemonic === 'RET' || /ret/i.test(row.text)));
  check('bytes and disassembly', disasm.rows.length);
  const callers = await rpc('calls', { ea: fixture.addresses.add, direction: 'callers' });
  assert(callers.calls.some(row => row.ea === fixture.addresses.spin)); check('real callers', callers);
  const references = await rpc('xrefs', { ea: fixture.addresses.add });
  assert(references.hits.length > 0); check('references', references.hits.length);
  const search = await rpc('search', { pattern: '488d0411c3' });
  assert(search.hits.includes(fixture.addresses.add)); check('byte search', search.hits.length);
  const exports = await rpc('listing', { kind: 'exports' }); assert(exports.rows.length >= 16); check('exports', exports.rows.length);
  const cfg = await rpc('cfg', { ea: fixture.addresses.branch }); assert(cfg.blocks.length > 1); assert.equal(cfg.total_edges, cfg.edges.length); assert(cfg.edges.length > 0); check('CFG', cfg.blocks.length);
  const stack = await rpc('stack', { ea: fixture.addresses.frame }); assert(stack.members.length > 0); check('stack frame', stack);
  const fingerprint = await rpc('fingerprint'); assert.equal(fingerprint.bits, 64); check('fingerprint', fingerprint);
  for (const kind of ['raw', 'high']) {
    const ir = await rpc('ir', { ea: fixture.addresses.add, kind });
    assert(ir.instructions.length > 0); assert(ir.blocks.length > 0); assert.equal(ir.idb_modified, false); check(kind + ' p-code', ir.instructions.length);
  }
  const slice = await rpc('slice', { ea: fixture.addresses.add }); assert(slice.variables.length > 0); assert(slice.lines.length > 0); assert.equal(slice.total_variables, slice.variables.length); assert(slice.slice_lines.every(row => row.line_no && row.code !== undefined)); check('HighFunction symbols', slice.variables.length);
  const semantics = await rpc('semantics', { limit: 100 }); assert(semantics.functions.length >= 16); assert(semantics.functions.every(row => row.semantic_hash && row.blocks.length)); check('semantic snapshots', semantics.count);
  const inspected = await rpc('inspect', { ea: fixture.addresses.add, size: 5 }); assert.equal(inspected.hex, bytes.hex); assert.equal(inspected.fileOffset, 0x400); check('sync inspect', inspected);
  const renamed = await rpc('rename', { ea: fixture.addresses.add, new_name: 'ig5_test_add' }); assert.equal(renamed.new, 'ig5_test_add');
  assert.equal((await rpc('undo', { action: 'list' })).journal.length, 1);
  assert.equal((await rpc('inspect', { ea: fixture.addresses.add })).name, 'ig5_test_add');
  assert.equal((await rpc('undo')).kind, 'rename'); assert.equal((await rpc('inspect', { ea: fixture.addresses.add })).name, inspected.name); check('rename and undo');
  await rpc('comment', { ea: fixture.addresses.add, text: 'IG5 Ghidra integration' });
  assert.equal((await rpc('inspect', { ea: fixture.addresses.add })).comment, 'IG5 Ghidra integration');
  assert.equal((await rpc('undo')).kind, 'comment'); assert.equal((await rpc('inspect', { ea: fixture.addresses.add })).comment, ''); check('comment and undo');
  await assert.rejects(rpc('patch', { ea: fixture.addresses.add, hex: '90', expected: '00' }), /expected/);
  assert.equal((await rpc('bytes', { ea: fixture.addresses.add, size: 5 })).hex, bytes.hex);
  await rpc('patch', { ea: fixture.addresses.add, hex: '90', expected: '48' });
  assert.equal((await rpc('bytes', { ea: fixture.addresses.add, size: 1 })).hex, '90');
  assert.equal((await rpc('undo')).kind, 'patch'); assert.equal((await rpc('bytes', { ea: fixture.addresses.add, size: 5 })).hex, bytes.hex); check('expected patch and undo');
  const dataBefore = (await rpc('bytes', { ea: '0x140003600', size: 4 })).hex;
  await rpc('patch', { ea: '0x140003600', hex: '11223344', expected: dataBefore });
  assert.equal((await rpc('bytes', { ea: '0x140003600', size: 4 })).hex, '11223344');
  await rpc('undo'); assert.equal((await rpc('bytes', { ea: '0x140003600', size: 4 })).hex, dataBefore); check('defined data patch and inverse');
  const typed = await rpc('set_type', { ea: fixture.addresses.add, type: 'long long ig5_add(long long a, long long b);' }); assert(/long\s*long/.test(typed.type)); assert.equal(typed.saved, false); assert.equal(typed.persistence, 'session-only'); assert.equal(typed.undoMode, 'native'); await rpc('undo'); check('prototype and undo', typed.type);
  const defined = await rpc('struct', { action: 'define', decl: 'struct IG5Pair { int first; int second; };' }); assert.equal(defined.size, 8);
  const layout = await rpc('struct', { action: 'get', name: 'IG5Pair' }); assert.equal(layout.members[1].offset, 4); assert(layout.is_struct); assert(layout.decl.includes('IG5Pair'));
  const types = await rpc('struct', { action: 'list', filter: 'IG5Pair' }); assert.equal(types.items.length, 1); assert.equal(types.total_types, 1);
  await rpc('struct', { action: 'apply', name: 'IG5Pair', ea: '0x140003600' }); await rpc('undo'); await rpc('undo'); check('structure define/get/apply/undo');
  const dataType = await rpc('set_type', { ea: '0x140003600', decl: 'unsigned int ig5_value;' }); assert.equal(dataType.type, 'uint'); await rpc('undo'); check('C data declaration and undo', dataType.type);
  await rpc('analyze', { action: 'delete_function', ea: fixture.addresses.case2 }); assert.equal((await rpc('funcs')).total, 15);
  await rpc('analyze', { action: 'create_function', ea: fixture.addresses.case2, size: 6 }); assert.equal((await rpc('funcs')).total, 16); await rpc('undo'); await rpc('undo');
  await rpc('analyze', { action: 'undefine', ea: fixture.addresses.case2, size: 6 }); assert.equal((await rpc('disasm', { ea: fixture.addresses.case2, size: 6 })).rows.length, 0);
  await rpc('analyze', { action: 'mark_code', ea: fixture.addresses.case2, size: 6 }); assert.equal((await rpc('disasm', { ea: fixture.addresses.case2, size: 6 })).rows.length, 2); await rpc('undo'); await rpc('undo'); check('create/delete function and mark/undefine native undo');
  const full = await rpc('analyze', { action: 'reanalyze', analysis_profile: 'full' });
  assert.equal(full.analysisProfile, 'full'); assert.deepEqual(full.skippedAnalyzers, []); assert.equal(full.partial, false);
  assert.equal(full.analysisScope, 'program'); assert.equal(full.analysisComplete, true);
  check('full reanalyze transaction');
  await assert.rejects(rpc('emulate'), error => error.code === 'unsupported'); check('unsupported explicit');
  await rpc('close'); assert.equal((await rpc('stats')).open, false);
  const reused = await rpc('open', { path: target }); await rpc('close');
  const persisted = await rpc('open', { path: target }); assert.equal(persisted.reusedProject, true); assert.equal(persisted.project, reused.project);
  await rpc('close');
  const keyed = await rpc('open', { path: target, database_key: 'integration-artifact' });
  await rpc('comment', { ea: fixture.addresses.add, text: 'persistent relocated identity' });
  await rpc('close');
  const relocated = path.join(temp, '移动样本.exe'); await copyFile(target, relocated);
  const relocatedState = await rpc('open', { path: relocated, database_key: 'integration-artifact' });
  assert.equal(relocatedState.project, keyed.project); assert.equal(relocatedState.revision, 1);
  assert.equal((await rpc('inspect', { ea: fixture.addresses.add })).comment, 'persistent relocated identity');
  await rpc('close'); check('database key survives sample relocation and revisions persist');
  if (process.argv.includes('--notepad')) {
    const samplePath = path.resolve(source, '..', '_research', 'fixtures', 'notepad.exe');
    const sourceBytes = await readFile(samplePath);
    const sampleCopy = path.join(temp, '真实记事本.exe'); await writeFile(sampleCopy, sourceBytes);
    const sample = await rpc('open', { path: sampleCopy, analysis_profile: 'interactive', timeout: 120 }, 180000);
    assert.equal(sample.partial, false); assert(sample.n_funcs > 100);
    assert.equal(sample.analysisProfile, 'interactive'); assert.deepEqual(sample.skippedAnalyzers, ['Decompiler Parameter ID']);
    const imports = await rpc('listing', { kind: 'imports', limit: 500 }); assert(imports.total > 0);
    const sampleStrings = await rpc('strings', { limit: 10 }); assert(sampleStrings.total > 20);
    let selected, sampleCalls;
    for (const fn of (await rpc('funcs', { limit: 100, user_only: true })).funcs) {
      const calls = await rpc('calls', { ea: fn.ea });
      if (calls.total > 0) { selected = fn; sampleCalls = calls; break; }
    }
    assert(selected); const entryCode = await rpc('decompile', { ea: selected.ea }); assert(entryCode.code.includes(selected.name));
    const entryIR = await rpc('ir', { ea: selected.ea, kind: 'high' }); assert(entryIR.instructions.length > 0);
    await rpc('close'); assert.deepEqual(await readFile(samplePath), sourceBytes); assert.deepEqual(await readFile(sampleCopy), sourceBytes);
    check('real notepad copy analysis', { functions: sample.n_funcs, imports: imports.total, strings: sampleStrings.total, entryIR: entryIR.count, calls: sampleCalls.total });
  }
  assert.deepEqual(await readFile(target), fixture.image); assert(!protocolError); check('source untouched, stable project reuse and strict JSONL');
  console.log('Ghidra integration passed; artifacts:', temp);
} catch (error) {
  console.error(error.stack, '\nWORKER STDERR:\n', stderr, '\nArtifacts:', temp);
  process.exitCode = 1;
} finally {
  child.stdin.end();
  const exited = await Promise.race([new Promise(resolve => child.once('exit', () => resolve(true))), new Promise(resolve => setTimeout(() => resolve(false), 5000))]);
  if (!exited && child.pid) {
    if (process.platform === 'win32') await new Promise(resolve => spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true }).once('exit', resolve));
    else child.kill('SIGKILL');
  }
  for (const slot of pending.values()) clearTimeout(slot.timer);
}
