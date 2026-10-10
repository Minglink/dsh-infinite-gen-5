// Real default .dsh project layout: native Java validation, import, persistence,
// process restart and decompilation. Generated fixture only; no PE execution.
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { runtimeConfiguration, terminateTree } from '../engine_runtime.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const source = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// An explicit source runtime is intentional here: this verifies the modified
// files against their patch proof before the parent reseals the full inventory.
const runtime = runtimeConfiguration({ ghidraRuntime: path.join(source, 'runtimes/ghidra/runtime.json') });
assert.ok(runtime.ghidra.available, runtime.ghidra.reason);
assert.equal(path.resolve(runtime.projectRoot).toLowerCase(), path.join(os.homedir(), '.dsh', 'ig5', 'projects').toLowerCase(),
  'Regression must use the actual default projectRoot; unset IG5_HOME/custom overrides');
const projectRoot = runtime.projectRoot;
const reportRoot = path.join(os.homedir(), '.dsh', 'ig5', 'artifacts', 'ghidra-project-path-regression', randomUUID());
await fs.mkdir(reportRoot, { recursive: true });
const fixture = buildPE64Fixture();
const target = path.join(reportRoot, '隐藏目录持久化夹具.exe');
await fs.writeFile(target, fixture.image, { flag: 'wx' });
const checks = [];
let active;
function passed(name, evidence) { checks.push({ name, ok: true, evidence }); console.log('PASS', name); }
const proof = JSON.parse(await fs.readFile(path.join(source, 'runtimes/ghidra/runtime.json'), 'utf8')).localProjectPathPatch;
assert.equal(proof.patch, 'ig5-ghidra-local-project-path-v1');
for (const [name, expected] of [[proof.jarPath, proof.patchedJarSHA256], [proof.sourceZipPath, proof.patchedSourceZipSHA256]])
  assert.equal(createHash('sha256').update(await fs.readFile(path.join(source, 'runtimes/ghidra', name))).digest('hex'), expected);
passed('patched runtime JAR and source ZIP match build proof', { jarSHA256: proof.patchedJarSHA256, sourceZipSHA256: proof.patchedSourceZipSHA256 });

async function start() {
  const child = spawn(runtime.ghidra.pythonExe, ['-I', '-B', path.join(source, 'adapters/ghidra/worker.py')], {
    env: { ...process.env, IG5_GHIDRA_HOME: runtime.ghidra.ghidraHome, IG5_JAVA_HOME: runtime.ghidra.javaHome,
      IG5_GHIDRA_PROJECT_ROOT: projectRoot }, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
  });
  let serial = 0, stderr = '', readyResolve, readyReject;
  const pending = new Map();
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const readyTimer = setTimeout(() => readyReject(new Error('Ghidra ready timed out\n' + stderr)), 120000);
  const exited = new Promise(resolve => child.once('exit', (code, signal) => {
    clearTimeout(readyTimer); const error = new Error(`worker exited ${code}/${signal}\n${stderr}`);
    readyReject(error);
    for (const slot of pending.values()) { clearTimeout(slot.timer); slot.reject(error); }
    pending.clear(); resolve({ code, signal });
  }));
  child.once('error', error => { clearTimeout(readyTimer); readyReject(error); });
  child.stderr.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-50000); });
  readline.createInterface({ input: child.stdout }).on('line', line => {
    let value;
    try { value = JSON.parse(line); } catch { readyReject(new Error('Invalid Ghidra protocol stdout')); return; }
    if (value.ig5 === 'ready') { clearTimeout(readyTimer); readyResolve(value); return; }
    if (value.ig5 === 'progress') return;
    const slot = pending.get(value.id);
    if (!slot) return;
    clearTimeout(slot.timer); pending.delete(value.id);
    if (value.error) slot.reject(Object.assign(new Error(value.error.message), value.error)); else slot.resolve(value.result);
  });
  const session = { child, exited, rpc(method, params = {}) {
    const id = ++serial;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(method + ' timed out\n' + stderr)); }, 120000);
      pending.set(id, { resolve, reject, timer });
      child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    });
  } };
  active = session; await ready; return session;
}
async function stop(session) {
  await session.rpc('close'); session.child.stdin.end();
  assert.deepEqual(await session.exited, { code: 0, signal: null });
  active = null;
}

let failure;
try {
  const buildFixture = path.join(reportRoot, 'isolated-maintainer-runtime');
  const configFile = path.join(source, 'runtimes/ghidra/runtime.json');
  const fixtureConfig = JSON.parse(await fs.readFile(configFile, 'utf8'));
  delete fixtureConfig.localProjectPathPatch;
  await fs.mkdir(path.join(buildFixture, fixtureConfig.javaHome), { recursive: true });
  for (const member of [proof.jarPath, proof.sourceZipPath]) {
    const destination = path.join(buildFixture, member); await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.copyFile(path.join(source, 'runtimes/ghidra', member), destination);
  }
  await fs.cp(path.join(source, 'runtimes/ghidra', proof.sourceRoot), path.join(buildFixture, proof.sourceRoot), { recursive: true });
  await fs.writeFile(path.join(buildFixture, 'runtime.json'), JSON.stringify(fixtureConfig) + '\n');
  const buildArgs = ['-I', '-B', path.join(source, 'adapters/ghidra/local-project-path/build_patch.py'),
    '--project', source, '--runtime-root', buildFixture, '--artifact-root', reportRoot];
  const restored = await promisify(execFile)(runtime.ghidra.pythonExe, buildArgs, { windowsHide: true, timeout: 120000 });
  assert.equal(JSON.parse(restored.stdout).alreadyPatched, true);
  const restoredConfig = JSON.parse(await fs.readFile(path.join(buildFixture, 'runtime.json'), 'utf8'));
  assert.equal(restoredConfig.localProjectPathPatch.patchedJarSHA256, proof.patchedJarSHA256);
  const repeated = await promisify(execFile)(runtime.ghidra.pythonExe, buildArgs, { windowsHide: true, timeout: 120000 });
  assert.equal(JSON.parse(repeated.stdout).alreadyPatched, true);
  // Reproduce the review finding: original source ZIP + modified JAR must fail
  // whenever the existing independent proof is recognized.
  const rollbackCode = `from pathlib import Path
import sys, zipfile
target = Path(sys.argv[1])
temporary = target.with_name('rollback.zip')
with zipfile.ZipFile(target) as previous, zipfile.ZipFile(temporary, 'w') as output:
    for info in previous.infolist():
        output.writestr(info, Path(sys.argv[2]).read_bytes() if info.filename == 'ghidra/framework/protocol/ghidra/GhidraURL.java' else previous.read(info))
temporary.replace(target)
`;
  await promisify(execFile)(runtime.ghidra.pythonExe, ['-I', '-B', '-c', rollbackCode,
    path.join(buildFixture, proof.sourceZipPath), path.join(source, 'runtimes/ghidra', proof.sourceRoot, 'upstream-GhidraURL.java')],
  { windowsHide: true, timeout: 120000 });
  await fs.appendFile(path.join(buildFixture, proof.jarPath), 'IG5 fixture corruption');
  await assert.rejects(promisify(execFile)(runtime.ghidra.pythonExe, buildArgs, { windowsHide: true, timeout: 120000 }),
    error => /Already patched runtime no longer matches its build proof/.test(error.stderr));
  passed('maintainer proof recovery is idempotent and rejects source rollback plus JAR corruption', { isolatedFixture: buildFixture });

  const validationScript = path.join(reportRoot, 'native_path_validation.py');
  await fs.writeFile(validationScript, `import json, os, sys
sys.path.insert(0, sys.argv[1])
import worker
instance = worker.Worker(sys.argv[2], sys.argv[3], sys.argv[4])
from ghidra.framework.protocol.ghidra import GhidraURL
from ghidra.framework.model import ProjectLocator
from java.lang import IllegalArgumentException
from java.io import File
checked = []
def reject(name, operation):
    try:
        operation()
    except IllegalArgumentException:
        checked.append(name)
        return
    raise AssertionError('Expected native rejection: ' + name)
root = sys.argv[4]
locator = ProjectLocator(root, 'ig5-path-validation')
url = GhidraURL.makeURL(root, 'ig5-path-validation')
roundtrip = GhidraURL.getProjectStorageLocator(url)
assert str(File(roundtrip.getLocation()).getCanonicalPath()).lower() == os.path.realpath(root).lower()
for location in ['C:/Users/Test/.dsh/ig5/projects', '/home/test/.dsh/ig5/projects', '//server/share/.dsh/projects']:
    assert '.dsh' in str(GhidraURL.checkLocalAbsolutePath(location, True))
    checked.append('valid-local-' + location)
for element in ['.', '..', '.. ', '...', '.bad?']:
    reject('local-segment-' + repr(element), lambda e=element: GhidraURL.checkLocalAbsolutePath('C:/root/' + e + '/projects', True))
reject('hidden-project-name', lambda: ProjectLocator(root, '.hidden'))
reject('internal-project-dot-directory', lambda: GhidraURL.makeURL(root, 'valid-project', '/.hidden', None))
reject('resolve-internal-dot-directory', lambda: GhidraURL.resolve(url, '/.hidden', None))
reject('hidden-repository-name', lambda: GhidraURL.makeURL('localhost', 13100, '.hidden', '/', None))
reject('repository-dot-directory', lambda: GhidraURL.makeURL('localhost', 13100, 'valid-repository', '/.hidden', None))
worker.emit({'ok': True, 'checks': checked, 'projectLocation': str(locator.getLocation()), 'roundtripURL': str(url)})
instance.m_close({})
`, 'utf8');
  const native = await promisify(execFile)(runtime.ghidra.pythonExe, ['-I', '-B', validationScript,
    path.join(source, 'adapters/ghidra'), runtime.ghidra.ghidraHome, runtime.ghidra.javaHome, projectRoot],
  { windowsHide: true, timeout: 120000, maxBuffer: 2 * 1024 * 1024 });
  const nativeValidation = JSON.parse(native.stdout.trim());
  assert.equal(nativeValidation.ok, true); assert.equal(nativeValidation.checks.length, 13);
  passed('native hidden-path URL roundtrip and 13 strict path/name boundaries', nativeValidation);

  const databaseKey = 'ig5-hidden-project-regression-' + randomUUID();
  const first = await start();
  const opened = await first.rpc('open', { path: target, database_key: databaseKey });
  assert.ok(opened.n_funcs >= 16); assert.equal(opened.partial, false);
  assert.equal(path.dirname(opened.databasePath).toLowerCase(), projectRoot.toLowerCase());
  assert.equal((await fs.stat(opened.databasePath)).isFile(), true);
  passed('real default .dsh project imports and analyzes generated PE', { databasePath: opened.databasePath, project: opened.project, functions: opened.n_funcs });
  const before = await first.rpc('decompile', { ea: fixture.addresses.add });
  assert.match(before.code, /return/);
  const renamed = await first.rpc('rename', { ea: fixture.addresses.add, new_name: 'ig5_hidden_persisted_add' });
  assert.equal(renamed.saved, true);
  await first.rpc('comment', { ea: fixture.addresses.add, text: 'IG5 .dsh native project persistence verified' });
  await stop(first);
  passed('native rename/comment checkpoint and clean close', { revision: renamed.revision });

  const second = await start();
  const reopened = await second.rpc('open', { path: target, database_key: databaseKey });
  assert.equal(reopened.reusedProject, true); assert.equal(reopened.project, opened.project);
  assert.equal(reopened.databasePath, opened.databasePath); assert.equal(reopened.revision, 2); assert.equal(reopened.durableRevision, 2);
  const inspected = await second.rpc('inspect', { ea: fixture.addresses.add });
  assert.equal(inspected.name, 'ig5_hidden_persisted_add'); assert.equal(inspected.comment, 'IG5 .dsh native project persistence verified');
  const after = await second.rpc('decompile', { ea: fixture.addresses.add });
  assert.match(after.code, /ig5_hidden_persisted_add/); assert.match(after.code, /return/);
  assert.equal((await second.rpc('bytes', { ea: fixture.addresses.add, size: 5 })).hex, '488d0411c3');
  await stop(second);
  assert.deepEqual(await fs.readFile(target), fixture.image);
  passed('new worker reopens same native database, revisions and decompilation persist', { project: reopened.project, revision: reopened.revision, code: after.code });
} catch (error) { failure = error; }
finally {
  if (active) { terminateTree(active.child); await active.exited; }
  const report = { ok: !failure, projectRoot, target, reportRoot, execution: 'Generated PE analyzed only; no process execution.',
    patch: proof.patch, checks, ...(failure ? { error: failure.stack } : {}) };
  const reportFile = path.join(reportRoot, 'report.json'); await fs.writeFile(reportFile, JSON.stringify(report, null, 2) + '\n');
  console.log('REPORT', reportFile);
}
if (failure) throw failure;
