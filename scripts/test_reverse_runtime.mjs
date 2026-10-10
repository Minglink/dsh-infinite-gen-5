// Read-only discovery of non-executable PE header fixtures; never starts a worker.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import vm from 'node:vm';
import { engineId } from '../engine_runtime.js';
import { resolveReverseRuntime } from '../source/reverse_runtime.js';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-reverse-discovery-'));
const cases = [];
const pass = (name, action) => { action(); cases.push(name); console.log('PASS', name); };
const write = (file, value) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, value); };
function pe(bits = 64) {
  const data = Buffer.alloc(256); data.write('MZ'); data.writeUInt32LE(64, 0x3c);
  data.writeUInt32LE(0x4550, 64); data.writeUInt16LE(bits === 64 ? 0x8664 : 0x14c, 68);
  data.writeUInt16LE(bits === 64 ? 0x20b : 0x10b, 88); return data;
}
function install(relative, python = 'python311') {
  const directory = path.join(scratch, relative);
  for (const file of ['idalib.dll', 'ida.dll', 'python/lib-dynload/_ida_idaapi.pyd']) write(path.join(directory, file), pe());
  for (const file of ['idalib/python/idapro/__init__.py', 'idalib/python/idapro/config.py', 'python/ida_idaapi.py']) write(path.join(directory, file), '# header fixture only\n');
  if (python) addPython(path.join(directory, python), python.replace(/[^0-9]/g, '') || '311');
  return directory;
}
function addPython(directory, version = '311', bits = 64) {
  write(path.join(directory, 'python.exe'), pe(bits));
  write(path.join(directory, `python${version}.dll`), pe(bits));
  return path.join(directory, 'python.exe');
}
const defaults = { host: { id: 'win32-x64' }, home: path.join(scratch, 'user'), env: {}, discoveryRoots: [] };
const resolve = (config = {}, options = {}) => resolveReverseRuntime(config, { ...defaults, ...options });
const core = install('IDA Professional 9.2');
try {
  pass('commercial kernel is absent by default; missing installation is explicit', () => {
    const runtime = resolve(); assert.equal(runtime.available, false); assert.equal(runtime.code, 'REVERSE_NOT_FOUND');
    assert.match(runtime.reason, /适配器不包含商业引擎内核/); assert.equal(runtime.runtimeReady, null);
  });
  pass('a complete configured installation is detected without claiming startup or license verification', () => {
    const runtime = resolve({ idaDir: core }); assert.equal(runtime.available, true); assert.equal(runtime.idaDir, core);
    assert.equal(runtime.readiness, 'detected'); assert.equal(runtime.startupVerified, false); assert.equal(runtime.runtimeReady, null);
    assert.equal(Object.hasOwn(runtime, 'licenseVerified'), false); assert.equal(runtime.source, 'config');
  });
  pass('plugin configuration overrides engine and Python environment values', () => {
    const envRoot = install('env/IDA9', 'python312');
    const runtime = resolve({ idaDir: core, pythonExe: path.join(core, 'python311/python.exe') },
      { env: { IG5_IDA_DIR: envRoot, IG5_PYTHON: path.join(envRoot, 'python312/python.exe') } });
    assert.equal(runtime.idaDir, core); assert.equal(runtime.pythonExe, path.join(core, 'python311/python.exe'));
  });
  pass('IG5_IDA_DIR and IG5_PYTHON support relocated custom installations', () => {
    const externalPython = addPython(path.join(scratch, 'custom-python'), '312');
    const runtime = resolve({}, { env: { IG5_IDA_DIR: core, IG5_PYTHON: externalPython } });
    assert.equal(runtime.available, true); assert.equal(runtime.source, 'environment'); assert.equal(runtime.pythonExe, externalPython);
  });
  pass('explicit nonexistent installation never silently switches to a discovered installation', () => {
    const runtime = resolve({ idaDir: path.join(scratch, 'missing') }, { discoveryRoots: [scratch] });
    assert.equal(runtime.available, false); assert.equal(runtime.code, 'REVERSE_INVALID_PATH');
  });
  pass('an empty directory or only idalib/python is not an available engine', () => {
    const empty = path.join(scratch, 'empty'); fs.mkdirSync(path.join(empty, 'idalib/python'), { recursive: true });
    const runtime = resolve({ idaDir: empty }); assert.equal(runtime.available, false); assert.equal(runtime.code, 'REVERSE_MISSING_KERNEL');
  });
  pass('a compatible installation with the alternate native kernel basename is accepted', () => {
    const root = install('alternate-kernel'); fs.renameSync(path.join(root, 'ida.dll'), path.join(root, 'ida64.dll'));
    assert.equal(resolve({ idaDir: root }).available, true);
  });
  pass('a GUI-only installation reports missing Python interfaces', () => {
    const root = install('gui-only'); fs.rmSync(path.join(root, 'idalib/python/idapro/config.py'));
    const runtime = resolve({ idaDir: root }); assert.equal(runtime.available, false); assert.equal(runtime.code, 'REVERSE_MISSING_BINDINGS');
  });
  pass('x86 kernel and native module are rejected on an x64 worker host', () => {
    const root = install('wrong-kernel'); write(path.join(root, 'idalib.dll'), pe(32));
    assert.equal(resolve({ idaDir: root }).code, 'REVERSE_MISSING_KERNEL');
    write(path.join(root, 'idalib.dll'), pe()); write(path.join(root, 'python/lib-dynload/_ida_idaapi.pyd'), pe(32));
    assert.equal(resolve({ idaDir: root }).code, 'REVERSE_MISSING_BINDINGS');
  });
  pass('explicit invalid Python never falls back to the bundled interpreter', () => {
    assert.equal(resolve({ idaDir: core, pythonExe: path.join(scratch, 'absent-python.exe') }).code, 'REVERSE_INVALID_PYTHON');
    assert.equal(resolve({ idaDir: core }, { env: { IG5_PYTHON: path.join(scratch, 'absent-python.exe') } }).code, 'REVERSE_INVALID_PYTHON');
  });
  pass('x86 Python and truncated executables are rejected', () => {
    const wrong = addPython(path.join(scratch, 'python32'), '311', 32);
    assert.equal(resolve({ idaDir: core, pythonExe: wrong }).code, 'REVERSE_INVALID_PYTHON');
    write(wrong, 'MZ'); assert.equal(resolve({ idaDir: core, pythonExe: wrong }).code, 'REVERSE_INVALID_PYTHON');
  });
  pass('an executable without its Python runtime DLL is not accepted as Python', () => {
    const onlyExe = path.join(scratch, 'only-exe/python.exe'); write(onlyExe, pe());
    assert.equal(resolve({ idaDir: core, pythonExe: onlyExe }).code, 'REVERSE_INVALID_PYTHON');
  });
  pass('engine-local Python versions are discovered beyond the previous python311 assumption', () => {
    const root = install('new-python', 'python312'); const runtime = resolve({ idaDir: root });
    assert.equal(runtime.available, true); assert.equal(runtime.pythonExe, path.join(root, 'python312/python.exe'));
  });
  pass('missing Python leaves an actionable dependency diagnostic', () => {
    const root = install('without-python', null); const runtime = resolve({ idaDir: root });
    assert.equal(runtime.available, false); assert.equal(runtime.code, 'REVERSE_MISSING_PYTHON');
  });
  pass('bounded PATH lookup resolves an explicitly named Python without executing it', () => {
    const exe = addPython(path.join(scratch, 'path-python'));
    assert.equal(resolve({ idaDir: core, pythonExe: 'python' }, { env: { PATH: path.dirname(exe) } }).pythonExe, exe);
  });
  pass('IDA9 directory names are recognized despite the former word-boundary miss', () => {
    const base = path.join(scratch, 'known-root'); const root = install('known-root/IDA9', 'python312');
    assert.equal(resolve({}, { discoveryRoots: [base] }).idaDir, root);
  });
  pass('Program Files/Hex-Rays nested installations are discovered at bounded depth', () => {
    const root = install('program-files/Hex-Rays/IDA Pro');
    assert.equal(resolve({}, { discoveryRoots: [path.join(scratch, 'program-files')] }).idaDir, root);
  });
  pass('OneDrive and USERPROFILE desktop locations are covered without scanning the whole disk', () => {
    const oneDrive = path.join(scratch, 'onedrive'); const root = install('onedrive/Desktop/IDA Pro');
    const options = { ...defaults, env: { USERPROFILE: path.join(scratch, 'actual-user'), OneDrive: oneDrive } };
    delete options.discoveryRoots;
    assert.equal(resolveReverseRuntime({}, options).idaDir, root);
  });
  pass('the existing official activation path is read as a hint without creating or changing configuration', () => {
    const appData = path.join(scratch, 'appdata'), cfg = path.join(appData, 'Hex-Rays/IDA Pro/ida-config.json');
    const before = JSON.stringify({ Paths: { 'ida-install-dir': core } }); write(cfg, before);
    const runtime = resolve({}, { env: { APPDATA: appData } }); assert.equal(runtime.idaDir, core);
    assert.equal(runtime.source, 'activation-config'); assert.equal(fs.readFileSync(cfg, 'utf8'), before);
  });
  pass('malformed or oversized activation config is ignored safely', () => {
    const user = path.join(scratch, 'ida-user'), cfg = path.join(user, 'ida-config.json');
    write(cfg, '{'); assert.equal(resolve({}, { env: { IDAUSR: user } }).code, 'REVERSE_NOT_FOUND');
    write(cfg, ' '.repeat(65537)); assert.equal(resolve({}, { env: { IDAUSR: user } }).code, 'REVERSE_NOT_FOUND');
  });
  pass('incomplete auto-discovered engines do not hide a later complete installation', () => {
    const base = path.join(scratch, 'multiple'); fs.mkdirSync(path.join(base, 'IDA0/idalib'), { recursive: true });
    const complete = install('multiple/IDA1'); assert.equal(resolve({}, { discoveryRoots: [base] }).idaDir, complete);
  });
  pass('discovery reads at most 257 directory entries and marks partial results', () => {
    let reads = 0, closes = 0;
    const io = { ...fs, opendirSync() { return { readSync() { reads++; return { name: 'unrelated', isDirectory: () => false, isSymbolicLink: () => false }; }, closeSync() { closes++; } }; } };
    const runtime = resolve({}, { fs: io, discoveryRoots: ['one-root'] });
    assert.equal(reads, 257); assert.equal(closes, 1); assert.equal(runtime.discoveryPartial, true); assert.equal(runtime.available, false);
  });
  pass('disabled and unsupported-host states do not inspect or start any installation', () => {
    const io = new Proxy({}, { get() { throw new Error('filesystem must not be inspected'); } });
    assert.equal(resolve({ reverse: false }, { fs: io }).code, 'REVERSE_DISABLED');
    assert.equal(resolve({}, { fs: io, host: { id: 'linux-arm64' } }).code, 'REVERSE_PLATFORM');
  });
  pass('public diagnostics never expose commercial versions or installation paths', () => {
    for (const runtime of [resolve(), resolve({ idaDir: core }), resolve({ idaDir: 'C:\\IDA Professional 9.2\\missing' }), resolve({ idaDir: core, pythonExe: 'C:\\IDA Professional 9.2\\bad.exe' })]) {
      assert.doesNotMatch(runtime.reason, /IDA Professional|idalib|Hex-Rays|9\.2|[A-Z]:[\\/]/i);
    }
  });

  const source = fs.readFileSync(new URL('../index.js', import.meta.url), 'utf8');
  const doctorStart = source.indexOf('  async doctor('), doctorEnd = source.indexOf('\n  engines()', doctorStart);
  let spawned = 0, terminated = 0, result = { idalib: 'loaded', python: '3.11', caps: {} }, startupFailure;
  const publicEngineError = () => 'Reverse startup declined by its runtime';
  const DoctorHarness = vm.runInNewContext(`(class { ${source.slice(doctorStart, doctorEnd)} })`, {
    doctorWorker: async () => { if (startupFailure) throw startupFailure; return result; },
    terminateTree: child => { if (child) terminated++; }, publicEngineError, engineId,
  });
  const doctor = new DoctorHarness();
  doctor.scope = { getStore: () => null }; doctor.rpcError = error => error;
  doctor.spawnWorker = () => { spawned++; return {}; };
  doctor.cfg = { defaultEngine: 'reverse', reverseAvailable: false, reverseRuntime: resolve() };
  await assert.rejects(doctor.doctor('reverse'), error => error.code === 'REVERSE_NOT_FOUND');
  assert.equal(spawned, 0); cases.push('doctor preflight rejects missing Reverse without starting a worker');
  doctor.cfg.reverseAvailable = true; doctor.cfg.reverseRuntime = resolve({ idaDir: core });
  const verified = await doctor.doctor('reverse'); assert.equal(verified.startupVerified, true);
  assert.equal(doctor.cfg.reverseRuntime.readiness, 'verified'); assert.equal(doctor.cfg.reverseRuntime.runtimeReady, true);
  assert.equal(Object.hasOwn(verified, 'licenseVerified'), false); assert.equal(terminated, 1);
  cases.push('doctor marks verified only after a real loaded-kernel result and retains license scope');
  result = { idalib: 'loaded', python: '3.11', idaVersion: 'private-version', idaDir: 'C:/private-engine', pythonExe: 'C:/private-python', caps: {} };
  const upper = await doctor.doctor('REVERSE'); assert.equal(upper.startupVerified, true);
  for (const key of ['idaVersion', 'idaDir', 'pythonExe']) assert.equal(Object.hasOwn(upper, key), false);
  assert.equal(terminated, 2); cases.push('case-normalized doctor never returns raw commercial engine fields');
  result = { idalib: 'not-loaded' }; await assert.rejects(doctor.doctor('reverse'));
  assert.equal(doctor.cfg.reverseRuntime.startupVerified, false); assert.equal(doctor.cfg.reverseRuntime.runtimeReady, false);
  assert.equal(doctor.cfg.reverseRuntime.readiness, 'startup-failed'); assert.equal(terminated, 3);
  cases.push('doctor refuses an unconfirmed kernel and marks startup failure');
  startupFailure = new Error('license unavailable: C:\\IDA Professional 9.2');
  await assert.rejects(doctor.doctor('reverse')); assert.doesNotMatch(doctor.cfg.reverseRuntime.reason, /IDA|9\.2|C:/);
  assert.equal(terminated, 4); cases.push('doctor failure diagnostic is redacted and its worker is recycled');
  console.log(JSON.stringify({ ok: true, checks: cases.length, nativeWorkersStarted: 0, samplesExecuted: 0, cases }));
} finally {
  const absolute = path.resolve(scratch), boundary = path.resolve(os.tmpdir()) + path.sep;
  assert(absolute.startsWith(boundary)); fs.rmSync(absolute, { recursive: true, force: true });
}
