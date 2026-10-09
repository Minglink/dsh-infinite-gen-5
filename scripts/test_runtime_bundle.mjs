// Runtime selection/relocation/structure tests. Tiny PE-header fixtures below are
// deliberately non-executable; the normal Ghidra/x64dbg runtime suites test natives.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runtimeConfiguration } from '../engine_runtime.js';

assert.equal(process.platform, 'win32'); assert.equal(process.arch, 'x64');
const source = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-runtime-bundle-'));
const relocated = path.join(scratch, '中文 搬移插件');
const bundle = path.join(relocated, 'runtimes');
const legacyHome = path.join(scratch, '空白用户数据');
const legacy = path.join(legacyHome, 'runtimes');
const envKeys = ['IG5_RUNTIME_ROOT', 'IG5_GHIDRA_RUNTIME', 'IG5_X64DBG_RUNTIME', 'IG5_HOME'];
const previous = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));
for (const key of envKeys) delete process.env[key];
const pass = label => console.log('PASS', label);
function write(file, body = 'isolated structural fixture\n') {
  fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, body);
}
function pe(bits) {
  const result = Buffer.alloc(512);
  result.write('MZ'); result.writeUInt32LE(0x80, 0x3c); result.write('PE\0\0', 0x80);
  result.writeUInt16LE(bits === 64 ? 0x8664 : 0x14c, 0x84);
  result.writeUInt16LE(bits === 64 ? 0x20b : 0x10b, 0x98); return result;
}
function tinyPacks(root) {
  const ghidra = path.join(root, 'ghidra');
  const gh = path.join(ghidra, 'ghidra'), java = path.join(ghidra, 'jdk'), python = path.join(ghidra, 'python');
  write(path.join(ghidra, 'runtime.json'), JSON.stringify({ schemaVersion: 1, engine: 'Ghidra', version: '12.1.4',
    pythonExe: 'python/python.exe', ghidraHome: 'ghidra', javaHome: 'jdk', jpypeBootstrap: {
      patch: 'ig5-jpype-context-v1', version: '1.5.2', property: 'ig5.jpype.native_filename', nativeFilename: '_jpype.cp312-win_amd64.pyd',
      sourceRoot: 'licenses/ig5-jpype-bootstrap', ...Object.fromEntries(['upstreamSourceSha256', 'upstreamJarSha256',
        'patchedJarSha256', 'patchedSourceSha256', 'patchSha256'].map(key => [key, '0'.repeat(64)])),
    } }));
  for (const name of ['LICENSE', 'UPSTREAM-NOTICE', 'NOTICE.txt', 'README.md', 'JPypeContext.java',
    'unicode-bootstrap.patch', 'upstream-JPypeContext.java', 'provenance.json']) write(path.join(ghidra, 'licenses/ig5-jpype-bootstrap', name));
  for (const [home, file] of [[python, 'python.exe'], [python, 'python312.dll'], [python, 'vcruntime140.dll'],
    [python, 'pylib/_jpype.cp312-win_amd64.pyd'], [java, 'bin/java.exe'], [java, 'bin/server/jvm.dll'],
    [gh, 'Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe']]) write(path.join(home, file), pe(64));
  for (const file of ['python312.zip', 'LICENSE.txt', 'pylib/pyghidra/__init__.py', 'pylib/pyghidra/launcher.py',
    'pylib/jpype/__init__.py', 'pylib/packaging/__init__.py', 'pylib/org.jpype.jar']) write(path.join(python, file));
  write(path.join(python, 'python312._pth'), 'python312.zip\n.\npylib\nimport site\n');
  write(path.join(java, 'release'), 'JAVA_VERSION="21.0.12.1"\nOS_ARCH="x86_64"\n');
  write(path.join(java, 'jmods/java.base.jmod'));
  fs.mkdirSync(path.join(java, 'legal'), { recursive: true });
  write(path.join(gh, 'Ghidra/application.properties'), 'application.version=12.1.4\napplication.java.min=21\n');
  for (const file of ['Ghidra/Framework/Utility/lib/Utility.jar', 'Ghidra/Features/Base/lib/Base.jar',
    'Ghidra/Features/PyGhidra/lib/PyGhidra.jar', 'Ghidra/Processors/x86/data/languages/x86-64.sla', 'LICENSE', 'bom.json']) write(path.join(gh, file));
  fs.mkdirSync(path.join(gh, 'licenses'), { recursive: true });
  const debug = path.join(root, 'x64dbg');
  write(path.join(debug, 'runtime.json'), JSON.stringify({ pythonExe: 'python/python.exe', bridge: 'ig5-native', mode: 'headless',
    x64dbgExe: 'snapshot/release/x64/x64dbg.exe', x32dbgExe: 'snapshot/release/x32/x32dbg.exe',
    headlessExe: 'snapshot/release/x64/headless.exe', headless32Exe: 'snapshot/release/x32/headless.exe' }));
  for (const file of ['python.exe', 'python312.dll', 'vcruntime140.dll']) write(path.join(debug, 'python', file), pe(64));
  for (const file of ['python312.zip', 'LICENSE.txt']) write(path.join(debug, 'python', file));
  write(path.join(debug, 'python/python312._pth'), 'python312.zip\n.\n');
  for (const bits of [64, 32]) {
    const home = path.join(debug, 'snapshot', 'release', 'x' + bits);
    for (const name of [`x${bits}dbg.exe`, 'headless.exe', `plugins/ig5-bridge.dp${bits}`, `x${bits}dbg.dll`, `x${bits}bridge.dll`,
      `x${bits}_dbg.dll`, `x${bits}_bridge.dll`, 'jansson.dll', 'TitanEngine.dll', 'Scylla.dll',
      'Qt5Core.dll', 'Qt5Gui.dll', 'Qt5Widgets.dll', 'msvcp140.dll', 'vcruntime140.dll']) write(path.join(home, name), pe(bits));
  }
  fs.mkdirSync(path.join(debug, 'licenses'), { recursive: true });
  inventory(root);
}
function inventory(root) {
  const files = [];
  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (entry.isFile() && file !== path.join(root, 'manifest.json')) {
        const data = fs.readFileSync(file);
        files.push({ path: path.relative(root, file).replaceAll('\\', '/'), bytes: data.length,
          sha256: createHash('sha256').update(data).digest('hex') });
      }
    }
  }
  visit(root);
  write(path.join(root, 'manifest.json'), JSON.stringify({ schemaVersion: 1, pluginVersion: '1.0.0',
    platform: 'win32-x64', engines: ['ghidra', 'x64dbg'], files }));
}
function cleanEnvironment(home) {
  const environment = { ...process.env, HOME: home, USERPROFILE: home, IG5_HOME: home, PATH: '',
    JAVA_HOME: '', JAVA_HOME_OVERRIDE: '', PYTHONHOME: '', PYTHONPATH: '' };
  for (const key of ['IG5_RUNTIME_ROOT', 'IG5_GHIDRA_RUNTIME', 'IG5_X64DBG_RUNTIME']) delete environment[key];
  return environment;
}
function cleanChild(module, home) {
  const command = `import {runtimeConfiguration} from ${JSON.stringify(pathToFileURL(module).href)};
    const value=runtimeConfiguration(); console.log(JSON.stringify({home:value.home,runtimeRoot:value.runtimeRoot,
    ghidra:{available:value.ghidra.available,source:value.ghidra.source,root:value.ghidra.root,reason:value.ghidra.reason},
    x64dbg:{available:value.x64dbg.available,source:value.x64dbg.source,root:value.x64dbg.root,reason:value.x64dbg.reason}}));`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', command], {
    env: cleanEnvironment(home), encoding: 'utf8', windowsHide: true, timeout: 30000,
  });
  assert.equal(result.status, 0, result.error?.message || result.stderr);
  return JSON.parse(result.stdout);
}
function available(configuration) {
  for (const name of ['ghidra', 'x64dbg']) assert.equal(configuration[name].available, true, configuration[name].reason);
}

try {
  tinyPacks(bundle); tinyPacks(legacy);
  write(path.join(relocated, 'package.json'), '{"type":"module"}');
  fs.copyFileSync(path.join(source, 'engine_runtime.js'), path.join(relocated, 'engine_runtime.js'));
  fs.mkdirSync(path.join(relocated, 'source'), { recursive: true });
  fs.copyFileSync(path.join(source, 'source/host_platform.js'), path.join(relocated, 'source/host_platform.js'));
  const moved = await import(pathToFileURL(path.join(relocated, 'engine_runtime.js')).href);
  const defaults = moved.runtimeConfiguration({ home: legacyHome });
  available(defaults); assert.equal(defaults.runtimeRoot, bundle);
  assert.equal(defaults.ghidra.source, 'bundled'); assert.equal(defaults.x64dbg.source, 'bundled');
  assert.equal(defaults.projectRoot, path.join(legacyHome, 'projects'));
  const noSystem = cleanChild(path.join(relocated, 'engine_runtime.js'), path.join(scratch, '不存在的 用户HOME'));
  available(noSystem); assert.equal(noSystem.runtimeRoot, bundle);
  assert.equal(noSystem.ghidra.root, path.join(bundle, 'ghidra'));
  pass('Chinese relocation resolves plugin-local packs with empty HOME/PATH and no external runtime');

  available(moved.runtimeConfiguration({ runtimeRoot: legacy }));
  process.env.IG5_RUNTIME_ROOT = legacy;
  assert.equal(moved.runtimeConfiguration().x64dbg.source, 'environment');
  process.env.IG5_GHIDRA_RUNTIME = path.join(bundle, 'ghidra', 'runtime.json');
  const precedence = moved.runtimeConfiguration({ runtimeRoot: legacy, ghidraRuntime: path.join(legacy, 'ghidra') });
  assert.equal(precedence.ghidra.source, 'config'); assert.equal(precedence.ghidra.root, path.join(legacy, 'ghidra'));
  assert.equal(moved.runtimeConfiguration({ runtimeRoot: legacy }).ghidra.source, 'environment');
  for (const key of envKeys) delete process.env[key];
  pass('explicit engine config/env and runtime-root overrides retain deterministic precedence');

  const debugManifestPath = path.join(bundle, 'x64dbg/runtime.json');
  const debugManifest = JSON.parse(fs.readFileSync(debugManifestPath, 'utf8'));
  for (const mode of ['headless', 'gui-hidden', 'gui']) {
    fs.writeFileSync(debugManifestPath, JSON.stringify({ ...debugManifest, mode })); inventory(bundle);
    const checked = moved.runtimeConfiguration();
    assert.equal(checked.x64dbg.available, mode !== 'gui', checked.x64dbg.reason);
    if (mode === 'gui') assert.match(checked.x64dbg.reason, /Unsupported x64dbg mode/);
  }
  fs.writeFileSync(debugManifestPath, JSON.stringify(debugManifest)); inventory(bundle);
  pass('debugger mode validation matches adapter headless/gui-hidden modes');

  const bridge = path.join(bundle, 'x64dbg/snapshot/release/x32/plugins/ig5-bridge.dp32');
  fs.renameSync(bridge, bridge + '.saved');
  const missing = moved.runtimeConfiguration({ home: legacyHome });
  assert.equal(missing.x64dbg.available, false); assert.equal(missing.x64dbg.source, 'bundled');
  assert.match(missing.x64dbg.reason, /native bridge/); assert.equal(missing.x64dbg.root, path.join(bundle, 'x64dbg'));
  fs.renameSync(bridge + '.saved', bridge);
  const cfgPath = path.join(bundle, 'ghidra/runtime.json'), originalManifest = fs.readFileSync(cfgPath);
  fs.writeFileSync(cfgPath, '{');
  const broken = moved.runtimeConfiguration({ home: legacyHome });
  assert.equal(broken.ghidra.available, false); assert.equal(broken.ghidra.source, 'bundled');
  fs.writeFileSync(cfgPath, originalManifest);
  pass('a damaged embedded pack is explicitly unavailable and never falls back to a valid legacy pack');

  const noBootstrap = JSON.parse(originalManifest); delete noBootstrap.jpypeBootstrap;
  fs.writeFileSync(cfgPath, JSON.stringify(noBootstrap)); inventory(bundle);
  const incompleteBootstrap = moved.runtimeConfiguration({ home: legacyHome });
  assert.equal(incompleteBootstrap.ghidra.available, false); assert.equal(incompleteBootstrap.ghidra.source, 'bundled');
  assert.match(incompleteBootstrap.ghidra.reason, /Unicode bootstrap provenance/);
  fs.writeFileSync(cfgPath, originalManifest); inventory(bundle);
  pass('bundled Unicode bootstrap metadata and license/source assets are required');

  const nativePython = path.join(bundle, 'ghidra/python/python.exe');
  fs.writeFileSync(nativePython, pe(32));
  const wrongPython = moved.runtimeConfiguration();
  assert.equal(wrongPython.ghidra.available, false); assert.match(wrongPython.ghidra.reason, /expected Windows x64 PE/);
  fs.writeFileSync(nativePython, pe(64));
  fs.writeFileSync(bridge, pe(64));
  const wrongBridge = moved.runtimeConfiguration();
  assert.equal(wrongBridge.x64dbg.available, false); assert.match(wrongBridge.x64dbg.reason, /expected Windows x32 PE/);
  fs.writeFileSync(bridge, pe(32));
  pass('Python/JVM/debugger bridge architecture is checked using small PE headers');

  const raw = JSON.parse(originalManifest);
  fs.writeFileSync(cfgPath, JSON.stringify({ ...raw, pythonExe: '../x64dbg/python/python.exe' })); inventory(bundle);
  const escaped = moved.runtimeConfiguration();
  assert.equal(escaped.ghidra.available, false); assert.match(escaped.ghidra.reason, /contained relative path/);
  fs.writeFileSync(cfgPath, originalManifest); inventory(bundle);
  const pythonPth = path.join(bundle, 'ghidra/python/python312._pth'), savedPth = fs.readFileSync(pythonPth);
  fs.writeFileSync(pythonPth, 'python312.zip\n.\npylib\n../../outside\n'); inventory(bundle);
  const escapedPython = moved.runtimeConfiguration();
  assert.equal(escapedPython.ghidra.available, false); assert.match(escapedPython.ghidra.reason, /Python search path escapes/);
  fs.writeFileSync(pythonPth, savedPth); inventory(bundle);
  const ghidraHome = path.join(bundle, 'ghidra/ghidra');
  fs.renameSync(ghidraHome, ghidraHome + '.saved');
  fs.symlinkSync(path.join(legacy, 'ghidra/ghidra'), ghidraHome, 'junction');
  const linked = moved.runtimeConfiguration();
  assert.equal(linked.ghidra.available, false); assert.match(linked.ghidra.reason, /through a link/);
  fs.renameSync(ghidraHome, ghidraHome + '.escaped-link'); fs.renameSync(ghidraHome + '.saved', ghidraHome);
  pass('manifest paths, isolated Python paths and directory junctions cannot escape the pack');

  const read = fs.readFileSync;
  fs.readFileSync = function(file, ...args) {
    assert.doesNotMatch(String(file), /\.(?:dll|exe|pyd|dp32|dp64|jar|jmod|sla|zip)$/i,
      'startup must not read/hash complete runtime binaries');
    return read.call(this, file, ...args);
  };
  try { available(moved.runtimeConfiguration()); }
  finally { fs.readFileSync = read; }
  pass('startup validates structure/PE headers without reading complete runtime binaries');

  // Also validate the installed source bundle, rather than only synthetic layouts.
  const actual = runtimeConfiguration({ home: path.join(scratch, '实际空白用户') });
  available(actual); assert.equal(actual.runtimeRoot, path.join(source, 'runtimes'));
  assert.equal(actual.ghidra.source, 'bundled'); assert.equal(actual.x64dbg.source, 'bundled');
  assert.equal(actual.ghidra.integrityVerified, false);
  const actualClean = cleanChild(path.join(source, 'engine_runtime.js'), path.join(scratch, '实际无外部运行时HOME'));
  available(actualClean); assert.equal(actualClean.runtimeRoot, path.join(source, 'runtimes'));
  pass('actual full bundles are selected with no user runtime or system Java/Python path');
  console.log('Runtime bundle tests passed; artifacts retained:', scratch);
} finally {
  for (const key of envKeys) {
    if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key];
  }
}
