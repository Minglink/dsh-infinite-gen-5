// Structural tests use non-executable ELF headers. They do not claim ARM64 native execution.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { hostPlatform } from '../source/host_platform.js';
import { runtimeConfiguration } from '../engine_runtime.js';

const source = fileURLToPath(new URL('..', import.meta.url));
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-platform-'));
const relocated = path.join(scratch, '中文 离线插件');
const root = path.join(relocated, 'runtimes', 'linux-arm64');
const pack = path.join(root, 'ghidra');
const pass = label => console.log('PASS', label);
function write(file, body = 'fixture\n') {
  fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, body);
  if (Buffer.isBuffer(body) && body.readUInt32BE(0) === 0x7f454c46) fs.chmodSync(file, 0o755);
}
function elf(machine = 183) {
  const value = Buffer.alloc(512);
  value.writeUInt32BE(0x7f454c46, 0); value[4] = 2; value[5] = 1; value[6] = 1;
  value.writeUInt16LE(3, 16); value.writeUInt16LE(machine, 18); value.writeUInt32LE(1, 20);
  value.writeUInt16LE(64, 52); return value;
}
const raw = {
  schemaVersion: 1, engine: 'ghidra', platform: 'linux-arm64', libc: 'glibc', minGlibc: '2.17',
  version: '12.1.4', pythonVersion: '3.12', pythonExe: 'python/bin/python3',
  pythonLibrary: 'python/lib/libpython3.12.so.1.0', pythonStdlib: 'python/lib/python3.12',
  pythonModules: 'python/lib/python3.12/site-packages',
  jpypeLibrary: 'python/lib/python3.12/site-packages/_jpype.cpython-312-aarch64-linux-gnu.so',
  javaHome: 'jdk', ghidraHome: 'ghidra',
};
write(path.join(pack, 'runtime.json'), JSON.stringify(raw));
for (const name of [raw.pythonExe, raw.pythonLibrary, raw.jpypeLibrary, 'jdk/bin/java',
  'jdk/lib/server/libjvm.so', 'jdk/lib/jli/libjli.so',
  'ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile']) write(path.join(pack, name), elf());
for (const name of ['os.py', 'site.py', 'encodings/__init__.py']) write(path.join(pack, raw.pythonStdlib, name));
for (const name of ['pyghidra/__init__.py', 'pyghidra/launcher.py', 'jpype/__init__.py', 'packaging/__init__.py', 'org.jpype.jar']) write(path.join(pack, raw.pythonModules, name));
for (const name of ['jdk/lib/modules', 'jdk/jmods/java.base.jmod', 'jdk/legal/LICENSE', 'python/LICENSE.txt',
  'ghidra/LICENSE', 'ghidra/bom.json', 'ghidra/licenses/LICENSE',
  'ghidra/Ghidra/Framework/Utility/lib/Utility.jar', 'ghidra/Ghidra/Features/Base/lib/Base.jar',
  'ghidra/Ghidra/Features/PyGhidra/lib/PyGhidra.jar',
  'ghidra/Ghidra/Processors/x86/data/languages/x86-64.sla']) write(path.join(pack, name));
write(path.join(pack, 'jdk/release'), 'JAVA_VERSION="21.0.12.1"\nOS_ARCH="aarch64"\nOS_NAME="Linux"\n');
write(path.join(pack, 'ghidra/Ghidra/application.properties'), 'application.version=12.1.4\napplication.java.min=21\n');
function inventory() {
  const files = [];
  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (file !== path.join(root, 'manifest.json')) {
        const bytes = fs.readFileSync(file);
        files.push({ path: path.relative(root, file).replaceAll('\\', '/'), bytes: bytes.length,
          sha256: createHash('sha256').update(bytes).digest('hex') });
      }
    }
  }
  visit(root); write(path.join(root, 'manifest.json'), JSON.stringify({ schemaVersion: 1,
    platform: 'linux-arm64', pluginVersion: '1.0.0', engines: ['ghidra'], files }));
}
inventory();
write(path.join(relocated, 'package.json'), '{"type":"module"}');
write(path.join(relocated, 'engine_runtime.js'), fs.readFileSync(path.join(source, 'engine_runtime.js')));
write(path.join(relocated, 'source/host_platform.js'), fs.readFileSync(path.join(source, 'source/host_platform.js')));
const moved = await import(pathToFileURL(path.join(relocated, 'engine_runtime.js')).href);
const linux = hostPlatform({ platform: 'linux', arch: 'arm64', env: {}, glibcVersion: '2.35' });
const android = hostPlatform({ platform: 'linux', arch: 'arm64', env: { ANDROID_ROOT: '/system' }, glibcVersion: '2.35' });
assert.equal(linux.execution, 'local-node-host'); assert.equal(android.execution, 'android-linux-rootfs');
assert.equal(android.supported, true); assert.equal(android.id, 'linux-arm64');
pass('DSH tool host identity distinguishes Linux ARM64/rootfs from its browser device');

const envKeys = ['IG5_RUNTIME_ROOT', 'IG5_GHIDRA_RUNTIME', 'IG5_X64DBG_RUNTIME'];
const old = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));
for (const key of envKeys) delete process.env[key];
try {
  const cfg = moved.runtimeConfiguration({ home: path.join(scratch, '空 HOME') }, { host: android });
  assert.equal(cfg.runtimeRoot, root); assert.equal(cfg.ghidra.available, true, cfg.ghidra.reason);
  assert.equal(cfg.ghidra.source, 'bundled'); assert.equal(cfg.ghidra.validation, 'structure-and-elf-headers');
  assert.equal(cfg.x64dbg.available, false); assert.match(cfg.x64dbg.reason, /requires a Windows/);
  assert.equal(cfg.ghidra.integrityVerified, false);
  pass('Chinese relocated Linux pack matches ELF/Python/JDK layout and never enables Windows x64dbg');

  fs.renameSync(root, root + '.saved');
  const missing = moved.runtimeConfiguration({}, { host: android });
  assert.equal(missing.ghidra.available, false); assert.equal(missing.ghidra.source, 'bundled');
  assert.match(missing.ghidra.reason, /Missing matching linux-arm64 runtime pack/);
  assert.equal(missing.runtimeRoot, root);
  fs.renameSync(root + '.saved', root);
  const windowsOnLinux = runtimeConfiguration({ ghidraRuntime: path.join(source, 'runtimes/ghidra') }, { host: android });
  assert.equal(windowsOnLinux.ghidra.available, false);
  assert.match(windowsOnLinux.ghidra.reason, /win32-x64.*linux-arm64/);
  pass('missing ARM64 pack is explicit; existing Windows binaries cannot be used as fallback');

  for (const [platform, arch] of [['ios', 'arm64'], ['android', 'arm64'], ['linux', 'x64'], ['darwin', 'arm64']]) {
    const host = hostPlatform({ platform, arch, env: {} });
    const value = moved.runtimeConfiguration({}, { host });
    assert.equal(host.supported, false); assert.equal(value.ghidra.available, false);
    assert.equal(value.x64dbg.available, false);
    assert.match(value.ghidra.reason, platform === 'ios' ? /No validated iOS/ : platform === 'android' ? /Bionic/ : /No matching/);
  }
  pass('iOS unknown-native-host and Android Bionic remain explicitly unsupported');

  for (const glibcVersion of [null, '2.16']) {
    const value = moved.runtimeConfiguration({}, { host: hostPlatform({ platform: 'linux', arch: 'arm64', env: {}, glibcVersion }) });
    assert.equal(value.ghidra.available, false); assert.match(value.ghidra.reason, /glibc/);
  }
  pass('glibc compatibility is checked rather than assuming every Linux ARM64 host matches');

  const python = path.join(pack, raw.pythonExe);
  write(python, elf(62));
  let value = moved.runtimeConfiguration({}, { host: linux });
  assert.equal(value.ghidra.available, false); assert.match(value.ghidra.reason, /expected Linux ELF64.*AArch64/);
  write(python, elf());
  const header = elf(); header[4] = 1; write(path.join(pack, raw.jpypeLibrary), header);
  value = moved.runtimeConfiguration({}, { host: linux });
  assert.equal(value.ghidra.available, false); assert.match(value.ghidra.reason, /JPype native extension/);
  write(path.join(pack, raw.jpypeLibrary), elf());
  const manifest = path.join(pack, 'runtime.json');
  write(manifest, JSON.stringify({ ...raw, pythonModules: '../escape' })); inventory();
  value = moved.runtimeConfiguration({}, { host: linux });
  assert.equal(value.ghidra.available, false); assert.match(value.ghidra.reason, /contained relative path/);
  write(manifest, JSON.stringify(raw)); inventory();
  pass('wrong ISA/ELF class and runtime path escape are rejected');

  fs.renameSync(path.join(pack, 'ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile'), python + '.decompile.saved');
  value = moved.runtimeConfiguration({}, { host: linux });
  assert.equal(value.ghidra.available, false); assert.match(value.ghidra.reason, /native decompiler/);
  fs.renameSync(python + '.decompile.saved', path.join(pack, 'ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile'));
  pass('a Java/Python-only pack is unavailable when native decompilation is missing');

  const read = fs.readFileSync;
  fs.readFileSync = function(file, ...args) {
    assert.doesNotMatch(String(file), /\.(?:so|jar|jmod|sla)$/i, 'startup must not read whole binaries');
    return read.call(this, file, ...args);
  };
  try { assert.equal(moved.runtimeConfiguration({}, { host: linux }).ghidra.available, true); }
  finally { fs.readFileSync = read; }
  pass('ELF startup validation reads small headers without full runtime hashing');
  console.log('Host platform structural tests passed; no ARM64 binary executed. Artifacts:', scratch);
} finally {
  for (const key of envKeys) old[key] === undefined ? delete process.env[key] : process.env[key] = old[key];
}
