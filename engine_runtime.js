import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const names = new Set(['reverse', 'ghidra', 'x64dbg']);
export function engineId(value) {
  const id = String(value || '').toLowerCase();
  if (!names.has(id)) throw new Error(`Unknown IG5 engine: ${value}`);
  return id;
}

const PLUGIN_ROOT = path.dirname(fileURLToPath(import.meta.url));
const BUNDLED_RUNTIME_ROOT = path.join(PLUGIN_ROOT, 'runtimes');
const pathKeys = ['pythonExe', 'ghidraHome', 'javaHome', 'headlessExe', 'headless32Exe', 'x64dbgExe', 'x32dbgExe'];
const inside = (root, value) => { const relative = path.relative(root, value); return !path.isAbsolute(relative) && relative !== '..' && !relative.startsWith('..' + path.sep); };
const relativePath = value => typeof value === 'string' && value.length > 0 && !/[\0:]/.test(value) && !path.isAbsolute(value) && !path.win32.isAbsolute(value);
const pathKey = value => process.platform === 'win32' ? value.replaceAll('\\', '/').toLowerCase() : value.replaceAll('\\', '/');

function readText(file, limit = 1048576) {
  if (fs.statSync(file).size > limit) throw new Error('Runtime metadata is too large: ' + file);
  return fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
}

function peArchitecture(file, expected) {
  const descriptor = fs.openSync(file, 'r');
  try {
    const dos = Buffer.alloc(64), pe = Buffer.alloc(26);
    if (fs.readSync(descriptor, dos, 0, dos.length, 0) !== dos.length || dos.toString('ascii', 0, 2) !== 'MZ') throw new Error('invalid DOS header');
    const offset = dos.readUInt32LE(0x3c);
    if (offset < 64 || offset > 16777216 || offset + pe.length > fs.fstatSync(descriptor).size
        || fs.readSync(descriptor, pe, 0, pe.length, offset) !== pe.length || pe.readUInt32LE(0) !== 0x4550) throw new Error('invalid PE header');
    const machine = pe.readUInt16LE(4), magic = pe.readUInt16LE(24);
    if (machine !== (expected === 64 ? 0x8664 : 0x14c) || magic !== (expected === 64 ? 0x20b : 0x10b)) throw new Error(`expected Windows x${expected} PE`);
  } finally { fs.closeSync(descriptor); }
}

/** Validate structure and small native headers. Full SHA-256 verification belongs to packaging/install. */
export function readRuntime(root, engine, override, options = {}) {
  const source = options.source || (override ? 'override' : 'config');
  const location = path.resolve(override || path.join(root, engine, 'runtime.json'));
  let file = location;
  try { if (fs.statSync(location).isDirectory()) file = path.join(location, 'runtime.json'); } catch {}
  const base = path.dirname(file), errors = [];
  let raw = {}, inventory, physicalBase;
  const failure = () => ({ ...raw, engine, source, manifest: file, root: base, available: false,
    validation: 'structure-and-pe-headers', integrityVerified: false, validationErrors: errors,
    reason: errors.slice(0, 8).join('; ') });
  try {
    if (!fs.statSync(file).isFile()) throw new Error('Runtime manifest is not a file');
    physicalBase = fs.realpathSync(base);
    if (!inside(physicalBase, fs.realpathSync(file))) throw new Error('Runtime manifest escapes its pack directory');
    raw = JSON.parse(readText(file));
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Runtime manifest must be an object');
    if (raw.engine && String(raw.engine).toLowerCase() !== engine) throw new Error('Runtime manifest engine does not match ' + engine);
    if (raw.schemaVersion !== undefined && raw.schemaVersion !== 1) throw new Error('Unsupported runtime manifest schema');
    if (!['ghidra', 'x64dbg'].includes(engine)) throw new Error('Unsupported standalone runtime engine');
    if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('This runtime pack requires a Windows x64 host');
    if (source === 'bundled') {
      const bundleRoot = path.resolve(options.bundleRoot || root), physicalBundle = fs.realpathSync(bundleRoot);
      if (!inside(fs.realpathSync(PLUGIN_ROOT), physicalBundle) || !inside(physicalBundle, physicalBase)) throw new Error('Bundled runtime directory escapes the plugin');
      const bundleFile = path.join(bundleRoot, 'manifest.json');
      if (!inside(physicalBundle, fs.realpathSync(bundleFile))) throw new Error('Bundle inventory escapes the runtime directory');
      const bundle = JSON.parse(readText(bundleFile, 67108864));
      if (bundle.schemaVersion !== 1 || bundle.platform !== 'win32-x64' || typeof bundle.pluginVersion !== 'string'
          || !Array.isArray(bundle.engines) || !['ghidra', 'x64dbg'].every(id => bundle.engines.includes(id))
          || !Array.isArray(bundle.files) || !bundle.files.length) throw new Error('Invalid bundled runtime inventory');
      inventory = { root: bundleRoot, files: new Map() };
      for (const entry of bundle.files) {
        if (!relativePath(entry.path) || !inside(bundleRoot, path.resolve(bundleRoot, entry.path)) || !Number.isSafeInteger(entry.bytes)
            || entry.bytes < 0 || !/^[0-9a-f]{64}$/i.test(entry.sha256 || '') || inventory.files.has(pathKey(entry.path))) throw new Error('Invalid file entry in bundled runtime inventory');
        inventory.files.set(pathKey(entry.path), entry.bytes);
      }
    }
  } catch (error) { errors.push('Runtime metadata unavailable: ' + error.message); return failure(); }

  const resolved = { ...raw, engine, source, manifest: file, root: base };
  for (const key of pathKeys) {
    if (!raw[key]) continue;
    const value = relativePath(raw[key]) ? path.resolve(base, raw[key]) : null;
    if (!value || !inside(base, value)) { errors.push(`Manifest ${key} must be a contained relative path`); continue; }
    resolved[key] = value;
  }
  const component = (value, label, kind = 'file', bits = null) => {
    try {
      if (!value || !path.isAbsolute(value) || !inside(base, value)) throw new Error('missing or unsafe path');
      const stat = fs.statSync(value);
      if (kind === 'directory' ? !stat.isDirectory() : !stat.isFile() || !stat.size) throw new Error('required ' + kind + ' is missing or empty');
      if (!inside(physicalBase, fs.realpathSync(value))) throw new Error('path escapes the runtime pack through a link');
      if (inventory && kind === 'file') {
        const expected = inventory.files.get(pathKey(path.relative(inventory.root, value)));
        if (expected === undefined || expected !== stat.size) throw new Error('file is missing from inventory or has a different byte size');
      }
      if (bits) peArchitecture(value, bits);
      return value;
    } catch (error) { errors.push(label + ': ' + error.message); return null; }
  };
  const under = (home, suffix, label, kind = 'file', bits = null) => component(home && path.join(home, suffix), label, kind, bits);
  component(file, 'runtime.json');
  const python = component(resolved.pythonExe, 'pythonExe', 'file', 64);
  const pythonHome = python && path.dirname(python);
  for (const name of ['python312.dll', 'vcruntime140.dll']) under(pythonHome, name, 'Python ' + name, 'file', 64);
  under(pythonHome, 'python312.zip', 'Python standard library');
  const pth = under(pythonHome, 'python312._pth', 'Python isolated search path');
  if (pth) {
    try {
      const entries = readText(pth, 65536).split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#') && line !== 'import site');
      if (!entries.includes('python312.zip') || !entries.includes('.')) throw new Error('isolated stdlib/runtime entries are missing');
      for (const entry of entries) {
        const item = relativePath(entry) ? path.resolve(pythonHome, entry) : null;
        if (!item || !inside(base, item) || !inside(physicalBase, fs.realpathSync(item))) throw new Error('Python search path escapes the runtime pack');
      }
      if (engine === 'ghidra' && !entries.includes('pylib')) throw new Error('isolated PyGhidra dependencies are missing');
    } catch (error) { errors.push('Python isolated search path: ' + error.message); }
  }
  if (engine === 'ghidra') {
    const ghidra = component(resolved.ghidraHome, 'ghidraHome', 'directory');
    const java = component(resolved.javaHome, 'javaHome', 'directory');
    const properties = under(ghidra, 'Ghidra/application.properties', 'Ghidra application properties');
    const release = under(java, 'release', 'JDK release');
    if (properties && release) {
      try {
        const app = readText(properties), jdk = readText(release, 65536);
        const minimum = Number(app.match(/^application\.java\.min=(\d+)/m)?.[1]);
        const major = Number(jdk.match(/^JAVA_VERSION="(\d+)/m)?.[1]);
        const actualVersion = app.match(/^application\.version=(.+)$/m)?.[1].trim();
        if (!minimum || !major || major < minimum || !/^OS_ARCH="(?:x86_64|amd64)"/m.test(jdk)) throw new Error('JDK architecture/version is incompatible with Ghidra');
        if (raw.version && raw.version !== actualVersion) throw new Error('Ghidra application version does not match its manifest');
      } catch (error) { errors.push('Ghidra/JDK metadata: ' + error.message); }
    }
    under(java, 'bin/java.exe', 'JDK java', 'file', 64);
    under(java, 'bin/server/jvm.dll', 'JDK JVM', 'file', 64);
    under(java, 'jmods/java.base.jmod', 'JDK base module');
    under(java, 'legal', 'JDK licenses', 'directory');
    for (const [suffix, label] of [
      ['Ghidra/Framework/Utility/lib/Utility.jar', 'Ghidra Utility.jar'],
      ['Ghidra/Features/Base/lib/Base.jar', 'Ghidra Base.jar'],
      ['Ghidra/Features/PyGhidra/lib/PyGhidra.jar', 'Ghidra PyGhidra.jar'],
      ['Ghidra/Processors/x86/data/languages/x86-64.sla', 'Ghidra x86 language'],
      ['LICENSE', 'Ghidra license'], ['bom.json', 'Ghidra component inventory'],
    ]) under(ghidra, suffix, label);
    under(ghidra, 'licenses', 'Ghidra third-party licenses', 'directory');
    under(ghidra, 'Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe', 'Ghidra native decompiler', 'file', 64);
    for (const name of ['pyghidra/__init__.py', 'pyghidra/launcher.py', 'jpype/__init__.py', 'packaging/__init__.py', 'org.jpype.jar']) under(pythonHome, 'pylib/' + name, 'Python dependency ' + name);
    under(pythonHome, 'pylib/_jpype.cp312-win_amd64.pyd', 'JPype native extension', 'file', 64);
    if (source === 'bundled') {
      const proof = raw.jpypeBootstrap;
      if (proof?.patch !== 'ig5-jpype-context-v1' || proof.version !== '1.5.2'
          || proof.property !== 'ig5.jpype.native_filename' || proof.nativeFilename !== '_jpype.cp312-win_amd64.pyd'
          || proof.sourceRoot !== 'licenses/ig5-jpype-bootstrap'
          || !['upstreamSourceSha256', 'upstreamJarSha256', 'patchedJarSha256', 'patchedSourceSha256', 'patchSha256']
            .every(key => /^[0-9a-f]{64}$/i.test(proof[key] || ''))) errors.push('Bundled JPype Unicode bootstrap provenance is missing or incompatible');
      for (const name of ['LICENSE', 'UPSTREAM-NOTICE', 'NOTICE.txt', 'README.md', 'JPypeContext.java',
        'unicode-bootstrap.patch', 'upstream-JPypeContext.java', 'provenance.json']) {
        under(base, 'licenses/ig5-jpype-bootstrap/' + name, 'JPype bootstrap ' + name);
      }
    }
  } else {
    if (raw.bridge !== 'ig5-native') errors.push('x64dbg requires the bundled ig5-native bridge');
    if (!['headless', 'gui-hidden'].includes(raw.mode || 'headless')) errors.push('Unsupported x64dbg mode');
    for (const bits of [64, 32]) {
      component(resolved[bits === 64 ? 'x64dbgExe' : 'x32dbgExe'], `x${bits} debugger`, 'file', bits);
      component(resolved[bits === 64 ? 'headlessExe' : 'headless32Exe'], `x${bits} headless debugger`, 'file', bits);
      const directory = path.join(base, 'snapshot', 'release', 'x' + bits);
      under(directory, `plugins/ig5-bridge.dp${bits}`, `x${bits} native bridge`, 'file', bits);
      for (const name of [`x${bits}dbg.dll`, `x${bits}bridge.dll`, `x${bits}_dbg.dll`, `x${bits}_bridge.dll`,
        'jansson.dll', 'TitanEngine.dll', 'Scylla.dll', 'Qt5Core.dll', 'Qt5Gui.dll', 'Qt5Widgets.dll', 'msvcp140.dll', 'vcruntime140.dll']) under(directory, name, `x${bits} ${name}`, 'file', bits);
    }
    under(base, 'licenses', 'x64dbg licenses', 'directory');
  }
  under(pythonHome, 'LICENSE.txt', 'Python license');
  return { ...resolved, available: errors.length === 0, portable: errors.length === 0,
    validation: 'structure-and-pe-headers', integrityVerified: false, validationErrors: errors,
    ...(errors.length ? { reason: errors.slice(0, 8).join('; ') } : {}) };
}

export function runtimeConfiguration(cfg = {}) {
  const home = path.resolve(cfg.home || process.env.IG5_HOME || path.join(os.homedir(), '.dsh', 'ig5'));
  const runtimeRoot = path.resolve(cfg.runtimeRoot || process.env.IG5_RUNTIME_ROOT || BUNDLED_RUNTIME_ROOT);
  const rootSource = cfg.runtimeRoot ? 'config' : process.env.IG5_RUNTIME_ROOT ? 'environment' : 'bundled';
  const select = engine => {
    const value = cfg[engine + 'Runtime'] || process.env['IG5_' + engine.toUpperCase() + '_RUNTIME'];
    const source = cfg[engine + 'Runtime'] ? 'config' : value ? 'environment' : rootSource;
    return readRuntime(runtimeRoot, engine, value, { source, bundleRoot: runtimeRoot });
  };
  return { home, runtimeRoot, projectRoot: path.resolve(cfg.projectRoot || path.join(home, 'projects')),
    ghidra: select('ghidra'), x64dbg: select('x64dbg') };
}

export function terminateTree(proc) {
  if (!proc?.pid || proc.exitCode !== null) return;
  // Only the process created by this instance and its children are terminated.
  if (process.platform === 'win32') {
    const killer = spawn('taskkill.exe', ['/PID', String(proc.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
    killer.on('error', () => { try { proc.kill(); } catch {} });
  } else { try { proc.kill(); } catch {} }
}
