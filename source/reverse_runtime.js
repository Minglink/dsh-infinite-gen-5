import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Discovery only reads known configuration/directories and small file headers.
// It neither imports the engine nor executes Python, and never changes the installation.
const MAX_ENTRIES = 256;
const MAX_CANDIDATES = 96;
const publicReasons = Object.freeze({
  disabled: 'Reverse 已在插件配置中关闭；可使用随包 Ghidra。',
  platform: 'Reverse 当前仅支持 Windows x64 宿主；请选择匹配的 Ghidra 运行包。',
  'not-found': '未发现已有的 Reverse 本机安装。插件随包提供 Ghidra/x64dbg；Reverse 适配器不包含商业引擎内核。已有安装可配置 idaDir 或 IG5_IDA_DIR。',
  'invalid-path': 'Reverse 安装路径配置无效；请修正 idaDir 或 IG5_IDA_DIR。不会自动替换显式指定的安装。',
  'missing-kernel': 'Reverse 安装缺少可用的 Windows x64 原生内核；请检查已有安装是否完整。',
  'missing-bindings': 'Reverse 安装缺少无头 Python 接口或原生 Python 模块；只有图形程序或空目录不能用于此后端。',
  'invalid-python': 'Reverse Python 配置不可用：需要实际的 Windows x64 Python 可执行文件。请修正 pythonExe 或 IG5_PYTHON；不会静默改用另一个解释器。',
  'missing-python': 'Reverse 已发现，但未找到可用的 Windows x64 Python；请设置 pythonExe 或 IG5_PYTHON。',
  detected: 'Reverse 安装与 Python 文件检查通过，尚未验证原生启动。请调用 ig5_doctor engine=reverse；启动及目标架构的反编译能力以实际结果为准。',
});

export function resolveReverseRuntime(config = {}, options = {}) {
  const io = options.fs || fs, paths = options.path || path;
  const env = options.env || process.env, home = options.home || os.homedir();
  const host = options.host || { id: `${process.platform}-${process.arch}` };
  const state = { available: false, detected: false, configured: false, startupVerified: false,
    runtimeReady: null, readiness: 'unavailable', validation: 'files-and-pe-headers',
    source: 'discovery', distribution: 'local-installation', discoveryPartial: false,
    idaDir: null, pythonExe: null };
  const fail = code => ({ ...state, code: `REVERSE_${code.replaceAll('-', '_').toUpperCase()}`, reason: publicReasons[code] });
  if (config.reverse === false) return fail('disabled');
  if (host.id !== 'win32-x64') return fail('platform');

  const entries = directory => {
    const found = [];
    let handle;
    try {
      handle = io.opendirSync(directory);
      let entry;
      while (found.length < MAX_ENTRIES && (entry = handle.readSync())) found.push(entry);
      if (found.length === MAX_ENTRIES && handle.readSync()) state.discoveryPartial = true;
    } catch { /* missing/unreadable discovery directories are not executable candidates */ }
    finally { try { handle?.closeSync(); } catch {} }
    return found;
  };
  const file = value => {
    try { const stat = io.statSync(value); return stat.isFile() && stat.size > 0; }
    catch { return false; }
  };
  const directory = value => {
    try { return io.statSync(value).isDirectory(); } catch { return false; }
  };
  const absolute = value => {
    if (typeof value !== 'string' || !value.trim() || /[\0\r\n]/.test(value)) return null;
    try { return paths.resolve(value); } catch { return null; }
  };
  const pe64 = value => {
    let descriptor;
    try {
      descriptor = io.openSync(value, 'r');
      const dos = Buffer.alloc(64), pe = Buffer.alloc(26);
      if (io.readSync(descriptor, dos, 0, 64, 0) !== 64 || dos.toString('ascii', 0, 2) !== 'MZ') return false;
      const offset = dos.readUInt32LE(0x3c);
      if (offset < 64 || offset > 16 * 1024 * 1024 || offset + 26 > io.fstatSync(descriptor).size) return false;
      return io.readSync(descriptor, pe, 0, 26, offset) === 26 && pe.readUInt32LE(0) === 0x4550
        && pe.readUInt16LE(4) === 0x8664 && pe.readUInt16LE(24) === 0x20b;
    } catch { return false; }
    finally { if (descriptor !== undefined) try { io.closeSync(descriptor); } catch {} }
  };
  const resolvePython = value => {
    if (typeof value !== 'string' || !value.trim()) return null;
    if (!/[\\/]/.test(value)) {
      const name = /\.exe$/i.test(value) ? value : `${value}.exe`;
      // Lookup, not execution: only this filename in the first bounded PATH entries.
      for (const item of String(env.PATH || env.Path || '').split(paths.delimiter).slice(0, 64)) {
        if (!item.trim()) continue;
        const candidate = paths.join(item.replace(/^"|"$/g, ''), name);
        if (file(candidate) && pe64(candidate) && entries(paths.dirname(candidate)).some(entry => /^python3\d{1,2}\.dll$/i.test(entry.name) && pe64(paths.join(paths.dirname(candidate), entry.name)))) return candidate;
      }
      return null;
    }
    const candidate = absolute(value);
    return candidate && file(candidate) && pe64(candidate)
      && entries(paths.dirname(candidate)).some(entry => /^python3\d{1,2}\.dll$/i.test(entry.name) && pe64(paths.join(paths.dirname(candidate), entry.name))) ? candidate : null;
  };
  const explicitDir = config.idaDir !== undefined ? config.idaDir : env.IG5_IDA_DIR;
  const explicitPython = config.pythonExe !== undefined ? config.pythonExe : env.IG5_PYTHON;
  state.configured = explicitDir !== undefined || explicitPython !== undefined;
  if (explicitDir !== undefined || explicitPython !== undefined) state.source = config.idaDir !== undefined || config.pythonExe !== undefined ? 'config' : 'environment';
  const configuredPython = explicitPython === undefined ? null : resolvePython(explicitPython);
  if (explicitPython !== undefined && !configuredPython) return fail('invalid-python');
  const candidates = [], seen = new Set();
  const add = (value, source) => {
    const candidate = absolute(value);
    if (!candidate) return;
    const key = candidate.toLowerCase();
    if (seen.has(key)) return;
    if (candidates.length >= MAX_CANDIDATES) { state.discoveryPartial = true; return; }
    seen.add(key); candidates.push({ directory: candidate, source });
  };
  if (explicitDir !== undefined) {
    state.configured = true;
    state.source = config.idaDir !== undefined ? 'config' : 'environment';
    if (!absolute(explicitDir)) return fail('invalid-path');
    add(explicitDir, state.source);
  } else {
    // idapro's own existing activation configuration is a path hint; never create it.
    const userConfigs = [env.IDAUSR && paths.join(env.IDAUSR, 'ida-config.json'),
      env.APPDATA && paths.join(env.APPDATA, 'Hex-Rays', 'IDA Pro', 'ida-config.json')].filter(Boolean);
    for (const configFile of userConfigs) {
      try {
        if (io.statSync(configFile).size > 65536) continue;
        const data = JSON.parse(io.readFileSync(configFile, 'utf8').replace(/^\uFEFF/, ''));
        add(data?.Paths?.['ida-install-dir'], 'activation-config');
      } catch { /* ignore malformed/missing hints; explicit plugin config is handled above */ }
    }
    const desktops = [paths.join(env.USERPROFILE || home, 'Desktop'), paths.join(home, 'Desktop'),
      ...[env.OneDrive, env.OneDriveConsumer, env.OneDriveCommercial, paths.join(env.USERPROFILE || home, 'OneDrive')]
        .filter(Boolean).map(root => paths.join(root, 'Desktop'))];
    const programRoots = [env.ProgramFiles, env['ProgramFiles(x86)'], env.ProgramW6432,
      'C:\\Program Files', 'C:\\Program Files (x86)'].filter(Boolean);
    for (const root of new Set(options.discoveryRoots || [...desktops, ...programRoots])) {
      for (const entry of entries(root)) {
        if (!(entry.isDirectory() || entry.isSymbolicLink())) continue;
        const candidate = paths.join(root, entry.name);
        if (/^ida(?:\b|\d)/i.test(entry.name)) add(candidate, 'discovery');
        if (/^hex[- ]?rays$/i.test(entry.name)) {
          for (const child of entries(candidate)) if (child.isDirectory() || child.isSymbolicLink()) add(paths.join(candidate, child.name), 'discovery');
        }
      }
    }
  }
  if (!candidates.length) return fail('not-found');

  let firstFailure;
  for (const candidate of candidates) {
    state.idaDir = candidate.directory; state.source = candidate.source;
    state.detected = directory(candidate.directory);
    let failure;
    if (!state.detected) failure = 'invalid-path';
    else if (!pe64(paths.join(candidate.directory, 'idalib.dll'))
      || !['ida.dll', 'ida64.dll'].some(name => pe64(paths.join(candidate.directory, name)))) failure = 'missing-kernel';
    else if (!file(paths.join(candidate.directory, 'idalib', 'python', 'idapro', '__init__.py'))
      || !file(paths.join(candidate.directory, 'idalib', 'python', 'idapro', 'config.py'))
      || !file(paths.join(candidate.directory, 'python', 'ida_idaapi.py'))
      || !pe64(paths.join(candidate.directory, 'python', 'lib-dynload', '_ida_idaapi.pyd'))) failure = 'missing-bindings';
    else {
      const pythonChoices = explicitPython !== undefined ? [configuredPython] : [
        ...entries(candidate.directory).filter(entry => (entry.isDirectory() || entry.isSymbolicLink()) && /^python\d+(?:\.\d+)?$/i.test(entry.name))
          .sort((a, b) => a.name.localeCompare(b.name, 'en', { numeric: true })).map(entry => paths.join(candidate.directory, entry.name, 'python.exe')),
        paths.join(candidate.directory, 'python', 'python.exe'), 'python', 'python3'];
      state.pythonExe = pythonChoices.map(resolvePython).find(Boolean) || null;
      if (!state.pythonExe) failure = explicitPython !== undefined ? 'invalid-python' : 'missing-python';
    }
    if (!failure) return { ...state, available: true, readiness: 'detected', code: 'REVERSE_DETECTED', reason: publicReasons.detected };
    const rejected = fail(failure);
    firstFailure ||= rejected;
    if (explicitDir !== undefined) return rejected;
  }
  return { ...firstFailure, discoveryPartial: state.discoveryPartial };
}
