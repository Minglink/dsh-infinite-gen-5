// Built-in zero-dependency static JS / Electron / ASAR topology extractor (engines layer; read-only).
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

export const BUILTIN_JS_STATIC_SOURCE = 'ig5-builtin-js-static-v1';
const MAX_FILE = 4 * 1024 * 1024, MAX_TOTAL = 32 * 1024 * 1024, MAX_NATIVE = 64 * 1024 * 1024;
const MAX_ENTRIES = 4096, MAX_DEPTH = 12;
const FUSE_SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'ascii');
const RE_WORDS = new Set(['return', 'throw', 'case', 'delete', 'void', 'typeof', 'instanceof', 'in', 'of', 'new', 'yield', 'await', 'else', 'do']);
const RE_CHARS = new Set('(,=:[!&|?{};+-*%^~<>');
const NATIVE_EXT = /\.(?:exe|dll|so|node)$/i, SRC_EXT = /\.(?:js|mjs|cjs|html|htm)$/i;

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const fail = (code, msg, extra = {}) => { throw Object.assign(new Error(msg), { code, retryable: false, ...extra }); };
const isRegFile = (p) => fs.existsSync(p) && !fs.lstatSync(p).isSymbolicLink() && fs.statSync(p).isFile();
const isRegDir = (p) => fs.existsSync(p) && !fs.lstatSync(p).isSymbolicLink() && fs.statSync(p).isDirectory();

function checkDeadline(dl, sig) {
  if (sig?.aborted) fail('ABORT_ERR', 'JS static analysis aborted');
  if (dl && Date.now() > dl) fail('ETIMEDOUT', 'JS static analysis exceeded timeout');
}

function hasSymlinkInChain(targetPath, stopDir = null) {
  const stopLow = stopDir ? path.resolve(stopDir).toLowerCase() : null, chain = [];
  for (let cur = path.resolve(targetPath); ; ) {
    chain.push(cur);
    if (stopLow && cur.toLowerCase() === stopLow) break;
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  for (const seg of chain.reverse()) if (fs.existsSync(seg) && fs.lstatSync(seg).isSymbolicLink()) return seg;
  return null;
}

function assertNoSymlinkPath(p) {
  const res = path.resolve(p), bad = hasSymlinkInChain(res);
  if (bad) fail('SYMLINK_REJECTED', `Refusing to traverse symbolic link in JS app path: ${bad}`);
  return res;
}

function skipQuoted(s, i, end = s.length) {
  for (const q = s[i++]; i < end; ) { if (s[i] === '\\') i += 2; else if (s[i++] === q) break; }
  return i;
}

export function parseAsarHeader(asarPath) {
  const res = assertNoSymlinkPath(asarPath), st = fs.lstatSync(res);
  if (!st.isFile() || st.size < 16) fail('INVALID_ASAR', `Invalid or truncated ASAR archive: ${res}`);
  const fd = fs.openSync(res, 'r');
  try {
    const pfx = Buffer.alloc(16);
    if (fs.readSync(fd, pfx, 0, 16, 0) !== 16) fail('INVALID_ASAR', 'Unable to read 16-byte ASAR pickle header');
    const szPay = pfx.readUInt32LE(0), hdrSz = pfx.readUInt32LE(4), hdrPay = pfx.readUInt32LE(8), jsonLen = pfx.readUInt32LE(12);
    if (szPay !== 4 || hdrSz < 8 || hdrSz > 16 * 1024 * 1024) fail('INVALID_ASAR', `Malformed ASAR pickle header (${szPay}, ${hdrSz})`);
    const baseOff = 8 + hdrSz;
    if (baseOff > st.size || jsonLen > hdrSz - 8 || 16 + jsonLen > st.size || hdrPay < 4 + jsonLen) fail('INVALID_ASAR', 'ASAR header exceeds bounds');
    const jb = Buffer.alloc(jsonLen);
    if (fs.readSync(fd, jb, 0, jsonLen, 16) !== jsonLen) fail('INVALID_ASAR', 'Truncated ASAR JSON header');
    let header;
    try { header = JSON.parse(jb.toString('utf8')); } catch (e) { fail('INVALID_ASAR', `Invalid ASAR JSON: ${e.message}`); }
    if (!header?.files || typeof header.files !== 'object') fail('INVALID_ASAR', 'ASAR header missing "files" map');
    return { asarPath: res, fileSize: st.size, dataBaseOffset: baseOff, header };
  } finally { fs.closeSync(fd); }
}

function makeCollector() {
  const st = { textFiles: [], nativeEntries: [], skippedEntries: [], totalTextBytes: 0, seenEntries: 0 };
  const addSrc = (rel, sz, rd) => {
    if (sz > MAX_FILE) { st.skippedEntries.push({ path: rel, reason: 'single-file-budget-exceeded', bytes: sz }); return; }
    if (st.totalTextBytes + sz > MAX_TOTAL) { st.skippedEntries.push({ path: rel, reason: 'total-byte-budget-exceeded', bytes: sz }); return; }
    const b = rd(); st.totalTextBytes += b.length;
    st.textFiles.push({ relativePath: rel, bytes: b.length, sha256: sha256(b), text: b.toString('utf8') });
  };
  const addNat = (rel, abs, sz, rd, ex = {}) => {
    if (sz <= MAX_NATIVE) { const b = rd(); st.nativeEntries.push({ relativePath: rel, absolutePath: abs, bytes: b.length, sha256: sha256(b), ...ex }); }
  };
  return { st, addSrc, addNat };
}

function collectAsarVirtualFiles(info, { deadlineMs, signal }) {
  const { st, addSrc, addNat } = makeCollector();
  const unpRoot = `${info.asarPath}.unpacked`, stopDir = path.dirname(info.asarPath), fd = fs.openSync(info.asarPath, 'r');
  try {
    const walk = (node, pfx, depth, inNm) => {
      checkDeadline(deadlineMs, signal);
      if (depth > MAX_DEPTH || !node || typeof node !== 'object') return;
      for (const name of Object.keys(node).sort()) {
        if (name === '.git' || name === '__proto__') continue;
        if (/[\\/\0]/.test(name) || name === '.' || name === '..') { st.skippedEntries.push({ path: `${pfx}${name}`, reason: 'unsafe-entry-name' }); continue; }
        if (++st.seenEntries > MAX_ENTRIES) { st.skippedEntries.push({ path: `${pfx}${name}`, reason: 'entry-budget-exceeded' }); return; }
        const ent = node[name], rel = pfx ? `${pfx}/${name}` : name, nextNm = inNm || name === 'node_modules';
        if (!ent || typeof ent !== 'object') continue;
        if (typeof ent.link === 'string') { st.skippedEntries.push({ path: rel, reason: 'asar-symlink-rejected' }); continue; }
        if (ent.files && typeof ent.files === 'object') { walk(ent.files, rel, depth + 1, nextNm); continue; }
        const sz = Number(ent.size);
        if (!Number.isSafeInteger(sz) || sz < 0) { st.skippedEntries.push({ path: rel, reason: 'invalid-size' }); continue; }
        const low = name.toLowerCase(), isNat = NATIVE_EXT.test(low), isSrc = !nextNm && (low === 'package.json' || SRC_EXT.test(low));
        if (ent.unpacked === true) {
          if (!isNat && !isSrc) continue;
          const uf = path.join(unpRoot, ...rel.split('/'));
          if (hasSymlinkInChain(uf, stopDir)) { st.skippedEntries.push({ path: rel, reason: 'unpacked-symlink-rejected' }); continue; }
          if (!fs.existsSync(uf) || !fs.statSync(uf).isFile()) continue;
          const dsz = fs.statSync(uf).size;
          if (isNat) addNat(rel, uf, dsz, () => fs.readFileSync(uf), { unpacked: true });
          else addSrc(rel, dsz, () => fs.readFileSync(uf));
          continue;
        }
        if (typeof ent.offset !== 'string' || !/^\d+$/.test(ent.offset)) { st.skippedEntries.push({ path: rel, reason: 'invalid-offset' }); continue; }
        const relOff = Number(ent.offset);
        if (!Number.isSafeInteger(relOff) || relOff < 0 || info.dataBaseOffset + relOff + sz > info.fileSize) {
          fail('INVALID_ASAR', `ASAR entry "${rel}" slice [${relOff}, +${sz}] exceeds archive size ${info.fileSize}`);
        }
        const rd = () => { const b = Buffer.alloc(sz); fs.readSync(fd, b, 0, sz, info.dataBaseOffset + relOff); return b; };
        if (isNat) addNat(rel, `${info.asarPath}!/${rel}`, sz, rd, { inAsar: true });
        else if (isSrc) addSrc(rel, sz, rd);
      }
    };
    walk(info.header.files, '', 0, false);
  } finally { fs.closeSync(fd); }
  return st;
}

function collectDirectoryFiles(rootDir, { deadlineMs, signal }) {
  const { st, addSrc, addNat } = makeCollector();
  const walk = (dir, depth, inNm) => {
    checkDeadline(deadlineMs, signal);
    if (depth > MAX_DEPTH) return;
    for (const ent of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (ent.name === '.git') continue;
      const full = path.join(dir, ent.name), rel = path.relative(rootDir, full).replaceAll('\\', '/');
      if (++st.seenEntries > MAX_ENTRIES) { st.skippedEntries.push({ path: rel, reason: 'entry-budget-exceeded' }); return; }
      const lst = fs.lstatSync(full);
      if (lst.isSymbolicLink()) { st.skippedEntries.push({ path: rel, reason: 'symlink-skipped' }); continue; }
      const nextNm = inNm || ent.name === 'node_modules';
      if (lst.isDirectory()) { walk(full, depth + 1, nextNm); continue; }
      if (!lst.isFile()) continue;
      const low = ent.name.toLowerCase();
      if (NATIVE_EXT.test(low)) addNat(rel, full, lst.size, () => fs.readFileSync(full));
      else if (!nextNm && (low === 'package.json' || SRC_EXT.test(low))) addSrc(rel, lst.size, () => fs.readFileSync(full));
    }
  };
  walk(rootDir, 0, false);
  return st;
}

export function stripJsComments(src) {
  const out = [], tpl = [], n = src.length;
  let i = 0, pSig = '', pTwo = '', pWord = '';
  const scanTpl = () => {
    while (i < n) {
      const c = src[i];
      if (c === '\\' && i + 1 < n) { out.push(c, src[i + 1]); i += 2; continue; }
      if (c === '$' && src[i + 1] === '{') { out.push('$', '{'); i += 2; tpl.push(0); pSig = '{'; pTwo = '${'; pWord = ''; return; }
      out.push(c); i += 1;
      if (c === '`') { pSig = '`'; pTwo = ''; pWord = ''; return; }
    }
  };
  while (i < n) {
    const ch = src[i], nx = src[i + 1];
    if (ch === "'" || ch === '"') { const end = skipQuoted(src, i, n); out.push(src.slice(i, end)); i = end; pSig = ch; pTwo = ''; pWord = ''; continue; }
    if (ch === '`') { out.push('`'); i += 1; scanTpl(); continue; }
    if (ch === '/' && nx === '/') { i += 2; while (i < n && src[i] !== '\n') i += 1; continue; }
    if (ch === '/' && nx === '*') { out.push(' '); i += 2; while (i + 1 < n && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] === '\n') out.push('\n'); i += 1; } i += 2; continue; }
    if (ch === '/' && (pSig === '' || (RE_CHARS.has(pSig) && pTwo !== '++' && pTwo !== '--') || RE_WORDS.has(pWord))) {
      out.push('/'); i += 1;
      for (let inCls = false; i < n; ) {
        const rc = src[i++];
        if (rc === '\n' || rc === '\r') { out.push(rc); break; }
        if (rc === '\\' && i < n) { const esc = src[i++]; out.push(' ', esc === '\n' ? '\n' : ' '); continue; }
        if (rc === '[') inCls = true; else if (rc === ']') inCls = false;
        else if (rc === '/' && !inCls) { out.push('/'); while (i < n && /[dgimsuvy]/.test(src[i])) out.push(src[i++]); break; }
        out.push(' ');
      }
      pSig = '/'; pTwo = ''; pWord = ''; continue;
    }
    if (tpl.length > 0) {
      if (ch === '{') tpl[tpl.length - 1] += 1;
      else if (ch === '}') {
        if (tpl[tpl.length - 1] === 0) { tpl.pop(); out.push('}'); i += 1; scanTpl(); continue; }
        tpl[tpl.length - 1] -= 1;
      }
    }
    if (/[A-Za-z0-9_$]/.test(ch)) {
      const s = i; while (i < n && /[A-Za-z0-9_$]/.test(src[i])) i += 1;
      pWord = src.slice(s, i); out.push(pWord); pSig = src[i - 1]; pTwo = ''; continue;
    }
    out.push(ch);
    if (!/\s/.test(ch)) { pTwo = pSig + ch; pSig = ch; pWord = ''; }
    i += 1;
  }
  return out.join('');
}

function extractBalancedBraces(code, openIdx, maxSpan = 4096) {
  if (code[openIdx] !== '{') return null;
  const lim = Math.min(code.length, openIdx + maxSpan);
  for (let d = 0, i = openIdx; i < lim; i++) {
    const ch = code[i];
    if (ch === "'" || ch === '"' || ch === '`') { i = skipQuoted(code, i, lim) - 1; continue; }
    if (ch === '{') d += 1;
    else if (ch === '}' && --d === 0) return { body: code.slice(openIdx + 1, i), endIdx: i + 1 };
  }
  return null;
}

function extractTopLevelObjectKeys(body) {
  const keys = [];
  for (let d = 0, i = 0, start = true; i < body.length && keys.length < 32; i++) {
    const ch = body[i];
    if (ch === "'" || ch === '"' || ch === '`') { i = skipQuoted(body, i) - 1; start = false; continue; }
    if (ch === '{' || ch === '(' || ch === '[') { d += 1; start = false; continue; }
    if (ch === '}' || ch === ')' || ch === ']') { d = Math.max(0, d - 1); start = false; continue; }
    if (d === 0 && ch === ',') { start = true; continue; }
    if (d === 0 && start && !/\s/.test(ch)) {
      const m = /^(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,63})\s*(?::|\()/.exec(body.slice(i, i + 96));
      if (m && !['function', 'return', 'get', 'set'].includes(m[1]) && !keys.includes(m[1])) keys.push(m[1]);
      start = false;
    }
  }
  return keys;
}

function inspectElectronFuses(exePath) {
  try {
    const st = fs.lstatSync(exePath);
    if (!st.isFile() || st.isSymbolicLink() || st.size > 256 * 1024 * 1024) return null;
    const fd = fs.openSync(exePath, 'r');
    try {
      for (let off = 0, carry = Buffer.alloc(0); off < st.size; ) {
        const len = Math.min(2 * 1024 * 1024, st.size - off), buf = Buffer.alloc(len), rd = fs.readSync(fd, buf, 0, len, off);
        if (rd <= 0) break;
        const win = carry.length ? Buffer.concat([carry, buf.subarray(0, rd)]) : buf.subarray(0, rd);
        const idx = win.indexOf(FUSE_SENTINEL);
        if (idx >= 0 && idx + FUSE_SENTINEL.length + 2 <= win.length) {
          const pos = idx + FUSE_SENTINEL.length, ver = win[pos], wLen = win[pos + 1];
          const wire = win.subarray(pos + 2, Math.min(win.length, pos + 2 + wLen));
          const bit = (p) => (p < wire.length ? (wire[p] === 0x31 ? true : wire[p] === 0x30 ? false : null) : null);
          return {
            executable: path.basename(exePath), sentinelFound: true, fuseVersion: ver, wireLength: wLen,
            runAsNode: bit(0), enableCookieEncryption: bit(1), enableNodeOptionsEnvironmentVariable: bit(2),
            enableNodeCliInspectArguments: bit(3), enableEmbeddedAsarIntegrityValidation: bit(4), onlyLoadAppFromAsar: bit(5),
          };
        }
        carry = win.subarray(Math.max(0, win.length - 64)); off += rd;
      }
      return { executable: path.basename(exePath), sentinelFound: false };
    } finally { fs.closeSync(fd); }
  } catch { return null; }
}

function extractHtmlControls(file, html) {
  const controls = [], scripts = [], tagRe = /<(button|input|select|textarea|form|a|div|span|pre|code|output|script)\b([^>]*)>/gi;
  let m;
  while ((m = tagRe.exec(html)) !== null && controls.length < 128) {
    const tag = m[1].toLowerCase(), attrs = m[2] || '';
    const av = (k) => { const am = new RegExp(`\\b${k}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>"']+))`, 'i').exec(attrs); return am ? (am[1] ?? am[2] ?? am[3] ?? null) : null; };
    if (tag === 'script') { const src = av('src'); if (src) scripts.push({ file, src }); continue; }
    const id = av('id'), name = av('name'), type = av('type'), dataAttrs = [], dRe = /\b(data-[a-z0-9_-]+)\s*=/gi;
    let dm;
    while ((dm = dRe.exec(attrs)) !== null && dataAttrs.length < 8) dataAttrs.push(dm[1].toLowerCase());
    if (!['button', 'input', 'select', 'textarea', 'form'].includes(tag) && !id && !dataAttrs.length) continue;
    const selector = id ? `#${id}` : name ? `${tag}[name="${name}"]` : dataAttrs.length ? `${tag}[${dataAttrs[0]}]` : tag;
    controls.push({ file, tag, id, name, type, dataAttributes: dataAttrs, selector });
  }
  return { controls, scripts };
}

function analyzeJsFileTopology(file, rawText) {
  const code = stripJsComments(rawText);
  const ipcChannels = [], boundaries = [], windows = [], preloadBridges = [], entryRefs = [];
  let m;
  const ipcRe = /\b(ipcMain|ipcRenderer)\s*\.\s*(handle|handleOnce|on|once|invoke|send|sendSync|sendToHost)\s*\(\s*(['"`])([^'"`\r\n]{1,128})\3/g;
  while ((m = ipcRe.exec(code)) !== null && ipcChannels.length < 256) {
    ipcChannels.push({ channel: m[4], actor: m[1], method: m[2], direction: m[1] === 'ipcMain' ? 'renderer-to-main' : 'renderer-call', file });
  }
  const brRe = /\bexposeInMainWorld\s*\(\s*(['"`])([A-Za-z_$][A-Za-z0-9_$]{0,63})\1\s*,\s*\{/g;
  while ((m = brRe.exec(code)) !== null && preloadBridges.length < 32) {
    const b = extractBalancedBraces(code, m.index + m[0].length - 1, 4096);
    if (!b) continue;
    preloadBridges.push({ global: m[2], methods: extractTopLevelObjectKeys(b.body), file });
    brRe.lastIndex = b.endIdx;
  }
  const bwRe = /\bnew\s+(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*)?BrowserWindow\s*\(\s*\{/g;
  while ((m = bwRe.exec(code)) !== null && windows.length < 16) {
    const b = extractBalancedBraces(code, m.index + m[0].length - 1, 3072);
    if (!b) continue;
    const pm = /preload\s*:\s*(?:[A-Za-z0-9_$.]*?(?:join|resolve)\s*\([^)]*?(['"`])([^'"`]+\.(?:c?m?js))\1|(['"`])([^'"`]+\.(?:c?m?js))\3)/.exec(b.body);
    const preload = pm ? (pm[2] || pm[4]) : null;
    if (preload) entryRefs.push({ role: 'preload', target: preload, declaredIn: file });
    const bOpt = (k) => { const bm = new RegExp(`\\b${k}\\s*:\\s*(true|false)`).exec(b.body); return bm ? bm[1] === 'true' : null; };
    windows.push({ file, preload, contextIsolation: bOpt('contextIsolation'), nodeIntegration: bOpt('nodeIntegration'), sandbox: bOpt('sandbox') });
    bwRe.lastIndex = b.endIdx;
  }
  const loadRe = /\.\s*(loadFile|loadURL)\s*\(\s*(?:[A-Za-z0-9_$.]*?(?:join|resolve)\s*\([^)]*?(['"`])([^'"`]+)\2|(['"`])([^'"`]+)\4)/g;
  while ((m = loadRe.exec(code)) !== null && entryRefs.length < 64) {
    entryRefs.push({ role: m[1] === 'loadFile' ? 'renderer-html' : 'renderer-url', target: m[3] || m[5], declaredIn: file });
  }
  const cpRe = /\b(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*)?(spawn|spawnSync|execFile|execFileSync|exec|execSync|fork)\s*\(([^;]{1,320})/g;
  while ((m = cpRe.exec(code)) !== null && boundaries.length < 128) {
    const api = m[1], argHead = m[2], lits = [], litRe = /(['"`])([^'"`\r\n]{1,160})\1/g;
    let lm;
    while ((lm = litRe.exec(argHead)) !== null && lits.length < 6) lits.push(lm[2]);
    const idm = /^\s*([A-Za-z_$][A-Za-z0-9_$]{0,63})\b/.exec(argHead);
    if (idm && !['path', 'process', 'require'].includes(idm[1])) {
      const dm = new RegExp(`\\b(?:const|let|var)\\s+${idm[1]}\\s*=\\s*([^;\\r\\n]{1,240})`).exec(code);
      if (dm) while ((lm = litRe.exec(dm[1])) !== null && lits.length < 8) if (!lits.includes(lm[2])) lits.push(lm[2]);
    }
    const targetCandidates = lits.filter((s) => /\.(?:exe|bat|cmd|ps1|py|sh|bin|out)$/i.test(s) || /^[A-Za-z0-9_./\\-]+$/.test(s)).slice(0, 4);
    boundaries.push({ kind: 'child-process', api, file, targetCandidates });
  }
  const natRe = /\b(?:process\.dlopen|require\s*\(\s*(['"`])([^'"`]+\.node)\1|bindings\s*\(\s*(['"`])([^'"`]+)\3|ffi-napi|koffi)/g;
  while ((m = natRe.exec(code)) !== null && boundaries.length < 160) {
    boundaries.push({ kind: 'native-addon', api: m[0].slice(0, 48), file, targetCandidates: [m[2] || m[4]].filter(Boolean) });
  }
  return { ipcChannels, boundaries, windows, preloadBridges, entryRefs };
}

function scanAppContainer(rootDir, opts) {
  const nAsar = path.join(rootDir, 'resources', 'app.asar'), dAsar = path.join(rootDir, 'app.asar'), nApp = path.join(rootDir, 'resources', 'app');
  const hasPkg = fs.existsSync(path.join(rootDir, 'package.json'));
  if (isRegFile(nAsar)) { const info = parseAsarHeader(nAsar); return { asarInfo: info, outerNative: collectDirectoryFiles(rootDir, opts).nativeEntries, col: collectAsarVirtualFiles(info, opts) }; }
  if (!hasPkg && isRegFile(dAsar)) { const info = parseAsarHeader(dAsar); return { asarInfo: info, outerNative: collectDirectoryFiles(rootDir, opts).nativeEntries, col: collectAsarVirtualFiles(info, opts) }; }
  if (!hasPkg && isRegDir(nApp)) return { asarInfo: null, outerNative: collectDirectoryFiles(rootDir, opts).nativeEntries, col: collectDirectoryFiles(nApp, opts) };
  return { asarInfo: null, outerNative: [], col: collectDirectoryFiles(rootDir, opts) };
}

export function analyzeJsApplicationBuiltin(appPath, { timeoutMs = 30_000, signal } = {}) {
  const resolved = assertNoSymlinkPath(appPath);
  if (!fs.existsSync(resolved)) fail('ENOENT', `JS/Electron application path does not exist: ${resolved}`);
  const opts = { deadlineMs: timeoutMs > 0 ? Date.now() + timeoutMs : 0, signal }, st = fs.lstatSync(resolved);
  let asarInfo = null, col = null, outerNative = [], electronFuses = null;

  if (st.isFile()) {
    const low = resolved.toLowerCase();
    if (low.endsWith('.asar')) { asarInfo = parseAsarHeader(resolved); col = collectAsarVirtualFiles(asarInfo, opts); }
    else if (low.endsWith('.exe')) { electronFuses = inspectElectronFuses(resolved); ({ asarInfo, outerNative, col } = scanAppContainer(path.dirname(resolved), opts)); }
    else if (st.size > MAX_FILE) col = { textFiles: [], nativeEntries: [], skippedEntries: [{ path: path.basename(resolved), reason: 'single-file-budget-exceeded', bytes: st.size }], totalTextBytes: 0 };
    else { const b = fs.readFileSync(resolved); col = { textFiles: [{ relativePath: path.basename(resolved), bytes: b.length, sha256: sha256(b), text: b.toString('utf8') }], nativeEntries: [], skippedEntries: [], totalTextBytes: b.length }; }
  } else if (st.isDirectory()) {
    for (const ent of fs.readdirSync(resolved, { withFileTypes: true })) {
      if (ent.isFile() && ent.name.toLowerCase().endsWith('.exe') && !/^unins/i.test(ent.name)) {
        const fc = inspectElectronFuses(path.join(resolved, ent.name));
        if (fc?.sentinelFound) { electronFuses = fc; break; }
        electronFuses ||= fc;
      }
    }
    ({ asarInfo, outerNative, col } = scanAppContainer(resolved, opts));
  } else fail('INVALID_INPUT', `Unsupported file type at ${resolved}`);

  let packageManifest = null;
  const pkgFile = col.textFiles.find((f) => f.relativePath === 'package.json') || col.textFiles.find((f) => f.relativePath.endsWith('/package.json'));
  if (pkgFile) {
    try {
      const p = JSON.parse(pkgFile.text);
      packageManifest = {
        path: pkgFile.relativePath, name: typeof p.name === 'string' ? p.name : null,
        version: typeof p.version === 'string' ? p.version : null, main: typeof p.main === 'string' ? p.main : 'index.js',
        type: typeof p.type === 'string' ? p.type : 'commonjs',
        dependencies: p.dependencies && typeof p.dependencies === 'object' ? Object.keys(p.dependencies).slice(0, 64) : [],
      };
    } catch { packageManifest = { path: pkgFile.relativePath, parseError: true }; }
  }

  const entrypoints = packageManifest?.main ? [{ role: 'main', path: packageManifest.main, source: packageManifest.path }] : [];
  const ipc = [], bounds = [], wins = [], bridges = [], controls = [];
  for (const file of col.textFiles) {
    checkDeadline(opts.deadlineMs, opts.signal);
    const low = file.relativePath.toLowerCase();
    if (low === 'package.json' || low.endsWith('/package.json')) continue;
    if (/\.(?:html|htm)$/i.test(low)) {
      const h = extractHtmlControls(file.relativePath, file.text);
      for (const c of h.controls) if (controls.length < 256) controls.push(c);
      for (const s of h.scripts) if (entrypoints.length < 64) entrypoints.push({ role: 'renderer-script', path: s.src, source: s.file });
      continue;
    }
    const t = analyzeJsFileTopology(file.relativePath, file.text);
    for (const r of t.entryRefs) if (entrypoints.length < 64 && !entrypoints.some((e) => e.role === r.role && e.path === r.target)) entrypoints.push({ role: r.role, path: r.target, source: r.declaredIn });
    for (const c of t.ipcChannels) if (ipc.length < 256) ipc.push(c);
    for (const b of t.boundaries) if (bounds.length < 160) bounds.push(b);
    for (const w of t.windows) if (wins.length < 32) wins.push(w);
    for (const pb of t.preloadBridges) if (bridges.length < 32) bridges.push(pb);
  }

  const natMap = new Map();
  for (const it of [...outerNative, ...col.nativeEntries]) if (!natMap.has(it.absolutePath)) natMap.set(it.absolutePath, it);
  const nativeArtifacts = [...natMap.values()];
  const applicationGraph = {
    entrypoints, ipc_channels: ipc, boundaries: bounds, windows: wins, preload_bridges: bridges, html_controls: controls,
    native_addons: nativeArtifacts.filter((n) => n.relativePath.toLowerCase().endsWith('.node')).map((n) => n.relativePath),
  };

  return {
    schema: 'ig5-js-app-static-report-v2', executionPerformed: false, evidenceSource: BUILTIN_JS_STATIC_SOURCE,
    reaEngine: { provider: 'ig5-builtin-js-static', version: '1.0.0', evidenceSource: BUILTIN_JS_STATIC_SOURCE, externalReaUsed: false },
    targetAppPath: resolved, nativeArtifacts,
    reaAnalysis: {
      evidenceSource: BUILTIN_JS_STATIC_SOURCE, package_manifest: packageManifest,
      asar_archive: asarInfo ? { path: asarInfo.asarPath, bytes: asarInfo.fileSize, dataBaseOffset: asarInfo.dataBaseOffset } : null,
      electron_fuses: electronFuses, application_graph: applicationGraph, entrypoints, ipc_channels: ipc, boundaries: bounds,
      scanned_files_count: col.textFiles.length, scanned_bytes: col.totalTextBytes, skipped_entries: col.skippedEntries.slice(0, 32),
      limitations: [
        'Lexical/regex static topology extraction only; no JavaScript AST evaluation, bundler deobfuscation, or target execution.',
        'Dynamically computed IPC channel names, obfuscated string arrays, or runtime-constructed child_process arguments require dynamic observation via ig5_app_observe.',
      ],
    },
  };
}
