// IG5 worker protocol test driver (小样验证，不进发布文件清单)
// Usage: node scripts/test_worker.mjs [targetExe]
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import fs from 'node:fs';
import assert from 'node:assert/strict';

const here = path.dirname(fileURLToPath(import.meta.url));
const pluginRoot = path.resolve(here, '..');
const WORKER = path.join(pluginRoot, 'worker', 'ig5_worker.py');
const IDA_DIR = process.env.IG5_IDA_DIR || 'C:\\Users\\Administrator\\Desktop\\IDA Professional 9.2';
const PYTHON = process.env.IG5_PYTHON || path.join(IDA_DIR, 'python311', 'python.exe');
const input = process.argv[2] || path.join(pluginRoot, '..', '_research', 'fixtures', 'notepad.exe');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-worker-'));
const TARGET = path.join(scratch, path.basename(input));
fs.copyFileSync(input, TARGET);

const child = spawn(PYTHON, ['-X', 'utf8', WORKER, '--ida-dir', IDA_DIR], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
const exited = new Promise(resolve => child.once('exit', resolve));
let buf = '';
let seq = 0;
const pending = new Map();
const noise = [];

child.stdout.on('data', (d) => {
  buf += d.toString('utf8');
  let idx;
  while ((idx = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    let obj = null;
    try { obj = JSON.parse(line); } catch { noise.push(line.slice(0, 60)); continue; }
    if (obj.ig5 === 'ready') { console.log('[ready] pid=' + obj.pid); run(); continue; }
    if (obj.ig5 === 'progress') continue;
    if (obj.id !== undefined && pending.has(obj.id)) {
      const p = pending.get(obj.id);
      pending.delete(obj.id);
      clearTimeout(p.timer);
      if (obj.error) p.reject(new Error(obj.error));
      else p.resolve(obj.result);
    }
  }
});
child.stderr.on('data', (d) => process.stderr.write('[worker:err] ' + d.toString('utf8')));
child.on('exit', (c) => console.log('[worker exit]', c));

function rpc(method, params, timeoutMs = 120000) {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`rpc timeout: ${method}`));
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
  });
}

async function run() {
  try {
    const doctor = await rpc('doctor', {}, 60000);
    assert.equal(doctor.idalib, 'loaded');
    console.log('[doctor] Reverse runtime loaded');
    const t0 = Date.now();
    const info = await rpc('open', { path: TARGET, auto: true });
    console.log(`[open] ${(Date.now() - t0)}ms n_funcs=${info.n_funcs} bits=${info.bits} proc=${info.proc}`);
    console.log('[segments]', info.segments.map((s) => s.name).join(', '));
    assert.ok(info.n_funcs > 0);
    const funcs = await rpc('funcs', { offset: 0, limit: 30 });
    console.log(`[funcs] total=${funcs.total} first=`, funcs.funcs.map((f) => `${f.ea} ${f.name}(${f.size})`).join(' | '));
    const strs = await rpc('strings', { offset: 0, limit: 6 });
    console.log(`[strings] total=${strs.total} first=`, strs.strings.map((s) => `"${s.text}"`).join(' | '));
    const ea = [...funcs.funcs].sort((a, b) => b.size - a.size)[0].ea;
    const dec = await rpc('decompile', { ea });
    assert.ok(dec.code.length > 0);
    console.log(`[decompile] ${dec.ea} ${dec.name} lines=${dec.lines}`);
    console.log(dec.code.split('\n').slice(0, 12).join('\n'));
    console.log('\n== WORKER PROTOCOL OK ==');
  } catch (e) {
    console.error('[FAIL]', e.message);
    process.exitCode = 1;
  } finally {
    try { await rpc('close', {}, 10000); } finally { child.stdin.end(); }
    await exited;
    assert.deepEqual(fs.readFileSync(TARGET), fs.readFileSync(input));
    assert.equal(path.dirname(path.resolve(scratch)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(scratch).startsWith('ig5-worker-'));
    await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 30, retryDelay: 100 });
  }
}
