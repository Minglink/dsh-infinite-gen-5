// Live test: worker progress notifications during auto-analysis.
// usage: node scripts/test_progress.mjs <targetBinary>
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import path from 'node:path';
import fs from 'node:fs';

const WORKSPACE = path.resolve(import.meta.dirname, '..');
const IDA_DIR = process.env.IG5_IDA_DIR || 'C:\\Users\\Administrator\\Desktop\\IDA Professional 9.2';
const target = process.argv[2];
if (!target) {
  console.error('usage: node scripts/test_progress.mjs <targetBinary>');
  process.exit(2);
}
const py = path.join(IDA_DIR, 'python311', 'python.exe');
const worker = path.join(WORKSPACE, 'worker', 'ig5_worker.py');
if (!fs.existsSync(py)) throw new Error(`python not found: ${py}`);

const t0 = Date.now();
const child = spawn(py, ['-u', worker, '--ida-dir', IDA_DIR], { stdio: ['pipe', 'pipe', 'pipe'] });
let progressCount = 0;
let firstAt = 0;
const rl = createInterface({ input: child.stdout });
rl.on('line', (line) => {
  const at = ((Date.now() - t0) / 1000).toFixed(1);
  if (line.startsWith('{"ig5": "ready"') || line.startsWith('{"ig5":"ready"')) {
    console.log(`[${at}s] ready -> sending open`);
    child.stdin.write(JSON.stringify({ id: 1, method: 'open', params: { path: target, auto: true, progress: true } }) + '\n');
    return;
  }
  let msg;
  try { msg = JSON.parse(line); } catch { console.log(`[${at}s] (noise) ${line.slice(0, 120)}`); return; }
  if (msg.ig5 === 'progress') {
    progressCount += 1;
    if (!firstAt) firstAt = Number(at);
    const p = msg.payload;
    console.log(`[${at}s] PROGRESS #${progressCount} stage=${p.stage} pct=${p.pct}% funcs=${p.functions ?? '-'} seg=${p.segment ?? '-'} bytes=${p.bytes ?? '-'}/${p.totalBytes ?? '-'} ${p.detail ?? ''}`);
    return;
  }
  if (msg.id === 1) {
    if (msg.error) {
      console.log(`[${at}s] OPEN FAILED:\n${String(msg.error).split('\n').slice(-6).join('\n')}`);
    } else {
      const r = msg.result;
      console.log(`[${at}s] OPEN OK: funcs=${r.n_funcs} segments=${r.segments.length} bits=${r.bits} proc=${r.proc} elapsed=${r.elapsedMs}ms`);
    }
    console.log(`\nsummary: ${progressCount} progress notifications, first at ${firstAt}s, done at ${at}s`);
    child.kill();
    process.exit(msg.error ? 1 : 0);
  }
});
child.stderr.on('data', (d) => {
  const s = String(d).trim();
  if (s) console.log(`[stderr] ${s.slice(0, 400)}`);
});
setTimeout(() => { console.log('TIMEOUT (10 min)'); child.kill(); process.exit(3); }, 600_000);
