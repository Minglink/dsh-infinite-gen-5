// IG5 host-side tool surface smoke test with a mock Cordis ctx (M1-A: background jobs)
// Usage: node scripts/test_host.mjs [targetBinary];  IG5_JOBS=1 forces the job path
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const pluginRoot = path.resolve(here, '..');
const mod = await import(pathToFileURL(path.join(pluginRoot, 'index.js')).href);

const IDA_DIR = process.env.IG5_IDA_DIR || 'C:\\Users\\Administrator\\Desktop\\IDA Professional 9.2';
const input = process.argv[2] || path.join(pluginRoot, '..', '_research', 'fixtures', 'notepad.exe');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-host-'));
const TARGET = path.join(scratch, path.basename(input));
fs.copyFileSync(input, TARGET);
const artifactDir = path.join(scratch, 'artifacts');

const tools = new Map();
const effects = [];
const routes = new Map();

// ── 作业服务 mock：记录 progress / append，并驱动 run() 的 hooks ──
const jobLog = [];
let jobSeq = 0;
const jobs = {
  start(spec) {
    const id = `${spec.kind}-${++jobSeq}`;
    const events = [];
    const handle = {
      id,
      append(text, opts) { events.push({ kind: 'append', channel: opts?.channel ?? null, text: String(text).slice(0, 200) }); },
      updateProgress(line) { events.push({ kind: 'progress', line: String(line) }); },
    };
    let hooks;
    try {
      hooks = spec.run(handle);
    } catch (e) {
      throw e;
    }
    jobLog.push({ id, kind: spec.kind, label: spec.label, owner: spec.owner ?? null, events, hooks });
    Promise.resolve(hooks.done).then((outcome) => { jobLog[jobLog.length - 1].outcome = outcome; });
    return id;
  },
};

const ctx = {
  tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
  listeners: new Map(),
  on(event, fn) {
    if (!ctx.listeners.has(event)) ctx.listeners.set(event, []);
    ctx.listeners.get(event).push(fn);
  },
  get(name) {
    if (name === 'jobs') return process.env.IG5_JOBS === '0' ? undefined : jobs;
    if (name === 'webServer') {
      return {
        register(spec) {
          routes.set(spec.path, spec.handler);
          return () => routes.delete(spec.path);
        },
      };
    }
    return undefined;
  },
  inject(names, cb) {
    if (names.some((name) => !ctx.get(name))) return { dispose() {} };
    // 简化：同步回灌一个满足记录体形态的 scope
    cb({
      webServer: ctx.get('webServer'),
      get: ctx.get,
    });
    return { dispose() {} };
  },
  effect(fn) {
    const disposer = fn();
    effects.push(typeof disposer === 'function' ? disposer : () => {});
  },
};

try {
// This legacy native API smoke specifically asserts Reverse outputs; the
// independent self-contained/catalog checks validate the bundled default.
mod.apply(ctx, { reverseProvider: 'commercial', idaDir: IDA_DIR, defaultEngine: 'reverse', toolset: 'full', artifactDir });
console.log('[registered]', [...tools.keys()].join(', '));
console.log('[routes]', [...routes.keys()].join(', '));

async function call(name, args, exec = {}) {
  const value = await tools.get(name).execute(args, exec);
  const rendered = tools.get(name).output.render(args, value);
  console.log(`\n== ${name} == render blocks: ${rendered.length}, text: ${String(rendered[0].text).slice(0, 160)}`);
  return value;
}

function readRoute(p) {
  return new Promise((resolve) => {
    const chunks = [];
    routes.get(p)({ method: 'GET', url: p, on() {} }, {
      writeHead() {},
      end(body) { chunks.push(body ?? ''); resolve(chunks.join('')); },
    });
  });
}

const doc = await call('ig5_doctor', {});
console.log('  engine:', JSON.stringify(doc.caps ?? {}), doc.idaVersion ?? '');

// 1) 后台作业路径（默认）
const started = await call('ig5_open', { path: TARGET, fresh: true }, { agent: { sessionId: 'session-test' } });
console.log('  ->', JSON.stringify(started));
if (started.kind !== 'background') throw new Error('expected a background job');
const rec = jobLog.find((j) => j.id === started.jobId);
if (!rec) throw new Error('job not registered');
console.log('  job owner =', rec.owner, 'label =', rec.label);
const outcome = await rec.hooks.done;
console.log('  outcome =', JSON.stringify(outcome).slice(0, 200));
const progressLines = rec.events.filter((e) => e.kind === 'progress');
console.log('  progress updates =', progressLines.length, '| first:', progressLines[0]?.line, '| last:', progressLines[progressLines.length - 1]?.line);
if (progressLines.length < 3) throw new Error('expected several progress updates');

// 2) /ig5-jobs 快照（工作台数据源）
const snap = JSON.parse(await readRoute('/ig5-jobs'));
console.log('  snapshot: sessions =', snap.sessions.length, 'jobs =', snap.jobs.length,
  '| job:', JSON.stringify(snap.jobs[0] ?? null).slice(0, 220));

// 3) 同步路径（background:false）
const inline = await call('ig5_open', { path: TARGET, background: false }, {});
console.log('  inline alreadyOpen =', inline.alreadyOpen, 'n_funcs =', inline.n_funcs);

const st = await call('ig5_status', {});
console.log('  sessions =', st.count, 'lastOp =', st.sessions[0]?.lastOp, 'stage =', st.sessions[0]?.lastStage);
const funcs = await call('ig5_funcs', { target: TARGET, limit: 5 });
console.log('  total =', funcs.total, 'first =', funcs.funcs[0]?.name);
const dec = await call('ig5_decompile', { target: TARGET, ea: funcs.funcs[0]?.ea });
console.log('  decompile:', dec.ea, dec.name, 'lines =', dec.lines);

// ── M1-B/C：审批门 + 写工具 + xrefs ──
const preList = ctx.listeners.get('tools/pre-execute') || [];
if (preList.length !== 1) throw new Error('expected exactly one pre-execute listener');
const gate = preList[0];
const next = async () => ({ kind: 'allow' });
async function deniedWithoutApproval(name, args) {
  let dispatched = false;
  const decision = await gate({ name, arguments: args }, async () => { dispatched = true; return { kind: 'allow' }; });
  assert.equal(decision.kind, 'deny', 'Missing agent/approval service must deny ' + name);
  assert.equal(dispatched, false);
  return decision;
}
const denied = await deniedWithoutApproval('ig5_patch_bytes', { ea: '0x140001000', hex: '90' });
console.log('  gate denies unapproved patch =', denied.kind === 'deny', '| reason:', (denied.reason || '').slice(0, 60));
const passed = await gate({ name: 'ig5_funcs', arguments: {} }, next);
assert.equal(passed.kind, 'allow');
console.log('  gate delegates reads =', passed.kind === 'allow');

const f0 = (await call('ig5_funcs', { target: TARGET, limit: 1 })).funcs[0];
const x = await call('ig5_xrefs', { target: TARGET, ea: f0.ea, limit: 5 });
console.log('  xrefs total =', x.total, 'first =', JSON.stringify(x.hits?.[0] ?? null).slice(0, 120));

const rn = await call('ig5_rename', { target: TARGET, ea: f0.ea, new_name: 'ig5_test_fn' });
console.log('  rename ok =', rn.ok, rn.old, '->', rn.new);
const cm = await call('ig5_comment', { target: TARGET, name: 'ig5_test_fn', text: 'IG5 审批门测试注释' });
console.log('  comment ok =', cm.ok);
const pt = await call('ig5_patch_bytes', { target: TARGET, ea: rn.ea, hex: '90 90' });
console.log('  patch before=', pt.before, 'after=', pt.after, 'applied =', pt.applied, 'fileOffset =', pt.fileOffset);
// mock 直调绕过注册表派发 → 手动驱动 post-execute 留痕（真实环境由 registry 自动触发）
const postListEarly = ctx.listeners.get('tools/post-execute') || [];
await postListEarly[0](
  { name: 'ig5_patch_bytes', arguments: { target: TARGET, ea: rn.ea, hex: '90 90' } },
  { isError: false, value: pt },
  async () => ({ kind: 'accept' }),
);

// ── M1-D：调用图 + 分析控制 + 类型 + decompile llm 微调 ──
const gatedAnalyze = await deniedWithoutApproval('ig5_analyze', { action: 'undefine', ea: f0.ea });
console.log('  gate denies unapproved analyze =', gatedAnalyze.kind === 'deny');
const gatedType = await deniedWithoutApproval('ig5_set_type', { decl: 'int f(void)' });
console.log('  gate denies unapproved set_type =', gatedType.kind === 'deny');

const cl = await call('ig5_calls', { target: TARGET, name: 'ig5_test_fn', direction: 'callees' });
console.log('  calls(callees) total =', cl.total);
const an = await call('ig5_analyze', { target: TARGET, action: 'mark_code', ea: f0.ea, size: 64 });
console.log('  analyze mark_code ok =', an.ok);
const st2 = await call('ig5_set_type', { target: TARGET, name: 'ig5_test_fn', decl: 'int ig5_test_fn(int a);' });
console.log('  set_type ok =', st2.ok, 'type =', st2.type);
const decl = await call('ig5_decompile', { target: TARGET, name: 'ig5_test_fn', style: 'llm' });
console.log('  decompile llm: callees =', JSON.stringify(decl.meta?.callees ?? null), 'strings =', (decl.meta?.strings || []).length);

// ── M2/M3：搜索 / 枚举 / 字节 / 撤销 / 情报 / 逃生舱 / diff 导出 / 调试车道 ──
const gatedPy = await deniedWithoutApproval('ig5_run_idapython', { code: 'print(1)' });
const gatedUndo = await deniedWithoutApproval('ig5_undo', {});
const gatedDbg = await deniedWithoutApproval('ig5_dbg', { op: 'start' });
console.log('  gate denies unapproved idapython/undo/dbg =', gatedPy.kind === 'deny', gatedUndo.kind === 'deny', gatedDbg.kind === 'deny');

const sr = await call('ig5_search', { target: TARGET, pattern: '90 90', limit: 5 });
console.log('  search 90 90 total =', sr.total, 'hits =', JSON.stringify(sr.hits));
const by = await call('ig5_bytes', { target: TARGET, ea: rn.ea, size: 4 });
console.log('  bytes @patched =', by.hex);
const seg = await call('ig5_listing', { target: TARGET, kind: 'segments', limit: 5 });
console.log('  segments total =', seg.total, 'first =', seg.items[0]?.name);
const imps = await call('ig5_listing', { target: TARGET, kind: 'imports', limit: 5 });
console.log('  imports total =', imps.total, 'first =', imps.items[0]?.name);
const exps = await call('ig5_listing', { target: TARGET, kind: 'exports', limit: 3 });
assert(exps.items.every(row => row.ea !== '0xffffffffffffffff' && row.name), 'entry ordinals must resolve to named native addresses');
console.log('  exports total =', exps.total);
const scan = await call('ig5_scan', { target: TARGET });
console.log('  scan: crypto =', JSON.stringify(scan.crypto), 'entropy segs =', scan.entropy?.length, 'strings =', JSON.stringify(scan.stringFamilies));
const py = await call('ig5_run_idapython', { target: TARGET, code: "import idautils\nprint('funcs=', len(list(idautils.Functions())))" });
console.log('  idapython ok =', py.ok, 'output =', (py.output || '').trim());
const dbgLoad = await call('ig5_dbg', { target: TARGET, op: 'load' });
console.log('  dbg load =', JSON.stringify(dbgLoad));
const diff = await call('ig5_export_diff', { target: TARGET });
console.log('  export_diff patches =', diff.patches, 'binary =', diff.patchedBinary ? 'written' : diff.note);
const jl = await call('ig5_undo', { target: TARGET, action: 'list' });
console.log('  journal entries =', jl.journal?.length, 'top =', JSON.stringify(jl.journal?.[0] ?? null).slice(0, 120));
const undo = await call('ig5_undo', { target: TARGET });
console.log('  undo ok =', undo.ok, 'kind =', undo.kind);
let undone = undo;
for (let i = 0; i < 6 && undone.kind !== 'bytes'; i++) {
  undone = await call('ig5_undo', { target: TARGET });
}
console.log('  rolled back to kind =', undone.kind, 'restored =', undone.restored);
const by2 = await call('ig5_bytes', { target: TARGET, ea: rn.ea, size: 4 });
console.log('  bytes after undo =', by2.hex, '(应还原为补丁前 4c8bdc..)');
const auditFile = path.join(artifactDir, 'approvals.jsonl');
// mock 直调 execute 绕过了注册表派发，这里直接驱动 post-execute 监听器验证留痕
const postList = ctx.listeners.get('tools/post-execute') || [];
if (postList.length !== 1) throw new Error('expected exactly one post-execute listener');
const postDecision = await postList[0](
  { name: 'ig5_patch_bytes', arguments: { target: TARGET, ea: rn.ea, hex: '90 90' } },
  { isError: false, value: pt },
  async () => ({ kind: 'accept' }),
);
console.log('  audit log exists =', fs.existsSync(auditFile), '| decision =', postDecision.kind);

await call('ig5_close', { target: TARGET });

console.log('\n== HOST SURFACE + BACKGROUND JOBS OK ==');
assert.deepEqual(fs.readFileSync(TARGET), fs.readFileSync(input));
} finally {
  for (const d of effects.reverse()) await d();
  assert.equal(path.dirname(path.resolve(scratch)), path.resolve(os.tmpdir()));
  assert.ok(path.basename(scratch).startsWith('ig5-host-'));
  await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 30, retryDelay: 100 });
}
