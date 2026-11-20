/**
 * Pre-registered M2 Phase-2 Real Native & Host Control Verification Suite (Pre-Orchestrated Tier).
 *
 * Kept strictly separate from default offline `tools/ci/gate.json` and scored separately from online
 * unscripted LLM sessions. Exercises real bundled Ghidra + real headless x64dbg + actual installed
 * DSH 0.2.2+ host packages (ToolsService, NativeToolExecutor, SessionStore, AgentRegistry, GoalPlugin,
 * ToolGoal) + IG5 plugin + m2_suite_guard over benign self-produced PE64 fixtures:
 *   - Control 1A: `ig5_dbg` `readmem` with `ea + address_space="rva"` produces persistent receipt accepted
 *                 by `assessRootInvestigation`, while bare runtime `ea` without `rva`/`address_space` is rejected.
 *   - Control 1B: Brand-new cold Ghidra worker process whose VERY FIRST shared-module operation after
 *                 `ig5_open` is `ig5_emulate` succeeds without `ModuleNotFoundError: cpu_emulator`.
 *   - Control 1C: Real DSH `ToolGoal` + `m2_suite_guard` `terminalControlReserve` at `ordinaryCallLimit`:
 *                 (i) `partial`/uncleaned investigation is denied by IG5 completion gate and can still `pause`;
 *                 (ii) repeated `get_goal` cannot consume final commit slot, invalid `paused` does not burn slot,
 *                      and natively verified `satisfied` + `cleanup="confirmed"` investigation completes host Goal.
 *   - Control 1D: Real native PE64 trigger-completeness probe suite (`evaluateTriggerCompleteness` with
 *                 `defaultNativeTriggerProbe`) passes true trigger spec and rejects missing CWD / superfluous flag.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { builtinModules } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as ig5Plugin from '../../index.js';
import * as m2Guard from './m2_suite_guard.mjs';
import { buildCliTransformPE64, computeExpectedCliTransformHex } from '../fixtures/pe64-cli-transform.mjs';
import { computeSourceTreeIdentity } from '../lib/source_tree_identity.mjs';
import { collectNativeProcessCheck, evaluateTriggerCompleteness } from './run_m2_blind_eval.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..');

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// Isolated child mode for Control 1B: brand-new cold Ghidra worker where ig5_emulate is the first shared-module call!
if (process.argv.includes('--child-cold-ghidra-emulate')) {
  const tmpChild = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-cold-emulate-child-'));
  const ig5HomeChild = path.join(tmpChild, 'ig5-home');
  const wsChild = path.join(tmpChild, 'workspace');
  fs.mkdirSync(ig5HomeChild, { recursive: true });
  fs.mkdirSync(wsChild, { recursive: true });
  process.env.IG5_HOME = ig5HomeChild;

  const pe = buildCliTransformPE64();
  const exePath = path.join(wsChild, 'cold_emulate_target.exe');
  fs.writeFileSync(exePath, pe.image);

  const tools = new Map();
  const preHooks = [];
  const effects = [];
  const ctx = {
    tools: { register: (d) => { tools.set(d.name, d); return () => tools.delete(d.name); } },
    on: (ev, fn) => { if (ev === 'tools/pre-execute') preHooks.push(fn); return () => {}; },
    get: (n) => (n === 'approval' ? { request: async () => 'allowed-once' } : undefined),
    inject: () => ({ dispose() {} }),
    effect: (fn) => { const d = fn(); if (typeof d === 'function') effects.push(d); return d; },
  };
  await ig5Plugin.apply(ctx, {
    projectRoot: path.join(ig5HomeChild, 'projects'),
    artifactDir: path.join(ig5HomeChild, 'artifacts'),
    stateRoot: path.join(ig5HomeChild, 'state'),
    backgroundOpen: false,
    toolset: 'full',
  });
  const agent = { id: 'cold-emulate-agent', session: { id: 'cold-emulate-agent', header: { id: 'cold-emulate-agent', cwd: wsChild } } };
  const callTool = async (name, args) => {
    const def = tools.get(name);
    const exec = { name, arguments: args, agent, callId: `ce-${randomUUID()}`, signal: new AbortController().signal };
    for (const h of preHooks) {
      const dec = await h(exec, async () => ({ kind: 'allow' }));
      if (dec && dec.kind !== 'allow') throw new Error(`Denied ${name}: ${JSON.stringify(dec)}`);
    }
    return def.execute(args, exec);
  };

  try {
    const opened = await callTool('ig5_open', { path: exePath, background: false, engine: 'ghidra' });
    // VERY FIRST shared-module operation in this fresh Ghidra worker process is ig5_emulate!
    const emu = await callTool('ig5_emulate', {
      target: exePath,
      engine: 'ghidra',
      ea: pe.transformVa,
      abi: 'win64',
      args: ['0x140003300', pe.outBufVa],
      memory: [{ ea: '0x140003300', hex: '41424344' }],
      capture: [{ ea: pe.outBufVa, size: 4 }],
    });
    await callTool('ig5_close', { target: exePath, engine: 'ghidra' });
    for (const d of effects.reverse()) { try { await d(); } catch { /* ignore */ } }
    process.stdout.write(JSON.stringify({ ok: true, openedSha256: opened.sha256, emulateResult: emu }) + '\n');
  } finally {
    try { fs.rmSync(tmpChild, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  process.exit(0);
}

// Build a small PE64 binary with both CWD suffix `\ctrl_stage` AND flag `--mode=check` + `K=<4B>` exiting 0 on match, 1 on fail
function buildTriggerProbePE64() {
  const image = Buffer.alloc(0x1e00, 0);
  const base = 0x140000000n;
  const optional = 0x98;
  const u16 = (off, v) => image.writeUInt16LE(v, off);
  const u32 = (off, v) => image.writeUInt32LE(v >>> 0, off);
  const u64 = (off, v) => image.writeBigUInt64LE(BigInt(v), off);
  const raw = (rva) => (rva < 0x2000 ? 0x400 + rva - 0x1000 : rva < 0x3000 ? 0x800 + rva - 0x2000 : 0xe00 + rva - 0x3000);
  const text = (off, v) => image.write(v, off, 'ascii');

  text(0, 'MZ'); u32(0x3c, 0x80); text(0x80, 'PE\0\0');
  u16(0x84, 0x8664); u16(0x86, 3); u16(0x94, 0xf0); u16(0x96, 0x22);
  u16(optional, 0x20b); image[optional + 2] = 14;
  u32(optional + 4, 0x400); u32(optional + 8, 0x1600);
  u32(optional + 16, 0x1000); u32(optional + 20, 0x1000); u64(optional + 24, base);
  u32(optional + 32, 0x1000); u32(optional + 36, 0x200);
  u16(optional + 40, 6); u16(optional + 48, 6);
  u32(optional + 56, 0x4000); u32(optional + 60, 0x400);
  u16(optional + 68, 3); u16(optional + 70, 0x100);
  u64(optional + 72, 0x100000); u64(optional + 80, 0x1000);
  u64(optional + 88, 0x100000); u64(optional + 96, 0x1000);
  u32(optional + 108, 16);
  u32(optional + 120, 0x2200); u32(optional + 124, 0x28);

  for (const [idx, name, rva, offset, size, flags] of [
    [0, '.text', 0x1000, 0x400, 0x400, 0x60000020],
    [1, '.rdata', 0x2000, 0x800, 0x600, 0x40000040],
    [2, '.data', 0x3000, 0xe00, 0x1000, 0xc0000040],
  ]) {
    const hdr = optional + 0xf0 + idx * 40;
    text(hdr, name); u32(hdr + 8, size); u32(hdr + 12, rva);
    u32(hdr + 16, size); u32(hdr + 20, offset); u32(hdr + 36, flags);
  }

  const imports = [
    ['GetCommandLineA', 0x2320, 0x2400],
    ['GetCurrentDirectoryA', 0x2340, 0x2408],
    ['ExitProcess', 0x2370, 0x2410],
  ];
  u32(raw(0x2200), 0x22c0); u32(raw(0x2200) + 12, 0x2260); u32(raw(0x2200) + 16, 0x2400);
  text(raw(0x2260), 'KERNEL32.dll\0');
  imports.forEach(([fnName, nameRva], idx) => {
    u64(raw(0x22c0) + idx * 8, nameRva);
    u64(raw(0x2400) + idx * 8, nameRva);
    u16(raw(nameRva), 0);
    text(raw(nameRva) + 2, fnName + '\0');
  });

  text(raw(0x2100), '\\ctrl_stage\0');  // len 11
  text(raw(0x2120), ' --mode=check ');  // len 14 (requires token boundary spaces!)
  text(raw(0x2140), ' K=');             // len 3

  function assembleAt(startRva, buildFn) {
    const chunks = [];
    const labels = new Map();
    const fixups = [];
    let pc = startRva;
    const emitHex = (h) => { const b = Buffer.from(h, 'hex'); chunks.push(b); pc += b.length; };
    const label = (n) => labels.set(n, pc);
    const emitRel32 = (prefixHex, target) => {
      const p = Buffer.from(prefixHex, 'hex');
      const patchOffset = pc - startRva + p.length;
      const nextPc = pc + p.length + 4;
      chunks.push(p, Buffer.alloc(4));
      fixups.push({ patchOffset, nextPc, target });
      pc = nextPc;
    };
    buildFn({ emitHex, label, emitRel32 });
    const code = Buffer.concat(chunks);
    for (const f of fixups) {
      const tRva = typeof f.target === 'number' ? f.target : labels.get(f.target);
      code.writeInt32LE(tRva - f.nextPc, f.patchOffset);
    }
    code.copy(image, raw(startRva));
  }

  // find_substr at 0x1200, mem_eq_n at 0x1260
  assembleAt(0x1200, (a) => {
    a.label('outer');
    a.emitHex('803900'); a.emitRel32('0f84', 'nf');
    a.emitHex('4531c9');
    a.label('inner');
    a.emitHex('4539c1'); a.emitRel32('0f83', 'ok');
    a.emitHex('420fb60409'); a.emitHex('460fb6140a'); a.emitHex('4439d0'); a.emitRel32('0f85', 'nx');
    a.emitHex('41ffc1'); a.emitRel32('e9', 'inner');
    a.label('nx'); a.emitHex('48ffc1'); a.emitRel32('e9', 'outer');
    a.label('ok'); a.emitHex('4a8d0401'); a.emitHex('c3');
    a.label('nf'); a.emitHex('31c0'); a.emitHex('c3');
  });
  assembleAt(0x1260, (a) => {
    a.emitHex('4531c9');
    a.label('lp');
    a.emitHex('4539c1'); a.emitRel32('0f83', 'eq');
    a.emitHex('420fb60409'); a.emitHex('460fb6140a'); a.emitHex('4439d0'); a.emitRel32('0f85', 'ne');
    a.emitHex('41ffc1'); a.emitRel32('e9', 'lp');
    a.label('eq'); a.emitHex('b801000000'); a.emitHex('c3');
    a.label('ne'); a.emitHex('31c0'); a.emitHex('c3');
  });

  // Entry at 0x1000:
  // 1) GetCurrentDirectoryA -> check len >= 11 and trailing 11 bytes == "\ctrl_stage"
  // 2) GetCommandLineA -> check " --mode=check " present AND " K=" followed by >= 4 non-space non-NUL bytes AND no extra args after K=XXXX!
  assembleAt(0x1000, (a) => {
    a.emitHex('4883ec38');
    a.emitHex('b904010000');
    a.emitRel32('488d15', 0x3200);
    a.emitRel32('ff15', 0x2408);                // GetCurrentDirectoryA(260, cwdBuf)
    a.emitHex('83f80b');                        // cmp eax, 11
    a.emitRel32('0f82', 'fail');
    a.emitHex('89c0');
    a.emitRel32('488d0d', 0x3200);
    a.emitHex('4801c1');
    a.emitHex('4883e90b');                      // rcx = cwdBuf + len - 11
    a.emitRel32('488d15', 0x2100);              // rdx = "\ctrl_stage"
    a.emitHex('41b80b000000');                  // r8d = 11
    a.emitRel32('e8', 0x1260);
    a.emitHex('85c0');
    a.emitRel32('0f84', 'fail');

    a.emitRel32('ff15', 0x2400);                // GetCommandLineA()
    a.emitHex('4889c3');                        // rbx = cmdLine
    // Check " --mode=check "
    a.emitHex('4889d9');
    a.emitRel32('488d15', 0x2120);
    a.emitHex('41b80e000000');                  // len 14
    a.emitRel32('e8', 0x1200);
    a.emitHex('4885c0');
    a.emitRel32('0f84', 'fail');
    // Immediately at rax (right after " --mode=check "), expect 'K='! (rejects extra flags between or before!)
    a.emitHex('6681384b3d');                    // cmp word ptr [rax], 'K=' (0x3d4b)
    a.emitRel32('0f85', 'fail');
    a.emitHex('4883c002');                      // rax += 2 -> 4-byte payload
    a.emitHex('803800'); a.emitRel32('0f84', 'fail');
    a.emitHex('803820'); a.emitRel32('0f84', 'fail');
    a.emitHex('80780100'); a.emitRel32('0f84', 'fail');
    a.emitHex('80780120'); a.emitRel32('0f84', 'fail');
    a.emitHex('80780200'); a.emitRel32('0f84', 'fail');
    a.emitHex('80780220'); a.emitRel32('0f84', 'fail');
    a.emitHex('80780300'); a.emitRel32('0f84', 'fail');
    a.emitHex('80780320'); a.emitRel32('0f84', 'fail');
    // Byte 4 must be NUL (exact 4B arg at end of command line)
    a.emitHex('80780400'); a.emitRel32('0f85', 'fail');

    a.emitHex('31c9');
    a.emitRel32('ff15', 0x2410);                // ExitProcess(0)
    a.label('fail');
    a.emitHex('b901000000');
    a.emitRel32('ff15', 0x2410);                // ExitProcess(1)
  });

  return image;
}

const evIdx = process.argv.indexOf('--evidence-dir');
const evidenceDir = evIdx >= 0 && process.argv[evIdx + 1]
  ? path.resolve(process.argv[evIdx + 1])
  : path.join(os.tmpdir(), `ig5-m2-native-controls-${randomUUID()}`);
fs.mkdirSync(evidenceDir, { recursive: true });

const asarPath = process.env.DSH_ASAR || path.join(
  process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'),
  'Programs', 'DeepSeek Harness', 'resources', 'app.asar',
);
assert(fs.existsSync(asarPath), `Installed DSH app.asar required at ${asarPath}`);

const tempRoot = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-m2-ctrl-native-'));
const sdkDir = path.join(tempRoot, 'sdk');
const workspaceDir = path.join(tempRoot, 'workspace');
const ig5Home = path.join(tempRoot, 'ig5-home');
fs.mkdirSync(workspaceDir, { recursive: true });
fs.mkdirSync(ig5Home, { recursive: true });
process.env.IG5_HOME = ig5Home;

const fd = fs.openSync(asarPath, 'r');
const hdr16 = Buffer.alloc(16);
fs.readSync(fd, hdr16, 0, 16, 0);
const headerSize = hdr16.readUInt32LE(4);
const jsonSize = hdr16.readUInt32LE(12);
const headerBuf = Buffer.alloc(jsonSize);
fs.readSync(fd, headerBuf, 0, jsonSize, 16);
const manifest = JSON.parse(headerBuf.toString('utf8'));
const entry = (p) => p.split('/').reduce((n, k) => n?.files?.[k], manifest);
const natives = new Set(builtinModules.flatMap((n) => [n, `node:${n}`]));
const copied = new Set();

function readAsarFile(p) {
  const info = entry(p);
  assert(info && !info.files && !info.unpacked, `Missing ASAR file: ${p}`);
  const buf = Buffer.alloc(info.size);
  fs.readSync(fd, buf, 0, buf.length, 8 + headerSize + Number(info.offset));
  return buf;
}

function copyPackage(pkgName) {
  if (copied.has(pkgName) || natives.has(pkgName) || pkgName.startsWith('node:')) return;
  copied.add(pkgName);
  const srcPrefix = `dsh/node_modules/${pkgName}`;
  const rootNode = entry(srcPrefix);
  assert(rootNode?.files, `DSH package absent: ${pkgName}`);
  const deps = new Set();
  function walk(node, rel = '') {
    for (const [part, info] of Object.entries(node.files || {})) {
      const f = rel + part;
      if (info.files) walk(info, `${f}/`);
      else if (/\.(?:js|mjs|cjs|json)$/.test(f)) {
        const bytes = readAsarFile(`${srcPrefix}/${f}`);
        const dest = path.join(sdkDir, 'node_modules', pkgName, f);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, bytes);
        if (/\.(?:js|mjs|cjs)$/.test(f)) {
          for (const m of bytes.toString('utf8').matchAll(/(?:^|\n)\s*(?:import|export)[^;\n]*?\bfrom\s*["']([^"']+)["']|(?:^|\n)\s*import\s*["']([^"']+)["']|\brequire\(["']([^"']+)["']\)/g)) {
            const spec = m[1] || m[2] || m[3];
            if (!spec.startsWith('.') && !spec.startsWith('/') && !natives.has(spec) && !spec.startsWith('node:')) {
              deps.add(spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]);
            }
          }
        }
      }
    }
  }
  walk(rootNode);
  for (const dep of deps) copyPackage(dep);
}

const dshPackages = [
  '@deepseek-ai/cordis',
  '@deepseek-ai/dsh-scope',
  '@deepseek-ai/dsh-system-prompt',
  '@deepseek-ai/dsh-tools',
  '@deepseek-ai/dsh-tool-executor-native',
  '@deepseek-ai/dsh-session',
  '@deepseek-ai/dsh-session-projection',
  '@deepseek-ai/dsh-agent',
  '@deepseek-ai/dsh-goal',
  '@deepseek-ai/dsh-tool-goal',
  '@deepseek-ai/dsh-llm',
];
const appPkg = JSON.parse(readAsarFile('package.json').toString('utf8'));
try {
  for (const p of dshPackages) copyPackage(p);
} finally {
  fs.closeSync(fd);
}

const loadPkg = (pkgName) => {
  const pkgRoot = path.join(sdkDir, 'node_modules', pkgName);
  const meta = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
  const mainRel = meta.exports?.['.']?.import || meta.exports?.['.']?.default || meta.module || meta.main || 'lib/index.js';
  return import(pathToFileURL(path.join(pkgRoot, typeof mainRel === 'string' ? mainRel : 'lib/index.js')).href);
};

const [
  { Context, Service },
  { createScope },
  { default: SystemPrompt },
  { default: ToolsService },
  nativeExecMod,
  { SessionStore },
  { default: SessionProjections },
  { default: AgentRegistry },
  goalMod,
  toolGoalMod,
  { createUserMessage },
] = await Promise.all(dshPackages.map(loadPkg));
const GoalPlugin = goalMod.default || goalMod;

const srcId = computeSourceTreeIdentity(repoRoot);
const peFixture = buildCliTransformPE64();
const sampleExe = path.join(workspaceDir, 'cli_transform_m2_ctrl.exe');
fs.writeFileSync(sampleExe, peFixture.image);
const sampleExeSha256 = sha256(peFixture.image);

const executableTransformRule = {
  schema: 'ig5-bounded-byte-rule-v1',
  inputLength: 4,
  outputLength: 4,
  constants: { K: '5aa533cc' },
  byteExpr: {
    op: 'add',
    args: [
      { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, { op: 'const', name: 'K', index: { op: 'i' } }] },
      { op: 'add', args: [{ op: 'mul', args: [{ op: 'i' }, 7] }, 3] },
    ],
  },
};

const report = {
  schema: 'ig5-m2-phase2-native-host-controls-v1',
  executedAt: new Date().toISOString(),
  scoringCategory: 'pre-orchestrated-native-and-host-control-verification',
  notCountedAsUnscriptedBlindModelSolve: true,
  sourceIdentity: {
    repoRoot,
    packageVersion: JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')).version,
    sourceTreeDigest: srcId.treeDigest,
    sourceTreeFileCount: srcId.fileCount,
  },
  host: { asarPath, desktopVersion: appPkg.version },
  controls: {},
};

let ctx;
try {
  // === CONTROL 1B FIRST: Fresh cold Ghidra worker process where ig5_emulate is the first shared-module operation ===
  console.log('[Control 1B] Spawning fresh cold Ghidra worker with ig5_emulate as first shared-module operation...');
  const coldStdout = execFileSync(process.execPath, [
    fileURLToPath(import.meta.url),
    '--child-cold-ghidra-emulate',
  ], {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 240_000,
    windowsHide: true,
  });
  const coldLine = coldStdout.trim().split(/\r?\n/).filter(Boolean).at(-1);
  const coldParsed = JSON.parse(coldLine);
  assert.equal(coldParsed.ok, true);
  assert.equal(coldParsed.openedSha256, sampleExeSha256);
  const expectedAbcdHex = computeExpectedCliTransformHex(Buffer.from('ABCD', 'ascii'));
  const capturedBuf = (coldParsed.emulateResult?.captured || coldParsed.emulateResult?.memory || [])[0];
  const capturedHex = String(capturedBuf?.hex || capturedBuf?.bytes || '').toLowerCase();
  assert.equal(capturedHex, expectedAbcdHex, `Cold Ghidra emulate captured hex mismatch: ${JSON.stringify(coldParsed.emulateResult)}`);
  report.controls.control1B_ghidraColdEmulate = {
    passed: true,
    freshChildProcess: true,
    firstSharedOperation: 'ig5_emulate',
    expectedHex: expectedAbcdHex,
    capturedHex,
    rawEmulateResult: coldParsed.emulateResult,
  };
  fs.mkdirSync(path.join(evidenceDir, 'raw-artifacts'), { recursive: true });
  fs.writeFileSync(path.join(evidenceDir, 'raw-artifacts', 'cold-ghidra-emulate.json'), JSON.stringify(coldParsed, null, 2), 'utf8');
  console.log('PASS [Control 1B] Fresh cold Ghidra worker executed ig5_emulate on first call ->', capturedHex);

  // === Mount real DSH 0.2.2-rc.1 host stack + IG5 plugin for Controls 1A & 1C ===
  ctx = new Context();
  class AutoApproval extends Service {
    constructor(c) { super(c, 'approval', true); }
    async request() { return 'allowed-once'; }
  }
  await ctx.plugin(AutoApproval);
  await ctx.plugin(SystemPrompt, {});
  await ctx.plugin(ToolsService);
  await ctx.plugin(nativeExecMod);
  await ctx.plugin(SessionProjections);
  await ctx.plugin(SessionStore);
  await ctx.plugin(AgentRegistry);
  await ctx.plugin(GoalPlugin, {});
  await ctx.plugin(toolGoalMod, { blockedAfterConsecutiveRounds: 3 });

  let innerCtx;
  await ctx.plugin(Object.assign((inner) => { innerCtx = inner; }, { inject: ['tools', 'systemPrompt', 'goals', 'agents', 'sessions'] }));
  await ctx.plugin(ig5Plugin, {
    artifactDir: path.join(ig5Home, 'artifacts'),
    projectRoot: path.join(ig5Home, 'projects'),
    stateRoot: path.join(ig5Home, 'state'),
    toolset: 'full',
    backgroundOpen: false,
  });

  const makeLiveAgent = async (sessionId) => {
    const sess = innerCtx.sessions.create(sessionId, { meta: { cwd: workspaceDir } });
    const agent = { id: sess.id, session: sess, status: 'idle', cancel() {} };
    agent.ctx = createScope(innerCtx, agent).ctx;
    await innerCtx.agents.register(agent);
    ctx.emit('agent/created', { agent });
    return agent;
  };

  let callCounter = 0;
  const execRaw = async (agent, name, args = {}) => {
    const batch = await innerCtx.tools.execute({
      calls: [{ id: `ctrl-call-${++callCounter}`, name, arguments: JSON.stringify(args) }],
      agent,
      signal: new AbortController().signal,
    });
    return batch.results[0].result;
  };
  const execOk = async (agent, name, args = {}) => {
    const res = await execRaw(agent, name, args);
    assert.equal(res.isError, false, `Expected ${name} to succeed, got: ${res.content?.[0]?.text}`);
    return JSON.parse(res.content[0].text);
  };
  const runInTurn = async (agent, turnNo, source, fn) => {
    agent.status = 'running';
    agent.session.append('turn/start', { turn: turnNo });
    agent.session.append('user/message', createUserMessage({ content: [{ type: 'text', text: `turn-${turnNo}` }], source }), { surfaceOp: 'append' });
    try {
      return await innerCtx.agents.runWithInitiator(agent, fn);
    } finally {
      agent.session.append('turn/end', { turn: turnNo, reason: { kind: 'completed' } });
      agent.status = 'idle';
    }
  };

  // Verify DSH ToolGoal update_goal schema matches M2_TERMINAL_GOAL_ACTIONS!
  const updateGoalSchema = innerCtx.tools.schemas().find((s) => s.name === 'update_goal');
  assert(updateGoalSchema, 'Real DSH update_goal schema must be registered');
  const hostUpdateActions = updateGoalSchema.parameters.properties.action.enum;
  assert.deepEqual(hostUpdateActions, ['edit', 'pause', 'resume', 'complete', 'blocked']);
  for (const act of m2Guard.M2_TERMINAL_GOAL_ACTIONS) {
    assert(hostUpdateActions.includes(act), `Guard terminal action "${act}" must exist in real DSH ToolGoal schema`);
  }

  // === CONTROL 1A: Native x64dbg `ea + address_space="rva"` receipt -> satisfied, bare `ea` -> rejected ===
  console.log('[Control 1A] Running real headless x64dbg with ea + address_space="rva" receipt...');
  const agentSat = await makeLiveAgent('ctrl1a-satisfied-agent');
  const goalSat = innerCtx.goals.create(agentSat, { objective: 'Verify address_space=rva receipt and terminal completion' });
  const invSat = (await execOk(agentSat, 'ig5_workspace', {
    workspace: {
      action: 'root-create',
      root: {
        deliverables: [{
          id: 'deliv-rva-alias',
          kind: 'io-transform',
          description: 'Recover 4B transform via ea + address_space="rva" receipts',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation'],
          minDistinctInputs: 2,
          holdoutRequired: true,
        }],
      },
    },
  })).workspace;

  const discHex = Buffer.from('ABCD', 'ascii').toString('hex');
  const holdHex = Buffer.from('1234', 'ascii').toString('hex');
  await execOk(agentSat, 'ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: invSat.rootId,
      root: {
        component: { componentId: 'comp-1a', path: sampleExe, role: 'main-pe' },
        scenarios: [
          {
            scenarioId: 'sc-disc',
            componentId: 'comp-1a',
            args: ['mode=run', 'X=ABCD'],
            cwd: workspaceDir,
            inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', summary: 'X=ABCD', sampleHex: discHex, caseId: 'disc', isHoldout: false },
          },
          {
            scenarioId: 'sc-hold',
            componentId: 'comp-1a',
            args: ['mode=verify', 'X=1234'],
            cwd: workspaceDir,
            inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', summary: 'X=1234', sampleHex: holdHex, caseId: 'hold', isHoldout: true },
          },
        ],
      },
    },
  });

  await execOk(agentSat, 'ig5_open', { path: sampleExe, background: false, research: { id: invSat.rootId, key: 'c1a-open' } });
  const decomp = await execOk(agentSat, 'ig5_decompile', { target: sampleExe, ea: peFixture.transformVa, research: { id: invSat.rootId, key: 'c1a-decomp' } });

  const runDbgRead = async (targetAgent, rootId, scenarioId, kind, cliArgs, readMemExtraArgs, expectedHex, tag) => {
    const sel = (await execOk(targetAgent, 'ig5_workspace', {
      workspace: { action: 'select', id: rootId, root: { kind, scenarioId, observer: 'bpt + readmem', hypothesis: `Test ${tag}` } },
    })).workspace;
    const st = await execOk(targetAgent, 'ig5_dbg', {
      target: sampleExe, op: 'start', backend: 'x64dbg', args: cliArgs, cwd: workspaceDir,
      research: { ...sel.researchBinding, key: `${tag}-st`, step: 0 },
    });
    const en = await execOk(targetAgent, 'ig5_dbg', {
      target: sampleExe, op: 'cont', backend: 'x64dbg', expected_run_id: st.runId, expected_stop_seq: st.stopSeq,
      research: { ...sel.researchBinding, key: `${tag}-en`, step: 1 },
    });
    await execOk(targetAgent, 'ig5_dbg', {
      target: sampleExe, op: 'bpt', backend: 'x64dbg', rva: peFixture.afterTransformRva, expected_run_id: en.runId, expected_stop_seq: en.stopSeq,
      research: { ...sel.researchBinding, key: `${tag}-bp`, step: 2 },
    });
    const hit = await execOk(targetAgent, 'ig5_dbg', {
      target: sampleExe, op: 'cont', backend: 'x64dbg', expected_run_id: en.runId, expected_stop_seq: en.stopSeq,
      research: { ...sel.researchBinding, key: `${tag}-ct`, step: 3 },
    });
    assert.equal(hit.eventName, 'breakpoint');
    const mem = await execOk(targetAgent, 'ig5_dbg', {
      target: sampleExe, op: 'readmem', backend: 'x64dbg', size: 4,
      ...readMemExtraArgs,
      expected_run_id: hit.runId, expected_stop_seq: hit.stopSeq,
      research: { ...sel.researchBinding, key: `${tag}-rm`, step: 4 },
    });
    assert.equal(mem.hex.toLowerCase(), expectedHex);
    const sp = await execOk(targetAgent, 'ig5_dbg', {
      target: sampleExe, op: 'stop', backend: 'x64dbg', research: { id: rootId, key: `${tag}-sp` },
    });
    assert.equal(sp.state, 'no-task');
    await execOk(targetAgent, 'ig5_workspace', {
      workspace: {
        action: 'evaluate', id: rootId,
        root: { expId: sel.experiment.expId, observationClass: 'non-empty', verdict: 'supports', whyNextChanged: 'Observed 4B', nextAction: 'Continue' },
      },
    });
    return mem._managedExecution.reportId;
  };

  // Use exact `ea: "0x3100", address_space: "rva"` syntax (no `rva` property!)
  const discRvaAliasReceipt = await runDbgRead(
    agentSat, invSat.rootId, 'sc-disc', 'dynamic-breakpoint-read', ['mode=run', 'X=ABCD'],
    { ea: peFixture.outBufRva, address_space: 'rva' },
    expectedAbcdHex, 'c1a-disc',
  );

  await execOk(agentSat, 'ig5_workspace', {
    workspace: {
      action: 'root-update', id: invSat.rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-rva-alias',
          summary: 'Pre-committed rule before holdout',
          outputSpec: { kind: 'memory', rva: peFixture.outBufRva, byteLength: 4 },
          executableRule: executableTransformRule,
          staticReceiptIds: [decomp._managedExecution.reportId],
          testVectors: [{ caseId: 'disc', receiptId: discRvaAliasReceipt }],
        },
      },
    },
  });

  const holdRvaAliasReceipt = await runDbgRead(
    agentSat, invSat.rootId, 'sc-hold', 'holdout-verify', ['mode=verify', 'X=1234'],
    { ea: peFixture.outBufRva, address_space: 'rva' },
    computeExpectedCliTransformHex(Buffer.from('1234', 'ascii')), 'c1a-hold',
  );

  await execOk(agentSat, 'ig5_workspace', {
    workspace: {
      action: 'root-update', id: invSat.rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-rva-alias',
          summary: 'Verified on discovery + holdout via ea + address_space=rva',
          outputSpec: { kind: 'memory', rva: peFixture.outBufRva, byteLength: 4 },
          executableRule: executableTransformRule,
          staticReceiptIds: [decomp._managedExecution.reportId],
          testVectors: [
            { caseId: 'disc', receiptId: discRvaAliasReceipt },
            { caseId: 'hold', receiptId: holdRvaAliasReceipt },
          ],
        },
      },
    },
  });

  const satAssess = (await execOk(agentSat, 'ig5_workspace', { workspace: { action: 'assess', id: invSat.rootId } })).workspace;
  assert.equal(satAssess.assessment, 'satisfied');
  assert.equal(satAssess.canCompleteHostGoal, true);

  // Negative counterpart: bare runtime `ea: "0x140003100"` WITHOUT `address_space="rva"` or `rva` MUST NOT silently guess RVA!
  const agentBareEa = await makeLiveAgent('ctrl1a-bare-ea-agent');
  innerCtx.goals.create(agentBareEa, { objective: 'Verify bare runtime EA is not guessed as RVA' });
  const invBare = (await execOk(agentBareEa, 'ig5_workspace', {
    workspace: {
      action: 'root-create',
      root: {
        deliverables: [{
          id: 'deliv-bare-ea',
          kind: 'io-transform',
          description: 'Negative check for bare runtime EA',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation'],
          minDistinctInputs: 1,
          holdoutRequired: false,
        }],
      },
    },
  })).workspace;
  await execOk(agentBareEa, 'ig5_workspace', {
    workspace: {
      action: 'root-update', id: invBare.rootId,
      root: {
        component: { componentId: 'comp-bare', path: sampleExe, role: 'main-pe' },
        scenario: {
          scenarioId: 'sc-bare',
          componentId: 'comp-bare',
          args: ['mode=run', 'X=ABCD'],
          cwd: workspaceDir,
          inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', summary: 'X=ABCD', sampleHex: discHex, caseId: 'disc', isHoldout: false },
        },
      },
    },
  });
  const bareDecomp = await execOk(agentBareEa, 'ig5_decompile', { target: sampleExe, ea: peFixture.transformVa, research: { id: invBare.rootId, key: 'bare-decomp' } });
  const bareReceipt = await runDbgRead(
    agentBareEa, invBare.rootId, 'sc-bare', 'dynamic-breakpoint-read', ['mode=run', 'X=ABCD'],
    { ea: peFixture.outBufVa }, // Bare runtime VA 0x140003100, no address_space='rva'
    expectedAbcdHex, 'c1a-bare',
  );
  await execOk(agentBareEa, 'ig5_workspace', {
    workspace: {
      action: 'root-update', id: invBare.rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-bare-ea',
          summary: 'Candidate expecting RVA 0x3100 backed only by bare runtime EA receipt',
          outputSpec: { kind: 'memory', rva: peFixture.outBufRva, byteLength: 4 },
          executableRule: executableTransformRule,
          staticReceiptIds: [bareDecomp._managedExecution.reportId],
          testVectors: [{ caseId: 'disc', receiptId: bareReceipt }],
        },
      },
    },
  });
  const bareAssess = (await execOk(agentBareEa, 'ig5_workspace', { workspace: { action: 'assess', id: invBare.rootId } })).workspace;
  assert.equal(bareAssess.canCompleteHostGoal, false, 'Bare runtime EA without address_space=rva must NOT satisfy RVA outputSpec');
  await execOk(agentSat, 'ig5_close', { target: sampleExe });

  report.controls.control1A_addressAliasNative = {
    passed: true,
    rvaAliasReceipts: [discRvaAliasReceipt, holdRvaAliasReceipt],
    rvaAliasAssessment: satAssess.assessment,
    rvaAliasCanCompleteHostGoal: satAssess.canCompleteHostGoal,
    bareRuntimeEaReceipt: bareReceipt,
    bareRuntimeEaAssessment: bareAssess.assessment,
    bareRuntimeEaCanCompleteHostGoal: bareAssess.canCompleteHostGoal,
    bareRuntimeEaDenialReasons: bareAssess.denialReasons,
  };
  console.log('PASS [Control 1A] Native x64dbg ea+address_space=rva satisfied; bare runtime EA rejected.');

  // === CONTROL 1C: Real Host `ToolGoal` + `m2_suite_guard` `terminalControlReserve` ===
  console.log('[Control 1C] Verifying real DSH ToolGoal + m2_suite_guard terminalControlReserve...');
  // Subcase i: Partial investigation at ordinaryCallLimit -> update_goal(complete) denied by IG5 gate, update_goal(pause) succeeds!
  const guardLogPartial = path.join(evidenceDir, 'ctrl1c-partial-guard.jsonl');
  const guardOwnerPartial = ctx.plugin(m2Guard, {
    workspaceRoot: workspaceDir,
    logPath: guardLogPartial,
    maxTotalToolCalls: 3, // ordinaryCallLimit = 1, terminalControlReserve = 2
    terminalControlReserve: 2,
  });
  await guardOwnerPartial;
  try {
    const goalBare = innerCtx.goals.get(agentBareEa);
    // Spend the 1 ordinary call
    assert.equal((await execRaw(agentBareEa, 'ig5_status', {})).isError, false);
    // Next ordinary call denied by budget
    const ordDenied = await execRaw(agentBareEa, 'ig5_status', {});
    assert.equal(ordDenied.isError, true);
    assert.match(ordDenied.content[0].text, /budget.*exhausted/i);

    await runInTurn(agentBareEa, 1, { kind: 'user' }, async () => {
      // Reserve slot 1 of 2: update_goal(complete) admitted by guard, DENIED by downstream IG5 checkGoalCompletionGate!
      const badComplete = await execRaw(agentBareEa, 'update_goal', {
        goal_id: goalBare.id,
        revision: goalBare.revision,
        action: 'complete',
      });
      assert.equal(badComplete.isError, true, 'Partial investigation must be denied completion by IG5 gate');
      assert.match(badComplete.content[0].text, /not verified for completion/i);
      assert.equal(innerCtx.goals.get(agentBareEa).phase, 'active');

      // Reserve slot 2 of 2: update_goal(pause) admitted by guard AND accepted by real DSH ToolGoal!
      const pauseOk = await execRaw(agentBareEa, 'update_goal', {
        goal_id: goalBare.id,
        revision: goalBare.revision,
        action: 'pause',
      });
      assert.equal(pauseOk.isError, false, `Expected update_goal(pause) to succeed: ${pauseOk.content?.[0]?.text}`);
      assert.equal(innerCtx.goals.get(agentBareEa).phase, 'paused');
    });
  } finally {
    await guardOwnerPartial.dispose();
  }

  // Subcase ii: Satisfied investigation at ordinaryCallLimit -> get_goal #1 ok, get_goal #2 denied, invalid 'paused' denied without burning slot, update_goal(complete) succeeds!
  const guardLogSat = path.join(evidenceDir, 'ctrl1c-satisfied-guard.jsonl');
  const guardOwnerSat = ctx.plugin(m2Guard, {
    workspaceRoot: workspaceDir,
    logPath: guardLogSat,
    maxTotalToolCalls: 3, // ordinaryCallLimit = 1, terminalControlReserve = 2
    terminalControlReserve: 2,
  });
  await guardOwnerSat;
  try {
    assert.equal((await execRaw(agentSat, 'ig5_status', {})).isError, false);
    assert.equal((await execRaw(agentSat, 'ig5_status', {})).isError, true);

    await runInTurn(agentSat, 1, { kind: 'goal', goalId: goalSat.id, revision: goalSat.revision, round: 1 }, async () => {
      // Reserve slot 1: get_goal #1 succeeds
      const gg1 = await execOk(agentSat, 'get_goal', {});
      assert.equal(gg1.goal.id, goalSat.id);

      // Repeat get_goal #2 is denied to protect the final commit slot!
      const gg2 = await execRaw(agentSat, 'get_goal', {});
      assert.equal(gg2.isError, true);
      assert.match(gg2.content[0].text, /cannot spend the last commit slot/i);

      // Invalid action 'paused' is denied by guard without burning the final commit slot!
      const invalidPaused = await execRaw(agentSat, 'update_goal', {
        goal_id: gg1.goal.id,
        revision: gg1.goal.revision,
        action: 'paused',
      });
      assert.equal(invalidPaused.isError, true);

      // Reserve slot 2: update_goal(complete) succeeds through IG5 completion gate & real DSH ToolGoal!
      const completeOk = await execRaw(agentSat, 'update_goal', {
        goal_id: gg1.goal.id,
        revision: gg1.goal.revision,
        action: 'complete',
      });
      assert.equal(completeOk.isError, false, `Expected update_goal(complete) to succeed: ${completeOk.content?.[0]?.text}`);
      assert.equal(innerCtx.goals.get(agentSat).phase, 'complete');

      // Reserve now 2/2 spent -> any further terminal call denied
      assert.equal((await execRaw(agentSat, 'update_goal', {
        goal_id: gg1.goal.id,
        revision: innerCtx.goals.get(agentSat).revision,
        action: 'complete',
      })).isError, true);
    });
  } finally {
    await guardOwnerSat.dispose();
  }

  report.controls.control1C_terminalReserveHostContract = {
    passed: true,
    realToolGoalActionsVerified: hostUpdateActions,
    partialCompletionDeniedByIg5Gate: true,
    partialTruthfulPauseSucceeded: true,
    repeatGetGoalBlockedPreservingCommitSlot: true,
    invalidPausedActionBlockedWithoutSpendingSlot: true,
    satisfiedGoalCompletedViaReserve: true,
  };
  console.log('PASS [Control 1C] Real DSH ToolGoal + IG5 completion gate + terminalControlReserve verified.');

  // === CONTROL 1D: Real native PE64 execution of `evaluateTriggerCompleteness` positive + negative probes ===
  console.log('[Control 1D] Running native PE64 positive + negative trigger completeness probes...');
  const trigExePath = path.join(workspaceDir, 'trigger_probe_ctrl.exe');
  fs.writeFileSync(trigExePath, buildTriggerProbePE64());
  const gtTrigger = { channel: 'cli-arg', requiredCwdSuffix: '\\ctrl_stage' };

  const trigValid = evaluateTriggerCompleteness({
    triggerSpec: {
      schema: 'ig5-m2-trigger-spec-v1',
      channel: 'cli-arg',
      requiredCwdSuffix: '\\ctrl_stage',
      argsTemplate: ['--mode=check', 'K=<INPUT_4B>'],
      inputEncoding: 'ascii',
    },
    binaryPath: trigExePath,
    groundTruthTrigger: gtTrigger,
  });
  assert.equal(trigValid.passed, true, `Expected valid trigger spec to pass native probes: ${JSON.stringify(trigValid)}`);

  const trigMissingCwd = evaluateTriggerCompleteness({
    triggerSpec: {
      schema: 'ig5-m2-trigger-spec-v1',
      channel: 'cli-arg',
      requiredCwdSuffix: null,
      argsTemplate: ['--mode=check', 'K=<INPUT_4B>'],
      inputEncoding: 'ascii',
    },
    binaryPath: trigExePath,
    groundTruthTrigger: gtTrigger,
  });
  assert.equal(trigMissingCwd.passed, false);

  const trigExtraFlag = evaluateTriggerCompleteness({
    triggerSpec: {
      schema: 'ig5-m2-trigger-spec-v1',
      channel: 'cli-arg',
      requiredCwdSuffix: '\\ctrl_stage',
      argsTemplate: ['--mode=check', '--extra-flag', 'K=<INPUT_4B>'],
      inputEncoding: 'ascii',
    },
    binaryPath: trigExePath,
    groundTruthTrigger: gtTrigger,
  });
  assert.equal(trigExtraFlag.passed, false);

  fs.writeFileSync(path.join(evidenceDir, 'raw-artifacts', 'trigger-probes-raw.json'), JSON.stringify({
    trigValid,
    trigMissingCwd,
    trigExtraFlag,
  }, null, 2), 'utf8');

  report.controls.control1D_nativeTriggerCompletenessProbes = {
    passed: true,
    scope: trigValid.scope,
    validSpecPositiveProbes: trigValid.positiveProbes.length,
    validSpecNegativeProbes: trigValid.negativeProbes.length,
    missingCwdRejected: !trigMissingCwd.passed,
    extraFlagRejected: !trigExtraFlag.passed,
  };
  console.log('PASS [Control 1D] Native PE64 trigger completeness positive + negative probes verified.');
} finally {
  await ctx?.fiber?.dispose();
  // Archive raw ig5-home receipts, blobs, and ledgers before cleaning tempRoot!
  if (fs.existsSync(ig5Home)) {
    fs.cpSync(ig5Home, path.join(evidenceDir, 'raw-artifacts', 'ig5-home'), { recursive: true });
  }
  try { fs.rmSync(tempRoot, { recursive: true, force: true }); } catch { /* ignore */ }
}

const finalProcCheck = collectNativeProcessCheck();
assert.equal(finalProcCheck.status, 'checked');
assert.equal(finalProcCheck.processes.length, 0, `Lingering native processes found: ${JSON.stringify(finalProcCheck)}`);
report.postVerificationNativeProcessCheck = finalProcCheck;
report.allControlsPassed = Object.values(report.controls).every((c) => c.passed === true);

const outReportPath = path.join(evidenceDir, 'native-host-controls-report.json');
fs.writeFileSync(outReportPath, JSON.stringify(report, null, 2), 'utf8');

function walkEvidenceFiles(dir, relPrefix = '', out = []) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const rel = relPrefix ? `${relPrefix}/${ent.name}` : ent.name;
    if (rel === 'manifest.json') continue;
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) walkEvidenceFiles(full, rel, out);
    else if (ent.isFile()) {
      const bytes = fs.readFileSync(full);
      out.push({ path: rel, size: bytes.length, sha256: sha256(bytes) });
    }
  }
  return out;
}
const manifestFiles = walkEvidenceFiles(evidenceDir);
fs.writeFileSync(path.join(evidenceDir, 'manifest.json'), JSON.stringify({
  schema: 'ig5-m2-controls-evidence-manifest-v1',
  generatedAt: new Date().toISOString(),
  sourceTreeDigest: report.sourceTreeDigest,
  fileCount: manifestFiles.length,
  files: manifestFiles,
}, null, 2), 'utf8');

console.log(`ALL PRE-ORCHESTRATED NATIVE & HOST CONTROLS PASSED -> ${outReportPath} (${manifestFiles.length} archived evidence files)`);
