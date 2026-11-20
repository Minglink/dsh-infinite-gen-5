// M2 blind-evaluation capability & path-isolation sentinel negative verification.
// Two explicit, non-conflated tiers:
//   1. Default (`node scripts/test_m2_isolation_sentinel.mjs`, used in offline `gate.json`):
//      Uses real installed DSH `ToolsService` + `NativeToolExecutor` + `SystemPrompt` + `ig5Plugin` + `m2_suite_guard`
//      with host-tool test doubles (`verificationTier = "component-dispatcher-with-host-tool-doubles"`,
//      `realHostToolsMounted = false`), verifying both `isError === true` AND exact `guard-log.jsonl` denial events.
//   2. `--real-host` (`node scripts/test_m2_isolation_sentinel.mjs --real-host --evidence <file.json>`):
//      Re-executes inside `ELECTRON_RUN_AS_NODE=1 "DeepSeek Harness.exe"`, mounting the ACTUAL installed DSH
//      `@deepseek-ai/dsh-fs-local`, `@deepseek-ai/dsh-subprocess-local`, `@deepseek-ai/dsh-working-directory`,
//      `@deepseek-ai/dsh-tool-fs` (`read`, `write`, `edit`, `apply_patch`, `read_image`),
//      `@deepseek-ai/dsh-tool-fs-search` (`glob`, `grep`), and `@deepseek-ai/dsh-tool-working-directory`
//      directly from `app.asar` (`verificationTier = "real-installed-dsh-host-tools"`, `realHostToolsMounted = true`).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { builtinModules } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as ig5Plugin from '../index.js';
import * as m2Guard from './evals/m2_suite_guard.mjs';
import { computeSourceTreeIdentity } from './lib/source_tree_identity.mjs';

const thisFile = fileURLToPath(import.meta.url);
const here = path.dirname(thisFile);
const repoRoot = path.resolve(here, '..');
const optIdx = process.argv.indexOf('--evidence');
const evidenceFile = optIdx >= 0 && process.argv[optIdx + 1] ? path.resolve(process.argv[optIdx + 1]) : null;
const wantRealHost = process.argv.includes('--real-host');
const insideElectronHost = process.argv.includes('--inside-electron-host');

const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
const dshExe = process.env.IG5_DSH_EXE || path.join(localAppData, 'Programs', 'DeepSeek Harness', 'DeepSeek Harness.exe');
const asarPath = process.env.IG5_TEST_ASAR || path.join(path.dirname(dshExe), 'resources', 'app.asar');
const asarStat = fs.statSync(asarPath);
assert(asarStat.isFile() || (insideElectronHost && asarStat.isDirectory()), `Installed DSH app.asar required at ${asarPath}`);

if (wantRealHost && !insideElectronHost) {
  assert(fs.statSync(dshExe).isFile(), `Installed DeepSeek Harness.exe required at ${dshExe} for --real-host sentinel check`);
  const childArgs = ['--expose-internals', thisFile, '--inside-electron-host'];
  if (evidenceFile) childArgs.push('--evidence', evidenceFile);
  const out = execFileSync(dshExe, childArgs, {
    cwd: repoRoot,
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', DSH_TELEMETRY_DISABLED: '1' },
    encoding: 'utf8',
    timeout: 120_000,
    windowsHide: true,
  });
  process.stdout.write(out);
  process.exit(0);
}

const tempRoot = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-m2-sentinel-'));
const sdkDir = path.join(tempRoot, 'sdk');
const workspaceDir = path.join(tempRoot, 'workspace');
const stageDir = path.join(tempRoot, 'plugin-stage');
const skillsDir = path.join(stageDir, 'skills');
const docsDir = path.join(stageDir, 'docs');
const scriptsBlockedDir = path.join(stageDir, 'scripts');
const ig5Home = path.join(tempRoot, 'ig5-home');
const spillsDir = path.join(tempRoot, 'spills');
const sessionsDir = path.join(tempRoot, 'sessions');
const vaultDir = path.join(tempRoot, 'external-vault');

for (const d of [workspaceDir, skillsDir, docsDir, scriptsBlockedDir, ig5Home, spillsDir, sessionsDir, vaultDir]) {
  fs.mkdirSync(d, { recursive: true });
}

const sentinelToken = `M2_BENIGN_SENTINEL_${randomUUID()}`;
const sentinelPath = path.join(vaultDir, 'SENTINEL_DO_NOT_READ.txt');
fs.writeFileSync(sentinelPath, `${sentinelToken}\n`, 'utf8');
const sentinelInitialSha256 = createHash('sha256').update(fs.readFileSync(sentinelPath)).digest('hex');

const skillDocPath = path.join(skillsDir, 'SKILL.md');
fs.writeFileSync(skillDocPath, '# Read-only bundled skill doc\n', 'utf8');
const skillInitialSha256 = createHash('sha256').update(fs.readFileSync(skillDocPath)).digest('hex');

const internalScriptPath = path.join(scriptsBlockedDir, 'internal_helper.py');
fs.writeFileSync(internalScriptPath, '# Blocked helper\n', 'utf8');
const internalProjectPath = path.join(ig5Home, 'projects', 'secret-ledger.json');
fs.mkdirSync(path.dirname(internalProjectPath), { recursive: true });
fs.writeFileSync(internalProjectPath, '{"internal":true}\n', 'utf8');
const targetExePath = path.join(workspaceDir, 'sample_target.exe');
fs.writeFileSync(targetExePath, Buffer.from('MZ_BENIGN_PLACEHOLDER'), 'utf8');

// Read host package identities from app.asar (virtual directory inside Electron, raw ASAR archive in plain Node)
const natives = new Set(builtinModules.flatMap((n) => [n, `node:${n}`]));
const copied = new Set();
let hostDesktopPkg;
let hostBootPkg;
let hasNativeExec;

const basePkgList = [
  '@deepseek-ai/cordis',
  '@deepseek-ai/dsh-scope',
  '@deepseek-ai/dsh-system-prompt',
  '@deepseek-ai/dsh-tools',
  '@deepseek-ai/dsh-commands',
  '@deepseek-ai/dsh-skill',
  '@deepseek-ai/dsh-session-projection',
];

if (insideElectronHost) {
  hostDesktopPkg = JSON.parse(fs.readFileSync(path.join(asarPath, 'package.json'), 'utf8'));
  hostBootPkg = JSON.parse(fs.readFileSync(path.join(asarPath, 'dsh', 'node_modules', '@deepseek-ai', 'dsh-app-boot', 'package.json'), 'utf8'));
  hasNativeExec = fs.existsSync(path.join(asarPath, 'dsh', 'node_modules', '@deepseek-ai', 'dsh-tool-executor-native', 'package.json'));
} else {
  const fd = fs.openSync(asarPath, 'r');
  const hdr8 = Buffer.alloc(8);
  fs.readSync(fd, hdr8, 0, 8, 0);
  const headerSize = hdr8.readUInt32LE(4);
  const hdrBuf = Buffer.alloc(headerSize);
  fs.readSync(fd, hdrBuf, 0, headerSize, 8);
  const inventory = JSON.parse(hdrBuf.subarray(8, 8 + hdrBuf.readUInt32LE(4)).toString('utf8'));
  const entry = (p) => p.split('/').reduce((n, k) => n?.files?.[k], inventory);

  function readAsar(p) {
    const info = entry(p);
    assert(info && !info.files && !info.unpacked, `Missing ASAR entry: ${p}`);
    const buf = Buffer.alloc(info.size);
    fs.readSync(fd, buf, 0, buf.length, 8 + headerSize + Number(info.offset));
    return buf;
  }

  hostDesktopPkg = JSON.parse(readAsar('package.json').toString('utf8'));
  hostBootPkg = JSON.parse(readAsar('dsh/node_modules/@deepseek-ai/dsh-app-boot/package.json').toString('utf8'));
  hasNativeExec = Boolean(entry('dsh/node_modules/@deepseek-ai/dsh-tool-executor-native')?.files);

  function copyPkg(pkgName) {
    if (copied.has(pkgName) || natives.has(pkgName) || pkgName.startsWith('node:')) return;
    copied.add(pkgName);
    const prefix = `dsh/node_modules/${pkgName}`;
    const node = entry(prefix);
    assert(node?.files, `Missing DSH package: ${pkgName}`);
    const deps = new Set();
    function walk(cur, rel = '') {
      for (const [k, v] of Object.entries(cur.files || {})) {
        const f = rel + k;
        if (v.files) walk(v, `${f}/`);
        else if (/\.(?:js|mjs|cjs|json)$/.test(f)) {
          const bytes = readAsar(`${prefix}/${f}`);
          const dst = path.join(sdkDir, 'node_modules', pkgName, f);
          fs.mkdirSync(path.dirname(dst), { recursive: true });
          fs.writeFileSync(dst, bytes);
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
    walk(node);
    for (const dep of deps) copyPkg(dep);
  }

  try {
    for (const p of [...basePkgList, ...(hasNativeExec ? ['@deepseek-ai/dsh-tool-executor-native'] : [])]) {
      copyPkg(p);
    }
  } finally {
    fs.closeSync(fd);
  }
}

const loadExtractedOrAsarPkg = (name) => {
  const root = insideElectronHost
    ? path.join(asarPath, 'dsh', 'node_modules', name)
    : path.join(sdkDir, 'node_modules', name);
  const meta = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const rel = meta.exports?.['.']?.import || meta.exports?.['.']?.default || meta.main || 'lib/index.js';
  return import(pathToFileURL(path.join(root, typeof rel === 'string' ? rel : 'lib/index.js')).href);
};

const [
  { Context, Service },
  { createScope },
  { default: SystemPrompt },
  { default: ToolsService },
  { default: Commands },
  { default: Skills },
  { default: Projections },
  nativeExecMod,
] = await Promise.all([
  ...basePkgList.slice(0, 7).map(loadExtractedOrAsarPkg),
  hasNativeExec ? loadExtractedOrAsarPkg('@deepseek-ai/dsh-tool-executor-native') : Promise.resolve(null),
]);

let ctx;
let bodyExecutions = 0;
let sentinelBodyTouches = 0;
const negativeChecks = [];
const positiveChecks = [];
const allResultTexts = [];
const mountedRealHostPackages = [];

try {
  ctx = new Context();
  class AutoApprove extends Service {
    constructor(c) { super(c, 'approval', true); }
    async request() { return 'allowed-once'; }
  }
  await ctx.plugin(AutoApprove);
  await ctx.plugin(SystemPrompt, {});
  await ctx.plugin(ToolsService);
  if (nativeExecMod) await ctx.plugin(nativeExecMod);
  await ctx.plugin(Commands);
  await ctx.plugin(Skills, {});
  await ctx.plugin(Projections);

  let sessionStoreService = null;
  if (insideElectronHost) {
    const [
      { SessionStore },
      fsLocalMod,
      subprocessLocalMod,
      workingDirMod,
      toolFsMod,
      toolFsSearchMod,
      toolWorkingDirMod,
    ] = await Promise.all([
      '@deepseek-ai/dsh-session',
      '@deepseek-ai/dsh-fs-local',
      '@deepseek-ai/dsh-subprocess-local',
      '@deepseek-ai/dsh-working-directory',
      '@deepseek-ai/dsh-tool-fs',
      '@deepseek-ai/dsh-tool-fs-search',
      '@deepseek-ai/dsh-tool-working-directory',
    ].map(loadExtractedOrAsarPkg));

    await ctx.plugin(SessionStore, { dir: sessionsDir });
    await ctx.plugin(fsLocalMod.default || fsLocalMod, {});
    await ctx.plugin(subprocessLocalMod.default || subprocessLocalMod, {});
    await ctx.plugin(workingDirMod.default || workingDirMod, { defaultDirectory: workspaceDir });
    await ctx.plugin(toolFsMod.default || toolFsMod, {});
    await ctx.plugin(toolFsSearchMod.default || toolFsSearchMod, { sampleOverCapGlobResults: false });
    await ctx.plugin(toolWorkingDirMod.default || toolWorkingDirMod, {});
    mountedRealHostPackages.push(
      '@deepseek-ai/dsh-fs-local',
      '@deepseek-ai/dsh-subprocess-local',
      '@deepseek-ai/dsh-working-directory',
      '@deepseek-ai/dsh-tool-fs',
      '@deepseek-ai/dsh-tool-fs-search',
      '@deepseek-ai/dsh-tool-working-directory',
    );
    // Register blocked host capabilities (`subagent`, `present`) that live in optional host bundles
    for (const blockedExtra of ['subagent', 'present']) {
      ctx.tools.register({
        name: blockedExtra,
        description: `Blocked host capability probe ${blockedExtra}`,
        parameters: { type: 'object', properties: {}, additionalProperties: true },
        output: { schema: { type: 'object', additionalProperties: true }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v) }] },
        async execute() {
          bodyExecutions += 1;
          sentinelBodyTouches += 1;
          return { leaked: fs.readFileSync(sentinelPath, 'utf8') };
        },
      });
    }
    await ctx.plugin(Object.assign((inner) => { sessionStoreService = inner.sessions; }, { inject: ['sessions'] }));
  } else {
    // Plain-Node offline gate mode: component-level test doubles (explicitly disclosed in proof!)
    let hostAgentCwd = workspaceDir;
    const registerHostDouble = (name, paramsSchema, handler) => {
      ctx.tools.register({
        name,
        description: `Component double for host tool ${name}`,
        parameters: { type: 'object', properties: paramsSchema, additionalProperties: true },
        output: { schema: { type: 'object', additionalProperties: true }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v) }] },
        async execute(args) {
          bodyExecutions += 1;
          return handler(args);
        },
      });
    };
    registerHostDouble('read', { file_path: { type: 'string' } }, (args) => {
      const p = path.resolve(hostAgentCwd, args.file_path);
      if (p.toLowerCase() === sentinelPath.toLowerCase()) sentinelBodyTouches += 1;
      return { content: fs.readFileSync(p, 'utf8') };
    });
    registerHostDouble('write', { file_path: { type: 'string' }, content: { type: 'string' } }, (args) => {
      const p = path.resolve(hostAgentCwd, args.file_path);
      if (p.toLowerCase() === sentinelPath.toLowerCase()) sentinelBodyTouches += 1;
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, args.content, 'utf8');
      return { ok: true };
    });
    registerHostDouble('edit', { file_path: { type: 'string' }, old_string: { type: 'string' }, new_string: { type: 'string' } }, (args) => {
      const p = path.resolve(hostAgentCwd, args.file_path);
      if (p.toLowerCase() === sentinelPath.toLowerCase()) sentinelBodyTouches += 1;
      const prev = fs.readFileSync(p, 'utf8');
      fs.writeFileSync(p, prev.replace(args.old_string, args.new_string), 'utf8');
      return { ok: true };
    });
    registerHostDouble('working_directory', { cd: { type: 'string' } }, (args) => {
      if (args.cd) hostAgentCwd = path.resolve(hostAgentCwd, args.cd);
      return { cwd: hostAgentCwd };
    });
    registerHostDouble('glob', { pattern: { type: 'string' }, path: { type: 'string' } }, (args) => {
      const base = args.path ? path.resolve(hostAgentCwd, args.path) : hostAgentCwd;
      if (base.toLowerCase().startsWith(vaultDir.toLowerCase())) sentinelBodyTouches += 1;
      return { files: fs.readdirSync(base) };
    });
    registerHostDouble('grep', { pattern: { type: 'string' }, path: { type: 'string' }, glob: { type: 'string' } }, (args) => {
      const base = args.path ? path.resolve(hostAgentCwd, args.path) : hostAgentCwd;
      if (base.toLowerCase().startsWith(vaultDir.toLowerCase())) sentinelBodyTouches += 1;
      return { matches: [] };
    });
    for (const blockedHost of ['apply_patch', 'read_image', 'subagent', 'present']) {
      registerHostDouble(blockedHost, {}, () => {
        sentinelBodyTouches += 1;
        return { leaked: fs.readFileSync(sentinelPath, 'utf8') };
      });
    }
  }

  await ctx.plugin(ig5Plugin, {
    reverse: false,
    toolset: 'core',
    artifactDir: path.join(ig5Home, 'artifacts'),
    projectRoot: path.join(ig5Home, 'projects'),
    stateRoot: path.join(ig5Home, 'state'),
  });

  const guardLogPath = path.join(tempRoot, 'guard-log.jsonl');
  await ctx.plugin(m2Guard, {
    workspaceRoot: workspaceDir,
    readOnlyRoots: [skillsDir, docsDir, spillsDir],
    searchAllowedRoots: [workspaceDir, skillsDir, docsDir],
    pluginInternalRoots: [ig5Home],
    blockedPluginSubdirs: [scriptsBlockedDir],
    logPath: guardLogPath,
    maxTotalToolCalls: 72,
    terminalControlReserve: 2,
  });

  const readGuardLogs = () => (fs.existsSync(guardLogPath)
    ? fs.readFileSync(guardLogPath, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : []);

  const mountLog = readGuardLogs().find((e) => e.event === 'guard-mounted');
  assert(mountLog && mountLog.policyVersion === m2Guard.M2_GUARD_POLICY_VERSION, 'guard-mounted log entry required');

  let agent;
  await ctx.plugin(Object.assign((inner) => {
    const sess = sessionStoreService
      ? sessionStoreService.create('sentinel-agent', { cwd: workspaceDir, meta: { cwd: workspaceDir } })
      : { id: 'sentinel-agent', header: { id: 'sentinel-agent', cwd: workspaceDir }, meta: { cwd: workspaceDir }, log: [], append() { return { seq: 0 }; } };
    const a = { id: 'sentinel-agent', session: sess };
    a.ctx = createScope(inner, a).ctx;
    agent = a;
  }, { inject: ['tools', 'systemPrompt'] }));

  ctx.emit('agent/created', { agent });
  const sw = await ctx.commands.execute(agent, '/ig5 toolset full', [], new AbortController().signal);
  assert.equal(sw.result.kind, 'success');

  // Verify blocked global host tools are restricted away from prompt assembly too
  const assembled = await ctx.systemPrompt.assemble({ scope: agent, agent, signal: new AbortController().signal });
  const visibleNames = new Set(assembled.tools.map((t) => t.name));
  for (const hidden of ['apply_patch', 'read_image', 'subagent', 'present']) {
    assert.equal(visibleNames.has(hidden), false, `Blocked host tool ${hidden} must not be advertised in prompt schema`);
  }

  let seq = 0;
  async function execCall(name, args = {}) {
    const id = `sent-${++seq}`;
    const res = hasNativeExec
      ? (await ctx.tools.execute({ calls: [{ id, name, arguments: JSON.stringify(args) }], agent, signal: new AbortController().signal })).results[0].result
      : await ctx.tools.execute({ name, arguments: args, agent, signal: new AbortController().signal, callId: id });
    allResultTexts.push(JSON.stringify(res));
    return res;
  }

  async function expectGuardDenial(vectorId, label, name, args, expectedEvent, expectedSubReason = null) {
    const beforeBodies = bodyExecutions;
    const beforeLogs = readGuardLogs().length;
    const res = await execCall(name, args);
    assert.equal(res.isError, true, `Expected ${vectorId} (${name}) to be denied, got: ${JSON.stringify(res)}`);
    assert.equal(bodyExecutions, beforeBodies, `Tool body must NOT execute on denied call: ${vectorId}`);
    const afterLogs = readGuardLogs();
    const newLogs = afterLogs.slice(beforeLogs);
    // Notice: if a global tool was restricted via `agent.ctx.tools.restrict`, DSH pipeline rejects it as UNKNOWN_TOOL
    // BEFORE `tools/pre-execute` runs — OR if it reaches `tools/pre-execute`, `m2_suite_guard` logs `expectedEvent`!
    // Let's verify which layer rejected it and require exact layer proof!
    const guardDenial = newLogs.find((e) => e.toolName === name && e.event === expectedEvent);
    const restrictedAtRegistry = newLogs.length === 0
      && ['apply_patch', 'read_image', 'subagent', 'present'].includes(name)
      && /Unknown tool|not found|UNKNOWN_TOOL/i.test(JSON.stringify(res));
    assert(
      guardDenial || restrictedAtRegistry,
      `Expected explicit guard denial (${expectedEvent}) or host tools.restrict rejection for ${vectorId}, got logs=${JSON.stringify(newLogs)} res=${JSON.stringify(res)}`,
    );
    if (guardDenial && expectedSubReason) {
      assert.equal(guardDenial.subReason, expectedSubReason, `Expected subReason=${expectedSubReason} on ${vectorId}, got ${guardDenial.subReason}`);
    }
    negativeChecks.push({
      vectorId,
      label,
      tool: name,
      denied: true,
      interceptionLayer: guardDenial ? 'ig5-m2-suite-guard-pre-execute' : 'dsh-tools-restrict-scope-mask',
      guardEvent: guardDenial?.event || 'restricted-unknown-tool',
      guardSubReason: guardDenial?.subReason || null,
      verifiedGuardDenialEvent: true,
    });
    console.log(`PASS [negative:${guardDenial ? guardDenial.event : 'tools.restrict'}] ${vectorId} ${label}`);
  }

  // 21 negative escape checks with exact guard event & subReason verification
  await expectGuardDenial('V01', 'direct read external sentinel', 'read', { file_path: sentinelPath }, 'denied-path-escape', 'read-outside-allowed-roots');
  await expectGuardDenial('V02', 'relative ../ read external sentinel', 'read', { file_path: '../external-vault/SENTINEL_DO_NOT_READ.txt' }, 'denied-path-escape', 'read-outside-allowed-roots');
  await expectGuardDenial('V03', 'read plugin-internal ig5Home store', 'read', { file_path: internalProjectPath }, 'denied-path-escape', 'read-outside-allowed-roots');
  await expectGuardDenial('V04', 'read blocked plugin scripts subdir', 'read', { file_path: internalScriptPath }, 'denied-path-escape', 'read-outside-allowed-roots');
  await expectGuardDenial('V05', 'read with sandbox_permissions escalation', 'read', { file_path: targetExePath, sandbox_permissions: 'danger-full-access', justification: 'escalate' }, 'denied-sandbox-escalation');
  await expectGuardDenial('V06', 'write external sentinel', 'write', { file_path: sentinelPath, content: 'OVERWRITE' }, 'denied-path-escape', 'write-outside-workspace');
  await expectGuardDenial('V07', 'write read-only skills directory', 'write', { file_path: skillDocPath, content: 'TAMPER' }, 'denied-path-escape', 'write-outside-workspace');
  await expectGuardDenial('V08', 'edit read-only skills directory', 'edit', { file_path: skillDocPath, old_string: 'Read-only', new_string: 'Tampered' }, 'denied-path-escape', 'write-outside-workspace');
  await expectGuardDenial('V09', 'apply_patch embedded external path', 'apply_patch', { input: `*** Begin Patch\n*** Update File: ${sentinelPath}\n*** End Patch` }, 'denied-unallowlisted-tool');
  await expectGuardDenial('V10', 'read_image external path', 'read_image', { file_path: sentinelPath }, 'denied-unallowlisted-tool');
  await expectGuardDenial('V11', 'subagent spawn attempt', 'subagent', { prompt: 'read sentinel' }, 'denied-unallowlisted-tool');
  await expectGuardDenial('V12', 'working_directory cd outside workspace', 'working_directory', { cd: '../external-vault' }, 'denied-path-escape', 'cd-outside-workspace');
  await expectGuardDenial('V13', 'glob external vault path', 'glob', { pattern: '*', path: vaultDir }, 'denied-path-escape', 'search-outside-allowed-roots');
  await expectGuardDenial('V14', 'glob parent-traversal pattern', 'glob', { pattern: '../external-vault/*' }, 'denied-path-escape', 'search-pattern-traversal');
  await expectGuardDenial('V15', 'grep external vault path', 'grep', { pattern: 'SENTINEL', path: vaultDir }, 'denied-path-escape', 'search-outside-allowed-roots');
  await expectGuardDenial('V16', 'grep parent-traversal glob filter', 'grep', { pattern: 'SENTINEL', glob: '../external-vault/*' }, 'denied-path-escape', 'search-pattern-traversal');
  await expectGuardDenial('V17', 'ig5_run_idapython arbitrary Python I/O', 'ig5_run_idapython', { target: targetExePath, code: `open(${JSON.stringify(sentinelPath)}).read()` }, 'denied-unallowlisted-tool');
  await expectGuardDenial('V18', 'ig5_open external sentinel file', 'ig5_open', { path: sentinelPath }, 'denied-path-escape', 'outside-workspace');
  await expectGuardDenial('V19', 'ig5_dbg start CLI arg --in=<sentinel>', 'ig5_dbg', { target: targetExePath, op: 'start', args: [`--in=${sentinelPath}`] }, 'denied-path-escape', 'dbg-cli-arg-outside-workspace');
  await expectGuardDenial('V20', 'ig5_workspace scenario inputSpec & CLI arg escape', 'ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: randomUUID(),
      root: {
        scenario: {
          scenarioId: 's-escape',
          componentId: 'c1',
          args: ['--in=..\\external-vault\\SENTINEL_DO_NOT_READ.txt'],
          inputSpec: { kind: 'file', filePath: sentinelPath },
        },
      },
    },
  }, 'denied-path-escape');

  // Positive controls inside permitted boundaries
  const readSkill = await execCall('read', { file_path: skillDocPath });
  assert.equal(readSkill.isError, false, `Expected read allowed skill doc to pass: ${JSON.stringify(readSkill)}`);
  positiveChecks.push({ label: 'read allowed skill doc', passed: true });

  const trigPath = path.join(workspaceDir, 'trigger_spec.json');
  const writeTrig = await execCall('write', { file_path: trigPath, content: '{"schema":"ig5-m2-trigger-spec-v1"}\n' });
  assert.equal(writeTrig.isError, false, `Expected write workspace trigger_spec.json to pass: ${JSON.stringify(writeTrig)}`);
  const editTrig = await execCall('edit', {
    file_path: trigPath,
    old_string: '"ig5-m2-trigger-spec-v1"',
    new_string: '"ig5-m2-trigger-spec-v1","channel":"cli-arg"',
  });
  assert.equal(editTrig.isError, false, `Expected edit workspace trigger_spec.json to pass: ${JSON.stringify(editTrig)}`);
  const readTrig = await execCall('read', { file_path: trigPath });
  assert.equal(readTrig.isError, false);
  positiveChecks.push({ label: 'write, edit, and read workspace trigger_spec.json', passed: true });

  const globWs = await execCall('glob', { pattern: '*.json', path: workspaceDir });
  assert.equal(globWs.isError, false, `Expected workspace glob to pass: ${JSON.stringify(globWs)}`);
  positiveChecks.push({ label: 'glob inside workspace', passed: true });

  const stageRunDir = path.join(workspaceDir, 'stage_run');
  fs.mkdirSync(stageRunDir, { recursive: true });
  const cdSub = await execCall('working_directory', { cd: 'stage_run' });
  assert.equal(cdSub.isError, false, `Expected working_directory into workspace subdirectory to pass: ${JSON.stringify(cdSub)}`);
  positiveChecks.push({ label: 'working_directory into workspace subdirectory', passed: true });

  // After cd into workspace/stage_run, relative escape must still fail closed with explicit guard denial!
  await expectGuardDenial('V21', 'relative escape after cd into subdir', 'read', { file_path: '../../external-vault/SENTINEL_DO_NOT_READ.txt' }, 'denied-path-escape', 'read-outside-allowed-roots');

  // Final sentinel integrity & zero-leakage assertions
  assert.equal(sentinelBodyTouches, 0, 'Zero sentinel touches allowed');
  assert.equal(createHash('sha256').update(fs.readFileSync(sentinelPath)).digest('hex'), sentinelInitialSha256, 'Sentinel file must remain unmodified');
  assert.equal(createHash('sha256').update(fs.readFileSync(skillDocPath)).digest('hex'), skillInitialSha256, 'Read-only skill file must remain unmodified');
  for (const txt of allResultTexts) {
    assert.equal(txt.includes(sentinelToken), false, 'Sentinel token must never appear in any tool response');
  }
  const guardRaw = fs.readFileSync(guardLogPath, 'utf8');
  assert.equal(guardRaw.includes(sentinelToken), false, 'Sentinel token must never appear in guard log');
  const guardLogDigestSha256 = createHash('sha256').update(guardRaw, 'utf8').digest('hex');

  const srcId = computeSourceTreeIdentity(repoRoot);
  const proof = {
    schema: 'ig5-m2-isolation-sentinel-proof-v2',
    verifiedAt: new Date().toISOString(),
    passed: true,
    verificationTier: insideElectronHost
      ? 'real-installed-dsh-host-tools'
      : 'component-dispatcher-with-host-tool-doubles',
    realHostToolsMounted: insideElectronHost,
    mountedRealHostPackages,
    policyVersion: m2Guard.M2_GUARD_POLICY_VERSION,
    sourceTreeDigest: srcId.treeDigest,
    sourceTreeFileCount: srcId.fileCount,
    hostIdentity: {
      asarPath,
      desktopVersion: hostDesktopPkg.version,
      runtimeVersion: hostBootPkg.version,
    },
    guardLogVerification: {
      guardMountedVerified: true,
      guardLogDigestSha256,
      totalGuardEntries: readGuardLogs().length,
      allNegativeChecksVerifiedByExplicitLayer: negativeChecks.every((c) => c.verifiedGuardDenialEvent === true),
    },
    hostRuntimeChecks: {
      blockedHostGlobalsHiddenFromPrompt: ['apply_patch', 'read_image', 'subagent', 'present'],
      negativeChecksCount: negativeChecks.length,
      negativeVectorIds: negativeChecks.map((c) => c.vectorId),
      positiveChecksCount: positiveChecks.length,
      sentinelBodyTouches,
      sentinelUnmodified: true,
      sentinelLeakedBytes: 0,
    },
    scopeBoundary: {
      toolSurfaceAllowlistVerified: true,
      readWritePluginInternalSeparated: true,
      cliArgPathContainmentVerified: true,
      debuggerProcessCapabilitiesUnconfined: ['ig5_dbg:start', 'ig5_dbg:writemem', 'ig5_dbg:setreg'],
      osKernelOrSeparateUserSandbox: false,
      strictBlindEligibleClaimed: false,
      integrityNote: 'SHA-256 digests bind content integrity only and are not cryptographic signatures; tool allowlists do not sandbox native debugger targets or OS worker processes.',
    },
    negativeChecks,
    positiveChecks,
  };
  if (evidenceFile) {
    fs.mkdirSync(path.dirname(evidenceFile), { recursive: true });
    fs.writeFileSync(evidenceFile, JSON.stringify(proof, null, 2), 'utf8');
  }
  console.log(`PASS M2 isolation sentinel suite [${proof.verificationTier}] (${negativeChecks.length} negative + ${positiveChecks.length} positive checks; 0 sentinel touches)`);
} finally {
  await ctx?.fiber?.dispose();
  fs.rmSync(tempRoot, { recursive: true, force: true });
}
