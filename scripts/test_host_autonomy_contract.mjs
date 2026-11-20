// M0 DSH Host Package Component Integration Verification against installed DeepSeek Harness (app.asar).
// Scope: Exercises real DSH 0.2.2-rc.1 SessionStore, SessionProjections, AgentRegistry, GoalService,
// ToolGoal, SystemPrompt, ToolsService, NativeToolExecutor, IG5 plugin autonomy/approval/control wiring,
// and real bundled Ghidra + headless x64dbg through ToolsService.execute.
// Boundary: Turns/events are driven programmatically with a deterministic MockApprovalService ('allowed-once');
// this script verifies host-package component integration, NOT a live desktop GUI or live LLM multi-round session.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { builtinModules } from 'node:module';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as ig5Plugin from '../index.js';
import { buildCliTransformPE64, computeExpectedCliTransformHex } from './fixtures/pe64-cli-transform.mjs';
import { computeSourceTreeIdentity } from './lib/source_tree_identity.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..');
const defaultDonorRuntimes = 'C:\\Users\\Administrator\\Desktop\\无限五代\\dsh-infinite-gen-5\\runtimes';
if (!process.env.IG5_RUNTIME_ROOT && !fs.existsSync(path.join(repoRoot, 'runtimes', 'manifest.json')) && fs.existsSync(defaultDonorRuntimes)) {
  process.env.IG5_RUNTIME_ROOT = defaultDonorRuntimes;
}

const asarPath = process.env.DSH_ASAR || path.join(
  process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'),
  'Programs',
  'DeepSeek Harness',
  'resources',
  'app.asar',
);
assert(fs.existsSync(asarPath), `Installed DSH app.asar required at ${asarPath}`);

const tempRoot = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-m0-host-contract-'));
const sdkDir = path.join(tempRoot, 'sdk');
const workspaceDir = path.join(tempRoot, 'workspace');
const ig5Home = path.join(tempRoot, 'ig5-home');
fs.mkdirSync(workspaceDir, { recursive: true });
fs.mkdirSync(ig5Home, { recursive: true });
process.env.IG5_HOME = ig5Home;

function sha256File(filePath) {
  return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function copyTree(src, dst) {
  if (!fs.existsSync(src)) return;
  const st = fs.statSync(src);
  if (st.isDirectory()) {
    fs.mkdirSync(dst, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      copyTree(path.join(src, entry), path.join(dst, entry));
    }
  } else if (st.isFile()) {
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.copyFileSync(src, dst);
  }
}

function buildEvidenceManifest(rootDir) {
  const files = [];
  function walk(dir) {
    for (const name of fs.readdirSync(dir).sort()) {
      const full = path.join(dir, name);
      const rel = path.relative(rootDir, full).split(path.sep).join('/');
      if (rel === 'manifest.json') continue;
      const st = fs.statSync(full);
      if (st.isDirectory()) walk(full);
      else if (st.isFile()) files.push({ path: rel, bytes: st.size, sha256: sha256File(full) });
    }
  }
  walk(rootDir);
  return {
    schema: 'ig5-evidence-bundle-manifest-v1',
    createdAt: new Date().toISOString(),
    fileCount: files.length,
    files,
  };
}

const fd = fs.openSync(asarPath, 'r');
const sizeBuf = Buffer.alloc(16);
fs.readSync(fd, sizeBuf, 0, 16, 0);
const headerSize = sizeBuf.readUInt32LE(4);
const jsonSize = sizeBuf.readUInt32LE(12);
const headerBuf = Buffer.alloc(jsonSize);
fs.readSync(fd, headerBuf, 0, jsonSize, 16);
const manifest = JSON.parse(headerBuf.toString('utf8'));

const copied = new Set();
const natives = new Set(builtinModules.flatMap(n => [n, `node:${n}`]));
let totalBytes = 0;

function entry(filename) {
  return filename.split('/').reduce((node, part) => node?.files?.[part], manifest);
}

function readAsarFile(filename) {
  const info = entry(filename);
  assert(info && !info.files && !info.unpacked && Number.isSafeInteger(info.size), `Missing ASAR file: ${filename}`);
  totalBytes += info.size;
  assert(totalBytes <= 64 * 1024 * 1024, 'M0 SDK extraction budget exceeded');
  const buf = Buffer.alloc(info.size);
  fs.readSync(fd, buf, 0, buf.length, 8 + headerSize + Number(info.offset));
  return buf;
}

function copyPackage(pkgName) {
  if (copied.has(pkgName) || natives.has(pkgName) || pkgName.startsWith('node:')) return;
  copied.add(pkgName);
  const srcPrefix = `dsh/node_modules/${pkgName}`;
  const rootNode = entry(srcPrefix);
  assert(rootNode?.files, `DSH package absent in app.asar: ${pkgName}`);
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
const appBootPkg = JSON.parse(readAsarFile('dsh/node_modules/@deepseek-ai/dsh-app-boot/package.json').toString('utf8'));
try {
  for (const p of dshPackages) copyPackage(p);
} finally {
  fs.closeSync(fd);
}

function loadPkg(pkgName) {
  const pkgRoot = path.join(sdkDir, 'node_modules', pkgName);
  const meta = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
  const mainRel = meta.exports?.['.']?.import || meta.exports?.['.']?.default || meta.module || meta.main || 'lib/index.js';
  return import(pathToFileURL(path.join(pkgRoot, typeof mainRel === 'string' ? mainRel : 'lib/index.js')).href);
}

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
] = await Promise.all([
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
].map(loadPkg));

const GoalPlugin = goalMod.default || goalMod;
const trackedSourceFiles = [
  'index.js',
  'source/approval_gate.js',
  'source/autonomy_host.js',
  'source/delegation_control.js',
  'source/delegation_execution.js',
  'source/experiment_planner.js',
  'source/investigation_assessment.js',
  'source/investigation_root.js',
  'source/investigation_verifier.js',
  'source/investigation_workflow.js',
];

const activeRuntimeRoot = process.env.IG5_RUNTIME_ROOT || path.join(repoRoot, 'runtimes');
const treeIdentity = computeSourceTreeIdentity(repoRoot);
const report = {
  schema: 'ig5-m0-host-contract-report-v3',
  verifiedAt: new Date().toISOString(),
  evidenceScope: {
    tier: 'host-package-component-integration-plus-native-public-cleanup',
    proves: [
      'Extracted DSH 0.2.2-rc.1 host packages (ToolsService, NativeToolExecutor, SessionStore, AgentRegistry, GoalService, ToolGoal, SystemPrompt) integrated with IG5 index.js',
      'Status-only direct-human messages do NOT clear cancellation latch; explicit resume action is required',
      'Post-cancel + exhausted-budget owner debugger stop passes through public ToolsService.execute + installApprovalGate + real headless x64dbg',
      'Unsupported custom/empty deliverable obligations are denied by update_goal(complete); pre-committed bounded candidate rule + typed CLI input provenance + verified launch witnesses allow update_goal(complete) only for the exact bound host Goal',
    ],
    doesNotClaim: [
      'Not a live Desktop Electron GUI interaction or live LLM autonomous multi-round session',
      'ApprovalService is a deterministic test service returning allowed-once',
    ],
  },
  sourceIdentity: {
    repoRoot,
    packageVersion: JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')).version,
    sourceTreeDigest: treeIdentity.treeDigest,
    sourceTreeFileCount: treeIdentity.fileCount,
    runtimeRoot: activeRuntimeRoot,
    runtimeManifestSha256: fs.existsSync(path.join(activeRuntimeRoot, 'manifest.json'))
      ? sha256File(path.join(activeRuntimeRoot, 'manifest.json'))
      : null,
    sourceSha256: Object.fromEntries(trackedSourceFiles.map(rel => [rel, sha256File(path.join(repoRoot, rel))])),
  },
  host: {
    asarPath,
    desktopVersion: appPkg.version,
    runtimeVersion: appBootPkg.version,
    extractedPackages: copied.size,
  },
  citedReceiptIds: [],
  checks: {},
  documentedGaps: [],
};

const peFixture = buildCliTransformPE64();
const sampleExe = path.join(workspaceDir, 'cli_transform_m0.exe');
fs.writeFileSync(sampleExe, peFixture.image);
const sampleExeSha256 = sha256File(sampleExe);

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

let ctx;
let approvalServiceInstance;
try {
  ctx = new Context();
  class MockApprovalService extends Service {
    constructor(c) {
      super(c, 'approval', true);
      this.requests = [];
      approvalServiceInstance = this;
    }
    async request(req) {
      this.requests.push({
        toolName: req.toolName,
        callId: req.callId,
        signalAbortedAtRequest: Boolean(req.signal?.aborted),
      });
      return 'allowed-once';
    }
  }
  await ctx.plugin(MockApprovalService);
  await ctx.plugin(SystemPrompt, {});
  await ctx.plugin(ToolsService);
  await ctx.plugin(nativeExecMod);
  await ctx.plugin(SessionProjections);
  await ctx.plugin(SessionStore);
  await ctx.plugin(AgentRegistry);
  await ctx.plugin(GoalPlugin, {});
  await ctx.plugin(toolGoalMod, { blockedAfterConsecutiveRounds: 3 });

  let agentFactoryCtx;
  await ctx.plugin(Object.assign(inner => {
    agentFactoryCtx = inner;
  }, { inject: ['tools', 'systemPrompt', 'goals', 'agents', 'sessions'] }));

  await ctx.plugin(ig5Plugin, {
    artifactDir: path.join(ig5Home, 'artifacts'),
    projectRoot: path.join(ig5Home, 'projects'),
    stateRoot: path.join(ig5Home, 'state'),
    toolset: 'full',
  });

  function makeLiveAgent(sessionId) {
    const sess = agentFactoryCtx.sessions.create(sessionId, { meta: { cwd: workspaceDir } });
    const agent = {
      id: sess.id,
      session: sess,
      status: 'idle',
      cancelCalls: [],
      cancel(reason) { this.cancelCalls.push(reason); },
    };
    agent.ctx = createScope(agentFactoryCtx, agent).ctx;
    return agent;
  }

  const rootAgent = makeLiveAgent('root-session-m0');
  await agentFactoryCtx.agents.register(rootAgent);

  let callCounter = 0;
  async function execBatch(agent, calls, signal = new AbortController().signal) {
    return agentFactoryCtx.tools.execute({
      calls: calls.map(c => ({
        id: `call-${++callCounter}`,
        name: c.name,
        arguments: JSON.stringify(c.args || {}),
      })),
      agent,
      signal,
    });
  }

  async function execOk(agent, name, args, signal) {
    const batch = await execBatch(agent, [{ name, args }], signal);
    const item = batch.results[0].result;
    assert.equal(item.isError, false, `Expected ${name} to succeed, got error: ${item.content?.[0]?.text}`);
    return JSON.parse(item.content[0].text);
  }

  async function runInTurn(agent, turnNo, source, fn, text = `turn-${turnNo}`) {
    agent.status = 'running';
    agent.session.append('turn/start', { turn: turnNo });
    agent.session.append('user/message', createUserMessage({
      content: [{ type: 'text', text }],
      source,
    }), { surfaceOp: 'append' });
    try {
      return await agentFactoryCtx.agents.runWithInitiator(agent, fn);
    } finally {
      agent.session.append('turn/end', { turn: turnNo, reason: { kind: 'completed' } });
      agent.status = 'idle';
    }
  }

  // 1) Human turn creates DSH Goal + IG5 root investigation; verify message attribution
  let createdGoal;
  let rootInv;
  await runInTurn(rootAgent, 1, { kind: 'user' }, async () => {
    createdGoal = (await execOk(rootAgent, 'create_goal', {
      objective: 'Recover CLI byte transform and verify holdout',
      max_goal_rounds: 6,
    })).goal;
    assert.equal(createdGoal.phase, 'active');

    const profileOut = await execOk(rootAgent, 'ig5_profile', {});
    assert.equal(profileOut.autonomy.lastMessageSource?.category, 'direct-human');
    assert.equal(profileOut.autonomy.completionGateInstalled, true);
    assert.equal(profileOut.autonomy.directGoalCompleteInterceptable, false);

    rootInv = (await execOk(rootAgent, 'ig5_workspace', {
      workspace: {
        action: 'root-create',
        root: {
          deliverables: [{
            id: 'deliv-1',
            kind: 'io-transform',
            description: 'Verify transform over discovery + holdout inputs',
            requiredObservations: ['static-locate', 'dynamic-runtime-observation'],
            minDistinctInputs: 2,
            holdoutRequired: true,
          }],
        },
      },
    })).workspace;
    assert.equal(rootInv.origin.hostGoalId, createdGoal.id);
    assert.equal(rootInv.origin.kind, 'host-goal');
  });
  report.checks.rootGoalAndMessageAttribution = {
    passed: true,
    goalId: createdGoal.id,
    rootInvestigationId: rootInv.rootId,
  };

  // 2) Deterministic pre-step brief in systemPrompt.context + suppression fallback
  const asm1 = await agentFactoryCtx.systemPrompt.assemble({ scope: rootAgent });
  const asm2 = await agentFactoryCtx.systemPrompt.assemble({ scope: rootAgent });
  const brief1 = asm1.contexts.find(c => c.name === 'ig5:investigation-brief');
  const brief2 = asm2.contexts.find(c => c.name === 'ig5:investigation-brief');
  assert(brief1 && brief1.text.includes(rootInv.rootId), 'ig5:investigation-brief must be assembled for rootAgent');
  assert.equal(brief1.text, brief2.text, 'Brief text must be byte-for-byte deterministic when investigation revision is unchanged');

  const unsuppress = rootAgent.ctx.systemPrompt.suppressRuntimeContext();
  const asmSuppressed = await agentFactoryCtx.systemPrompt.assemble({ scope: rootAgent });
  assert.equal(asmSuppressed.contexts.find(c => c.name === 'ig5:investigation-brief'), undefined);
  const pullBriefOut = await execOk(rootAgent, 'ig5_workspace', {
    workspace: { action: 'root-brief', id: rootInv.rootId },
  });
  assert(pullBriefOut.workspace.brief.includes(rootInv.rootId));
  unsuppress();

  report.checks.deterministicPreStepBrief = {
    passed: true,
    deterministicAcrossUnchangedSteps: true,
    suppressionPullFallbackVerified: true,
  };

  // 3) Pre-commit gate DENIES unverified completion AND DENIES unsupported custom/empty obligations ([P1 #3])
  await runInTurn(rootAgent, 2, {
    kind: 'goal',
    goalId: createdGoal.id,
    revision: createdGoal.revision,
    round: 1,
  }, async () => {
    const prematureComplete = await execBatch(rootAgent, [{
      name: 'update_goal',
      args: { goal_id: createdGoal.id, revision: createdGoal.revision, action: 'complete' },
    }]);
    assert.equal(prematureComplete.results[0].result.isError, true, 'Premature update_goal(complete) must be denied');
    assert.match(prematureComplete.results[0].result.content[0].text, /not verified for completion/i);
    assert.equal(agentFactoryCtx.goals.get(rootAgent).phase, 'active');
  });

  const unsupportedAgent = makeLiveAgent('root-session-unsupported');
  await agentFactoryCtx.agents.register(unsupportedAgent);
  const gUnsupported = agentFactoryCtx.goals.create(unsupportedAgent, { objective: 'Attempt weak custom contract' });
  const invUnsupported = (await execOk(unsupportedAgent, 'ig5_workspace', {
    workspace: {
      action: 'root-create',
      root: {
        deliverables: [{
          id: 'deliv-weak',
          kind: 'custom',
          description: 'Weak custom contract with empty obligations',
          requiredObservations: [],
          holdoutRequired: false,
        }],
      },
    },
  })).workspace;
  await execOk(unsupportedAgent, 'ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: invUnsupported.rootId,
      root: { candidate: { deliverableId: 'deliv-weak', summary: 'Claim only without verifier' } },
    },
  });
  const unsupportedAssess = (await execOk(unsupportedAgent, 'ig5_workspace', {
    workspace: { action: 'assess', id: invUnsupported.rootId },
  })).workspace;
  assert.equal(unsupportedAssess.assessment, 'unsupported');
  assert.equal(unsupportedAssess.canCompleteHostGoal, false);
  await runInTurn(unsupportedAgent, 1, {
    kind: 'goal',
    goalId: gUnsupported.id,
    revision: gUnsupported.revision,
    round: 1,
  }, async () => {
    const deniedWeakComplete = await execBatch(unsupportedAgent, [{
      name: 'update_goal',
      args: { goal_id: gUnsupported.id, revision: gUnsupported.revision, action: 'complete' },
    }]);
    assert.equal(deniedWeakComplete.results[0].result.isError, true, 'Unsupported deliverable kind must block update_goal(complete)');
    assert.equal(agentFactoryCtx.goals.get(unsupportedAgent).phase, 'active');
  });

  report.checks.goalCompletePreCommitDenial = {
    passed: true,
    durableGoalPhaseAfterPrematureDenial: agentFactoryCtx.goals.get(rootAgent).phase,
    unsupportedCustomContractAssessment: unsupportedAssess.assessment,
    durableGoalPhaseAfterUnsupportedDenial: agentFactoryCtx.goals.get(unsupportedAgent).phase,
  };

  // 4) Real DSH ToolsService.execute: tight budget + cancel latch + status-only human message non-clear ([P1 #4])
  //    + public owner debugger cleanup ([P1 #5]) + explicit human resume
  await execOk(rootAgent, 'ig5_open', { path: sampleExe, background: false });
  const cleanupAgent = makeLiveAgent('root-session-public-cleanup');
  await agentFactoryCtx.agents.register(cleanupAgent);
  await execOk(cleanupAgent, 'ig5_profile', { collaboration: { action: 'start', max_calls: 2 } });
  const dbgStart = await execOk(cleanupAgent, 'ig5_dbg', {
    target: sampleExe,
    op: 'start',
    backend: 'x64dbg',
    args: ['X=ABCD'],
    cwd: workspaceDir,
  });
  assert.equal(dbgStart.state, 'suspended');
  if (dbgStart._managedExecution?.reportId) report.citedReceiptIds.push(dbgStart._managedExecution.reportId);

  // Ordinary budget is exhausted because 1 call was used by start and 1 is reserved for owner stop
  const exhaustedRegs = await execBatch(cleanupAgent, [{
    name: 'ig5_dbg',
    args: {
      target: sampleExe,
      op: 'regs',
      backend: 'x64dbg',
      expected_run_id: dbgStart.runId,
      expected_stop_seq: dbgStart.stopSeq,
    },
  }]);
  assert.equal(exhaustedRegs.results[0].result.isError, true);
  assert.match(exhaustedRegs.results[0].result.content[0].text, /budget|exhausted/i);

  // User aborts turn -> latches IG5 cancellation
  cleanupAgent.session.append('turn/start', { turn: 1 });
  cleanupAgent.session.append('turn/end', { turn: 1, reason: { kind: 'aborted', reason: { kind: 'user' } } });

  // Auxiliary non-human notices do NOT clear cancellation
  for (const noticeKind of ['repeat-tool-reminder', 'time-context', 'runtime-context']) {
    cleanupAgent.session.append('user/message', createUserMessage({
      content: [{ type: 'text', text: `[${noticeKind}]` }],
      source: { kind: noticeKind, form: 'notice', summary: noticeKind },
    }), { surfaceOp: 'append' });
  }
  const blockedAfterNotice = await execBatch(cleanupAgent, [{ name: 'ig5_status', args: {} }]);
  assert.equal(blockedAfterNotice.results[0].result.isError, true);

  // [P1 #4]: Ordinary direct-human status message MUST NOT clear cancellation!
  await runInTurn(cleanupAgent, 2, { kind: 'user' }, async () => {
    const stillBlocked = await execBatch(cleanupAgent, [{ name: 'ig5_status', args: {} }]);
    assert.equal(stillBlocked.results[0].result.isError, true, 'Status-only human message must NOT clear cancellation latch');
    assert.match(stillBlocked.results[0].result.content[0].text, /cancellation|cancelled/i);
  }, '现在进展怎么样？先不要继续执行。');

  // [P1 #5]: Under active cancellation + exhausted ordinary budget, public ToolsService.execute allows owner `ig5_dbg op=stop`!
  const approvalsBeforeStop = approvalServiceInstance.requests.length;
  const dbgStopOut = await execOk(cleanupAgent, 'ig5_dbg', {
    target: sampleExe,
    op: 'stop',
    backend: 'x64dbg',
  });
  assert.equal(dbgStopOut.state, 'no-task');
  assert.equal(approvalServiceInstance.requests.length, approvalsBeforeStop + 1, 'Public pre-execute approval gate must run on owner stop');
  if (dbgStopOut._managedExecution?.reportId) report.citedReceiptIds.push(dbgStopOut._managedExecution.reportId);

  // Non-human goal turn attempting root-control resume MUST be rejected!
  await runInTurn(cleanupAgent, 3, { kind: 'goal', goalId: 'goal-nonhuman', revision: 1, round: 1 }, async () => {
    const forgedResume = await execBatch(cleanupAgent, [{
      name: 'ig5_workspace',
      args: { workspace: { action: 'root-control', root: { controlAction: 'resume' } } },
    }]);
    assert.equal(forgedResume.results[0].result.isError, true, 'Non-human turn must not clear cancellation via root-control');
    assert.match(forgedResume.results[0].result.content[0].text, /direct-human/i);
  });

  // Explicit root-control resume inside a direct-human turn clears cancellation; status query works again
  let resumedControl;
  await runInTurn(cleanupAgent, 4, { kind: 'user' }, async () => {
    resumedControl = (await execOk(cleanupAgent, 'ig5_workspace', {
      workspace: {
        action: 'root-control',
        root: { controlAction: 'resume', reason: 'Explicit human resume after verifying debugger teardown' },
      },
    })).workspace;
    assert.equal(resumedControl.cancelled, false);
    const budgetStatus = (await execOk(cleanupAgent, 'ig5_profile', { collaboration: { action: 'status' } })).collaboration;
    assert.equal(budgetStatus.limit, 2);
    assert.equal(budgetStatus.used, 2);
    assert.equal(budgetStatus.reserved, 0);
  }, '确认已清理，现在显式恢复控制状态。');

  // Also verify Goal pause disarms and blocks business dispatch, and model cannot self-resume a paused goal
  const pausedGoal = agentFactoryCtx.goals.pause(rootAgent, { id: createdGoal.id, revision: agentFactoryCtx.goals.get(rootAgent).revision });
  assert.equal(pausedGoal.phase, 'paused');
  assert.equal(pausedGoal.activation, 'disarmed');
  const blockedWhilePaused = await execBatch(rootAgent, [{
    name: 'ig5_workspace',
    args: { workspace: { action: 'root-get', id: rootInv.rootId } },
  }]);
  assert.equal(blockedWhilePaused.results[0].result.isError, true);

  await runInTurn(rootAgent, 3, { kind: 'user' }, async () => {
    const illegalModelResume = await execBatch(rootAgent, [{
      name: 'update_goal',
      args: { goal_id: pausedGoal.id, revision: pausedGoal.revision, action: 'resume' },
    }]);
    assert.equal(illegalModelResume.results[0].result.isError, true, 'DSH rejects model resume of paused goal');
  });

  const resumedGoal = agentFactoryCtx.goals.resume(rootAgent, { id: pausedGoal.id, revision: pausedGoal.revision });
  assert.equal(resumedGoal.phase, 'active');
  assert.equal(resumedGoal.activation, 'armed');

  report.checks.cancelCleanupPauseAndExplicitResume = {
    passed: true,
    noticesDidNotClearCancel: true,
    statusHumanMessageDidNotClearCancel: true,
    publicToolsServiceOwnerCleanupState: dbgStopOut.state,
    nonHumanResumeRejected: true,
    explicitHumanControlResumeGeneration: resumedControl.generation,
    pausedGoalBlockedDispatch: true,
    modelCannotResumePausedGoal: true,
  };

  // 5) Genuine io-transform with executable candidate rule + frozen discovery & holdout receipts ALLOWS update_goal(complete)
  const agentSat = makeLiveAgent('root-session-satisfied');
  await agentFactoryCtx.agents.register(agentSat);
  const gSat = agentFactoryCtx.goals.create(agentSat, { objective: 'Recover CLI byte transform and verify holdout' });
  const invSat = (await execOk(agentSat, 'ig5_workspace', {
    workspace: {
      action: 'root-create',
      root: {
        deliverables: [{
          id: 'deliv-io',
          kind: 'io-transform',
          description: 'Recover exact 4-byte transform over discovery + holdout CLI runs',
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
        component: { componentId: 'comp-m0', path: sampleExe, role: 'main-pe' },
        scenarios: [
          {
            scenarioId: 'm0-disc',
            componentId: 'comp-m0',
            args: ['mode=run', 'X=ABCD'],
            cwd: workspaceDir,
            inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', summary: 'X=ABCD', sampleHex: discHex, caseId: 'disc', isHoldout: false },
          },
          {
            scenarioId: 'm0-hold',
            componentId: 'comp-m0',
            args: ['mode=verify', 'X=1234'],
            cwd: workspaceDir,
            inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', summary: 'X=1234', sampleHex: holdHex, caseId: 'hold', isHoldout: true },
          },
        ],
      },
    },
  });

  const m0Open = await execOk(agentSat, 'ig5_open', {
    path: sampleExe,
    background: false,
    research: { id: invSat.rootId, key: 'm0-open' },
  });
  assert.equal(m0Open.sha256, sampleExeSha256);
  const m0Decomp = await execOk(agentSat, 'ig5_decompile', {
    target: sampleExe,
    ea: peFixture.transformVa,
    research: { id: invSat.rootId, key: 'm0-decomp' },
  });
  report.citedReceiptIds.push(m0Open._managedExecution.reportId, m0Decomp._managedExecution.reportId);

  async function runScenarioRead(scenarioId, kind, cliArgs, expectedHex, prefix) {
    const sel = (await execOk(agentSat, 'ig5_workspace', {
      workspace: {
        action: 'select',
        id: invSat.rootId,
        root: {
          kind,
          scenarioId,
          observer: `breakpoint at ${peFixture.afterTransformRva} + readmem(${peFixture.outBufRva}, 4)`,
          hypothesis: `Verify ${scenarioId} output`,
        },
      },
    })).workspace;
    const st = await execOk(agentSat, 'ig5_dbg', {
      target: sampleExe,
      op: 'start',
      backend: 'x64dbg',
      args: cliArgs,
      cwd: workspaceDir,
      research: { ...sel.researchBinding, key: `${prefix}-start`, step: 0 },
    });
    const en = await execOk(agentSat, 'ig5_dbg', {
      target: sampleExe,
      op: 'cont',
      backend: 'x64dbg',
      expected_run_id: st.runId,
      expected_stop_seq: st.stopSeq,
      research: { ...sel.researchBinding, key: `${prefix}-entry`, step: 1 },
    });
    await execOk(agentSat, 'ig5_dbg', {
      target: sampleExe,
      op: 'bpt',
      backend: 'x64dbg',
      rva: peFixture.afterTransformRva,
      expected_run_id: en.runId,
      expected_stop_seq: en.stopSeq,
      research: { ...sel.researchBinding, key: `${prefix}-bpt`, step: 2 },
    });
    const hit = await execOk(agentSat, 'ig5_dbg', {
      target: sampleExe,
      op: 'cont',
      backend: 'x64dbg',
      expected_run_id: en.runId,
      expected_stop_seq: en.stopSeq,
      research: { ...sel.researchBinding, key: `${prefix}-cont`, step: 3 },
    });
    assert.equal(hit.eventName, 'breakpoint');
    const mem = await execOk(agentSat, 'ig5_dbg', {
      target: sampleExe,
      op: 'readmem',
      backend: 'x64dbg',
      rva: peFixture.outBufRva,
      size: 4,
      expected_run_id: hit.runId,
      expected_stop_seq: hit.stopSeq,
      research: { ...sel.researchBinding, key: `${prefix}-read`, step: 4 },
    });
    assert.equal(mem.hex.toLowerCase(), expectedHex);
    const sp = await execOk(agentSat, 'ig5_dbg', {
      target: sampleExe,
      op: 'stop',
      backend: 'x64dbg',
      research: { id: invSat.rootId, key: `${prefix}-stop` },
    });
    assert.equal(sp.state, 'no-task');
    await execOk(agentSat, 'ig5_workspace', {
      workspace: {
        action: 'evaluate',
        id: invSat.rootId,
        root: {
          expId: sel.experiment.expId,
          observationClass: 'non-empty',
          verdict: 'supports',
          whyNextChanged: `${scenarioId} matched expected transform output`,
          nextAction: 'Proceed with verification',
        },
      },
    });
    report.citedReceiptIds.push(mem._managedExecution.reportId);
    return mem._managedExecution.reportId;
  }

  const m0DiscReceiptId = await runScenarioRead(
    'm0-disc',
    'dynamic-breakpoint-read',
    ['mode=run', 'X=ABCD'],
    computeExpectedCliTransformHex(Buffer.from('ABCD', 'ascii')),
    'm0d',
  );

  // Pre-commit Candidate Revision 1 BEFORE selecting & observing the independent holdout scenario!
  await execOk(agentSat, 'ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: invSat.rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-io',
          summary: 'Exact 4-byte XOR+affine transform committed prior to holdout run',
          outputSpec: { kind: 'memory', rva: peFixture.outBufRva, byteLength: 4 },
          executableRule: executableTransformRule,
          staticReceiptIds: [m0Decomp._managedExecution.reportId],
          testVectors: [
            { caseId: 'disc', receiptId: m0DiscReceiptId },
          ],
        },
      },
    },
  });

  const m0HoldReceiptId = await runScenarioRead(
    'm0-hold',
    'holdout-verify',
    ['mode=verify', 'X=1234'],
    computeExpectedCliTransformHex(Buffer.from('1234', 'ascii')),
    'm0h',
  );

  await execOk(agentSat, 'ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: invSat.rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-io',
          summary: 'Exact 4-byte XOR+affine transform verified on discovery + holdout CLI runs',
          outputSpec: { kind: 'memory', rva: peFixture.outBufRva, byteLength: 4 },
          executableRule: executableTransformRule,
          staticReceiptIds: [m0Decomp._managedExecution.reportId],
          testVectors: [
            { caseId: 'disc', receiptId: m0DiscReceiptId },
            { caseId: 'hold', receiptId: m0HoldReceiptId },
          ],
        },
      },
    },
  });
  await execOk(agentSat, 'ig5_close', { target: sampleExe });

  await runInTurn(agentSat, 1, { kind: 'goal', goalId: gSat.id, revision: gSat.revision, round: 1 }, async () => {
    const okComplete = await execBatch(agentSat, [{
      name: 'update_goal',
      args: { goal_id: gSat.id, revision: gSat.revision, action: 'complete' },
    }]);
    assert.equal(
      okComplete.results[0].result.isError,
      false,
      `Independently verified io-transform investigation must pass update_goal(complete): ${okComplete.results[0].result.content?.[0]?.text}`,
    );
    assert.equal(agentFactoryCtx.goals.get(agentSat).phase, 'complete');
  });

  // Verify Goal switching on the SAME session (`agentSat`): clearing `gSat` and creating `gNext` MUST NOT reuse `invSat`!
  agentFactoryCtx.goals.clear(agentSat, { id: gSat.id, revision: agentFactoryCtx.goals.get(agentSat).revision });
  const gNext = agentFactoryCtx.goals.create(agentSat, { objective: 'Recover second distinct stage on same session' });
  await runInTurn(agentSat, 2, { kind: 'goal', goalId: gNext.id, revision: gNext.revision, round: 1 }, async () => {
    const deniedNextComplete = await execBatch(agentSat, [{
      name: 'update_goal',
      args: { goal_id: gNext.id, revision: gNext.revision, action: 'complete' },
    }]);
    assert.equal(deniedNextComplete.results[0].result.isError, true, 'Subsequent Goal B on same session must NOT complete using Goal A investigation');
    assert.equal(agentFactoryCtx.goals.get(agentSat).phase, 'active');
  });

  report.checks.goalCompletePreCommitAllowWhenSatisfied = {
    passed: true,
    finalGoalPhase: 'complete',
    subsequentGoalOnSameSessionDeniedWithoutOwnVerification: true,
    discoveryReceiptId: m0DiscReceiptId,
    holdoutReceiptId: m0HoldReceiptId,
  };

  // 6) Direct ctx.goals.complete bypass detection on another session
  const agent2 = makeLiveAgent('root-session-bypass');
  await agentFactoryCtx.agents.register(agent2);
  const g2 = agentFactoryCtx.goals.create(agent2, { objective: 'Test direct RPC complete divergence' });
  const inv2 = (await execOk(agent2, 'ig5_workspace', {
    workspace: { action: 'root-create', goal: 'Test divergence' },
  })).workspace;

  agentFactoryCtx.goals.complete(agent2, { id: g2.id, revision: g2.revision });
  const assess2 = (await execOk(agent2, 'ig5_workspace', {
    workspace: { action: 'assess', id: inv2.rootId },
  })).workspace;
  assert.equal(assess2.assessment, 'unverified');
  assert.equal(assess2.hostGoalState, 'complete');
  assert.equal(assess2.goalAssessmentAligned, false);
  assert.equal(assess2.hostCompletedWithoutInvestigationAcceptance, true);

  report.checks.directHostCompleteDivergenceDetected = {
    passed: true,
    hostGoalState: assess2.hostGoalState,
    investigationAssessment: assess2.assessment,
    goalAssessmentAligned: assess2.goalAssessmentAligned,
  };

  report.documentedGaps = [
    {
      id: 'DSH-GAP-DIRECT-GOAL-COMPLETE',
      component: '@deepseek-ai/dsh-goal GoalService.complete',
      finding: 'Desktop UI @Remote("complete") mutates GoalService directly without ToolsService pre-execute/guard hooks.',
      degradation: 'IG5 intercepts all model-initiated update_goal(action="complete") calls before commit, and on direct host GoalService.complete records goalAssessmentAligned=false / hostCompletedWithoutInvestigationAcceptance=true without promoting investigation assessment.',
    },
    {
      id: 'DSH-GAP-CUMULATIVE-TOOL-BUDGET',
      component: '@deepseek-ai/dsh-goal-round-driver',
      finding: 'Host bounds maxGoalRounds and per-step maxTokens only; no cross-round cumulative plugin tool/cost budget service exists.',
      degradation: 'IG5 DelegationControl enforces persistent root+descendant max_calls with pre-reserved owner resource cleanup.',
    },
    {
      id: 'DSH-GAP-OPTIONAL-RUNTIME-CONTEXT-SUPPRESSION',
      component: '@deepseek-ai/dsh-system-prompt suppressRuntimeContext',
      finding: 'Host presets may suppress non-required runtime-context sections.',
      degradation: 'ig5:investigation-brief auto-projects when enabled; ig5_workspace root-brief/root-resume provides deterministic pull fallback.',
    },
  ];

  // Dispose plugin fiber cleanly BEFORE exporting evidence so all workers/locks flush cleanly
  await ctx.fiber.dispose();
  ctx = null;

  const evidenceDir = process.env.IG5_M0_EVIDENCE_DIR ? path.resolve(process.env.IG5_M0_EVIDENCE_DIR) : null;
  if (evidenceDir) {
    fs.rmSync(evidenceDir, { recursive: true, force: true });
    fs.mkdirSync(evidenceDir, { recursive: true });
    copyTree(path.join(ig5Home, 'projects'), path.join(evidenceDir, 'projects'));
    copyTree(path.join(ig5Home, 'artifacts'), path.join(evidenceDir, 'artifacts'));
    fs.copyFileSync(sampleExe, path.join(evidenceDir, 'cli_transform_m0.exe'));
    fs.writeFileSync(path.join(evidenceDir, 'summary.json'), JSON.stringify(report, null, 2) + '\n', 'utf8');
    const bundleManifest = buildEvidenceManifest(evidenceDir);
    fs.writeFileSync(path.join(evidenceDir, 'manifest.json'), JSON.stringify(bundleManifest, null, 2) + '\n', 'utf8');
    for (const rid of report.citedReceiptIds) {
      const recFile = path.join(evidenceDir, 'artifacts', 'analysis-data', 'records', `${rid}.json`);
      assert(fs.existsSync(recFile), `Preserved M0 evidence bundle must contain receipt record ${rid}`);
    }
    assert(fs.existsSync(path.join(evidenceDir, 'artifacts', 'approvals.jsonl')), 'Preserved M0 evidence bundle must contain approvals.jsonl');
  }

  const outPath = process.env.IG5_M0_REPORT_PATH;
  if (outPath) {
    fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
    fs.writeFileSync(path.resolve(outPath), JSON.stringify(report, null, 2) + '\n', 'utf8');
  }
  console.log(`PASS M0 DSH ${appBootPkg.version} host-package component integration (${Object.keys(report.checks).length} contract groups verified)`);
} finally {
  try { await ctx?.fiber?.dispose(); } catch { /* ignore teardown error */ }
  assert(tempRoot.startsWith(fs.realpathSync(os.tmpdir()) + path.sep));
  try { fs.rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* Windows file handle release delay */ }
}
