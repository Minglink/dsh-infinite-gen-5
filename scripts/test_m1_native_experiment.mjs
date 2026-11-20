// M1 Scripted Real Native Closed-Loop Experiment Verification.
// Scope: Executes a root investigation closed loop through IG5 public tools (`index.js` apply + public
// `tools/pre-execute` approval gate + `runManagedToolExecution` + `tools/post-execute` audit log)
// over a self-produced benign PE64 CLI binary using REAL bundled Ghidra + REAL headless x64dbg:
//   1. root-create -> registerComponent -> root-plan -> real Ghidra static locate (ig5_open, ig5_funcs, ig5_bytes, ig5_decompile)
//   2. Exp 1: unhit-breakpoint scenario (`args=['help']`) selected verbatim from `root-plan` -> `not-triggered` (rejects fake negative)
//   3. Exp 2: discovery scenario (`args=['mode=run','X=ABCD']`, `cwd=runCwd`) -> breakpoint hit, regs + readmem
//             verifies real OS GetCurrentDirectoryA (`cwd`), exact retransmission after stop, IDEMPOTENCY_CONFLICT,
//             refutes naive identity hypothesis (retaining counterexample cx-1), and commits Candidate Revision 1 (`executableRule`)
//   4. Exp 3: independent holdout scenario (`args=['mode=verify','X=1234']`, `isHoldout=true`) bound to Candidate Revision 1 ->
//             resolves counterexample -> verbatim `root-plan` `assess-deliverables` & `cleanup-owned-resource` ->
//             independent bounded-transform execution over frozen scenarios satisfies assessment
//   5. Tight shared budget (`max_calls=2`) + cancellation on real headless x64dbg: `start` pre-reserves `stop`,
//      blocks `regs`, and allows cancelled owner `stop` through the PUBLIC `tools/pre-execute` gate with an aborted signal!
// Boundary: Target addresses, inputs, and sequence are scripted in this test (M1 proves the execution/receipt/verifier
// chain over real native engines; M2 proves unscripted model route selection).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as ig5Plugin from '../index.js';
import { buildCliTransformPE64, computeExpectedCliTransformHex } from './fixtures/pe64-cli-transform.mjs';
import { computeSourceTreeIdentity } from './lib/source_tree_identity.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..');
const defaultDonorRuntimes = 'C:\\Users\\Administrator\\Desktop\\无限五代\\dsh-infinite-gen-5\\runtimes';
if (!process.env.IG5_RUNTIME_ROOT && !fs.existsSync(path.join(repoRoot, 'runtimes', 'manifest.json')) && fs.existsSync(defaultDonorRuntimes)) {
  process.env.IG5_RUNTIME_ROOT = defaultDonorRuntimes;
}

const tempRoot = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-m1-native-exp-'));
const workspaceDir = path.join(tempRoot, 'workspace');
const runCwd = path.join(workspaceDir, 'scenario-cwd');
const ig5Home = path.join(tempRoot, 'ig5-home');
fs.mkdirSync(runCwd, { recursive: true });
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

const tools = new Map();
const eventListeners = new Map();
const effects = [];
const approvalRequests = [];
const approvalService = {
  async request(req) {
    approvalRequests.push({
      toolName: req.toolName,
      callId: req.callId,
      signalAbortedAtRequest: Boolean(req.signal?.aborted),
    });
    return 'allowed-once';
  },
};

const hostCtx = {
  tools: {
    register(def) {
      tools.set(def.name, def);
      return () => tools.delete(def.name);
    },
    get(name) { return tools.get(name); },
  },
  get(name) {
    if (name === 'tools') return hostCtx.tools;
    if (name === 'approval') return approvalService;
    if (name === 'agents') return { get: id => agentsById.get(id), roots: () => [...agentsById.values()] };
    return undefined;
  },
  on(name, handler) {
    const set = eventListeners.get(name) || new Set();
    if (name.startsWith('tools/')) assert.equal(set.size, 0, 'Single tools/* middleware invariant');
    set.add(handler);
    eventListeners.set(name, set);
    return () => set.delete(handler);
  },
  inject(names, cb) {
    const d = names.every(n => hostCtx.get(n)) ? cb({ get: hostCtx.get, tools: hostCtx.tools }) : undefined;
    if (typeof d === 'function') effects.push(d);
    return { dispose: async () => { if (typeof d === 'function') await d(); } };
  },
  effect(fn) {
    const d = fn();
    if (typeof d === 'function') effects.push(d);
  },
};

const agentsById = new Map();
function makeRootAgent(id) {
  const agent = {
    id,
    session: { header: { id, cwd: workspaceDir } },
  };
  agentsById.set(id, agent);
  return agent;
}

const rootAgent = makeRootAgent('m1-root-agent');
const budgetAgent = makeRootAgent('m1-tight-budget-agent');

let callSeq = 0;
async function callTool(name, args = {}, { agent = rootAgent, signal = new AbortController().signal } = {}) {
  const def = tools.get(name);
  assert(def, `Public tool "${name}" must be registered`);
  const callId = `m1-call-${++callSeq}`;
  const preHandlers = [...(eventListeners.get('tools/pre-execute') || [])];
  for (const h of preHandlers) {
    const decision = await h({ name, arguments: args, agent, callId, signal }, async () => ({ kind: 'allow' }));
    if (decision && decision.kind !== 'allow') {
      throw Object.assign(new Error(decision.reason || `Tool ${name} ${decision.kind}`), { code: 'PRE_EXECUTE_DENIED', decision });
    }
  }
  const value = await def.execute(args, { agent, callId, signal });
  const postHandlers = [...(eventListeners.get('tools/post-execute') || [])];
  for (const h of postHandlers) {
    await h({ name, arguments: args, agent, callId, signal }, { isError: false, value }, async () => ({ kind: 'accept' }));
  }
  return value;
}

function invokePlanned(candidate, extraArgs = {}) {
  assert(candidate && candidate.operationExecutableNow === true && candidate.request, 'Candidate must be executable now');
  const { tool, ...toolArgs } = candidate.request;
  return callTool(tool, { ...toolArgs, ...extraArgs });
}

const peFixture = buildCliTransformPE64();
const targetExe = path.join(workspaceDir, 'cli_transform_m1.exe');
fs.writeFileSync(targetExe, peFixture.image);
const targetSha256 = sha256File(targetExe);

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
const evidenceReport = {
  schema: 'ig5-m1-native-experiment-report-v3',
  executedAt: new Date().toISOString(),
  evidenceScope: {
    tier: 'scripted-real-native-closed-loop',
    proves: [
      'Real bundled Ghidra + real headless x64dbg executed through public IG5 tools, pre-execute approval gate, managed execution receipts, and post-execute audit log',
      'Root-plan executable candidates (select-discriminating-experiment, assess-deliverables, cleanup-owned-resource) execute verbatim against public tools',
      'Typed CLI input provenance (argIndex=1, prefix=X=, encoding=ascii), mandatory ig5_dbg:start launch witnesses, pre-committed Candidate Revision 1, and independent bounded-transform AST evaluation over real native memory receipts',
      'Tight budget (max_calls=2) + active cancellation + aborted caller AbortSignal permits owner debugger stop through the public pre-execute gate without internal bypass',
    ],
    doesNotClaim: [
      'Target RVAs and CLI payloads are scripted in this test; autonomous model route selection and address discovery belong to M2 blind evaluation',
      'Host context here is a lightweight harness invoking tools/pre-execute -> execute -> tools/post-execute (DSH package integration is covered by M0)',
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
  target: {
    path: targetExe,
    sha256: targetSha256,
    bytes: peFixture.image.length,
    afterTransformRva: peFixture.afterTransformRva,
    keyRva: peFixture.keyRva,
    outBufRva: peFixture.outBufRva,
    cwdBufRva: peFixture.cwdBufRva,
  },
  citedReceiptIds: [],
  stages: {},
};

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

try {
  ig5Plugin.apply(hostCtx, {
    artifactDir: path.join(ig5Home, 'artifacts'),
    projectRoot: path.join(ig5Home, 'projects'),
    stateRoot: path.join(ig5Home, 'state'),
    toolset: 'full',
  });

  // 1) Root investigation created BEFORE opening any static database
  const rootCreated = (await callTool('ig5_workspace', {
    workspace: {
      action: 'root-create',
      goal: 'Recover the 4-byte CLI X=<payload> transformation in cli_transform_m1.exe and verify on an independent holdout input',
      root: {
        deliverables: [{
          id: 'deliv-transform',
          kind: 'io-transform',
          description: 'Recover exact 4-byte output formula from X=<4-bytes> CLI input and verify discovery + holdout outputs',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation'],
          minDistinctInputs: 2,
          holdoutRequired: true,
        }],
      },
    },
  })).workspace;
  const rootId = rootCreated.rootId;

  // Register component + short route (no scenario yet -> verify planner proposes non-executable template prepare-runtime-scenario)
  await callTool('ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: rootId,
      root: {
        component: { componentId: 'comp-pe', path: targetExe, role: 'main-pe' },
        route: {
          routeId: 'route-1',
          deliverableId: 'deliv-transform',
          question: 'How does transform_block transform the 4 bytes after X=?',
          targetObservation: 'Key bytes at .data 0x3000 and runtime output bytes at 0x3100 after transform_block returns',
          missingPrerequisites: ['static-rva', 'runtime-scenario'],
          preparationSteps: ['ig5_open', 'ig5_funcs', 'ig5_bytes', 'ig5_decompile'],
          preparationBudgetCalls: 6,
          discriminatingExperiment: 'Start in headless x64dbg with CLI args, break at afterTransformRva, read regs and outBuf',
        },
      },
    },
  });
  const preScenarioPlan = (await callTool('ig5_workspace', {
    workspace: { action: 'root-plan', id: rootId },
  })).workspace;
  const prepScenCand = preScenarioPlan.candidates.find(c => c.kind === 'prepare-runtime-scenario');
  assert(prepScenCand, 'Planner must propose prepare-runtime-scenario when dynamic route lacks scenarios');
  assert.equal(prepScenCand.operationExecutableNow, false);
  assert.equal(prepScenCand.request, null);
  assert(Array.isArray(prepScenCand.missingParameters) && prepScenCand.missingParameters.length > 0);

  // 2) Real Ghidra static inspection with inline research bindings
  const openRes = await callTool('ig5_open', {
    path: targetExe,
    background: false,
    research: { id: rootId, key: 'm1-open', note: 'Open benign CLI PE in bundled Ghidra' },
  });
  assert.equal(openRes.sha256, targetSha256);

  const funcsRes = await callTool('ig5_funcs', {
    target: targetExe,
    research: { id: rootId, key: 'm1-funcs', note: 'Locate entry and transform_block functions' },
  });
  const funcsList = Array.isArray(funcsRes.funcs) ? funcsRes.funcs : [];
  assert(funcsList.length >= 2, `Ghidra ig5_funcs must return at least entry and transform_block, got ${funcsList.length}`);

  const keyBytesRes = await callTool('ig5_bytes', {
    target: targetExe,
    ea: peFixture.keyVa,
    size: 4,
    research: { id: rootId, key: 'm1-key-bytes', note: 'Read 4-byte key table at 0x140003000' },
  });
  assert.equal(keyBytesRes.hex.slice(0, 8).toLowerCase(), '5aa533cc');

  const decompRes = await callTool('ig5_decompile', {
    target: targetExe,
    ea: peFixture.transformVa,
    research: { id: rootId, key: 'm1-decomp', note: 'Decompile transform_block at 0x140001080' },
  });
  assert(typeof decompRes.code === 'string' && decompRes.code.length > 20);
  evidenceReport.citedReceiptIds.push(
    openRes._managedExecution.reportId,
    funcsRes._managedExecution.reportId,
    keyBytesRes._managedExecution.reportId,
    decompRes._managedExecution.reportId,
  );

  evidenceReport.stages.staticGhidra = {
    openReceiptId: openRes._managedExecution.reportId,
    funcsReceiptId: funcsRes._managedExecution.reportId,
    funcsCount: funcsList.length,
    discoveredFuncAddresses: funcsList.slice(0, 8).map(f => f.ea || f.address || f.name),
    keyHex: keyBytesRes.hex.slice(0, 8),
    decompileReceiptId: decompRes._managedExecution.reportId,
    decompiledSnippet: decompRes.code.slice(0, 240),
  };

  // 3) Experiment 1: Real x64dbg run with `args=['help']` selected VERBATIM from `root-plan`!
  await callTool('ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: rootId,
      root: {
        scenario: {
          scenarioId: 'scen-help',
          componentId: 'comp-pe',
          args: ['help'],
          cwd: runCwd,
          trigger: 'Pass CLI arg "help" without X= prefix',
        },
        route: {
          routeId: 'route-1',
          deliverableId: 'deliv-transform',
          question: 'How does transform_block transform the 4 bytes after X=?',
          targetObservation: `breakpoint at RVA ${peFixture.afterTransformRva}`,
          missingPrerequisites: [],
          discriminatingExperiment: 'Generic "help" CLI argument triggers transform_block',
        },
      },
    },
  });
  const readyPlan1 = (await callTool('ig5_workspace', {
    workspace: { action: 'root-plan', id: rootId },
  })).workspace;
  const verbatimSelectCand = readyPlan1.candidates.find(c => c.kind === 'select-discriminating-experiment');
  assert(verbatimSelectCand && verbatimSelectCand.operationExecutableNow === true);
  // Execute planner's exact `request` verbatim with zero edits!
  const exp1Sel = (await invokePlanned(verbatimSelectCand)).workspace;

  const e1Start = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'start',
    backend: 'x64dbg',
    args: ['help'],
    cwd: runCwd,
    research: { ...exp1Sel.researchBinding, key: 'e1-start', step: 0 },
  });
  assert.equal(e1Start.state, 'suspended');
  assert.deepEqual(e1Start.launchScenario?.argv, ['help']);

  const e1Entry = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'cont',
    backend: 'x64dbg',
    expected_run_id: e1Start.runId,
    expected_stop_seq: e1Start.stopSeq,
    research: { ...exp1Sel.researchBinding, key: 'e1-entry', step: 1 },
  });
  assert.equal(e1Entry.state, 'suspended');

  await callTool('ig5_dbg', {
    target: targetExe,
    op: 'bpt',
    backend: 'x64dbg',
    rva: peFixture.afterTransformRva,
    expected_run_id: e1Entry.runId,
    expected_stop_seq: e1Entry.stopSeq,
    research: { ...exp1Sel.researchBinding, key: 'e1-bpt', step: 2 },
  });

  const e1Cont = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'cont',
    backend: 'x64dbg',
    expected_run_id: e1Entry.runId,
    expected_stop_seq: e1Entry.stopSeq,
    research: { ...exp1Sel.researchBinding, key: 'e1-cont', step: 3 },
  });
  assert.equal(e1Cont.state, 'no-task', 'Without X= marker, debuggee exits cleanly without hitting afterTransformRva');

  await assert.rejects(
    () => callTool('ig5_workspace', {
      workspace: {
        action: 'evaluate',
        id: rootId,
        root: {
          expId: exp1Sel.experiment.expId,
          observationClass: 'negative-within-verified-scope',
          triggerConfirmed: true,
          observerConfirmed: true,
          verdict: 'inconclusive',
          whyNextChanged: 'Should reject',
          nextAction: 'Should reject',
        },
      },
    }),
    err => err.code === 'UNVERIFIED_NEGATIVE_SCOPE',
  );

  await callTool('ig5_workspace', {
    workspace: {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: exp1Sel.experiment.expId,
        observationClass: 'not-triggered',
        verdict: 'inconclusive',
        newObservations: ['Process exited to no-task without reaching afterTransformRva because GetCommandLineA lacked "X="'],
        whyNextChanged: 'Entry scan requires "X=<4-bytes>" in CLI arguments; add discovery scenario with X=ABCD',
        nextAction: 'Define scen-discovery with args=["mode=run","X=ABCD"] and run breakpoint read',
      },
    },
  });
  evidenceReport.stages.experiment1NotTriggered = {
    expId: exp1Sel.experiment.expId,
    selectedVerbatimFromPlanner: true,
    contState: e1Cont.state,
    contReason: e1Cont.reason || null,
    classifiedAs: 'not-triggered',
  };

  // 4) Experiment 2: Discovery scenario `args=['mode=run','X=ABCD']`, `cwd=runCwd`
  const discInputHex = Buffer.from('ABCD', 'ascii').toString('hex'); // 41424344
  const discExpectedHex = computeExpectedCliTransformHex(Buffer.from('ABCD', 'ascii')); // 1ef181a0

  await callTool('ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: rootId,
      root: {
        scenario: {
          scenarioId: 'scen-discovery',
          componentId: 'comp-pe',
          args: ['mode=run', 'X=ABCD'],
          cwd: runCwd,
          inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', summary: 'X=ABCD', sampleHex: discInputHex, caseId: 'disc-abcd', isHoldout: false },
          trigger: 'Pass X=ABCD on CLI so entry invokes transform_block',
        },
      },
    },
  });

  const exp2Sel = (await callTool('ig5_workspace', {
    workspace: {
      action: 'select',
      id: rootId,
      root: {
        kind: 'dynamic-breakpoint-read',
        routeId: 'route-1',
        scenarioId: 'scen-discovery',
        observer: `breakpoint at RVA ${peFixture.afterTransformRva} + regs + readmem(outBuf,cwdBuf)`,
        hypothesis: 'Naive hypothesis: output buffer equals raw ASCII input 41424344 without key schedule',
      },
    },
  })).workspace;

  const e2Start = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'start',
    backend: 'x64dbg',
    args: ['mode=run', 'X=ABCD'],
    cwd: runCwd,
    research: { ...exp2Sel.researchBinding, key: 'e2-start', step: 0 },
  });
  assert.equal(e2Start.state, 'suspended');

  const e2Entry = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'cont',
    backend: 'x64dbg',
    expected_run_id: e2Start.runId,
    expected_stop_seq: e2Start.stopSeq,
    research: { ...exp2Sel.researchBinding, key: 'e2-entry', step: 1 },
  });
  assert.equal(e2Entry.state, 'suspended');

  await callTool('ig5_dbg', {
    target: targetExe,
    op: 'bpt',
    backend: 'x64dbg',
    rva: peFixture.afterTransformRva,
    expected_run_id: e2Entry.runId,
    expected_stop_seq: e2Entry.stopSeq,
    research: { ...exp2Sel.researchBinding, key: 'e2-bpt', step: 2 },
  });

  const e2Cont = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'cont',
    backend: 'x64dbg',
    expected_run_id: e2Entry.runId,
    expected_stop_seq: e2Entry.stopSeq,
    research: { ...exp2Sel.researchBinding, key: 'e2-cont', step: 3 },
  });
  assert.equal(e2Cont.state, 'suspended');
  assert.equal(e2Cont.eventName, 'breakpoint');

  const e2Regs = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'regs',
    backend: 'x64dbg',
    expected_run_id: e2Cont.runId,
    expected_stop_seq: e2Cont.stopSeq,
    research: { ...exp2Sel.researchBinding, key: 'e2-regs', step: 4 },
  });

  const e2OutReadArgs = {
    target: targetExe,
    op: 'readmem',
    backend: 'x64dbg',
    rva: peFixture.outBufRva,
    size: 4,
    expected_run_id: e2Cont.runId,
    expected_stop_seq: e2Cont.stopSeq,
    research: { ...exp2Sel.researchBinding, key: 'e2-read-out', step: 5 },
  };
  const e2OutMem = await callTool('ig5_dbg', e2OutReadArgs);
  assert.equal(e2OutMem.hex.toLowerCase(), discExpectedHex);
  evidenceReport.citedReceiptIds.push(e2Start._managedExecution.reportId, e2OutMem._managedExecution.reportId);

  const e2CwdMem = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'readmem',
    backend: 'x64dbg',
    rva: peFixture.cwdBufRva,
    size: 160,
    expected_run_id: e2Cont.runId,
    expected_stop_seq: e2Cont.stopSeq,
    research: { ...exp2Sel.researchBinding, key: 'e2-read-cwd', step: 6 },
  });
  const cwdBytes = Buffer.from(e2CwdMem.hex, 'hex');
  const nulIdx = cwdBytes.indexOf(0);
  const observedLiveCwd = cwdBytes.subarray(0, nulIdx >= 0 ? nulIdx : cwdBytes.length).toString('utf8');
  assert.equal(path.resolve(observedLiveCwd).toLowerCase(), path.resolve(runCwd).toLowerCase(), 'Debuggee OS working directory must match scenario cwd');

  const e2Stop = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'stop',
    backend: 'x64dbg',
    research: { id: rootId, key: 'e2-stop' },
  });
  assert.equal(e2Stop.state, 'no-task');

  // Exact retransmission AFTER debuggee stopped (`no-task`): must return original receipt without failing on stale runId/stopSeq!
  const replayedOutMem = await callTool('ig5_dbg', e2OutReadArgs);
  assert.equal(replayedOutMem._managedExecution.replayed, true);
  assert.equal(replayedOutMem._managedExecution.reportId, e2OutMem._managedExecution.reportId);
  assert.equal(replayedOutMem.hex.toLowerCase(), discExpectedHex);

  // Same request key with altered parameter (`size: 8`) must fail with IDEMPOTENCY_CONFLICT!
  await assert.rejects(
    () => callTool('ig5_dbg', { ...e2OutReadArgs, size: 8 }),
    err => err.code === 'IDEMPOTENCY_CONFLICT',
  );

  // Evaluate Exp 2 as refuting naive identity -> retains counterexample cx-1!
  const eval2 = (await callTool('ig5_workspace', {
    workspace: {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: exp2Sel.experiment.expId,
        observationClass: 'non-empty',
        verdict: 'refutes',
        newObservations: [`Input 41424344 (ABCD) produced ${discExpectedHex}, refuting naive identity`],
        prerequisiteChanges: [{ prerequisite: 'static-rva', status: 'established' }, { prerequisite: 'runtime-scenario', status: 'established' }],
        candidateChanges: 'Formulated exact executable rule out[i] = ((in[i] ^ K[i]) + (i*7 + 3)) & 0xff with K=[5a,a5,33,cc]',
        whyNextChanged: 'Identity refuted; commit Candidate Revision 1 and test on independent holdout input X=1234',
        nextAction: 'Commit Candidate Revision 1, create holdout scenario X=1234, and verify output 6ea11110',
      },
    },
  })).workspace;
  assert.equal(eval2.counterexample.status, 'unresolved');

  // Commit Candidate Revision 1 BEFORE selecting the holdout experiment so holdout binds to Candidate Revision 1's ruleSha256!
  const candRev1 = (await callTool('ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-transform',
          summary: 'CLI parameter X=<4-bytes> is transformed by out[i] = ((in[i] ^ K[i]) + (i*7 + 3)) & 0xff with K=[0x5a,0xa5,0x33,0xcc]',
          rule: 'out[i] = ((in[i] ^ [0x5a,0xa5,0x33,0xcc][i]) + (i*7 + 3)) & 0xff',
          outputSpec: { kind: 'memory', rva: peFixture.outBufRva, byteLength: 4 },
          executableRule: executableTransformRule,
          staticReceiptIds: [decompRes._managedExecution.reportId],
          testVectors: [
            { caseId: 'disc-abcd', receiptId: e2OutMem._managedExecution.reportId },
          ],
        },
      },
    },
  })).workspace;
  assert.equal(candRev1.updated.candidate.candidateRevision, 1);

  evidenceReport.stages.experiment2Discovery = {
    expId: exp2Sel.experiment.expId,
    runId: e2Start.runId,
    raxAtAfterTransform: e2Regs.regs.rax,
    observedOutputHex: e2OutMem.hex,
    expectedOutputHex: discExpectedHex,
    observedDebuggeeCwd: observedLiveCwd,
    readReceiptId: e2OutMem._managedExecution.reportId,
    replayedAfterStopVerified: true,
    retainedCounterexampleId: eval2.counterexample.counterexampleId,
    candidateRevisionBeforeHoldout: candRev1.updated.candidate.candidateRevision,
    candidateRuleSha256: candRev1.updated.candidate.candidateExplanation.ruleSha256,
  };

  // 5) Experiment 3: Independent Holdout Scenario `X=1234` (`31323334` -> `6ea11110`) bound to Candidate Revision 1
  const holdInputHex = Buffer.from('1234', 'ascii').toString('hex'); // 31323334
  const holdExpectedHex = computeExpectedCliTransformHex(Buffer.from('1234', 'ascii')); // 6ea11110

  await callTool('ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: rootId,
      root: {
        scenario: {
          scenarioId: 'scen-holdout',
          componentId: 'comp-pe',
          args: ['mode=verify', 'X=1234'],
          cwd: runCwd,
          inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', summary: 'Holdout X=1234', sampleHex: holdInputHex, caseId: 'hold-1234', isHoldout: true },
          trigger: 'Pass holdout X=1234 on CLI',
        },
      },
    },
  });

  const exp3Sel = (await callTool('ig5_workspace', {
    workspace: {
      action: 'select',
      id: rootId,
      root: {
        kind: 'holdout-verify',
        routeId: 'route-1',
        scenarioId: 'scen-holdout',
        observer: `breakpoint at RVA ${peFixture.afterTransformRva} + readmem(outBuf)`,
        hypothesis: `Formula ((in[i] ^ K[i]) + (i*7 + 3)) & 0xff predicts ${holdInputHex} -> ${holdExpectedHex}`,
      },
    },
  })).workspace;
  assert.equal(exp3Sel.experiment.boundCandidateRuleSha256, candRev1.updated.candidate.candidateExplanation.ruleSha256);

  const e3Start = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'start',
    backend: 'x64dbg',
    args: ['mode=verify', 'X=1234'],
    cwd: runCwd,
    research: { ...exp3Sel.researchBinding, key: 'e3-start', step: 0 },
  });
  const e3Entry = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'cont',
    backend: 'x64dbg',
    expected_run_id: e3Start.runId,
    expected_stop_seq: e3Start.stopSeq,
    research: { ...exp3Sel.researchBinding, key: 'e3-entry', step: 1 },
  });
  await callTool('ig5_dbg', {
    target: targetExe,
    op: 'bpt',
    backend: 'x64dbg',
    rva: peFixture.afterTransformRva,
    expected_run_id: e3Entry.runId,
    expected_stop_seq: e3Entry.stopSeq,
    research: { ...exp3Sel.researchBinding, key: 'e3-bpt', step: 2 },
  });
  const e3Cont = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'cont',
    backend: 'x64dbg',
    expected_run_id: e3Entry.runId,
    expected_stop_seq: e3Entry.stopSeq,
    research: { ...exp3Sel.researchBinding, key: 'e3-cont', step: 3 },
  });
  assert.equal(e3Cont.eventName, 'breakpoint');

  const e3OutMem = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'readmem',
    backend: 'x64dbg',
    rva: peFixture.outBufRva,
    size: 4,
    expected_run_id: e3Cont.runId,
    expected_stop_seq: e3Cont.stopSeq,
    research: { ...exp3Sel.researchBinding, key: 'e3-read-out', step: 4 },
  });
  assert.equal(e3OutMem.hex.toLowerCase(), holdExpectedHex);
  evidenceReport.citedReceiptIds.push(e3Start._managedExecution.reportId, e3OutMem._managedExecution.reportId);

  await callTool('ig5_workspace', {
    workspace: {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: exp3Sel.experiment.expId,
        observationClass: 'non-empty',
        verdict: 'supports',
        resolveCounterexampleId: eval2.counterexample.counterexampleId,
        newObservations: [`Holdout 31323334 (1234) produced exact predicted ${holdExpectedHex}`],
        whyNextChanged: 'Holdout verified formula and resolved counterexample cx-1',
        nextAction: 'Attach holdout receipt to Candidate Revision 1, stop debugger, and assess',
      },
    },
  });

  await callTool('ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-transform',
          summary: 'CLI parameter X=<4-bytes> is transformed by out[i] = ((in[i] ^ K[i]) + (i*7 + 3)) & 0xff with K=[0x5a,0xa5,0x33,0xcc]',
          rule: 'out[i] = ((in[i] ^ [0x5a,0xa5,0x33,0xcc][i]) + (i*7 + 3)) & 0xff',
          outputSpec: { kind: 'memory', rva: peFixture.outBufRva, byteLength: 4 },
          executableRule: executableTransformRule,
          staticReceiptIds: [decompRes._managedExecution.reportId],
          testVectors: [
            { caseId: 'disc-abcd', receiptId: e2OutMem._managedExecution.reportId },
            { caseId: 'hold-1234', receiptId: e3OutMem._managedExecution.reportId },
          ],
        },
      },
    },
  });

  // Execute `assess-deliverables` and `cleanup-owned-resource` VERBATIM from `root-plan`!
  const planWhileDbgOpen = (await callTool('ig5_workspace', {
    workspace: { action: 'root-plan', id: rootId },
  })).workspace;
  const assessCand = planWhileDbgOpen.candidates.find(c => c.kind === 'assess-deliverables');
  const cleanupCand = planWhileDbgOpen.candidates.find(c => c.kind === 'cleanup-owned-resource');
  assert(assessCand && assessCand.operationExecutableNow === true);
  assert(cleanupCand && cleanupCand.operationExecutableNow === true);

  const assessWhileDbgOpen = (await invokePlanned(assessCand)).workspace;
  assert.equal(assessWhileDbgOpen.assessment, 'satisfied');
  assert.equal(assessWhileDbgOpen.cleanup, 'pending');
  assert.equal(assessWhileDbgOpen.canCompleteHostGoal, false, 'Pending debugger cleanup must block host goal completion');

  // Stop debuggee using planner's verbatim cleanup request!
  const e3Stop = await invokePlanned(cleanupCand, {
    research: { id: rootId, key: 'e3-stop' },
  });
  assert.equal(e3Stop.state, 'no-task');
  evidenceReport.citedReceiptIds.push(e3Stop._managedExecution.reportId);

  const finalAssess = (await invokePlanned(assessCand)).workspace;
  assert.equal(finalAssess.assessment, 'satisfied');
  assert.equal(finalAssess.cleanup, 'confirmed');
  assert.equal(finalAssess.canCompleteHostGoal, true);
  assert.equal(finalAssess.deliverables[0].verifiedReceipts.length, 3);

  evidenceReport.stages.experiment3HoldoutAndAcceptance = {
    expId: exp3Sel.experiment.expId,
    holdoutObservedHex: e3OutMem.hex,
    holdoutExpectedHex: holdExpectedHex,
    holdoutReceiptId: e3OutMem._managedExecution.reportId,
    assessBeforeStop: {
      assessment: assessWhileDbgOpen.assessment,
      cleanup: assessWhileDbgOpen.cleanup,
      canCompleteHostGoal: assessWhileDbgOpen.canCompleteHostGoal,
    },
    finalAssessment: {
      assessment: finalAssess.assessment,
      cleanup: finalAssess.cleanup,
      canCompleteHostGoal: finalAssess.canCompleteHostGoal,
      candidateRuleSha256: finalAssess.deliverables[0].candidateRuleSha256,
      verifiedReceipts: finalAssess.deliverables[0].verifiedReceipts,
    },
  };

  // 6) Tight Shared Budget (`max_calls = 2`) + Active Cancellation + Aborted Caller Signal on REAL headless x64dbg:
  //    MUST pass through the PUBLIC `callTool` (`tools/pre-execute` -> `approvalService` -> `execute` -> `tools/post-execute`)
  //    with ZERO direct `.execute(...)` bypass!
  await callTool('ig5_profile', {
    collaboration: { action: 'start', max_calls: 2 },
  }, { agent: budgetAgent });

  const bStart = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'start',
    backend: 'x64dbg',
    args: ['X=ZZZZ'],
    cwd: runCwd,
  }, { agent: budgetAgent });
  assert.equal(bStart.state, 'suspended');
  if (bStart._managedExecution?.reportId) evidenceReport.citedReceiptIds.push(bStart._managedExecution.reportId);

  await assert.rejects(
    () => callTool('ig5_dbg', {
      target: targetExe,
      op: 'regs',
      backend: 'x64dbg',
      expected_run_id: bStart.runId,
      expected_stop_seq: bStart.stopSeq,
    }, { agent: budgetAgent }),
    err => err.code === 'IG5_SHARED_BUDGET_EXHAUSTED',
  );

  // Latch cancellation on budgetAgent via public root-control cancel
  const cancelledControl = (await callTool('ig5_workspace', {
    workspace: { action: 'root-control', root: { controlAction: 'cancel', reason: 'User cancelled tight-budget turn' } },
  }, { agent: budgetAgent })).workspace;
  assert.equal(cancelledControl.cancelled, true);

  // Non-owner agent trying `op=stop` with an aborted signal MUST be rejected at `tools/pre-execute`!
  const abortedCtrl = new AbortController();
  abortedCtrl.abort('user-cancelled');
  await assert.rejects(
    () => callTool('ig5_dbg', { target: targetExe, op: 'stop', backend: 'x64dbg' }, { agent: rootAgent, signal: abortedCtrl.signal }),
    err => err.code === 'PRE_EXECUTE_DENIED' && err.decision?.kind === 'cancel',
  );

  // Actual owner (`budgetAgent`) calling public `callTool` with `abortedCtrl.signal` under active cancel latch + 0 ordinary budget SUCCEEDS!
  const approvalsBeforeEmergencyStop = approvalRequests.length;
  const bStop = await callTool('ig5_dbg', {
    target: targetExe,
    op: 'stop',
    backend: 'x64dbg',
  }, { agent: budgetAgent, signal: abortedCtrl.signal });
  assert.equal(bStop.state, 'no-task');
  assert.equal(approvalRequests.length, approvalsBeforeEmergencyStop + 1, 'Public pre-execute approval gate must run and pass bounded non-aborted signal');
  assert.equal(approvalRequests.at(-1).signalAbortedAtRequest, false);
  if (bStop._managedExecution?.reportId) evidenceReport.citedReceiptIds.push(bStop._managedExecution.reportId);

  const budgetAfterStop = (await callTool('ig5_profile', {
    collaboration: { action: 'status' },
  }, { agent: budgetAgent })).collaboration;
  assert.equal(budgetAfterStop.limit, 2);
  assert.equal(budgetAfterStop.used, 2);
  assert.equal(budgetAfterStop.reserved, 0);

  evidenceReport.stages.realDebuggerTightBudgetPublicCleanup = {
    budgetLimit: budgetAfterStop.limit,
    budgetUsed: budgetAfterStop.used,
    budgetReserved: budgetAfterStop.reserved,
    cancelledLatchActive: true,
    callerSignalAborted: true,
    passedThroughPublicPreExecuteGate: true,
    stopStateUnderAbortedSignal: bStop.state,
    stopReceiptId: bStop._managedExecution?.reportId || null,
  };

  await callTool('ig5_close', { target: targetExe });

  // Cleanly dispose all registered plugin effects BEFORE snapshotting evidence so all workers/locks flush cleanly!
  for (const fn of effects.splice(0).reverse()) {
    await fn();
  }

  const evidenceDir = process.env.IG5_M1_EVIDENCE_DIR ? path.resolve(process.env.IG5_M1_EVIDENCE_DIR) : null;
  if (evidenceDir) {
    fs.rmSync(evidenceDir, { recursive: true, force: true });
    fs.mkdirSync(evidenceDir, { recursive: true });
    copyTree(path.join(ig5Home, 'projects'), path.join(evidenceDir, 'projects'));
    copyTree(path.join(ig5Home, 'artifacts'), path.join(evidenceDir, 'artifacts'));
    fs.copyFileSync(targetExe, path.join(evidenceDir, 'cli_transform_m1.exe'));
    fs.writeFileSync(path.join(evidenceDir, 'summary.json'), JSON.stringify(evidenceReport, null, 2) + '\n', 'utf8');
    const bundleManifest = buildEvidenceManifest(evidenceDir);
    fs.writeFileSync(path.join(evidenceDir, 'manifest.json'), JSON.stringify(bundleManifest, null, 2) + '\n', 'utf8');
    for (const rid of evidenceReport.citedReceiptIds) {
      const recFile = path.join(evidenceDir, 'artifacts', 'analysis-data', 'records', `${rid}.json`);
      assert(fs.existsSync(recFile), `Preserved M1 evidence bundle must contain receipt record ${rid}`);
    }
    assert(fs.existsSync(path.join(evidenceDir, 'artifacts', 'approvals.jsonl')), 'Preserved M1 evidence bundle must contain approvals.jsonl');
  }

  const outPath = process.env.IG5_M1_REPORT_PATH;
  if (outPath) {
    fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
    fs.writeFileSync(path.resolve(outPath), JSON.stringify(evidenceReport, null, 2) + '\n', 'utf8');
  }
  console.log(`PASS M1 scripted real native Ghidra + headless x64dbg closed-loop experiment (${targetSha256.slice(0, 16)})`);
} finally {
  for (const fn of effects.splice(0).reverse()) {
    try { await fn(); } catch { /* ignore */ }
  }
  assert(tempRoot.startsWith(fs.realpathSync(os.tmpdir()) + path.sep));
  try { fs.rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* ignore */ }
}
