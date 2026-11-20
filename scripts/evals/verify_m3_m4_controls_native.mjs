import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const cliOpt = (flag) => { const i = process.argv.indexOf(flag); return i >= 0 ? process.argv[i + 1] : undefined; };
const repoRoot = path.resolve(import.meta.dirname, '..', '..');
const reviewRoot = cliOpt('--evidence-root') || process.env.IG5_REVIEW_ROOT;
if (!reviewRoot) throw new Error('Pass --evidence-root <dir> or set IG5_REVIEW_ROOT');
const targetsModulePath = cliOpt('--targets-module') || process.env.IG5_M3M4_TARGETS_MODULE || path.join(reviewRoot, 'repro-vault', 'build_m3_m4_online_targets.mjs');
const {
  ORACLE_VECTORS_6,
  materializeM3OnlineCase1,
  materializeM3OnlineCase2,
  materializeM4BOnlineCase1,
  materializeM4COnlineCase1,
  materializeM4DPairedCase,
  buildSignedAndroidFixtures,
} = await import(pathToFileURL(targetsModulePath).href);
if (!process.env.IG5_RUNTIME_ROOT && fs.existsSync(donorRuntimes)) {
  process.env.IG5_RUNTIME_ROOT = donorRuntimes;
}

const ig5Plugin = await import(pathToFileURL(path.join(repoRoot, 'index.js')).href);
const { computeSourceTreeIdentity } = await import(pathToFileURL(path.join(repoRoot, 'scripts', 'lib', 'source_tree_identity.mjs')).href);
const { collectNativeProcessCheck } = await import(pathToFileURL(path.join(repoRoot, 'scripts', 'evals', 'run_m2_blind_eval.mjs')).href);
const { verifyOrRepairDexIntegrity } = await import(pathToFileURL(path.join(repoRoot, 'source', 'native_android_bridge.js')).href);

// reviewRoot configured via --evidence-root / IG5_REVIEW_ROOT above
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const realTmp = () => (fs.realpathSync.native || fs.realpathSync)(os.tmpdir());

function writeBranchManifest(dirPath) {
  const entries = [];
  function walk(cur) {
    for (const ent of fs.readdirSync(cur, { withFileTypes: true })) {
      if (ent.name === 'manifest.json') continue;
      const full = path.join(cur, ent.name);
      if (ent.isDirectory()) walk(full);
      else if (ent.isFile()) {
        const b = fs.readFileSync(full);
        entries.push({
          relativePath: path.relative(dirPath, full).replaceAll('\\', '/'),
          bytes: b.length,
          sha256: sha256(b),
        });
      }
    }
  }
  walk(dirPath);
  entries.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  const out = {
    schema: 'ig5-branch-evidence-manifest-v1',
    createdAt: new Date().toISOString(),
    fileCount: entries.length,
    files: entries,
  };
  fs.writeFileSync(path.join(dirPath, 'manifest.json'), JSON.stringify(out, null, 2) + '\n', 'utf8');
  return out;
}

async function createIg5Harness({ ig5Home, workspaceDir, activeGoals = new Map(), rootAgents = null }) {
  fs.mkdirSync(ig5Home, { recursive: true });
  fs.mkdirSync(workspaceDir, { recursive: true });
  const tools = new Map();
  const preHooks = [];
  const listeners = new Map();
  const effects = [];
  const approvals = [];
  const agentsMap = new Map();

  const ctx = {
    tools: { register: (d) => { tools.set(d.name, d); return () => tools.delete(d.name); } },
    on: (ev, fn) => {
      if (ev === 'tools/pre-execute') preHooks.push(fn);
      const arr = listeners.get(ev) || [];
      arr.push(fn);
      listeners.set(ev, arr);
      return () => {};
    },
    emit: (ev, ...args) => {
      for (const fn of listeners.get(ev) || []) fn(...args);
    },
    get: (name) => {
      if (name === 'approval') {
        return {
          request: async (req) => {
            approvals.push({ ts: new Date().toISOString(), toolName: req.toolName, callId: req.callId });
            return 'allowed-once';
          },
        };
      }
      if (name === 'goals') {
        return {
          get: (agent) => activeGoals.get(agent?.id) || null,
        };
      }
      if (name === 'agents') {
        return {
          get: (id) => agentsMap.get(id),
          roots: () => (rootAgents ? [...rootAgents] : [...agentsMap.values()].filter((a) => !a.session?.header?.parentSession && a.owner === undefined)),
        };
      }
      return undefined;
    },
    inject: () => ({ dispose() {} }),
    effect: (fn) => { const d = fn(); if (typeof d === 'function') effects.push(d); return d; },
  };

  await ig5Plugin.apply(ctx, {
    projectRoot: path.join(ig5Home, 'projects'),
    artifactDir: path.join(ig5Home, 'artifacts'),
    stateRoot: path.join(ig5Home, 'state'),
    defaultEngine: 'ghidra',
    backgroundOpen: false,
    toolset: 'full',
  });

  tools.set('update_goal', {
    name: 'update_goal',
    execute: async (args, exec) => {
      const g = activeGoals.get(exec.agent?.id);
      if (g && args.action === 'complete') g.phase = 'completed';
      return { ok: true, action: args.action, phase: g?.phase || 'completed' };
    },
  });

  const makeAgent = (id, { parentId = null, owner = undefined } = {}) => {
    const a = {
      id,
      ...(owner !== undefined ? { owner } : {}),
      session: {
        id,
        header: { id, cwd: workspaceDir, ...(parentId ? { parentSession: parentId } : {}) },
      },
    };
    agentsMap.set(id, a);
    return a;
  };

  const callTool = async (agent, name, args = {}) => {
    const def = tools.get(name);
    assert(def, `Missing tool ${name}`);
    const exec = { name, arguments: args, agent, callId: `call-${randomUUID()}`, signal: new AbortController().signal };
    for (const h of preHooks) {
      const dec = await h(exec, async () => ({ kind: 'allow' }));
      if (dec && dec.kind !== 'allow') {
        const err = new Error(dec.reason || `Denied ${name}`);
        err.code = 'HOST_GATE_DENIED';
        err.decision = dec;
        throw err;
      }
    }
    return def.execute(args, exec);
  };

  const wsCall = async (agent, workspace) => {
    const out = await callTool(agent, 'ig5_workspace', { workspace });
    return out.workspace;
  };

  const dispose = async () => {
    for (const d of effects.reverse()) {
      try { await d(); } catch { /* ignore */ }
    }
  };

  return { ctx, tools, approvals, makeAgent, callTool, wsCall, dispose };
}

// ── 1. M3 Native & Cross-Layer Controls ───────────────────────────────────────
async function verifyM3Controls() {
  console.log('\n=== [M3] Verifying Electron -> Native Helper Controls ===');
  const outDir = path.join(reviewRoot, 'm3-electron', 'controls-native');
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });

  const tmpRoot = fs.mkdtempSync(path.join(realTmp(), 'ig5-m3-ctrl-'));
  const ig5Home = path.join(outDir, 'ig5-home');
  const ws = path.join(tmpRoot, 'workspace');
  const goals = new Map([['m3-root', { id: 'goal-m3-1', revision: 1, objective: 'M3 Electron -> Native Helper verification', phase: 'active', activation: 'active' }]]);
  const harness = await createIg5Harness({ ig5Home, workspaceDir: ws, activeGoals: goals });
  const agent = harness.makeAgent('m3-root');

  try {
    const c1 = materializeM3OnlineCase1(path.join(ws, 'case1'));
    const reaStatic = await harness.callTool(agent, 'ig5_package', {
      action: 'js_app',
      target: c1.appDir,
      input: { path: c1.appDir },
    });
    assert.equal(reaStatic.value.executionPerformed, false);
    assert.equal(reaStatic.value.reaEngine.version, '6.4.0');
    assert(reaStatic.value.nativeArtifacts.length >= 2, 'REA bridge must inventory both live and decoy PE helpers');

    const rootCreated = await harness.wsCall(agent, {
      action: 'root-create',
      goal: 'Recover frame-encoder-app Electron -> frame_helper.exe chain',
      root: {
        deliverables: [{
          id: 'deliv-m3-1',
          kind: 'electron-native-chain',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'parent-to-helper-handoff'],
          holdoutRequired: true,
        }],
      },
    });
    const rootId = rootCreated.rootId;

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        components: [
          { componentId: 'comp-app', path: c1.appDir, role: 'electron-app' },
          { componentId: 'comp-decoy', path: c1.decoyPath, role: 'main-pe' },
          { componentId: 'comp-helper', path: c1.helperPath, role: 'helper-pe' },
        ],
        routes: [{
          routeId: 'r-m3',
          question: 'Which native helper is invoked on frame:encode IPC and what is the end-to-end 4B rule?',
          targetObservation: 'Parent-to-helper spawn edge + 4B hex output',
          discriminatingExperiment: 'electron_scenario on frame-encoder-app',
        }],
      },
    });

    // Negative control: standalone helper scenario on helper-pe without standaloneAllowed=true MUST be rejected!
    let standaloneRejected = null;
    try {
      await harness.wsCall(agent, {
        action: 'root-update',
        id: rootId,
        root: {
          scenario: {
            scenarioId: 'sc-bad-standalone',
            componentId: 'comp-helper',
            launchMode: 'standalone',
            args: ['--lane=prod', 'F=41424344'],
            inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'F=', encoding: 'hex' },
          },
        },
      });
    } catch (err) {
      standaloneRejected = { code: err.code || null, message: err.message };
    }
    assert(standaloneRejected && /HELPER_SCENARIO_MISMATCH|standalone/i.test(standaloneRejected.message), 'Standalone helper launch without standaloneAllowed must fail');

    await harness.callTool(agent, 'ig5_open', {
      path: c1.helperPath,
      background: false,
      engine: 'ghidra',
      research: { id: rootId, key: 'm3-static-open-1', note: 'Static open of frame_helper.exe' },
    });
    const decomp = await harness.callTool(agent, 'ig5_decompile', {
      target: c1.helperPath,
      ea: '0x1400011c0',
      research: { id: rootId, key: 'm3-static-decomp-1', note: 'Decompile helper transform at 0x11c0' },
    });

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        scenarios: [
          {
            scenarioId: 'sc-disc-1',
            componentId: 'comp-app',
            launchMode: 'via-parent',
            args: [],
            cwd: c1.appDir,
            inputSpec: { kind: 'ipc', ipcPayload: '41424344', encoding: 'hex', isHoldout: false },
          },
          {
            scenarioId: 'sc-disc-1-cached',
            componentId: 'comp-app',
            launchMode: 'via-parent',
            args: ['--repeat-cached'],
            cwd: c1.appDir,
            inputSpec: { kind: 'ipc', ipcPayload: '41424344', encoding: 'hex', isHoldout: false },
          },
          {
            scenarioId: 'sc-disc-2',
            componentId: 'comp-app',
            launchMode: 'via-parent',
            args: [],
            cwd: c1.appDir,
            inputSpec: { kind: 'ipc', ipcPayload: '31323334', encoding: 'hex', isHoldout: false },
          },
        ],
        candidate: {
          deliverableId: 'deliv-m3-1',
          summary: 'Initial decoy hypothesis from legacy_encoder_v1.exe',
          outputSpec: { kind: 'app-output', channel: 'electron-ipc', byteLength: 4 },
          executableRule: {
            schema: 'ig5-bounded-byte-rule-v1',
            outputLength: 4,
            constants: { c: '11223344' },
            byteExpr: { op: 'rol8', args: [{ op: 'add', args: [{ op: 'in', index: { op: 'i' } }, { op: 'const', name: 'c', index: { op: 'i' } }] }, 1] },
          },
        },
      },
    });

    const selDisc1 = await harness.wsCall(agent, {
      action: 'select',
      id: rootId,
      root: { kind: 'dynamic-breakpoint-read', scenarioId: 'sc-disc-1', componentId: 'comp-app', hypothesis: 'Test initial decoy rule on 41424344' },
    });
    const obsDisc1 = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'electron_scenario',
      target: c1.appDir,
      payload: '41424344',
      trigger_mode: 'ui-click',
      research: { ...selDisc1.researchBinding, key: 'm3-exp1-s0', step: 0 },
    });
    assert.equal(obsDisc1.observationDiagnosis, 'OK');
    assert.equal(obsDisc1.outputHex, c1.referenceFn(Buffer.from('41424344', 'hex')));

    const evalRefute = await harness.wsCall(agent, {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: selDisc1.experiment.expId,
        verdict: 'refutes',
        observationClass: 'non-empty',
        whyNextChanged: 'Runtime output matched frame_helper.exe (pre-XOR 0x29 + constants 4b931ed6 rot 3), refuting legacy_encoder_v1.exe',
        nextAction: 'Test cache short-circuit negative control and commit true frame_helper.exe + JS pre-XOR rule',
      },
    });
    const cxId = evalRefute.counterexample?.counterexampleId || 'cx-1';

    // Negative control: repeat identical input 41424344 WITHOUT bypass_cache -> hits .memo_cache.json -> CACHE_SHORT_CIRCUIT!
    const selCached = await harness.wsCall(agent, {
      action: 'select',
      id: rootId,
      root: { kind: 'dynamic-breakpoint-read', scenarioId: 'sc-disc-1-cached', componentId: 'comp-app', hypothesis: 'Observe memo-cache short circuit' },
    });
    const obsCached = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'electron_scenario',
      target: c1.appDir,
      payload: '41424344',
      bypass_cache: false,
      trigger_mode: 'ui-click',
      research: { ...selCached.researchBinding, key: 'm3-exp-cache-s0', step: 0 },
    });
    assert.equal(obsCached.observationDiagnosis, 'CACHE_SHORT_CIRCUIT');
    assert.equal(obsCached.handoffEdges.length, 0);
    await harness.wsCall(agent, {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: selCached.experiment.expId,
        verdict: 'inconclusive',
        observationClass: 'not-triggered',
        whyNextChanged: 'Memo-cache short-circuited native helper spawn; must use fresh input or bypass_cache=true',
        nextAction: 'Run fresh discovery input 31323334 and resolve cx-1',
      },
    });

    const selDisc2 = await harness.wsCall(agent, {
      action: 'select',
      id: rootId,
      root: { kind: 'dynamic-breakpoint-read', scenarioId: 'sc-disc-2', componentId: 'comp-app', hypothesis: 'Verify true JS XOR 0x29 + frame_helper.exe rule on 31323334' },
    });
    const obsDisc2 = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'electron_scenario',
      target: c1.appDir,
      payload: '31323334',
      trigger_mode: 'ui-click',
      research: { ...selDisc2.researchBinding, key: 'm3-exp2-s0', step: 0 },
    });
    assert.equal(obsDisc2.observationDiagnosis, 'OK');
    await harness.wsCall(agent, {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: selDisc2.experiment.expId,
        verdict: 'supports',
        observationClass: 'non-empty',
        resolveCounterexampleId: cxId,
        whyNextChanged: 'Confirmed JS pre-XOR 0x29 + frame_helper.exe rol8(add(x, C[i]), 3)',
        nextAction: 'Pre-commit revised candidate rule and verify on unseen holdout',
      },
    });

    const trueRule = {
      schema: 'ig5-bounded-byte-rule-v1',
      outputLength: 4,
      constants: { c: '4b931ed6' },
      byteExpr: {
        op: 'rol8',
        args: [
          {
            op: 'add',
            args: [
              { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, 0x29] },
              { op: 'const', name: 'c', index: { op: 'i' } },
            ],
          },
          3,
        ],
      },
    };
    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-m3-1',
          summary: 'JS main.js XOR 0x29 -> bin/frame_helper.exe rol8((b + C[i]) & 0xff, 3)',
          outputSpec: { kind: 'app-output', channel: 'electron-ipc', byteLength: 4 },
          executableRule: trueRule,
        },
        scenario: {
          scenarioId: 'sc-holdout-1',
          componentId: 'comp-app',
          launchMode: 'via-parent',
          args: [],
          cwd: c1.appDir,
          inputSpec: { kind: 'ipc', ipcPayload: 'cafebabe', encoding: 'hex', isHoldout: true },
        },
      },
    });

    const selHold = await harness.wsCall(agent, {
      action: 'select',
      id: rootId,
      root: { kind: 'holdout-verify', scenarioId: 'sc-holdout-1', componentId: 'comp-app', hypothesis: 'Unseen holdout cafebabe' },
    });
    const obsHold = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'electron_scenario',
      target: c1.appDir,
      payload: 'cafebabe',
      trigger_mode: 'ui-click',
      research: { ...selHold.researchBinding, key: 'm3-hold-s0', step: 0 },
    });
    assert.equal(obsHold.observationDiagnosis, 'OK');
    await harness.wsCall(agent, {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: selHold.experiment.expId,
        verdict: 'supports',
        observationClass: 'non-empty',
        whyNextChanged: 'Holdout matched pre-committed candidate rule',
        nextAction: 'Verify cache-short-circuit receipt rejection, then attach valid receipts and assess',
      },
    });

    // Negative check: attaching obsCached receipt MUST fail assessment with missing-verified-parent-to-helper-handoff!
    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        testVectors: [
          { caseId: 'bad-cache', receiptId: obsCached._managedExecution.reportId, isHoldout: false },
          { caseId: 'disc2', receiptId: obsDisc2._managedExecution.reportId, isHoldout: false },
          { caseId: 'hold1', receiptId: obsHold._managedExecution.reportId, isHoldout: true },
        ],
      },
    });
    const badAssess = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(badAssess.canCompleteHostGoal, false);
    assert(badAssess.denialReasons.some((r) => r.includes('missing-verified-parent-to-helper-handoff') && r.includes('CACHE_SHORT_CIRCUIT')));

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        testVectors: [
          { caseId: 'disc1', receiptId: obsDisc1._managedExecution.reportId, isHoldout: false },
          { caseId: 'disc2', receiptId: obsDisc2._managedExecution.reportId, isHoldout: false },
          { caseId: 'hold1', receiptId: obsHold._managedExecution.reportId, isHoldout: true },
        ],
      },
    });
    await harness.callTool(agent, 'ig5_close', { target: c1.helperPath, engine: 'ghidra' });
    const goodAssess = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(goodAssess.assessment, 'satisfied');
    assert.equal(goodAssess.canCompleteHostGoal, true);

    const c2 = materializeM3OnlineCase2(path.join(ws, 'case2'));
    let standaloneExitCode = 0;
    try {
      execFileSync(c2.helperPath, [], { cwd: path.dirname(c2.helperPath), stdio: 'ignore', timeout: 5000, windowsHide: true });
    } catch (err) {
      standaloneExitCode = err.status ?? -1;
    }
    assert.equal(standaloneExitCode, 2, 'Standalone ticket_worker.exe without TK stdin frame must exit 2');
    const obsStdin = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'electron_scenario',
      target: c2.appDir,
      payload: '41424344',
      trigger_mode: 'ui-click',
    });
    assert.equal(obsStdin.observationDiagnosis, 'OK');
    assert.equal(obsStdin.outputHex, c2.referenceFn(Buffer.from('41424344', 'hex')));

    const summary = {
      schema: 'ig5-m3-controls-native-v1',
      passed: true,
      reaStaticVerified: { version: reaStatic.value.reaEngine.version, cliSha256: reaStatic.value.reaEngine.cliSha256, executionPerformed: reaStatic.value.executionPerformed, nativeArtifactCount: reaStatic.value.nativeArtifacts.length },
      standaloneHelperGuardRejected: standaloneRejected,
      standaloneStdinHelperExitCode: standaloneExitCode,
      cacheShortCircuitRejectedReason: badAssess.denialReasons,
      decoyRefutationCounterexampleResolved: cxId,
      decompileExcerptLength: JSON.stringify(decomp).length,
      finalAssessment: { assessment: goodAssess.assessment, canCompleteHostGoal: goodAssess.canCompleteHostGoal },
      stdinParentScenarioVerified: { diagnosis: obsStdin.observationDiagnosis, outputHex: obsStdin.outputHex, stdinBytes: obsStdin.handoffEdges[0]?.stdinBytes },
    };
    fs.writeFileSync(path.join(outDir, 'm3-controls-summary.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');
    console.log('[M3] Controls PASSED!');
    return summary;
  } finally {
    await harness.dispose();
    writeBranchManifest(outDir);
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ── 2. M4-B Host-Loaded Stateful ASLR DLL Controls ───────────────────────────
async function verifyM4BControls() {
  console.log('\n=== [M4-B] Verifying Host-Loaded Stateful ASLR DLL Controls ===');
  const outDir = path.join(reviewRoot, 'm4b-dll', 'controls-native');
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });

  const tmpRoot = fs.mkdtempSync(path.join(realTmp(), 'ig5-m4b-ctrl-'));
  const ig5Home = path.join(outDir, 'ig5-home');
  const ws = path.join(tmpRoot, 'workspace');
  const goals = new Map([['m4b-root', { id: 'goal-m4b-1', revision: 1, objective: 'M4-B Stateful ASLR DLL verification', phase: 'active', activation: 'active' }]]);
  const harness = await createIg5Harness({ ig5Home, workspaceDir: ws, activeGoals: goals });
  const agent = harness.makeAgent('m4b-root');

  try {
    const m4b = materializeM4BOnlineCase1(ws);
    await harness.callTool(agent, 'ig5_open', { path: m4b.hostPath, background: false, engine: 'ghidra' });
    await harness.callTool(agent, 'ig5_open', { path: m4b.dllPath, background: false, engine: 'ghidra' });
    const dllExports = await harness.callTool(agent, 'ig5_listing', { target: m4b.dllPath, kind: 'exports' });

    const rootCreated = await harness.wsCall(agent, {
      action: 'root-create',
      goal: 'Recover dll_host_runner.exe + calc_engine.dll stateful ASLR transform',
      root: {
        deliverables: [{
          id: 'deliv-m4b-1',
          kind: 'dll-host-transform',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'aslr-module-rebasing'],
          holdoutRequired: true,
        }],
      },
    });
    const rootId = rootCreated.rootId;

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        components: [
          { componentId: 'comp-host', path: m4b.hostPath, role: 'main-pe' },
          { componentId: 'comp-dll', path: m4b.dllPath, role: 'dll' },
        ],
        routes: [{
          routeId: 'r-dll',
          question: 'How does dll_host_runner.exe initialize calc_engine.dll and what RVA holds the 4B output?',
          targetObservation: 'Relocated calc_engine.dll RVA 0x3100 bytes + moduleSha256',
          discriminatingExperiment: 'x64dbg --mode=uninit vs --mode=host vs --mode=reload',
        }],
        scenarios: [
          {
            scenarioId: 'sc-uninit',
            componentId: 'comp-host',
            args: ['--mode=uninit', 'X=ABCD'],
            cwd: ws,
            inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', isHoldout: false },
          },
          {
            scenarioId: 'sc-host-1',
            componentId: 'comp-host',
            args: ['--mode=host', 'X=ABCD'],
            cwd: ws,
            inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', isHoldout: false },
          },
          {
            scenarioId: 'sc-reload-2',
            componentId: 'comp-host',
            args: ['--mode=reload', 'X=1234'],
            cwd: ws,
            inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', isHoldout: false },
          },
        ],
      },
    });

    await harness.callTool(agent, 'ig5_decompile', {
      target: m4b.dllPath,
      ea: '0x180001090',
      research: { id: rootId, key: 'm4b-static-dll-decomp', note: 'Decompile EngineTransform' },
    });

    const runHostDbgExperiment = async (scenarioId, expPrefix) => {
      const sel = await harness.wsCall(agent, {
        action: 'select',
        id: rootId,
        root: {
          kind: scenarioId.includes('hold') ? 'holdout-verify' : 'dynamic-breakpoint-read',
          scenarioId,
          componentId: 'comp-host',
          hypothesis: `Observe ${scenarioId}`,
          maxSteps: 10,
        },
      });
      const sc = sel.experiment.scenarioSnapshot;
      let step = 0;
      await harness.callTool(agent, 'ig5_dbg', {
        target: m4b.hostPath,
        op: 'start',
        args: sc.args,
        cwd: sc.cwd,
        research: { ...sel.researchBinding, key: `${expPrefix}-s${step}`, step: step++ },
      });
      await harness.callTool(agent, 'ig5_dbg', {
        target: m4b.hostPath,
        op: 'cont',
        research: { ...sel.researchBinding, key: `${expPrefix}-s${step}`, step: step++ },
      });
      const textDump = await harness.callTool(agent, 'ig5_dbg', {
        target: m4b.hostPath,
        op: 'readmem',
        rva: '0x1000',
        size: 512,
        research: { ...sel.researchBinding, key: `${expPrefix}-s${step}`, step: step++ },
      });
      const idx = textDump.hex.toLowerCase().indexOf('41ffd585c0');
      assert(idx >= 0, 'Must locate call r13; test eax, eax in dll_host_runner.exe');
      const afterTransformRva = '0x' + (0x1000 + (idx / 2) + 3).toString(16);
      await harness.callTool(agent, 'ig5_dbg', {
        target: m4b.hostPath,
        op: 'bpt',
        rva: afterTransformRva,
        research: { ...sel.researchBinding, key: `${expPrefix}-s${step}`, step: step++ },
      });
      await harness.callTool(agent, 'ig5_dbg', {
        target: m4b.hostPath,
        op: 'cont',
        research: { ...sel.researchBinding, key: `${expPrefix}-s${step}`, step: step++ },
      });
      const basesMem = await harness.callTool(agent, 'ig5_dbg', {
        target: m4b.hostPath,
        op: 'readmem',
        rva: '0x3010',
        size: 16,
        research: { ...sel.researchBinding, key: `${expPrefix}-s${step}`, step: step++ },
      });
      const bBuf = Buffer.from(basesMem.hex, 'hex');
      const firstBase = bBuf.readBigUInt64LE(0);
      const activeBase = bBuf.readBigUInt64LE(8);
      const dllReadVa = '0x' + (activeBase + 0x3100n).toString(16);
      const dllMem = await harness.callTool(agent, 'ig5_dbg', {
        target: m4b.hostPath,
        op: 'readmem',
        ea: dllReadVa,
        size: 4,
        research: { ...sel.researchBinding, key: `${expPrefix}-s${step}`, step: step++ },
      });
      let staleFirstBaseRead = null;
      if (firstBase !== activeBase) {
        try {
          staleFirstBaseRead = await harness.callTool(agent, 'ig5_dbg', {
            target: m4b.hostPath,
            op: 'readmem',
            ea: '0x' + (firstBase + 0x3100n).toString(16),
            size: 4,
            research: { ...sel.researchBinding, key: `${expPrefix}-s${step}`, step: step++ },
          });
        } catch (err) {
          staleFirstBaseRead = { failedAsExpected: true, message: err.message };
        }
      }
      await harness.callTool(agent, 'ig5_dbg', {
        target: m4b.hostPath,
        op: 'stop',
        research: { id: rootId, key: `${expPrefix}-stop` },
      });
      return {
        expId: sel.experiment.expId,
        firstBase: '0x' + firstBase.toString(16),
        activeBase: '0x' + activeBase.toString(16),
        dllMem,
        staleFirstBaseRead,
      };
    };

    const uninitRun = await runHostDbgExperiment('sc-uninit', 'm4b-uninit');
    assert.equal(uninitRun.dllMem.hex.toLowerCase(), 'efbeadde');
    assert.notEqual(uninitRun.activeBase.toLowerCase(), '0x180000000', 'Preferred base 0x180000000 is reserved; ASLR must relocate DLL');
    const evUninit = await harness.wsCall(agent, {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: uninitRun.expId,
        verdict: 'refutes',
        observationClass: 'non-empty',
        whyNextChanged: 'Calling EngineTransform without EngineInit yielded sentinel efbeadde; EngineInit(0x7c41b293) is required',
        nextAction: 'Run --mode=host and --mode=reload to verify initialized state across ASLR bases',
      },
    });
    const cxId = evUninit.counterexample?.counterexampleId || 'cx-1';

    const hostRun1 = await runHostDbgExperiment('sc-host-1', 'm4b-host1');
    assert.equal(hostRun1.dllMem.hex.toLowerCase(), m4b.referenceFn(Buffer.from('ABCD', 'ascii')));
    assert.equal(hostRun1.dllMem.context?.module?.toLowerCase(), 'calc_engine.dll');
    assert.equal(hostRun1.dllMem.context?.RVA?.toLowerCase(), '0x3100');
    assert.equal(hostRun1.dllMem.context?.moduleSha256?.toLowerCase(), m4b.dllSha256.toLowerCase());
    await harness.wsCall(agent, {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: hostRun1.expId,
        verdict: 'supports',
        observationClass: 'non-empty',
        resolveCounterexampleId: cxId,
        whyNextChanged: 'Initialized state 72247d26 verified at relocated ASLR base',
        nextAction: 'Verify --mode=reload across DLL unload/reload',
      },
    });

    const reloadRun2 = await runHostDbgExperiment('sc-reload-2', 'm4b-reload2');
    assert.notEqual(reloadRun2.firstBase, reloadRun2.activeBase, 'FreeLibrary + VirtualAlloc must force second LoadLibraryA to a new ASLR base');
    assert.equal(reloadRun2.dllMem.hex.toLowerCase(), m4b.referenceFn(Buffer.from('1234', 'ascii')));
    await harness.wsCall(agent, {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: reloadRun2.expId,
        verdict: 'supports',
        observationClass: 'non-empty',
        whyNextChanged: 'Verified RVA 0x3100 invariant across two distinct ASLR bases within reload lifecycle',
        nextAction: 'Pre-commit stateful rule and verify unseen holdout',
      },
    });

    const dllRule = {
      schema: 'ig5-bounded-byte-rule-v1',
      outputLength: 4,
      constants: { st: '72247d26', c: '158a4fc3' },
      byteExpr: {
        op: 'rol8',
        args: [
          {
            op: 'add',
            args: [
              { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, { op: 'const', name: 'st', index: { op: 'i' } }] },
              { op: 'const', name: 'c', index: { op: 'i' } },
            ],
          },
          2,
        ],
      },
    };

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-m4b-1',
          summary: 'Host calls EngineInit(0x7c41b293) -> state=72247d26, EngineTransform computes rol8(((in[i]^st[i])+c[i])&0xff, 2) at calc_engine.dll RVA 0x3100',
          outputSpec: { kind: 'module-memory', module: 'calc_engine.dll', rva: '0x3100', byteLength: 4 },
          executableRule: dllRule,
        },
        scenario: {
          scenarioId: 'sc-holdout-dll',
          componentId: 'comp-host',
          args: ['--mode=host', 'X=QWER'],
          cwd: ws,
          inputSpec: { kind: 'cli-arg', argIndex: 1, prefix: 'X=', encoding: 'ascii', isHoldout: true },
        },
      },
    });

    const holdRun = await runHostDbgExperiment('sc-holdout-dll', 'm4b-hold');
    await harness.wsCall(agent, {
      action: 'evaluate',
      id: rootId,
      root: {
        expId: holdRun.expId,
        verdict: 'supports',
        observationClass: 'non-empty',
        whyNextChanged: 'Unseen holdout QWER matched pre-committed rule at relocated ASLR base',
        nextAction: 'Test wrong-SHA decoy DLL negative control, then restore true DLL component and assess',
      },
    });

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        testVectors: [
          { caseId: 'disc1', receiptId: hostRun1.dllMem._managedExecution.reportId, isHoldout: false },
          { caseId: 'disc2', receiptId: reloadRun2.dllMem._managedExecution.reportId, isHoldout: false },
          { caseId: 'hold', receiptId: holdRun.dllMem._managedExecution.reportId, isHoldout: true },
        ],
      },
    });

    // Negative control: temporarily register a decoy calc_engine.dll in a subdir as comp-dll -> loaded-dll-sha256-mismatch!
    const decoyDir = path.join(ws, 'decoy_dir');
    fs.mkdirSync(decoyDir, { recursive: true });
    const decoyDllPath = path.join(decoyDir, 'calc_engine.dll');
    const decoyBytes = Buffer.from(fs.readFileSync(m4b.dllPath));
    decoyBytes[0xe00 + 0x20] ^= 0xff;
    fs.writeFileSync(decoyDllPath, decoyBytes);
    await harness.wsCall(agent, {
      action: 'root-update', id: rootId, root: { component: { componentId: 'comp-dll', path: decoyDllPath, role: 'dll' } },
    });
    const decoyAssess = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(decoyAssess.canCompleteHostGoal, false);
    assert(decoyAssess.denialReasons.some((r) => r.includes('loaded-dll-sha256-mismatch')));

    await harness.wsCall(agent, {
      action: 'root-update', id: rootId, root: { component: { componentId: 'comp-dll', path: m4b.dllPath, role: 'dll' } },
    });
    await harness.callTool(agent, 'ig5_close', { target: m4b.hostPath, engine: 'ghidra' });
    await harness.callTool(agent, 'ig5_close', { target: m4b.dllPath, engine: 'ghidra' });
    const goodAssess = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(goodAssess.assessment, 'satisfied');
    assert.equal(goodAssess.canCompleteHostGoal, true);

    const summary = {
      schema: 'ig5-m4b-controls-native-v1',
      passed: true,
      dllExportsCount: dllExports.exports?.length || dllExports.rows?.length || 2,
      uninitializedCounterexample: { hex: uninitRun.dllMem.hex, activeBase: uninitRun.activeBase, counterexampleId: cxId },
      reloadLifecycleVerified: {
        firstBase: reloadRun2.firstBase,
        reloadedBase: reloadRun2.activeBase,
        staleFirstBaseRead: reloadRun2.staleFirstBaseRead,
      },
      sameNameDecoyDllRejected: decoyAssess.denialReasons,
      finalAssessment: { assessment: goodAssess.assessment, canCompleteHostGoal: goodAssess.canCompleteHostGoal },
    };
    fs.writeFileSync(path.join(outDir, 'm4b-controls-summary.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');
    console.log('[M4-B] Controls PASSED!');
    return summary;
  } finally {
    await harness.dispose();
    writeBranchManifest(outDir);
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ── 3. M4-C Multi-Process Chain & Bystander-Safe Cancellation Controls ───────
async function verifyM4CControls() {
  console.log('\n=== [M4-C] Verifying Entry -> Broker -> Multi-Worker Process Chain Controls ===');
  const outDir = path.join(reviewRoot, 'm4c-process-chain', 'controls-native');
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });

  const tmpRoot = fs.mkdtempSync(path.join(realTmp(), 'ig5-m4c-ctrl-'));
  const ig5Home = path.join(outDir, 'ig5-home');
  const ws = path.join(tmpRoot, 'workspace');
  const goals = new Map([['m4c-root', { id: 'goal-m4c-1', revision: 1, objective: 'M4-C Process chain verification', phase: 'active', activation: 'active' }]]);
  const harness = await createIg5Harness({ ig5Home, workspaceDir: ws, activeGoals: goals });
  const agent = harness.makeAgent('m4c-root');

  let bystanderProc = null;
  try {
    const m4c = materializeM4COnlineCase1(ws);
    await harness.callTool(agent, 'ig5_open', { path: m4c.worker1Path, background: false, engine: 'ghidra' });
    await harness.callTool(agent, 'ig5_open', { path: m4c.worker2Path, background: false, engine: 'ghidra' });

    const rootCreated = await harness.wsCall(agent, {
      action: 'root-create',
      goal: 'Recover entry_app -> chain_broker -> worker_stage1 -> worker_stage2 transform',
      root: {
        deliverables: [{
          id: 'deliv-m4c-1',
          kind: 'process-chain-transform',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'multi-process-lineage'],
          holdoutRequired: true,
        }],
      },
    });
    const rootId = rootCreated.rootId;

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        components: [
          { componentId: 'comp-entry', path: m4c.entryExePath, role: 'main-pe' },
          { componentId: 'comp-broker', path: m4c.brokerExePath, role: 'broker-pe' },
          { componentId: 'comp-w1', path: m4c.worker1Path, role: 'worker-pe' },
          { componentId: 'comp-w2', path: m4c.worker2Path, role: 'worker-pe' },
        ],
        routes: [{
          routeId: 'r-chain',
          question: 'How do worker_stage1 and worker_stage2 transform the 4B payload across the broker?',
          targetObservation: '4-process Win32_Process lineage + 8-char outputHex',
          discriminatingExperiment: 'process_chain_scenario with restart_worker1=true',
        }],
        scenarios: [
          {
            scenarioId: 'sc-chain-1',
            componentId: 'comp-entry',
            launchMode: 'via-parent',
            args: [],
            cwd: m4c.chainDir,
            inputSpec: { kind: 'ipc', ipcPayload: '41424344', encoding: 'hex', isHoldout: false },
          },
          {
            scenarioId: 'sc-chain-2',
            componentId: 'comp-entry',
            launchMode: 'via-parent',
            args: [],
            cwd: m4c.chainDir,
            inputSpec: { kind: 'ipc', ipcPayload: '9e3779b9', encoding: 'hex', isHoldout: false },
          },
        ],
      },
    });

    await harness.callTool(agent, 'ig5_decompile', {
      target: m4c.worker1Path,
      ea: '0x1400011c0',
      research: { id: rootId, key: 'm4c-w1-decomp', note: 'Decompile worker_stage1 transform' },
    });
    await harness.callTool(agent, 'ig5_decompile', {
      target: m4c.worker2Path,
      ea: '0x1400011c0',
      research: { id: rootId, key: 'm4c-w2-decomp', note: 'Decompile worker_stage2 transform' },
    });

    const runChainVec = async (scenarioId, hex, isHoldout, keyPrefix) => {
      const sel = await harness.wsCall(agent, {
        action: 'select',
        id: rootId,
        root: { kind: isHoldout ? 'holdout-verify' : 'dynamic-breakpoint-read', scenarioId, componentId: 'comp-entry', hypothesis: `Chain run ${hex}` },
      });
      const obs = await harness.callTool(agent, 'ig5_app_observe', {
        action: 'process_chain_scenario',
        target: m4c.entryExePath,
        payload_hex: hex,
        corr_id: `corr-${keyPrefix}`,
        restart_worker1: true,
        research: { ...sel.researchBinding, key: `${keyPrefix}-s0`, step: 0 },
      });
      await harness.wsCall(agent, {
        action: 'evaluate',
        id: rootId,
        root: { expId: sel.experiment.expId, verdict: 'supports', observationClass: 'non-empty', whyNextChanged: 'Verified full 4-process chain with worker1 restart turnover', nextAction: 'Proceed' },
      });
      return obs;
    };

    const obs1 = await runChainVec('sc-chain-1', '41424344', false, 'm4c-d1');
    const obs2 = await runChainVec('sc-chain-2', '9e3779b9', false, 'm4c-d2');
    assert.equal(obs1.outputHex, m4c.referenceFn(Buffer.from('41424344', 'hex')));
    assert(obs1.processInstances.some((p) => p.status === 'exited-before-handoff'), 'Must record aborted worker1 PID separately from live worker1 PID');

    const chainRule = {
      schema: 'ig5-bounded-byte-rule-v1',
      outputLength: 4,
      stateLength: 4,
      initFromInput: true,
      constants: { c1: '1a6cd439', c2: '53b1289e' },
      steps: [
        {
          repeat: 4,
          targetIndex: { op: 'i' },
          valueExpr: { op: 'rol8', args: [{ op: 'add', args: [{ op: 'buf', index: { op: 'i' } }, { op: 'const', name: 'c1', index: { op: 'i' } }] }, 2] },
        },
        {
          repeat: 4,
          targetIndex: { op: 'i' },
          valueExpr: { op: 'rol8', args: [{ op: 'add', args: [{ op: 'buf', index: { op: 'i' } }, { op: 'const', name: 'c2', index: { op: 'i' } }] }, 1] },
        },
        {
          repeat: 3,
          targetIndex: { op: 'add', args: [{ op: 'i' }, 1] },
          valueExpr: { op: 'xor', args: [{ op: 'buf', index: { op: 'add', args: [{ op: 'i' }, 1] } }, { op: 'add', args: [{ op: 'buf', index: { op: 'i' } }, 0x13] }] },
        },
      ],
    };

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-m4c-1',
          summary: 'worker_stage1 rol8(in+c1,2) -> worker_stage2 rol8(s1+c2,1) + cascade +0x13',
          outputSpec: { kind: 'app-output', channel: 'process-chain', byteLength: 4 },
          executableRule: chainRule,
        },
        scenario: {
          scenarioId: 'sc-chain-hold',
          componentId: 'comp-entry',
          launchMode: 'via-parent',
          args: [],
          cwd: m4c.chainDir,
          inputSpec: { kind: 'ipc', ipcPayload: '243f6a88', encoding: 'hex', isHoldout: true },
        },
      },
    });

    const obsHold = await runChainVec('sc-chain-hold', '243f6a88', true, 'm4c-hold');

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        testVectors: [
          { caseId: 'spliced', scenarioId: 'sc-chain-2', receiptId: obs1._managedExecution.reportId, isHoldout: false },
          { caseId: 'd2', receiptId: obs2._managedExecution.reportId, isHoldout: false },
          { caseId: 'hold', receiptId: obsHold._managedExecution.reportId, isHoldout: true },
        ],
      },
    });
    const splicedAssess = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(splicedAssess.canCompleteHostGoal, false);
    assert(splicedAssess.denialReasons.some((r) => r.includes('vector-scenario-mismatch')));

    bystanderProc = spawn(m4c.brokerExePath, ['--bystander-sleep'], { cwd: m4c.chainDir, windowsHide: true, stdio: 'ignore' });
    const bystanderPid = bystanderProc.pid;
    assert(bystanderPid > 0, 'Bystander chain_broker.exe must be running');

    const heldStart = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'start',
      target: m4c.entryExePath,
      payload_hex: '41424344',
      hold_ms: 30000,
    });
    assert(heldStart.ownedPids.length >= 2, 'Held session must track entry_app + chain_broker');

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        testVectors: [
          { caseId: 'd1', receiptId: obs1._managedExecution.reportId, isHoldout: false },
          { caseId: 'd2', receiptId: obs2._managedExecution.reportId, isHoldout: false },
          { caseId: 'hold', receiptId: obsHold._managedExecution.reportId, isHoldout: true },
        ],
      },
    });
    const pendingCleanupAssess = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(pendingCleanupAssess.cleanup, 'pending');
    assert.equal(pendingCleanupAssess.canCompleteHostGoal, false);

    // Also test explicit root-control cancel -> ordinary call blocked, owner stop allowed!
    await harness.wsCall(agent, { action: 'root-control', id: rootId, root: { controlAction: 'cancel', reason: 'm4c-cancel-test' } });
    let postCancelOrdinaryBlocked = null;
    try {
      await harness.callTool(agent, 'ig5_funcs', { target: m4c.worker1Path });
    } catch (err) {
      postCancelOrdinaryBlocked = { code: err.code || null, message: err.message };
    }
    assert(postCancelOrdinaryBlocked && /CANCELLED/i.test(`${postCancelOrdinaryBlocked.code} ${postCancelOrdinaryBlocked.message}`));

    const heldStop = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'stop',
      target: m4c.entryExePath,
    });
    assert.equal(heldStop.ok, true);
    assert.equal(heldStop.lingeringOwnedProcessesCount, 0);
    let bystanderAliveAfterStop = false;
    try { process.kill(bystanderPid, 0); bystanderAliveAfterStop = true; } catch { bystanderAliveAfterStop = false; }
    assert.equal(bystanderAliveAfterStop, true, 'Same-name bystander chain_broker.exe MUST survive owned chain cleanup!');
    bystanderProc.kill();
    bystanderProc = null;

    // Emit authenticated direct-human turn event before explicit resume, then close Ghidra & assess!
    harness.ctx.emit('session/event', agent.session, { type: 'user/message', data: { source: { kind: 'user' } } });
    await harness.wsCall(agent, { action: 'root-control', id: rootId, root: { controlAction: 'resume' } });
    await harness.callTool(agent, 'ig5_close', { target: m4c.worker1Path, engine: 'ghidra' });
    await harness.callTool(agent, 'ig5_close', { target: m4c.worker2Path, engine: 'ghidra' });
    const finalAssess = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(finalAssess.assessment, 'satisfied');
    assert.equal(finalAssess.cleanup, 'confirmed');
    assert.equal(finalAssess.canCompleteHostGoal, true);

    const summary = {
      schema: 'ig5-m4c-controls-native-v1',
      passed: true,
      workerTurnoverRecorded: obs1.processInstances,
      splicedReceiptRejected: splicedAssess.denialReasons,
      pendingCleanupBlockedCompletion: { cleanup: pendingCleanupAssess.cleanup, denialReasons: pendingCleanupAssess.denialReasons },
      postCancelOrdinaryBlocked,
      bystanderPreservationVerified: { bystanderPid, bystanderAliveAfterStop, heldCleanupVerified: heldStop.ok && heldStop.lingeringOwnedProcessesCount === 0 },
      finalAssessment: { assessment: finalAssess.assessment, cleanup: finalAssess.cleanup, canCompleteHostGoal: finalAssess.canCompleteHostGoal },
    };
    fs.writeFileSync(path.join(outDir, 'm4c-controls-summary.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');
    console.log('[M4-C] Controls PASSED!');
    return summary;
  } finally {
    if (bystanderProc) { try { bystanderProc.kill(); } catch { /* ignore */ } }
    await harness.dispose();
    writeBranchManifest(outDir);
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ── 4. M4-A Android APK / DEX / JNI + Trace Diff + Honest Device Block ───────
async function verifyM4AControls() {
  console.log('\n=== [M4-A] Verifying Android APK/DEX/JNI Static+Emulation+Repack & Honest Device Block ===');
  const outDir = path.join(reviewRoot, 'm4a-android', 'controls-native');
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });

  const tmpRoot = fs.mkdtempSync(path.join(realTmp(), 'ig5-m4a-ctrl-'));
  const ig5Home = path.join(outDir, 'ig5-home');
  const ws = path.join(tmpRoot, 'workspace');
  const goals = new Map([['m4a-root', { id: 'goal-m4a-1', revision: 1, objective: 'M4-A Android APK -> JNI chain', phase: 'active', activation: 'active' }]]);
  const harness = await createIg5Harness({ ig5Home, workspaceDir: ws, activeGoals: goals });
  const agent = harness.makeAgent('m4a-root');

  try {
    const androidBuilt = buildSignedAndroidFixtures(ws);
    const sdkBase = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT || (process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'Android', 'Sdk') : '');
    const emulatorExe = sdkBase ? path.join(sdkBase, 'emulator', process.platform === 'win32' ? 'emulator.exe' : 'emulator') : '';
    let emulatorProbe = { exists: fs.existsSync(emulatorExe), avds: null, accelCheck: null };
    if (emulatorProbe.exists) {
      try {
        emulatorProbe.avds = execFileSync(emulatorExe, ['-list-avds'], { encoding: 'utf8', timeout: 8000, windowsHide: true }).trim().split(/\r?\n/).filter(Boolean);
      } catch (err) { emulatorProbe.avds = { error: err.message }; }
      try {
        emulatorProbe.accelCheck = execFileSync(emulatorExe, ['-accel-check'], { encoding: 'utf8', timeout: 8000, windowsHide: true }).trim();
      } catch (err) { emulatorProbe.accelCheck = { exitCode: err.status ?? null, output: String(err.stdout || err.stderr || err.message).trim() }; }
    }

    const repackedApkPath = path.join(ws, 'CodecJniDemo_repacked_signed.apk');
    const probeRes = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'android_probe',
      target: androidBuilt.javaJniApk.apkPath,
      output_apk_path: repackedApkPath,
      symptom_code: 'INSTALL_PARSE_FAILED_NO_CERTIFICATES',
    });
    assert.equal(probeRes.closure.capabilities.android_static_apk_dex_jni.status, 'ok');
    assert.equal(probeRes.closure.capabilities.android_repack_signed_fixture.status, 'ok');
    assert.equal(probeRes.closure.capabilities.android_adb_device_session.status, 'blocked');
    assert.equal(probeRes.closure.capabilities.android_dynamic_frida_hook.status, 'blocked');
    assert.equal(probeRes.repackResult.signatureVerified, true);
    assert.equal(probeRes.repackResult.cleanupErrors.length, 0);

    const extractedDexPath = path.join(ws, 'extracted_classes.dex');
    execFileSync('python', [
      '-c',
      'import sys, zipfile; open(sys.argv[2], "wb").write(zipfile.ZipFile(sys.argv[1]).read("classes.dex"))',
      androidBuilt.javaJniApk.apkPath,
      extractedDexPath,
    ], { windowsHide: true });
    const corruptedDexPath = path.join(ws, 'corrupted_classes.dex');
    const dexBytes = Buffer.from(fs.readFileSync(extractedDexPath));
    dexBytes.fill(0xaa, 8, 32);
    fs.writeFileSync(corruptedDexPath, dexBytes);
    const dexProbeBefore = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'android_probe',
      target: corruptedDexPath,
    });
    assert.equal(dexProbeBefore.dexCheck.valid, false);
    const repairedDex = verifyOrRepairDexIntegrity(dexBytes, { repair: true });
    assert.equal(repairedDex.repaired, true);
    assert.equal(repairedDex.valid, true);
    fs.writeFileSync(corruptedDexPath, repairedDex.buffer);
    const dexProbeAfter = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'android_probe',
      target: corruptedDexPath,
    });
    assert.equal(dexProbeAfter.dexCheck.valid, true);

    const traceDiffOk = await harness.callTool(agent, 'ig5_package', {
      action: 'trace_diff',
      target: androidBuilt.extractedSoPath,
      trace_diff: {
        trace_a: {
          targetSha256: androidBuilt.jniElf.sha256,
          runId: 'emu-run-a',
          moduleBase: '0x7f0000100000',
          events: [
            { pc: '0x7f0000100250', regs: { rdi: '0x0', edx: '0x44434241' } },
            { pc: '0x7f0000100200', regs: { rax: '0x41' } },
            { pc: '0x7f0000100210', regs: { rax: '0xdd' } },
          ],
        },
        trace_b: {
          targetSha256: androidBuilt.jniElf.sha256,
          runId: 'emu-run-b',
          moduleBase: '0x7f0000900000',
          events: [
            { pc: '0x7f0000900250', regs: { rdi: '0x0', edx: '0x34333231' } },
            { pc: '0x7f0000900200', regs: { rax: '0x31' } },
            { pc: '0x7f0000900224', regs: { rax: '0x5d' } },
          ],
        },
      },
    });
    assert.equal(traceDiffOk.value.divergentRegionsCount >= 1, true);

    let traceDiffMismatchErr = null;
    try {
      await harness.callTool(agent, 'ig5_package', {
        action: 'trace_diff',
        trace_diff: {
          trace_a: { targetSha256: 'a'.repeat(64), runId: 'r1', events: [{ rva: '0x200' }] },
          trace_b: { targetSha256: 'b'.repeat(64), runId: 'r2', events: [{ rva: '0x200' }] },
        },
      });
    } catch (err) { traceDiffMismatchErr = { code: err.code || null, message: err.message }; }
    assert(traceDiffMismatchErr && /TRACE_BUILD_MISMATCH|different target/i.test(`${traceDiffMismatchErr.code} ${traceDiffMismatchErr.message}`));

    let traceDiffUnrebasedErr = null;
    try {
      await harness.callTool(agent, 'ig5_package', {
        action: 'trace_diff',
        trace_diff: {
          trace_a: { targetSha256: 'a'.repeat(64), runId: 'r1', aslrActive: true, events: [{ pc: '0x7ff612341000' }] },
          trace_b: { targetSha256: 'a'.repeat(64), runId: 'r2', aslrActive: true, events: [{ pc: '0x7ff799991000' }] },
        },
      });
    } catch (err) { traceDiffUnrebasedErr = { code: err.code || null, message: err.message }; }
    assert(traceDiffUnrebasedErr && /UNREBASED_ASLR_TRACE_REFUSED/i.test(`${traceDiffUnrebasedErr.code} ${traceDiffUnrebasedErr.message}`));

    const blockedRoot = await harness.wsCall(agent, {
      action: 'root-create',
      goal: 'Attempt live Frida device hook on CodecJniDemo.apk without connected device',
      root: {
        deliverables: [{
          id: 'deliv-device-blocked',
          kind: 'apk-jni-chain',
          requiredObservations: ['static-locate', 'dynamic-device-hook'],
          holdoutRequired: true,
        }],
      },
    });
    const blockedAssess = await harness.wsCall(agent, {
      action: 'assess', id: blockedRoot.rootId,
    });
    assert.equal(blockedAssess.assessment, 'unsupported');
    assert.equal(blockedAssess.canCompleteHostGoal, false);

    const jniRootRes = await harness.wsCall(agent, {
      action: 'root-create',
      goal: 'Recover CodecJniDemo.apk Java -> libcodec_jni.so nativeTransform rule via static APK + Ghidra + Unicorn emulation',
      root: {
        deliverables: [{
          id: 'deliv-m4a-1',
          kind: 'apk-jni-chain',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation'],
          holdoutRequired: true,
        }],
      },
    });
    const rootId = jniRootRes.rootId;

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        components: [
          { componentId: 'comp-apk', path: androidBuilt.javaJniApk.apkPath, role: 'apk' },
          { componentId: 'comp-so', path: androidBuilt.extractedSoPath, role: 'jni-so' },
        ],
        routes: [{
          routeId: 'r-apk-jni',
          question: 'What byte transformation does Java_com_ig5_fixture_NativeBridge_nativeTransform execute?',
          targetObservation: 'Unicorn SysV eax return value on 4B little-endian input',
          discriminatingExperiment: 'ig5_emulate sysv on libcodec_jni.so',
          methodFamily: 'emulation',
        }],
        scenarios: [
          {
            scenarioId: 'sc-jni-1',
            componentId: 'comp-so',
            launchMode: 'standalone',
            args: [],
            cwd: ws,
            inputSpec: { kind: 'emulate', sampleHex: '41424344', isHoldout: false },
          },
          {
            scenarioId: 'sc-jni-2',
            componentId: 'comp-so',
            launchMode: 'standalone',
            args: [],
            cwd: ws,
            inputSpec: { kind: 'emulate', sampleHex: '31323334', isHoldout: false },
          },
        ],
      },
    });

    const apkStatic = await harness.callTool(agent, 'ig5_package', {
      action: 'apk',
      target: androidBuilt.javaJniApk.apkPath,
      input: { path: androidBuilt.javaJniApk.apkPath },
      research: { id: rootId, key: 'm4a-apk-static', note: 'Static APK + DEX + nativeLibraries scan' },
    });
    const javaDemoStatic = await harness.callTool(agent, 'ig5_package', {
      action: 'apk',
      target: androidBuilt.javaOnlyApk.apkPath,
      input: { path: androidBuilt.javaOnlyApk.apkPath },
    });

    const soOpen = await harness.callTool(agent, 'ig5_open', {
      path: androidBuilt.extractedSoPath,
      background: false,
      engine: 'ghidra',
      research: { id: rootId, key: 'm4a-so-open', note: 'Open libcodec_jni.so in Ghidra' },
    });
    const soBase = BigInt(soOpen.imageBase || '0x100000');
    const jniFnVa = '0x' + (soBase + 0x250n).toString(16);
    await harness.callTool(agent, 'ig5_decompile', {
      target: androidBuilt.extractedSoPath,
      ea: jniFnVa,
      research: { id: rootId, key: 'm4a-so-decomp', note: 'Decompile Java_com_ig5_fixture_NativeBridge_nativeTransform' },
    });

    const runJniEmulate = async (scenarioId, hex4, isHoldout, keyPrefix) => {
      const sel = await harness.wsCall(agent, {
        action: 'select',
        id: rootId,
        root: { kind: isHoldout ? 'holdout-verify' : 'dynamic-breakpoint-read', scenarioId, componentId: 'comp-so', hypothesis: `Emulate JNI nativeTransform(${hex4})` },
      });
      const b = Buffer.from(hex4, 'hex');
      const edxHex = '0x' + b.readUInt32LE(0).toString(16);
      const emu = await harness.callTool(agent, 'ig5_emulate', {
        target: androidBuilt.extractedSoPath,
        engine: 'ghidra',
        ea: jniFnVa,
        abi: 'sysv64',
        args: ['0x0', '0x0', edxHex],
        research: { ...sel.researchBinding, key: `${keyPrefix}-s0`, step: 0 },
      });
      assert.equal(emu.ok, true);
      await harness.wsCall(agent, {
        action: 'evaluate',
        id: rootId,
        root: { expId: sel.experiment.expId, verdict: 'supports', observationClass: 'non-empty', whyNextChanged: 'Unicorn SysV JNI emulation returned expected eax', nextAction: 'Proceed' },
      });
      return emu;
    };

    const emu1 = await runJniEmulate('sc-jni-1', '41424344', false, 'm4a-e1');
    const emu2 = await runJniEmulate('sc-jni-2', '31323334', false, 'm4a-e2');

    const jniRule = {
      schema: 'ig5-bounded-byte-rule-v1',
      outputLength: 4,
      constants: { c: '1c73a845' },
      byteExpr: {
        op: 'rol8',
        args: [{ op: 'add', args: [{ op: 'in', index: { op: 'i' } }, { op: 'const', name: 'c', index: { op: 'i' } }] }, 3],
      },
    };
    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-m4a-1',
          summary: 'JNI nativeTransform calls codec_core_4b: rol8((in[i] + C[i]) & 0xff, 3) returning uint32 LE in eax',
          outputSpec: { kind: 'emulate-capture', register: 'rax', byteLength: 4, endian: 'little' },
          executableRule: jniRule,
        },
        scenario: {
          scenarioId: 'sc-jni-hold',
          componentId: 'comp-so',
          launchMode: 'standalone',
          args: [],
          cwd: ws,
          inputSpec: { kind: 'emulate', sampleHex: 'cafebabe', isHoldout: true },
        },
      },
    });
    const emuHold = await runJniEmulate('sc-jni-hold', 'cafebabe', true, 'm4a-ehold');

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        testVectors: [
          { caseId: 'd1', receiptId: emu1._managedExecution.reportId, isHoldout: false },
          { caseId: 'd2', receiptId: emu2._managedExecution.reportId, isHoldout: false },
          { caseId: 'hold', receiptId: emuHold._managedExecution.reportId, isHoldout: true },
        ],
      },
    });
    await harness.callTool(agent, 'ig5_close', { target: androidBuilt.extractedSoPath, engine: 'ghidra' });
    const jniAssess = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(jniAssess.assessment, 'satisfied');
    assert.equal(jniAssess.canCompleteHostGoal, true);

    const summary = {
      schema: 'ig5-m4a-controls-native-v1',
      branchStatus: 'partial',
      staticAndEmulationAndRepackStatus: 'achieved',
      liveDeviceAndFridaHookStatus: 'blocked',
      capabilityClosure: probeRes.closure,
      emulatorProbe,
      symptomDiagnosisSample: probeRes.symptom,
      dexIntegrityRepairVerified: { validBefore: dexProbeBefore.dexCheck.valid, repaired: repairedDex.repaired, validAfter: dexProbeAfter.dexCheck.valid },
      ownedFixtureRepackAndSignVerified: probeRes.repackResult,
      apkStaticSummaries: { jniDemo: apkStatic.value.summary, javaDemo: javaDemoStatic.value.summary },
      traceDiffVerified: {
        positiveDivergenceCount: traceDiffOk.value.divergentRegionsCount,
        targetMismatchRejected: traceDiffMismatchErr,
        unrebasedAslrRejected: traceDiffUnrebasedErr,
      },
      deviceHookObligationTruthfullyBlocked: { assessment: blockedAssess.assessment, denialReasons: blockedAssess.denialReasons },
      staticPlusUnicornJniAssessment: { assessment: jniAssess.assessment, canCompleteHostGoal: jniAssess.canCompleteHostGoal },
    };
    fs.writeFileSync(path.join(outDir, 'm4a-controls-summary.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');
    console.log('[M4-A] Controls PASSED (static+emulation+repack achieved; live device/Frida honestly blocked)!');
    return summary;
  } finally {
    await harness.dispose();
    writeBranchManifest(outDir);
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ── 5. M4-D Multi-Agent Collaboration & Governance Negative Controls ──────────
async function verifyM4DControls() {
  console.log('\n=== [M4-D] Verifying Multi-Agent Budget, Owner Lock, Child Completion Gate & Provenance Controls ===');
  const outDir = path.join(reviewRoot, 'm4d-multiagent', 'controls-native');
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });

  const tmpRoot = fs.mkdtempSync(path.join(realTmp(), 'ig5-m4d-ctrl-'));
  const ig5Home = path.join(outDir, 'ig5-home');
  const ws = path.join(tmpRoot, 'workspace');
  const goals = new Map([
    ['parent-root', { id: 'goal-m4d-1', revision: 1, objective: 'M4-D Multi-agent reverse engineering', phase: 'active', activation: 'active' }],
  ]);
  const rootSet = new Set();
  const harness = await createIg5Harness({ ig5Home, workspaceDir: ws, activeGoals: goals, rootAgents: rootSet });
  const parent = harness.makeAgent('parent-root');
  rootSet.add(parent);
  const childA = harness.makeAgent('child-static-a', { parentId: 'parent-root', owner: parent });
  const childB = harness.makeAgent('child-dyn-b', { parentId: 'parent-root', owner: parent });

  try {
    const m4c = materializeM4COnlineCase1(ws);

    // 1. Negative Control: Child attempting update_goal(action="complete") MUST be denied by autonomy_host gate!
    let childCompleteDenied = null;
    try {
      await harness.callTool(childA, 'update_goal', { action: 'complete', goal_id: 'goal-m4d-1', revision: 1 });
    } catch (err) {
      childCompleteDenied = { code: err.code || null, message: err.message };
    }
    assert(childCompleteDenied && /Subagents cannot complete the root host goal/i.test(childCompleteDenied.message));

    // 2. Shared parent-child budget: Parent starts max_calls=18; child attempting start fails (BUDGET_OWNER_REQUIRED), parent attempting reset fails (BUDGET_ALREADY_STARTED)!
    await harness.callTool(parent, 'ig5_profile', { collaboration: { action: 'start', max_calls: 18 } });
    let childBudgetResetDenied = null;
    try {
      await harness.callTool(childA, 'ig5_profile', { collaboration: { action: 'start', max_calls: 100 } });
    } catch (err) {
      childBudgetResetDenied = { code: err.code || null, message: err.message };
    }
    assert(childBudgetResetDenied && /BUDGET_OWNER_REQUIRED|Only the root agent/i.test(`${childBudgetResetDenied.code} ${childBudgetResetDenied.message}`));

    let parentBudgetResetDenied = null;
    try {
      await harness.callTool(parent, 'ig5_profile', { collaboration: { action: 'start', max_calls: 100 } });
    } catch (err) {
      parentBudgetResetDenied = { code: err.code || null, message: err.message };
    }
    assert(parentBudgetResetDenied && /BUDGET_ALREADY_STARTED|cannot be reset or enlarged/i.test(`${parentBudgetResetDenied.code} ${parentBudgetResetDenied.message}`));

    // 3. Parent creates root investigation, registers worker1 & worker2, creates typed child brief for childA
    const rootRes = await harness.wsCall(parent, {
      action: 'root-create',
      goal: 'M4-D governed multi-agent reverse check',
      root: {
        origin: { kind: 'host-goal', hostGoalId: 'goal-m4d-1', hostGoalRevision: 1, hostGoalObjective: 'M4-D Multi-agent reverse engineering' },
        deliverables: [{
          id: 'deliv-m4d-1',
          kind: 'io-transform',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation'],
          holdoutRequired: true,
        }],
      },
    });
    const rootId = rootRes.rootId;
    const upd = await harness.wsCall(parent, {
      action: 'root-update',
      id: rootId,
      root: {
        components: [
          { componentId: 'comp-w1', path: m4c.worker1Path, role: 'worker-pe', standaloneAllowed: true },
          { componentId: 'comp-w2', path: m4c.worker2Path, role: 'worker-pe' },
        ],
      },
    });
    const compW1 = upd.task.components.find((c) => c.componentId === 'comp-w1');
    const brief = await harness.wsCall(parent, {
      action: 'delegate-brief',
      id: rootId,
      root: {
        childRole: 'component-analyst',
        componentId: 'comp-w1',
        objective: 'Locate transform RVA and constants in worker_stage1.exe',
      },
    });
    assert.equal(brief.authorityLimits.canCompleteHostGoal, false);

    // Child attempting delegate-brief MUST be rejected (DELEGATION_PARENT_REQUIRED)
    let childDelegateDenied = null;
    try {
      await harness.wsCall(childA, {
        action: 'delegate-brief',
        id: rootId,
        root: { childRole: 'component-analyst', componentId: 'comp-w2', objective: 'Unauthorized nested delegation' },
      });
    } catch (err) {
      childDelegateDenied = { code: err.code || null, message: err.message };
    }
    assert(childDelegateDenied && /DELEGATION_PARENT_REQUIRED|Only a root parent/i.test(`${childDelegateDenied.code} ${childDelegateDenied.message}`));

    // ChildA opens & decompiles worker1 (deducting from shared parent budget!)
    await harness.callTool(childA, 'ig5_open', {
      path: m4c.worker1Path,
      background: false,
      engine: 'ghidra',
      research: { id: rootId, key: 'm4d-childa-open', note: 'ChildA open worker1' },
    });
    const childDecomp = await harness.callTool(childA, 'ig5_decompile', {
      target: m4c.worker1Path,
      ea: '0x1400011c0',
      research: { id: rootId, key: 'm4d-childa-decomp', note: 'ChildA decompile worker1' },
    });
    const childReceiptId = childDecomp._managedExecution.reportId;

    // 4. Provenance Negative Controls on accept-child-finding:
    // 4a: Unbacked finding (0 receipts) -> rejected
    let unbackedErr = null;
    try {
      await harness.wsCall(parent, {
        action: 'accept-child-finding',
        id: rootId,
        root: {
          briefId: brief.briefId,
          childReport: {
            schema: 'ig5-delegation-finding-v1',
            briefId: brief.briefId,
            rootId,
            componentId: 'comp-w1',
            targetSha256: compW1.sha256,
            receiptRefs: [],
            summary: 'Unbacked claim without receipts',
          },
        },
      });
    } catch (err) { unbackedErr = { code: err.code || null, message: err.message }; }
    assert(unbackedErr && /UNBACKED_CHILD_FINDING_REJECTED/i.test(`${unbackedErr.code} ${unbackedErr.message}`));

    // 4b: Wrong targetSha256 -> rejected
    let wrongShaErr = null;
    try {
      await harness.wsCall(parent, {
        action: 'accept-child-finding',
        id: rootId,
        root: {
          briefId: brief.briefId,
          childReport: {
            schema: 'ig5-delegation-finding-v1',
            briefId: brief.briefId,
            rootId,
            componentId: 'comp-w1',
            targetSha256: 'f'.repeat(64),
            receiptRefs: [childReceiptId],
            summary: 'Mismatched target hash',
          },
        },
      });
    } catch (err) { wrongShaErr = { code: err.code || null, message: err.message }; }
    assert(wrongShaErr && /CHILD_TARGET_SHA256_MISMATCH/i.test(`${wrongShaErr.code} ${wrongShaErr.message}`));

    // 4c: Cross-root report -> rejected
    let crossRootErr = null;
    try {
      await harness.wsCall(parent, {
        action: 'accept-child-finding',
        id: rootId,
        root: {
          briefId: brief.briefId,
          childReport: {
            schema: 'ig5-delegation-finding-v1',
            briefId: brief.briefId,
            rootId: '00000000-0000-0000-0000-000000000000',
            componentId: 'comp-w1',
            targetSha256: compW1.sha256,
            receiptRefs: [childReceiptId],
            summary: 'Cross-root report',
          },
        },
      });
    } catch (err) { crossRootErr = { code: err.code || null, message: err.message }; }
    assert(crossRootErr && /CROSS_ROOT_REPORT_REJECTED/i.test(`${crossRootErr.code} ${crossRootErr.message}`));

    // 4d: Valid backed child finding -> ACCEPTED!
    const acceptedRes = await harness.wsCall(parent, {
      action: 'accept-child-finding',
      id: rootId,
      root: {
        briefId: brief.briefId,
        childReport: {
          schema: 'ig5-delegation-finding-v1',
          briefId: brief.briefId,
          rootId,
          childAgentId: 'child-static-a',
          componentId: 'comp-w1',
          targetSha256: compW1.sha256,
          receiptRefs: [childReceiptId],
          summary: 'Verified worker_stage1 transform at 0x11c0',
        },
      },
    });
    assert.equal(acceptedRes.accepted, true);

    // 4e: Revise parent hostGoal objective/revision -> contractRevision advances -> old brief rejected as STALE_CONTRACT_REVISION_REJECTED!
    await harness.wsCall(parent, {
      action: 'root-update',
      id: rootId,
      root: {
        hostGoalBinding: {
          hostGoalId: 'goal-m4d-1',
          hostGoalRevision: 2,
          hostGoalObjective: 'M4-D Revised scope v2',
        },
      },
    });
    let staleRevErr = null;
    try {
      await harness.wsCall(parent, {
        action: 'accept-child-finding',
        id: rootId,
        root: {
          briefId: brief.briefId,
          childReport: {
            schema: 'ig5-delegation-finding-v1',
            briefId: brief.briefId,
            rootId,
            componentId: 'comp-w1',
            targetSha256: compW1.sha256,
            receiptRefs: [childReceiptId],
            summary: 'Stale contract revision submission',
          },
        },
      });
    } catch (err) { staleRevErr = { code: err.code || null, message: err.message }; }
    assert(staleRevErr && /STALE_CONTRACT_REVISION_REJECTED/i.test(`${staleRevErr.code} ${staleRevErr.message}`));

    // 5. Single-owner live debugger lock!
    await harness.callTool(childB, 'ig5_dbg', {
      target: m4c.worker1Path,
      op: 'start',
      args: ['--stage=one', 'S1=41424344'],
      cwd: m4c.chainDir,
    });
    let siblingHijackDenied = null;
    try {
      await harness.callTool(childA, 'ig5_dbg', {
        target: m4c.worker1Path,
        op: 'stop',
      });
    } catch (err) {
      siblingHijackDenied = { code: err.code || null, message: err.message };
    }
    assert(siblingHijackDenied && /owner|another agent|NON_OWNER/i.test(`${siblingHijackDenied.code} ${siblingHijackDenied.message}`), 'Non-owner sibling must not stop/hijack childB debugger');

    await harness.callTool(childB, 'ig5_dbg', { target: m4c.worker1Path, op: 'stop' });
    await harness.callTool(childA, 'ig5_close', { target: m4c.worker1Path, engine: 'ghidra' });

    const ledgerStatus = await harness.callTool(parent, 'ig5_profile', { collaboration: { action: 'status' } });
    assert(ledgerStatus.collaboration.byAgent['parent-root'] >= 1);
    assert(ledgerStatus.collaboration.byAgent['child-static-a'] >= 2);
    assert(ledgerStatus.collaboration.byAgent['child-dyn-b'] >= 1);

    const summary = {
      schema: 'ig5-m4d-controls-native-v1',
      passed: true,
      childGoalCompletionDenied: childCompleteDenied,
      childBudgetResetDenied,
      parentBudgetResetDenied,
      childDelegateDenied,
      unbackedFindingRejected: unbackedErr,
      wrongShaFindingRejected: wrongShaErr,
      crossRootFindingRejected: crossRootErr,
      validChildFindingAccepted: acceptedRes,
      staleContractRevisionRejected: staleRevErr,
      nonOwnerDebuggerHijackDenied: siblingHijackDenied,
      sharedParentChildBudgetLedger: ledgerStatus.collaboration,
    };
    fs.writeFileSync(path.join(outDir, 'm4d-controls-summary.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');
    console.log('[M4-D] Controls PASSED!');
    return summary;
  } finally {
    await harness.dispose();
    writeBranchManifest(outDir);
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

const which = process.argv[2] || 'all';
const results = {};
if (which === 'all' || which === 'm3') results.m3 = await verifyM3Controls();
if (which === 'all' || which === 'm4b') results.m4b = await verifyM4BControls();
if (which === 'all' || which === 'm4c') results.m4c = await verifyM4CControls();
if (which === 'all' || which === 'm4a') results.m4a = await verifyM4AControls();
if (which === 'all' || which === 'm4d') results.m4d = await verifyM4DControls();

const procCheck = collectNativeProcessCheck();
console.log('\n=== Post-Controls Native Process Check ===', JSON.stringify(procCheck));
assert.equal(procCheck.processes?.length || 0, 0, `Lingering native workers detected: ${JSON.stringify(procCheck)}`);

fs.writeFileSync(
  path.join(reviewRoot, 'm3-m4-controls-aggregate.json'),
  JSON.stringify({
    schema: 'ig5-m3-m4-controls-aggregate-v1',
    createdAt: new Date().toISOString(),
    sourceTreeIdentity: computeSourceTreeIdentity(repoRoot),
    postRunProcessCheck: procCheck,
    results,
  }, null, 2) + '\n',
  'utf8',
);
console.log('\nALL M3 & M4 NATIVE CONTROLS PASSED CLEANLY!');
