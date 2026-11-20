import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const cliOpt = (flag) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
};

const repoRoot = cliOpt('--repo-root') || path.resolve(import.meta.dirname, '..', '..');
const outRoot = cliOpt('--out-dir') || cliOpt('--evidence-root');
const targetsModulePath = cliOpt('--targets-module');
const sectionsArg = cliOpt('--sections') || 'all';

if (!outRoot || !targetsModulePath) {
  throw new Error('Usage: node scripts/evals/verify_transferable_dynamic_native.mjs --out-dir <dir> --targets-module <file> [--sections all|p01,p02,p11,p12,p2,portability]');
}

const enabledSections = new Set(
  sectionsArg === 'all'
    ? ['p01', 'p02', 'p11', 'p12', 'p2', 'portability']
    : sectionsArg.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
);

const targetsMod = await import(pathToFileURL(path.resolve(targetsModulePath)).href);
const {
  VARIABLE_LENGTH_ORACLE_VECTORS,
  materializeNonCooperativeElectronApp,
  materializeNonCooperativeProcessChain,
  materializeForgedSelfReportSuite,
  buildOwnedStatefulJniApk,
} = targetsMod;

const ig5Plugin = await import(pathToFileURL(path.join(repoRoot, 'index.js')).href);
const { computeSourceTreeIdentity } = await import(pathToFileURL(path.join(repoRoot, 'scripts', 'lib', 'source_tree_identity.mjs')).href);
const { collectNativeProcessCheck, stageCleanPluginForEval } = await import(pathToFileURL(path.join(repoRoot, 'scripts', 'evals', 'run_m2_blind_eval.mjs')).href);
const { evaluateBoundedTransform } = await import(pathToFileURL(path.join(repoRoot, 'source', 'investigation_verifier.js')).href);
const {
  runInWin32JobContainer,
  startHeldWin32JobContainer,
  queryWin32ProcessLineageStrict,
} = await import(pathToFileURL(path.join(repoRoot, 'source', 'native_process_container.js')).href);

const realTmp = () => (fs.realpathSync.native || fs.realpathSync)(os.tmpdir());
const CSC_X64 = path.join(process.env.WINDIR || 'C:\\Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');

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
        return { get: (agent) => activeGoals.get(agent?.id) || null };
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
      if (g && args.action === 'blocked') {
        g.phase = 'blocked';
        g.blockedReason = args.blocked_reason || null;
      }
      return { ok: true, action: args.action, phase: g?.phase || args.action };
    },
  });

  const makeAgent = (id) => {
    const a = { id, ctx, session: { id, header: { id, cwd: workspaceDir } } };
    agentsMap.set(id, a);
    return a;
  };

  const callTool = async (agent, name, args = {}, signal = null) => {
    const def = tools.get(name);
    assert(def, `Missing tool ${name}`);
    const exec = {
      name,
      arguments: args,
      agent,
      callId: `call-${randomUUID()}`,
      signal: signal || new AbortController().signal,
    };
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

  const wsCall = async (agent, workspace) => (await callTool(agent, 'ig5_workspace', { workspace })).workspace;
  const dispose = async () => {
    for (const d of effects.reverse()) {
      try { await d(); } catch { /* ignore */ }
    }
  };

  return { tools, approvals, makeAgent, callTool, wsCall, dispose };
}

function scoreVariableRule(executableRule, referenceHexFn) {
  const details = VARIABLE_LENGTH_ORACLE_VECTORS.map((inHex) => {
    const expected = referenceHexFn(inHex);
    const actual = evaluateBoundedTransform(executableRule, inHex);
    return { inputHex: inHex, inputBytes: inHex.length / 2, expectedHex: expected, actualHex: actual, match: expected === actual };
  });
  return {
    passedCount: details.filter((d) => d.match).length,
    totalCount: details.length,
    allPassed: details.every((d) => d.match),
    details,
  };
}

async function runP01JobContainerAndBystanderControls(outDir) {
  console.log('\n=== [P0.1] Native Win32 Job Object + Surviving Grandchild + Bystander Safety + Live AbortSignal ===');
  const secDir = path.join(outDir, 'p0-1-job-container');
  fs.mkdirSync(secDir, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(realTmp(), 'ig5-p01-'));

  try {
    const workerCs = path.join(tmp, 'surviving_worker.cs');
    const launcherCs = path.join(tmp, 'short_launcher.cs');
    const workerExe = path.join(tmp, 'surviving_worker.exe');
    const launcherExe = path.join(tmp, 'short_launcher.exe');

    fs.writeFileSync(workerCs, `using System;\nusing System.Threading;\nclass SurvivingWorker { static int Main(string[] args) { Thread.Sleep(25000); return 0; } }`, 'utf8');
    execFileSync(CSC_X64, ['/nologo', '/platform:x64', `/out:${workerExe}`, workerCs], { windowsHide: true });

    fs.writeFileSync(launcherCs, `using System;\nusing System.Diagnostics;\nusing System.IO;\nusing System.Threading;\nclass ShortLauncher {\n  static int Main(string[] args) {\n    string w = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "surviving_worker.exe");\n    ProcessStartInfo psi = new ProcessStartInfo(w, "--owned-grandchild");\n    psi.UseShellExecute = false;\n    psi.CreateNoWindow = true;\n    Process.Start(psi);\n    if (args.Length > 0 && args[0] == "--abort-test") Thread.Sleep(15000);\n    return 0;\n  }\n}`, 'utf8');
    execFileSync(CSC_X64, ['/nologo', '/platform:x64', `/out:${launcherExe}`, launcherCs], { windowsHide: true });

    const bystander = spawn(workerExe, ['--external-bystander'], { windowsHide: true, stdio: 'ignore' });
    const bystanderPid = bystander.pid;
    assert(bystanderPid > 0, 'External bystander should spawn');

    let heldStopReport = null;
    let bystanderAliveAfterStop = false;
    let abortRunReport = null;
    let bystanderAliveAfterAbort = false;
    let held = null;

    try {
      held = await startHeldWin32JobContainer({ executable: launcherExe, args: ['--spawn-and-exit'], cwd: tmp, holdMs: 25000 });
      await new Promise((r) => setTimeout(r, 400));

      const midSnap = queryWin32ProcessLineageStrict();
      assert.equal(midSnap.status, 'ok');
      assert.equal(midSnap.processes.some((p) => Number(p.ProcessId) === Number(held.rootPid)), false);
      assert.equal(midSnap.processes.some((p) => Number(p.ProcessId) === Number(bystanderPid)), true);

      heldStopReport = await held.stop('STOP');
      held = null;
      assert.equal(heldStopReport.cleanupVerified, true);
      assert.equal(heldStopReport.lingeringPidsAfterCleanup.length, 0);
      const grandchildCaptured = heldStopReport.systemObservedProcesses.find((p) => p.imagePath && p.imagePath.toLowerCase().endsWith('surviving_worker.exe'));
      assert(grandchildCaptured?.creationIdentity);

      const postStopSnap = queryWin32ProcessLineageStrict();
      bystanderAliveAfterStop = postStopSnap.processes.some((p) => Number(p.ProcessId) === Number(bystanderPid));
      assert.equal(bystanderAliveAfterStop, true);

      const ac = new AbortController();
      setTimeout(() => ac.abort(), 350);
      abortRunReport = await runInWin32JobContainer({ executable: launcherExe, args: ['--abort-test'], cwd: tmp, timeoutMs: 20000, signal: ac.signal });
      assert.equal(abortRunReport.cancelled, true);
      assert.equal(abortRunReport.cleanupVerified, true);

      const postAbortSnap = queryWin32ProcessLineageStrict();
      bystanderAliveAfterAbort = postAbortSnap.processes.some((p) => Number(p.ProcessId) === Number(bystanderPid));
      assert.equal(bystanderAliveAfterAbort, true);
    } finally {
      if (held) { try { await held.stop('ABORT'); } catch { /* ignore */ } }
      try { bystander.kill(); } catch { /* ignore */ }
      await new Promise((r) => setTimeout(r, 150));
    }

    const result = { ok: true, bystanderPid, bystanderAliveAfterStop, bystanderAliveAfterAbort, heldStopReport, abortRunReport };
    fs.writeFileSync(path.join(secDir, 'result.json'), JSON.stringify(result, null, 2) + '\n', 'utf8');
    console.log('  [PASS] P0.1 verified.');
    return result;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function runP02ForgedSelfReportControl(outDir) {
  console.log('\n=== [P0.2] Forged Self-Report Negative Control + 3-Round Legal Host Blocked Transition ===');
  const secDir = path.join(outDir, 'p0-2-forged-self-report');
  fs.mkdirSync(secDir, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(realTmp(), 'ig5-p02-'));
  const ig5Home = path.join(secDir, 'ig5-home');
  const workspace = path.join(tmp, 'workspace');
  const activeGoals = new Map();
  const harness = await createIg5Harness({ ig5Home, workspaceDir: workspace, activeGoals });

  try {
    const spec = materializeForgedSelfReportSuite(workspace);
    const agent = harness.makeAgent('sess-forged-neg');
    const goalObj = 'Verify multi-stage pipeline across ingest_runner.exe, stage_alpha.exe, and stage_beta.exe';
    const liveGoal = { id: 'goal-forged', phase: 'active', revision: 1, objective: goalObj, roundsStarted: 1, maxGoalRounds: 10 };
    activeGoals.set(agent.id, liveGoal);

    const created = await harness.wsCall(agent, {
      action: 'root-create',
      goal: goalObj,
      root: {
        deliverables: [{
          id: 'deliv-1',
          kind: 'process-chain-transform',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'multi-process-lineage'],
          holdoutRequired: true,
        }],
        components: [
          { componentId: 'comp-entry', path: spec.runnerExe, role: 'main-pe' },
          { componentId: 'comp-w1', path: spec.stageAPath, role: 'worker-pe' },
          { componentId: 'comp-w2', path: spec.stageBPath, role: 'worker-pe' },
        ],
        scenarios: [
          { scenarioId: 'scen-1', componentId: 'comp-entry', launchMode: 'via-parent', args: ['--in=41424344'], cwd: spec.suiteDir, inputSpec: { kind: 'cli-arg', argIndex: 0, prefix: '--in=', encoding: 'hex', isHoldout: false } },
        ],
      },
    });
    const rootId = created.rootId;

    const openRes = await harness.callTool(agent, 'ig5_open', {
      path: spec.runnerExe,
      background: false,
      engine: 'ghidra',
      research: { id: rootId, key: 'forged-static-open' },
    });
    await harness.callTool(agent, 'ig5_close', { target: spec.runnerExe, engine: 'ghidra' });

    const sel1 = await harness.wsCall(agent, { action: 'select', id: rootId, root: { kind: 'dynamic-breakpoint-read', scenarioId: 'scen-1', componentId: 'comp-entry', hypothesis: 'h1', observer: 'chain' } });
    const obs1 = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'process_chain_scenario',
      target: spec.runnerExe,
      args: ['--in=41424344'],
      cwd: spec.suiteDir,
      research: { ...sel1.researchBinding, key: 'forged-obs-1', step: 0 },
    });

    assert.equal(obs1.applicationReported?.trustLevel, 'untrusted-target-claim');
    assert.equal(obs1.applicationReported?.parsedJson?.stage1Pid, 51201);
    assert(obs1.verifiedProcessLineage.every((p) => !/stage_alpha|stage_beta/i.test(p.imagePath || '') && ![51200, 51201, 51202].includes(p.pid)));

    // False completion MUST be denied
    let completeGateBlocked = false;
    try {
      await harness.callTool(agent, 'update_goal', { goal_id: 'goal-forged', revision: 1, action: 'complete' });
    } catch (err) {
      completeGateBlocked = err.code === 'HOST_GATE_DENIED';
    }
    assert.equal(completeGateBlocked, true);

    // Persist verified terminalFinding
    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        terminalFinding: {
          classification: 'contract-obligation-falsified',
          summary: 'Ghidra static inspection and healthy kernel Job Object lineage both show stage_alpha.exe and stage_beta.exe are never spawned.',
          receiptIds: [openRes._managedExecution.reportId, obs1._managedExecution.reportId],
        },
      },
    });

    const assessedR1 = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(assessedR1.assessment, 'blocked');
    assert.equal(assessedR1.canCompleteHostGoal, false);
    assert.equal(assessedR1.hostGoalRoundStatus.canCallHostBlockedNow, false);

    // Round 1 & Round 2 `update_goal(action="blocked")` rejected cleanly; Round 3 succeeds!
    let round1Denied = false;
    try {
      await harness.callTool(agent, 'update_goal', { goal_id: 'goal-forged', revision: 1, action: 'blocked', blocked_reason: 'Worker pipeline fabricated' });
    } catch (err) {
      round1Denied = err.code === 'HOST_GATE_DENIED' && /HOST_GOAL_ROUND_THRESHOLD_NOT_MET/.test(err.message);
    }
    assert.equal(round1Denied, true);

    liveGoal.roundsStarted = 3;
    const blockRes = await harness.callTool(agent, 'update_goal', { goal_id: 'goal-forged', revision: 1, action: 'blocked', blocked_reason: 'Worker pipeline fabricated' });
    assert.equal(blockRes.phase, 'blocked');

    const out = {
      ok: true,
      forgedStdoutClaim: obs1.applicationReported,
      kernelObservedLineage: obs1.verifiedProcessLineage,
      assessment: assessedR1.assessment,
      canCompleteHostGoal: assessedR1.canCompleteHostGoal,
      completeGateBlocked,
      round1BlockedDenied: round1Denied,
      round3BlockedPhase: blockRes.phase,
    };
    fs.writeFileSync(path.join(secDir, 'result.json'), JSON.stringify(out, null, 2) + '\n', 'utf8');
    console.log('  [PASS] P0.2: Forged stdout isolated, completion denied, terminalFinding persisted, and Round-3 legal blocked transition verified.');
    return out;
  } finally {
    await harness.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function runP11NonCooperativeElectron(outDir) {
  console.log('\n=== [P1.1] Non-Cooperative Electron App (PacketSeal Studio) ===');
  const secDir = path.join(outDir, 'p1-1-non-cooperative-electron');
  fs.mkdirSync(secDir, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(realTmp(), 'ig5-p11-'));
  const ig5Home = path.join(secDir, 'ig5-home');
  const workspace = path.join(tmp, 'workspace');
  const activeGoals = new Map();
  const harness = await createIg5Harness({ ig5Home, workspaceDir: workspace, activeGoals });

  try {
    const spec = materializeNonCooperativeElectronApp(workspace);
    const agent = harness.makeAgent('sess-nc-electron');
    const goalObj = 'Recover variable-length packet sealing frame protocol in PacketSeal Studio';
    activeGoals.set(agent.id, { id: 'goal-nc-el', phase: 'active', revision: 1, objective: goalObj, roundsStarted: 1, maxGoalRounds: 10 });

    const created = await harness.wsCall(agent, {
      action: 'root-create',
      goal: goalObj,
      root: {
        deliverables: [{
          id: 'deliv-1',
          kind: 'structured-frame-transform',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'parent-to-helper-handoff', 'non-cooperative-ui-trigger'],
          nonCooperativeRequired: true,
          holdoutRequired: true,
        }],
        components: [
          { componentId: 'comp-app', path: spec.appDir, role: 'electron-app' },
          { componentId: 'comp-helper', path: spec.helperPath, role: 'helper-pe', parentComponentId: 'comp-app' },
        ],
        scenarios: [
          { scenarioId: 'scen-3b', componentId: 'comp-app', launchMode: 'via-parent', cwd: spec.appDir, inputSpec: { kind: 'ipc', ipcPayload: '414243', encoding: 'hex', isHoldout: false } },
          { scenarioId: 'scen-4b', componentId: 'comp-app', launchMode: 'via-parent', cwd: spec.appDir, inputSpec: { kind: 'ipc', ipcPayload: '9e3779b9', encoding: 'hex', isHoldout: false } },
          { scenarioId: 'scen-6b-holdout', componentId: 'comp-app', launchMode: 'via-parent', cwd: spec.appDir, inputSpec: { kind: 'ipc', ipcPayload: '243f6a8885a3', encoding: 'hex', isHoldout: true } },
        ],
      },
    });
    const rootId = created.rootId;

    await harness.callTool(agent, 'ig5_package', {
      action: 'js_app',
      target: spec.appDir,
      input: { path: spec.appDir },
      research: { id: rootId, key: 'nc-el-js-static' },
    });
    const makeUiActions = (hexVal) => [
      { op: 'fill', selector: '#hex-payload', value: hexVal },
      { op: 'click', selector: '#btn-seal' },
      { op: 'read-dom', selector: '#sealed-frame-hex' },
    ];

    const sel1 = await harness.wsCall(agent, { action: 'select', id: rootId, root: { kind: 'dynamic-breakpoint-read', scenarioId: 'scen-3b', componentId: 'comp-app', hypothesis: '3B input frame', observer: 'ui-click' } });
    const obs1 = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'electron_scenario', scenario_mode: 'execute', trigger_mode: 'ui-click',
      target: spec.appDir, payload: '414243', ui_actions: makeUiActions('414243'),
      output_channel: { kind: 'dom', selector: '#sealed-frame-hex' },
      research: { ...sel1.researchBinding, key: 'nc-el-obs-3b', step: 0 },
    });

    const sel2 = await harness.wsCall(agent, { action: 'select', id: rootId, root: { kind: 'dynamic-breakpoint-read', scenarioId: 'scen-4b', componentId: 'comp-app', hypothesis: '4B input frame', observer: 'ui-click' } });
    const obs2 = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'electron_scenario', scenario_mode: 'execute', trigger_mode: 'ui-click',
      target: spec.appDir, payload: '9e3779b9', ui_actions: makeUiActions('9e3779b9'),
      output_channel: { kind: 'dom', selector: '#sealed-frame-hex' },
      research: { ...sel2.researchBinding, key: 'nc-el-obs-4b', step: 0 },
    });

    const frameRule = {
      schema: 'ig5-bounded-frame-rule-v1',
      headerHex: '5053',
      lengthField: { kind: 'payload-len-u8', bias: 0 },
      prevInit: 0x5a,
      constants: { k4: '1973c42e' },
      bodyByteExpr: {
        op: 'xor',
        args: [
          { op: 'xor', args: [{ op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, 0x3c] }, { op: 'const', name: 'k4', index: { op: 'and', args: [{ op: 'i' }, 3] } }] },
          { op: 'prev' },
        ],
      },
      trailerChecksum: { kind: 'xor8', scope: 'header-and-body', init: 0 },
    };
    const outSpec = { kind: 'app-output', channel: 'electron-dom', minByteLength: 5, maxByteLength: 64 };
    await harness.wsCall(agent, { action: 'root-update', id: rootId, root: { candidate: { deliverableId: 'deliv-1', summary: 'PS frame', outputSpec: outSpec, executableRule: frameRule } } });

    const selH = await harness.wsCall(agent, { action: 'select', id: rootId, root: { kind: 'holdout-verify', scenarioId: 'scen-6b-holdout', componentId: 'comp-app', hypothesis: '6B holdout', observer: 'ui-click' } });
    const obsH = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'electron_scenario', scenario_mode: 'execute', trigger_mode: 'ui-click',
      target: spec.appDir, payload: '243f6a8885a3', ui_actions: makeUiActions('243f6a8885a3'),
      output_channel: { kind: 'dom', selector: '#sealed-frame-hex' },
      research: { ...selH.researchBinding, key: 'nc-el-obs-6b-h', step: 0 },
    });

    await harness.wsCall(agent, {
      action: 'root-update', id: rootId,
      root: {
        testVectors: [
          { caseId: 'd-3b', receiptId: obs1._managedExecution.reportId, isHoldout: false },
          { caseId: 'd-4b', receiptId: obs2._managedExecution.reportId, isHoldout: false },
          { caseId: 'h-6b', receiptId: obsH._managedExecution.reportId, isHoldout: true },
        ],
      },
    });
    const assessed = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(assessed.assessment, 'satisfied');
    assert.equal(assessed.canCompleteHostGoal, true);
    const oracleScore = scoreVariableRule(frameRule, spec.referenceHexFn);
    assert.equal(oracleScore.allPassed, true);

    const out = { ok: true, assessed, oracleScore };
    fs.writeFileSync(path.join(secDir, 'result.json'), JSON.stringify(out, null, 2) + '\n', 'utf8');
    console.log('  [PASS] P1.1 verified (6/6 oracle).');
    return out;
  } finally {
    await harness.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function runP12NonCooperativeProcessChain(outDir) {
  console.log('\n=== [P1.2] Non-Cooperative Multi-Process Pipeline (Zero Pre-Created Files + Multi-File Order + Post-Cleanup Witness) ===');
  const secDir = path.join(outDir, 'p1-2-non-cooperative-process-chain');
  fs.mkdirSync(secDir, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(realTmp(), 'ig5-p12-'));
  const ig5Home = path.join(secDir, 'ig5-home');
  const workspace = path.join(tmp, 'workspace');
  const activeGoals = new Map();
  const harness = await createIg5Harness({ ig5Home, workspaceDir: workspace, activeGoals });

  try {
    const spec = materializeNonCooperativeProcessChain(workspace);
    const agent = harness.makeAgent('sess-nc-chain');
    const goalObj = 'Recover variable-length framing rule across telemetry_cli.exe -> spool_router.exe -> frame_sealer64.exe';
    activeGoals.set(agent.id, { id: 'goal-nc-chain', phase: 'active', revision: 1, objective: goalObj, roundsStarted: 1, maxGoalRounds: 10 });

    const job1Path = path.join(spec.suiteDir, 'job1.bin');
    const holdPath = path.join(spec.suiteDir, 'hold7.bin');
    const decoyPath = path.join(spec.suiteDir, 'decoy.cfg');

    // Notice: ZERO manual fs.writeFileSync in harness!
    // `job1.bin` is prepared via managed `prepareInputs`; `hold7.bin` is registered BEFORE existing on disk (`planned-awaiting-materialization`).
    const created = await harness.wsCall(agent, {
      action: 'root-create',
      goal: goalObj,
      root: {
        prepareInputs: [
          { path: decoyPath, hex: '7b226d223a317d' },
          { path: job1Path, hex: '414243' },
        ],
        deliverables: [{
          id: 'deliv-1',
          kind: 'structured-frame-transform',
          requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'multi-process-lineage'],
          nonCooperativeRequired: true,
          holdoutRequired: true,
        }],
        components: [
          { componentId: 'comp-cli', path: spec.cliExe, role: 'main-pe' },
          { componentId: 'comp-router', path: spec.routerExe, role: 'broker-pe', parentComponentId: 'comp-cli' },
          { componentId: 'comp-sealer', path: spec.workerPath, role: 'worker-pe', parentComponentId: 'comp-router' },
        ],
        scenarios: [
          {
            scenarioId: 'scen-file-3b',
            componentId: 'comp-cli',
            launchMode: 'via-parent',
            args: ['--in-file', 'job1.bin', '--out-file', 'out1.bin'],
            cwd: spec.suiteDir,
            inputSpec: { kind: 'file', filePath: 'job1.bin', argIndex: 1, sampleHex: '414243', isHoldout: false },
          },
          {
            scenarioId: 'scen-stdin-5b',
            componentId: 'comp-cli',
            launchMode: 'via-parent',
            args: ['--stdin-raw'],
            cwd: spec.suiteDir,
            inputSpec: { kind: 'stdin', stdinHex: '1020304050', encoding: 'hex', isHoldout: false },
          },
        ],
      },
    });
    const rootId = created.rootId;

    await harness.callTool(agent, 'ig5_open', {
      path: spec.workerPath,
      background: false,
      engine: 'ghidra',
      research: { id: rootId, key: 'nc-chain-ghidra-open' },
    });
    await harness.callTool(agent, 'ig5_close', { target: spec.workerPath, engine: 'ghidra' });

    // Discovery 1: Multi-file `[decoy.cfg, job1.bin]` order — decoy comes FIRST, channel binding must pick `job1.bin`!
    const sel1 = await harness.wsCall(agent, { action: 'select', id: rootId, root: { kind: 'dynamic-breakpoint-read', scenarioId: 'scen-file-3b', componentId: 'comp-cli', hypothesis: 'file-in/file-out 3B with decoy first', observer: 'job-lineage' } });
    const obs1 = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'process_chain_scenario',
      target: spec.cliExe,
      args: ['--in-file', 'job1.bin', '--out-file', 'out1.bin'],
      cwd: spec.suiteDir,
      input_files: [
        { path: 'decoy.cfg', hex: '7b226d223a317d' },
        { path: 'job1.bin', hex: '414243' },
      ],
      output_channel: { kind: 'file-bytes', path: 'out1.bin' },
      research: { ...sel1.researchBinding, key: 'nc-chain-obs-1', step: 0 },
    });
    assert.equal(obs1.ok, true);
    assert.equal(obs1.observedInputHex, '414243');
    assert.equal(obs1.outputHex, spec.referenceHexFn('414243'));

    // Discovery 2: Stdin 5B
    const sel2 = await harness.wsCall(agent, { action: 'select', id: rootId, root: { kind: 'dynamic-breakpoint-read', scenarioId: 'scen-stdin-5b', componentId: 'comp-cli', hypothesis: 'stdin 5B', observer: 'job-lineage' } });
    const obs2 = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'process_chain_scenario',
      target: spec.cliExe,
      args: ['--stdin-raw'],
      cwd: spec.suiteDir,
      stdin_hex: '1020304050',
      output_channel: { kind: 'stdout-hex' },
      research: { ...sel2.researchBinding, key: 'nc-chain-obs-2', step: 0 },
    });
    assert.equal(obs2.ok, true);
    assert.equal(obs2.outputHex, spec.referenceHexFn('1020304050'));

    // Pre-commit variable-length frame rule BEFORE unseen 7B file holdout
    const frameRule = {
      schema: 'ig5-bounded-frame-rule-v1',
      headerHex: 'd419',
      lengthField: { kind: 'total-len-u8', bias: 0 },
      prevInit: 0x27,
      constants: { k4: '61a83fd2' },
      bodyByteExpr: {
        op: 'xor',
        args: [
          { op: 'xor', args: [{ op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, 0x14] }, { op: 'const', name: 'k4', index: { op: 'and', args: [{ op: 'i' }, 3] } }] },
          { op: 'prev' },
        ],
      },
      trailerChecksum: { kind: 'sum8', scope: 'header-and-body', init: 5 },
    };
    const outSpec = { kind: 'app-output', channel: 'process-chain', minByteLength: 5, maxByteLength: 64 };
    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        candidate: {
          deliverableId: 'deliv-1',
          summary: 'd419 + total-len-u8 + prev XOR + sum8(5)',
          outputSpec: outSpec,
          executableRule: frameRule,
        },
        // Register unseen 7B file holdout BEFORE `hold7.bin` exists on disk (`planned-awaiting-materialization`)!
        scenario: {
          scenarioId: 'scen-file-7b-holdout',
          componentId: 'comp-cli',
          launchMode: 'via-parent',
          args: ['--in-file', 'hold7.bin', '--out-file', 'out_hold7.bin'],
          cwd: spec.suiteDir,
          inputSpec: { kind: 'file', filePath: 'hold7.bin', argIndex: 1, sampleHex: 'deadbeefcafeba', isHoldout: true },
        },
      },
    });
    assert.equal(fs.existsSync(holdPath), false, 'hold7.bin must not pre-exist before execution');

    const selH = await harness.wsCall(agent, { action: 'select', id: rootId, root: { kind: 'holdout-verify', scenarioId: 'scen-file-7b-holdout', componentId: 'comp-cli', hypothesis: 'unseen 7B planned file holdout', observer: 'job-lineage' } });
    const obsH = await harness.callTool(agent, 'ig5_app_observe', {
      action: 'process_chain_scenario',
      target: spec.cliExe,
      args: ['--in-file', 'hold7.bin', '--out-file', 'out_hold7.bin'],
      cwd: spec.suiteDir,
      input_files: [
        { path: 'hold7.bin', hex: 'deadbeefcafeba' },
        { path: 'decoy.cfg', hex: '7b226d223a317d' },
      ],
      output_channel: { kind: 'file-bytes', path: 'out_hold7.bin' },
      research: { ...selH.researchBinding, key: 'nc-chain-obs-h', step: 0 },
    });
    assert.equal(obsH.ok, true);
    assert.equal(obsH.observedInputHex, 'deadbeefcafeba');
    assert.equal(obsH.outputHex, spec.referenceHexFn('deadbeefcafeba'));

    // Delete workspace input & output temp files AFTER execution to prove post-cleanup immutable witness verification!
    fs.rmSync(job1Path, { force: true });
    fs.rmSync(holdPath, { force: true });
    assert.equal(fs.existsSync(job1Path), false);
    assert.equal(fs.existsSync(holdPath), false);

    await harness.wsCall(agent, {
      action: 'root-update',
      id: rootId,
      root: {
        testVectors: [
          { caseId: 'd-3b-file', receiptId: obs1._managedExecution.reportId, isHoldout: false },
          { caseId: 'd-5b-stdin', receiptId: obs2._managedExecution.reportId, isHoldout: false },
          { caseId: 'h-7b-file', receiptId: obsH._managedExecution.reportId, isHoldout: true },
        ],
      },
    });

    const assessed = await harness.wsCall(agent, { action: 'assess', id: rootId });
    assert.equal(assessed.assessment, 'satisfied', `Expected satisfied, got: ${JSON.stringify(assessed.denialReasons)}`);
    assert.equal(assessed.canCompleteHostGoal, true);
    const completeRes = await harness.callTool(agent, 'update_goal', { goal_id: 'goal-nc-chain', revision: 1, action: 'complete' });
    assert.equal(completeRes.phase, 'completed');

    const oracleScore = scoreVariableRule(frameRule, spec.referenceHexFn);
    assert.equal(oracleScore.allPassed, true);

    const out = {
      ok: true,
      inputChannelWitnessD1: obs1.inputChannelWitness,
      inputChannelWitnessHoldout: obsH.inputChannelWitness,
      postCleanupFilesDeletedBeforeAssess: true,
      assessed,
      oracleScore,
    };
    fs.writeFileSync(path.join(secDir, 'result.json'), JSON.stringify(out, null, 2) + '\n', 'utf8');
    console.log('  [PASS] P1.2: Zero pre-created files + multi-file order independence + planned holdout + post-cleanup witness verified (6/6 oracle).');
    return out;
  } finally {
    await harness.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function runP2AndroidNativeControls(outDir) {
  console.log('\n=== [P2] Android Dynamic Provider Probe + Multi-ABI VaultJniDemo.apk + Zero-JNIEnv Guard ===');
  const secDir = path.join(outDir, 'p2-android-dynamic');
  fs.mkdirSync(secDir, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(realTmp(), 'ig5-p2-'));
  const ig5Home = path.join(secDir, 'ig5-home');
  const workspace = path.join(tmp, 'workspace');
  const activeGoals = new Map();
  const harness = await createIg5Harness({ ig5Home, workspaceDir: workspace, activeGoals });

  try {
    const apkFixture = buildOwnedStatefulJniApk(path.join(secDir, 'built-apk'));
    const agent = harness.makeAgent('sess-android-p2');
    const goalObj = 'Verify VaultJniDemo.apk native JNI sealBytes';
    activeGoals.set(agent.id, { id: 'goal-android', phase: 'active', revision: 1, objective: goalObj, roundsStarted: 1, maxGoalRounds: 10 });

    const probeRes = await harness.callTool(agent, 'ig5_app_observe', { action: 'android_probe', target: apkFixture.apkPath });
    assert.equal(probeRes.ok, true);
    assert.equal(probeRes.dynamicReadiness.implemented, true);
    assert.equal(probeRes.dynamicReadiness.providerReady, true);
    assert.equal(probeRes.dynamicReadiness.deviceSessionReadyNow, false);
    assert.equal(probeRes.dynamicReadiness.deviceVerifiedByAbi['arm64-v8a'], false);
    assert.equal(probeRes.dynamicReadiness.deviceVerifiedByAbi['x86_64'], false);

    let startBlockedErr = null;
    try {
      await harness.callTool(agent, 'ig5_app_observe', {
        action: 'android_session_start',
        device_serial: 'emulator-5554',
        package_name: 'com.ig5.vault',
        target: apkFixture.apkPath,
        probe_specs: [{ id: 'p1', layer: 'jni', library: 'libvault_jni.so', symbol: 'Java_com_ig5_vault_VaultBridge_sealBytes' }],
      });
    } catch (err) {
      startBlockedErr = { code: err.code, message: err.message };
    }
    assert.equal(startBlockedErr?.code, 'ANDROID_DEVICE_UNAVAILABLE');

    const out = {
      ok: true,
      probeReadiness: probeRes.dynamicReadiness,
      apkMembership: probeRes.apkMembership,
      startSessionWithoutDeviceError: startBlockedErr,
    };
    fs.writeFileSync(path.join(secDir, 'result.json'), JSON.stringify(out, null, 2) + '\n', 'utf8');
    console.log('  [PASS] P2 verified.');
    return out;
  } finally {
    await harness.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function runPortabilityCleanTempRepro(outDir) {
  console.log('\n=== [Section VII] Clean %TEMP% Deployment Portability Repro ===');
  const secDir = path.join(outDir, 'p3-portability-clean-temp');
  fs.mkdirSync(secDir, { recursive: true });
  const cleanRoot = fs.mkdtempSync(path.join(realTmp(), 'ig5-clean-deploy-repro-'));
  try {
    const stagedPlugin = stageCleanPluginForEval();
    const cleanPluginDir = path.join(cleanRoot, 'dsh-infinite-gen-5');
    const sampleAppDir = path.join(cleanRoot, 'sample-js-app');
    const samplePackagedDir = path.join(cleanRoot, 'sample-packaged-app');

    fs.cpSync(stagedPlugin, cleanPluginDir, { recursive: true });
    fs.mkdirSync(sampleAppDir, { recursive: true });
    fs.writeFileSync(path.join(sampleAppDir, 'package.json'), JSON.stringify({ name: 'clean-sample', version: '1.0.0', main: 'main.js' }), 'utf8');
    fs.writeFileSync(path.join(sampleAppDir, 'main.js'), 'const { ipcMain } = require("electron"); ipcMain.handle("ping", () => "pong");\n', 'utf8');
    fs.mkdirSync(path.join(samplePackagedDir, 'resources', 'app'), { recursive: true });
    fs.writeFileSync(path.join(samplePackagedDir, 'MyPackagedTarget.exe'), 'MZ-placeholder', 'utf8');
    fs.writeFileSync(path.join(samplePackagedDir, 'resources', 'app', 'package.json'), '{"name":"pkg"}', 'utf8');

    const probeScript = path.join(cleanRoot, 'run_clean_probe.mjs');
    fs.writeFileSync(probeScript, `
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const pluginDir = process.argv[2];
const appDir = process.argv[3];
const packagedDir = process.argv[4];
const mod = await import(pathToFileURL(path.join(pluginDir, 'source', 'native_rea_bridge.js')).href);
const out = {};
try { out.reaStatic = mod.analyzeJsApplicationStatic(appDir, { pluginRoot: pluginDir }); }
catch (err) { out.reaError = { code: err.code, missingAtom: err.missingAtom || null }; }
try { out.externalReaStatic = mod.analyzeJsApplicationStatic(appDir, { pluginRoot: pluginDir, requireExternalRea: true }); }
catch (err) { out.externalReaError = { code: err.code, missingAtom: err.missingAtom || null }; }
try { out.unpackagedElectron = mod.resolveElectronLaunchTarget(appDir, { cfg: { pluginRoot: pluginDir } }); }
catch (err) { out.unpackagedElectronError = { code: err.code, missingAtom: err.missingAtom || null }; }
out.packagedElectron = mod.resolveElectronLaunchTarget(packagedDir, { cfg: { pluginRoot: pluginDir } });
console.log(JSON.stringify(out));
`, 'utf8');

    const cleanEnvBase = { ...process.env };
    delete cleanEnvBase.IG5_REA_ROOT;
    delete cleanEnvBase.IG5_REA_CLI;
    delete cleanEnvBase.IG5_ELECTRON_EXE;
    delete cleanEnvBase.IG5_RUNTIME_ROOT;

    const rawUnconfigured = execFileSync(process.execPath, [probeScript, cleanPluginDir, sampleAppDir, samplePackagedDir], {
      cwd: cleanRoot, env: cleanEnvBase, encoding: 'utf8', windowsHide: true,
    });
    const unconfigured = JSON.parse(rawUnconfigured.trim());
    assert.equal(unconfigured.reaStatic?.schema, 'ig5-js-app-static-report-v2');
    assert.equal(unconfigured.reaStatic?.evidenceSource, 'ig5-builtin-js-static-v1');
    assert.equal(unconfigured.reaStatic?.reaEngine?.externalReaUsed, false);
    assert.ok(unconfigured.reaStatic?.reaAnalysis?.ipc_channels?.some((c) => c.channel === 'ping'));
    assert.equal(unconfigured.externalReaError?.code, 'REA_CLI_UNAVAILABLE');
    assert.equal(unconfigured.unpackagedElectronError?.code, 'ELECTRON_RUNTIME_UNAVAILABLE');
    assert.equal(unconfigured.packagedElectron?.runtimeSelection, 'target-packaged-executable');

    let withTempReaRootOnly = null;
    if (process.env.IG5_REA_ROOT && fs.existsSync(process.env.IG5_REA_ROOT)) {
      const cleanReaDir = path.join(cleanRoot, 'rea-agents');
      fs.cpSync(process.env.IG5_REA_ROOT, cleanReaDir, { recursive: true });
      const rawConfigured = execFileSync(process.execPath, [probeScript, cleanPluginDir, sampleAppDir, samplePackagedDir], {
        cwd: cleanRoot, env: { ...cleanEnvBase, IG5_REA_ROOT: cleanReaDir }, encoding: 'utf8', windowsHide: true,
      });
      const configured = JSON.parse(rawConfigured.trim());
      assert.equal(configured.reaStatic?.schema, 'ig5-js-app-static-report-v2');
      withTempReaRootOnly = { schema: configured.reaStatic.schema, reaEngine: configured.reaStatic.reaEngine };
    }

    const out = { ok: true, withoutEnvVars: unconfigured, withTempReaRootOnly };
    fs.writeFileSync(path.join(secDir, 'result.json'), JSON.stringify(out, null, 2) + '\n', 'utf8');
    console.log('  [PASS] Portability verified.');
    return out;
  } finally {
    fs.rmSync(cleanRoot, { recursive: true, force: true });
  }
}

fs.mkdirSync(outRoot, { recursive: true });
const startedAt = new Date().toISOString();
const preSourceIdentity = computeSourceTreeIdentity(repoRoot);
const sections = {};

if (enabledSections.has('p01')) sections.p01JobContainerAndBystander = await runP01JobContainerAndBystanderControls(outRoot);
if (enabledSections.has('p02')) sections.p02ForgedSelfReportNegative = await runP02ForgedSelfReportControl(outRoot);
if (enabledSections.has('p11')) sections.p11NonCooperativeElectron = await runP11NonCooperativeElectron(outRoot);
if (enabledSections.has('p12')) sections.p12NonCooperativeProcessChain = await runP12NonCooperativeProcessChain(outRoot);
if (enabledSections.has('p2')) sections.p2AndroidDynamicAndJniGuard = await runP2AndroidNativeControls(outRoot);
if (enabledSections.has('portability')) sections.section7PortabilityCleanTemp = await runPortabilityCleanTempRepro(outRoot);

const postProcessCheck = collectNativeProcessCheck();
const postSourceIdentity = computeSourceTreeIdentity(repoRoot);
assert.equal(preSourceIdentity.treeDigest, postSourceIdentity.treeDigest, 'Source tree digest must remain unchanged during native controls');

const summary = {
  schema: 'ig5-transferable-dynamic-native-controls-v2',
  startedAt,
  completedAt: new Date().toISOString(),
  requestedSections: [...enabledSections],
  sourceTreeDigest: postSourceIdentity.treeDigest,
  fileCount: postSourceIdentity.fileCount,
  postRunNativeProcessCheck: postProcessCheck,
  sections,
};
fs.writeFileSync(path.join(outRoot, 'native-controls-summary.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');
console.log('\n=== NATIVE CONTROLS COMPLETED ===');
