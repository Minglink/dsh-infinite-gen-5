import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';

import {
  resolveHostPaths,
  stageCleanPluginForEval,
  collectNativeProcessCheck,
  buildCleanupAssessment,
} from './run_m2_blind_eval.mjs';
import { computeSourceTreeIdentity } from '../lib/source_tree_identity.mjs';
import { evaluateBoundedTransform } from '../../source/investigation_verifier.js';
import { RootInvestigationStore } from '../../source/investigation_root.js';
import { assessRootInvestigation } from '../../source/investigation_assessment.js';
import { AnalysisArtifacts } from '../../source/analysis_artifacts.js';
import { DelegationControl } from '../../source/delegation_control.js';
import {
  classifyPromptGuidance,
  analyzeTokenUsage,
  analyzeCallAndErrorPartitions,
  buildTransparentCleanupReport,
  auditRootContractAgainstSpec,
  buildMultiDimensionalOutcome,
} from './eval_metrics_and_contracts.mjs';

const cliOpt = (flag) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
};

const repoRoot = cliOpt('--repo-root') || path.resolve(import.meta.dirname, '..', '..');
const outRoot = cliOpt('--out-root');
const suiteModulePath = cliOpt('--suite-module');
const caseFilter = cliOpt('--case') || 'all';
const maxTotalToolCalls = Number(cliOpt('--max-calls') || 72);
const terminalControlReserve = Number(cliOpt('--terminal-reserve') || 2);
const wallTimeoutMs = Number(cliOpt('--wall-timeout-ms') || 720_000);

if (!outRoot || !suiteModulePath) {
  throw new Error('Usage: node scripts/evals/run_transferable_dynamic_online.mjs --out-root <fresh-dir> --suite-module <suite.mjs> [--case all|<caseKey>]');
}

const guardPluginPath = path.join(repoRoot, 'scripts', 'evals', 'm2_suite_guard.mjs');
const realTmp = () => (fs.realpathSync.native || fs.realpathSync)(os.tmpdir());

function getProviderBlock(realDshHome) {
  const desktopPatchRaw = fs.readFileSync(path.join(realDshHome, 'profiles', 'desktop', 'cordis.patch.yml'), 'utf8');
  const llmBlock = [];
  let inLlm = false;
  for (const line of desktopPatchRaw.split(/\r?\n/)) {
    if (line.startsWith('- id: llm-pi-ai')) inLlm = true;
    else if (inLlm && /^- (?:id:|insert:)/.test(line)) break;
    if (inLlm) llmBlock.push(line);
  }
  return llmBlock.join('\n') + '\n';
}

function scoreVariableLengthOracle({ executableRule, oracleVectors, referenceHexFn, observedInputs = [] }) {
  if (!executableRule || typeof referenceHexFn !== 'function' || !Array.isArray(oracleVectors)) {
    return {
      evaluated: false,
      passedCount: 0,
      totalCount: Array.isArray(oracleVectors) ? oracleVectors.length : 0,
      allPassed: false,
      overlapWithSessionInputs: [],
      unseenVectorsPassed: 0,
      unseenVectorsTotal: Array.isArray(oracleVectors) ? oracleVectors.length : 0,
      details: [],
    };
  }
  const obsSet = new Set(observedInputs.map((x) => String(x).toLowerCase()));
  const details = [];
  for (const vec of oracleVectors) {
    const expectedHex = referenceHexFn(vec);
    let actualHex = null;
    let evalError = null;
    try {
      actualHex = evaluateBoundedTransform(executableRule, vec);
    } catch (err) {
      evalError = err.code || err.message;
    }
    const match = actualHex === expectedHex;
    details.push({
      inputHex: vec,
      inputBytes: vec.length / 2,
      wasObservedInSession: obsSet.has(vec.toLowerCase()),
      expectedHex,
      actualHex,
      evalError,
      match,
    });
  }
  const passedCount = details.filter((d) => d.match).length;
  const unseen = details.filter((d) => !d.wasObservedInSession);
  return {
    evaluated: true,
    passedCount,
    totalCount: details.length,
    allPassed: passedCount === details.length,
    overlapWithSessionInputs: details.filter((d) => d.wasObservedInSession).map((d) => d.inputHex),
    unseenVectorsPassed: unseen.filter((d) => d.match).length,
    unseenVectorsTotal: unseen.length,
    details,
  };
}

async function runSingleOnlineCase(caseDef, suiteMeta) {
  const outDir = path.join(outRoot, caseDef.outSubdir);
  if (fs.existsSync(outDir) && fs.readdirSync(outDir).length > 0) {
    throw new Error(`Refusing to overwrite non-empty case output directory "${outDir}"; allocate a new attempt directory to preserve full failure denominators.`);
  }
  fs.mkdirSync(outDir, { recursive: true });

  const hostPaths = resolveHostPaths();
  const stagePluginDir = stageCleanPluginForEval();
  const execRoot = fs.mkdtempSync(path.join(realTmp(), `ig5-online-${caseDef.caseKey}-`));
  const dshHome = path.join(execRoot, 'dsh-home');
  const ig5Home = path.join(execRoot, 'ig5-home');
  const workspace = path.join(execRoot, 'workspace');
  fs.mkdirSync(path.join(dshHome, 'plugins'), { recursive: true });
  fs.mkdirSync(ig5Home, { recursive: true });
  fs.mkdirSync(workspace, { recursive: true });

  const spec = caseDef.materializeFn(workspace);
  fs.copyFileSync(path.join(hostPaths.realDshHome, '.credentials.yaml'), path.join(dshHome, '.credentials.yaml'));
  const providerPatchPath = path.join(execRoot, 'provider.patch.yml');
  fs.writeFileSync(providerPatchPath, getProviderBlock(hostPaths.realDshHome), 'utf8');

  execFileSync(hostPaths.electron, ['--expose-internals', hostPaths.cli, '--profile', 'ig5-online-eval', '--from-default-profile', 'sdk', '--help'], {
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', DSH_HOME: dshHome, DSH_TELEMETRY_DISABLED: '1' },
    stdio: 'pipe',
  });

  const pluginDest = path.join(dshHome, 'plugins', 'dsh-infinite-gen-5');
  fs.symlinkSync(stagePluginDir, pluginDest, 'junction');
  const profileDir = path.join(dshHome, 'profiles', 'ig5-online-eval');
  const pkgPath = path.join(profileDir, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  pkg.dependencies = { ...(pkg.dependencies || {}), 'dsh-infinite-gen-5': 'file:../../plugins/dsh-infinite-gen-5' };
  pkg.dsh.profile.bundles = [...pkg.dsh.profile.bundles.filter((b) => b !== 'dsh-infinite-gen-5'), 'dsh-infinite-gen-5'];
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n', 'utf8');
  fs.mkdirSync(path.join(profileDir, 'node_modules'), { recursive: true });
  fs.symlinkSync(pluginDest, path.join(profileDir, 'node_modules', 'dsh-infinite-gen-5'), 'junction');

  const guardLogPath = path.join(outDir, 'guard-log.jsonl');
  const evalOverlay = [
    { id: 'goal', config: { defaultMaxGoalRounds: 10 } },
    { id: 'tool-pwsh', disabled: true },
    { id: 'tool-web', disabled: true },
    { id: 'tool-plugin-manager', disabled: true },
    { id: 'tool-schedule', disabled: true },
    { id: 'tool-ask-user', disabled: true },
    { id: 'skill-office', disabled: true },
    {
      insert: [
        {
          id: 'ig5-m2-suite-guard',
          name: guardPluginPath,
          config: {
            policyVersion: 'r3-evidence-closure-allowlist-v1',
            extraAllowedTools: ['ig5_package', 'ig5_app_observe'],
            allowedPackageActions: ['js_app', 'apk', 'trace_diff', 'result'],
            workspaceRoot: workspace,
            readOnlyRoots: [
              path.join(stagePluginDir, 'skills'),
              path.join(stagePluginDir, 'docs'),
              path.join(dshHome, 'spills'),
            ],
            searchAllowedRoots: [
              workspace,
              path.join(stagePluginDir, 'skills'),
              path.join(stagePluginDir, 'docs'),
            ],
            pluginInternalRoots: [ig5Home],
            blockedPluginSubdirs: [path.join(stagePluginDir, 'scripts')],
            logPath: guardLogPath,
            maxTotalToolCalls,
            terminalControlReserve,
            minGoalRoundsForBlocked: 3,
          },
        },
      ],
    },
  ];
  const evalPatchPath = path.join(execRoot, 'eval-overlay.patch.yml');
  fs.writeFileSync(evalPatchPath, JSON.stringify(evalOverlay, null, 2) + '\n', 'utf8');

  const objective = caseDef.buildPrompt(spec, workspace);
  const promptAudit = classifyPromptGuidance(objective);
  if (suiteMeta.requirePureBusinessPrompts && promptAudit.guidanceLevel !== 'pure-business-only') {
    throw new Error(`Unseen acceptance prompt for "${caseDef.caseId}" violated pure-business-only policy: ${JSON.stringify(promptAudit)}`);
  }
  fs.writeFileSync(path.join(outDir, 'user-prompt.txt'), objective + '\n', 'utf8');

  const provider = process.env.IG5_EVAL_PROVIDER || 'expr';
  const model = process.env.IG5_EVAL_MODEL || 'deepseek-v4.1-flash-uncensored';

  console.log(`\n>>> Starting Online Session [${caseDef.caseId}] (guidance=${promptAudit.guidanceLevel}) <<<`);
  const child = spawn(hostPaths.electron, [
    '--expose-internals', hostPaths.cli,
    '--profile', 'ig5-online-eval',
    '--patch', providerPatchPath,
    '--patch', evalPatchPath,
  ], {
    cwd: workspace,
    windowsHide: true,
    env: {
      ...process.env,
      ELECTRON_RUN_AS_NODE: '1',
      DSH_HOME: dshHome,
      IG5_HOME: ig5Home,
      DSH_TELEMETRY_DISABLED: '1',
      DSH_MAX_TOKENS_AS_SUCCESS: 'false',
    },
  });

  const pending = new Map();
  const events = [];
  const approvals = [];
  const stderrChunks = [];
  const queryCompletionWaiters = [];
  let seq = 0;
  let buffer = '';
  let exited = false;
  let runnerTerminated = false;
  let runnerTerminationReason = null;

  const latestGoalPhase = () => {
    let phase = 'active';
    for (const ev of events) {
      if (ev.type === 'goal/change' && ev.data?.goal?.phase) phase = ev.data.goal.phase;
    }
    return phase;
  };

  const checkUnrecoverableExhaustionAtTurnEnd = () => {
    if (!fs.existsSync(guardLogPath)) return;
    if (['complete', 'completed', 'blocked', 'paused'].includes(latestGoalPhase())) return;
    try {
      const gLines = fs.readFileSync(guardLogPath, 'utf8').split(/\r?\n/).filter(Boolean).map(JSON.parse);
      const lastEntry = gLines[gLines.length - 1];
      if (lastEntry && lastEntry.ordinaryAllowedCount >= (maxTotalToolCalls - terminalControlReserve)
        && lastEntry.terminalReserveUsed >= terminalControlReserve) {
        runnerTerminated = true;
        runnerTerminationReason = 'ordinary-and-terminal-reserve-exhausted-while-goal-still-active';
        console.log(`[${caseDef.caseId}] Both ordinary and terminal reserve exhausted while goal still active; terminating stuck session cleanly (runnerTerminated=true).`);
        try { child.kill(); } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
  };

  child.stdout.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    let nl;
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }
      if (msg.id !== undefined && !msg.method) {
        const p = pending.get(msg.id);
        if (p) {
          pending.delete(msg.id);
          if (msg.error) p.reject(Object.assign(new Error(msg.error.message), { code: msg.error.code }));
          else p.resolve(msg.result);
        }
        continue;
      }
      if (msg.method === 'session.event') {
        const ev = msg.params.event;
        events.push(ev);
        if (ev.type === 'tool/call') {
          console.log(`[${caseDef.caseId}][tool] ${ev.data?.name} ${(ev.data?.arguments || '').slice(0, 120)}`);
        } else if (ev.type === 'goal/change') {
          console.log(`[${caseDef.caseId}][goal] op=${ev.data?.operation} phase=${ev.data?.goal?.phase} rev=${ev.data?.goal?.revision}`);
        } else if (ev.type === 'turn/start') {
          console.log(`[${caseDef.caseId}][turn/start] turn=${ev.data?.turn}`);
        } else if (ev.type === 'turn/end') {
          checkUnrecoverableExhaustionAtTurnEnd();
        }
        continue;
      }
      if (msg.method === 'session.query.completed') {
        console.log(`[${caseDef.caseId}][query.completed] finishReason=${msg.params?.finishReason}`);
        while (queryCompletionWaiters.length) queryCompletionWaiters.shift()(msg.params);
        continue;
      }
      if (msg.method === 'approval/request' && msg.id !== undefined) {
        approvals.push({
          ts: new Date().toISOString(),
          toolName: msg.params?.toolName,
          callId: msg.params?.callId,
          outcome: 'allowed-once',
        });
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { outcome: 'allowed-once' } }) + '\n');
        continue;
      }
      if (msg.method && msg.id !== undefined) {
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `Unsupported: ${msg.method}` } }) + '\n');
      }
    }
  });
  child.stderr.on('data', (c) => stderrChunks.push(c.toString('utf8')));

  const exitPromise = new Promise((resolve) => {
    child.on('exit', (code, signal) => {
      exited = true;
      for (const p of pending.values()) p.reject(new Error('SDK process exited'));
      pending.clear();
      while (queryCompletionWaiters.length) queryCompletionWaiters.shift()({ finishReason: 'process-exited' });
      resolve({ code, signal });
    });
  });

  const rpc = (method, params, timeoutMs = 60_000) => new Promise((resolve, reject) => {
    const id = `req_${++seq}`;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`RPC ${method} timeout`)); }, timeoutMs);
    pending.set(id, {
      resolve: (v) => { clearTimeout(timer); resolve(v); },
      reject: (e) => { clearTimeout(timer); reject(e); },
    });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });

  const waitNextCompleted = (timeoutMs) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Query timeout after ${timeoutMs}ms`)), timeoutMs);
    queryCompletionWaiters.push((res) => { clearTimeout(timer); resolve(res); });
  });

  const sessionId = `session-${caseDef.caseId}-${randomUUID()}`;
  const startedAt = Date.now();
  let runError = null;
  let providerResumes = 0;

  try {
    await rpc('initialize', { cwd: workspace, provider, model, approvalRequests: true, maxTokens: 16384 });
    const wait1 = waitNextCompleted(wallTimeoutMs);
    await rpc('session/query', {
      sessionId,
      contentBlocks: [{ type: 'text', text: `/goal ${objective.replace(/\s*\n\s*/g, ' ')}` }],
    });
    let qRes = await wait1;
    await rpc('session/wait', { sessionId }, 30_000).catch(() => {});
    while (qRes?.finishReason === 'error' && !runnerTerminated && !['complete', 'completed', 'blocked'].includes(latestGoalPhase()) && providerResumes < 2) {
      const rem = wallTimeoutMs - (Date.now() - startedAt);
      if (rem < 60_000) break;
      providerResumes += 1;
      console.log(`[${caseDef.caseId}] Transient stream error while goal active; resuming in same session without budget reset (${providerResumes}/2)...`);
      const waitNext = waitNextCompleted(rem);
      await rpc('session/query', {
        sessionId,
        contentBlocks: [{ type: 'text', text: '/goal resume' }],
      });
      qRes = await waitNext;
      await rpc('session/wait', { sessionId }, 30_000).catch(() => {});
    }
  } catch (err) {
    runError = { message: err.message, code: err.code || null };
  } finally {
    if (!exited) {
      try { child.stdin.end(); } catch { /* ignore */ }
      await Promise.race([exitPromise, new Promise((r) => setTimeout(r, 8000))]);
      if (!exited) { try { child.kill(); } catch { /* ignore */ } }
    }
  }

  const elapsedMs = Date.now() - startedAt;
  const processCheck = collectNativeProcessCheck();

  fs.writeFileSync(path.join(outDir, 'events.jsonl'), events.map((e) => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  fs.writeFileSync(path.join(outDir, 'approvals.json'), JSON.stringify(approvals, null, 2) + '\n', 'utf8');
  fs.writeFileSync(path.join(outDir, 'stderr.log'), stderrChunks.join(''), 'utf8');
  if (fs.existsSync(ig5Home)) {
    fs.cpSync(ig5Home, path.join(outDir, 'ig5-home'), { recursive: true });
  }
  const archivedDshSessions = path.join(outDir, 'dsh-sessions');
  if (fs.existsSync(path.join(dshHome, 'sessions'))) {
    fs.cpSync(path.join(dshHome, 'sessions'), archivedDshSessions, { recursive: true });
  }

  const archivedIg5Home = path.join(outDir, 'ig5-home');
  const rStore = new RootInvestigationStore({ projectRoot: path.join(archivedIg5Home, 'projects') });
  const artifacts = new AnalysisArtifacts(path.join(archivedIg5Home, 'artifacts', 'analysis-data'));
  const coord = new DelegationControl({ root: path.join(archivedIg5Home, 'projects') });
  const roots = rStore.list({ rootSessionId: sessionId });
  const chosenSummary = roots[0] || rStore.list()[0] || null;
  const rootTask = chosenSummary ? rStore.get(chosenSummary.rootId) : null;
  const deliv = rootTask?.deliverables?.[0] || null;
  const cand = deliv?.candidateExplanation || null;

  let postRunAssess = null;
  if (rootTask) {
    try {
      postRunAssess = assessRootInvestigation({
        rootTask,
        mgr: { analysis: { artifacts }, artifacts, coordination: coord },
        execution: { agent: { id: sessionId, session: { id: sessionId, header: { id: sessionId } } } },
        hostGoal: null,
      });
    } catch (err) {
      postRunAssess = { error: err.message };
    }
  }

  const observedInputs = (rootTask?.experiments || [])
    .map((e) => e.scenarioSnapshot?.inputHex || e.scenarioSnapshot?.plannedInputHex)
    .filter(Boolean);

  const oracleScore = caseDef.isNegativeControl
    ? { note: 'Negative control: multi-worker pipeline obligation is fabricated at runtime; completion must be denied and host goal marked blocked.' }
    : scoreVariableLengthOracle({
      executableRule: cand?.executableRule || null,
      oracleVectors: suiteMeta.oracleVectors,
      referenceHexFn: spec.referenceHexFn,
      observedInputs,
    });

  const controlState = coord.controlStatus({ id: sessionId, session: { id: sessionId, header: { id: sessionId } } });
  const cleanup = buildCleanupAssessment({
    processCheck,
    cleanupReservations: controlState?.cleanupReservations || [],
  });

  const loadJsonlSafe = (fp) => (fs.existsSync(fp) ? fs.readFileSync(fp, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l)) : []);
  const dshRows = [];
  if (fs.existsSync(archivedDshSessions)) {
    const walk = (dir) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) walk(full);
        else if (ent.isFile() && ent.name.endsWith('.jsonl')) dshRows.push(...loadJsonlSafe(full));
      }
    };
    walk(archivedDshSessions);
  }
  const guardEntries = loadJsonlSafe(guardLogPath);
  const tokenUsage = analyzeTokenUsage({ dshSessionObjects: dshRows, sessionEvents: events });
  const callAndErrors = analyzeCallAndErrorPartitions({
    sessionEvents: events,
    guardEntries,
    ordinaryCallLimit: maxTotalToolCalls - terminalControlReserve,
  });
  const ephemeralJobRunsCount = (rootTask?.receipts || []).filter((r) =>
    r.tool === 'ig5_app_observe' && ['ig5_app_observe:electron_scenario', 'ig5_app_observe:process_chain_scenario'].includes(r.action),
  ).length;
  const timedOut = Boolean(runError && /timeout/i.test(runError.message || ''));
  const cleanupAttribution = buildTransparentCleanupReport({
    processCheck: { status: cleanup?.processCheckStatus || 'checked', processes: processCheck?.lingeringIg5Processes || [] },
    cleanupReservations: controlState?.cleanupReservations || [],
    explicitCleanupCallsCount: callAndErrors.explicitCleanupCallsCount,
    ephemeralJobContainersAutoReclaimedCount: ephemeralJobRunsCount,
    runnerFallbackKillUsed: timedOut || runnerTerminated,
  });
  const contractAudit = auditRootContractAgainstSpec(rootTask, caseDef.expectedContract);
  const finalGoalPhase = latestGoalPhase();
  const goalRoundMessages = events.filter((e) => e.type === 'user/message' && e.data?.source?.kind === 'goal');
  const goalChanges = events.filter((e) => e.type === 'goal/change').map((e) => ({
    seq: e.seq,
    operation: e.data?.operation,
    phase: e.data?.goal?.phase,
    revision: e.data?.goal?.revision,
    roundsStarted: e.data?.roundsStarted ?? null,
  }));
  const outcomes = buildMultiDimensionalOutcome({
    isNegativeControl: Boolean(caseDef.isNegativeControl),
    finalGoalPhase,
    postRunAssess,
    oracleScore,
    contractAudit,
    callPartitions: callAndErrors,
    cleanupReport: cleanup,
    timedOut,
    runnerTerminated,
  });
  const hostGoalCompleted = finalGoalPhase === 'complete' || finalGoalPhase === 'completed';
  const deliverableCorrect = caseDef.isNegativeControl
    ? Boolean(outcomes.truthfulRejection && outcomes.hostStoppedLegally)
    : Boolean(outcomes.strictEndToEndAutonomousClosure);

  const srcId = computeSourceTreeIdentity(repoRoot);
  const summary = {
    schema: 'ig5-transferable-dynamic-online-case-v2',
    strictBlindEligible: false,
    suiteId: suiteMeta.suiteId,
    caseKey: caseDef.caseKey,
    caseId: caseDef.caseId,
    isNegativeControl: Boolean(caseDef.isNegativeControl),
    sourceTreeIdentity: {
      treeDigest: srcId.treeDigest,
      fileCount: srcId.fileCount,
    },
    provider,
    model,
    sessionId,
    elapsedMs,
    providerResumes,
    runnerTerminated,
    runnerTerminationReason,
    humanGuidanceMessagesCount: 0,
    autoAllowedApprovalRequestsCount: approvals.length,
    runError,
    promptAudit,
    contractAudit,
    callPartitions: callAndErrors,
    errorMetrics: callAndErrors.executionAndErrors,
    tokenUsage,
    cleanupAttribution,
    goalTrajectory: {
      goalRoundsObserved: goalRoundMessages.length,
      maxGoalRoundNumber: goalRoundMessages.reduce((m, e) => Math.max(m, Number(e.data?.source?.round || 0)), 0),
      goalChanges,
    },
    outcomes,
    finalGoalPhase,
    hostGoalCompleted,
    deliverableCorrect,
    falseCompletion: outcomes.falseCompletion,
    cleanupConfirmed: cleanup.cleanupConfirmed,
    cleanup,
    rootInvestigationSummary: rootTask ? {
      rootId: rootTask.rootId,
      deliverableKind: deliv?.kind || null,
      nonCooperativeRequired: Boolean(deliv?.nonCooperativeRequired),
      componentsCount: rootTask.components?.length || 0,
      experimentsCount: rootTask.experiments?.length || 0,
      receiptsCount: rootTask.receipts?.length || 0,
      counterexamplesCount: rootTask.counterexamples?.length || 0,
      candidateRuleSchema: cand?.executableRule?.schema || null,
      terminalFinding: rootTask.terminalFinding || null,
    } : null,
    postRunAssess: postRunAssess ? {
      assessment: postRunAssess.assessment,
      cleanup: postRunAssess.cleanup,
      canCompleteHostGoal: postRunAssess.canCompleteHostGoal,
      denialReasons: postRunAssess.denialReasons,
      terminalFinding: postRunAssess.terminalFinding || null,
      hostGoalRoundStatus: postRunAssess.hostGoalRoundStatus || null,
    } : null,
    oracleScore,
  };

  fs.writeFileSync(path.join(outDir, 'case-result.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');
  try { await artifacts.dispose(); } catch { /* ignore */ }
  fs.rmSync(execRoot, { recursive: true, force: true });

  console.log(`<<< Finished [${caseDef.caseId}]: phase=${summary.finalGoalPhase}, strictClosure=${summary.outcomes.strictEndToEndAutonomousClosure}, deliverableCorrect=${summary.deliverableCorrect}, hostStoppedLegally=${summary.outcomes.hostStoppedLegally}, attempted=${summary.callPartitions.attemptedCalls}, dispatched=${summary.errorMetrics.actuallyDispatchedCalls}, errors=${summary.errorMetrics.totalErrorResults} >>>`);
  return summary;
}

const suiteMod = await import(pathToFileURL(path.resolve(suiteModulePath)).href);
const suiteDef = typeof suiteMod.getSuiteDefinition === 'function' ? suiteMod.getSuiteDefinition() : suiteMod.SUITE_DEFINITION;
if (!suiteDef || !Array.isArray(suiteDef.cases)) {
  throw new Error(`Suite module "${suiteModulePath}" must export SUITE_DEFINITION or getSuiteDefinition() with { suiteId, oracleVectors, cases }`);
}

fs.mkdirSync(outRoot, { recursive: true });
const selectedCases = caseFilter === 'all'
  ? suiteDef.cases
  : suiteDef.cases.filter((c) => c.caseKey === caseFilter || c.caseId === caseFilter);
if (selectedCases.length === 0) {
  throw new Error(`No cases matched --case ${caseFilter}`);
}

const allRuns = [];
for (const c of selectedCases) {
  allRuns.push(await runSingleOnlineCase(c, suiteDef));
}

if (caseFilter === 'all') {
  const positiveRuns = allRuns.filter((r) => !r.isNegativeControl);
  const negativeRuns = allRuns.filter((r) => r.isNegativeControl);
  const suiteSrcId = computeSourceTreeIdentity(repoRoot);
  const suiteSummary = {
    schema: 'ig5-transferable-dynamic-online-summary-v2',
    createdAt: new Date().toISOString(),
    suiteId: suiteDef.suiteId,
    strictBlindEligible: false,
    sourceTreeIdentity: {
      treeDigest: suiteSrcId.treeDigest,
      fileCount: suiteSrcId.fileCount,
    },
    positiveDeliverableAndContractCount: positiveRuns.filter((r) => r.outcomes.strictEndToEndAutonomousClosure).length,
    positiveTotalCount: positiveRuns.length,
    negativeTruthfulRejectionCount: negativeRuns.filter((r) => r.outcomes.truthfulRejection).length,
    negativeHostStoppedLegallyCount: negativeRuns.filter((r) => r.outcomes.strictEndToEndAutonomousClosure).length,
    negativeTotalCount: negativeRuns.length,
    falseCompletionsTotal: allRuns.filter((r) => r.falseCompletion).length,
    runnerTerminatedCount: allRuns.filter((r) => r.outcomes.runnerTerminated).length,
    timeoutCount: allRuns.filter((r) => r.outcomes.timeout).length,
    cleanupConfirmedCount: allRuns.filter((r) => r.cleanupConfirmed).length,
    contractAlignedCount: allRuns.filter((r) => r.outcomes.contractAligned).length,
    totalSessionsCount: allRuns.length,
    runs: allRuns,
  };
  fs.writeFileSync(path.join(outRoot, 'suite-summary.json'), JSON.stringify(suiteSummary, null, 2) + '\n', 'utf8');
  console.log('\n=== ONLINE SUITE SUMMARY ===');
  console.log(JSON.stringify({
    suiteId: suiteSummary.suiteId,
    positiveStrictClosure: `${suiteSummary.positiveDeliverableAndContractCount}/${suiteSummary.positiveTotalCount}`,
    negativeTruthfulRejection: `${suiteSummary.negativeTruthfulRejectionCount}/${suiteSummary.negativeTotalCount}`,
    negativeLegalHostStop: `${suiteSummary.negativeHostStoppedLegallyCount}/${suiteSummary.negativeTotalCount}`,
    falseCompletionsTotal: suiteSummary.falseCompletionsTotal,
    runnerTerminatedCount: suiteSummary.runnerTerminatedCount,
    timeoutCount: suiteSummary.timeoutCount,
    cleanupConfirmed: `${suiteSummary.cleanupConfirmedCount}/${suiteSummary.totalSessionsCount}`,
    contractAligned: `${suiteSummary.contractAlignedCount}/${suiteSummary.totalSessionsCount}`,
  }, null, 2));
}
