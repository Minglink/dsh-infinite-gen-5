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

const {
  resolveHostPaths,
  stageCleanPluginForEval,
  collectNativeProcessCheck,
  buildCleanupAssessment,
  buildTransformScore,
} = await import(pathToFileURL(path.join(repoRoot, 'scripts', 'evals', 'run_m2_blind_eval.mjs')).href);
const { computeSourceTreeIdentity } = await import(pathToFileURL(path.join(repoRoot, 'scripts', 'lib', 'source_tree_identity.mjs')).href);
const { RootInvestigationStore } = await import(pathToFileURL(path.join(repoRoot, 'source', 'investigation_root.js')).href);
const { assessRootInvestigation } = await import(pathToFileURL(path.join(repoRoot, 'source', 'investigation_assessment.js')).href);
const { AnalysisArtifacts } = await import(pathToFileURL(path.join(repoRoot, 'source', 'analysis_artifacts.js')).href);
const { DelegationControl } = await import(pathToFileURL(path.join(repoRoot, 'source', 'delegation_control.js')).href);

const guardPluginPath = path.join(repoRoot, 'scripts', 'evals', 'm2_suite_guard.mjs');
// reviewRoot configured via --evidence-root / IG5_REVIEW_ROOT above
const realTmp = () => (fs.realpathSync.native || fs.realpathSync)(os.tmpdir());
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

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

function buildOnlinePrompt(spec, workspace) {
  const commonFooter = [
    `Important operational rules:`,
    `- Operate strictly inside workspace: ${workspace}`,
    `- Non-cleanup tool-call budget: 70 ordinary calls + 2 reserved terminal calls (get_goal / update_goal complete|blocked|pause).`,
    `- Pre-commit your executable candidate rule (schema="ig5-bounded-byte-rule-v1") and outputSpec BEFORE selecting and running an unseen independent holdout input experiment (isHoldout=true, kind="holdout-verify").`,
    `- Attach >=2 non-holdout discovery receipts and >=1 unseen holdout receipt in testVectors, stop/close owned runtime sessions, confirm workspace action="assess" reports assessment="satisfied" and canCompleteHostGoal=true, then call update_goal(action="complete").`,
  ];

  if (spec.branch === 'M3') {
    return [
      `Autonomous cross-layer Electron -> Native Helper reverse-engineering task (blind workspace):`,
      `Target Electron application directory: ${spec.appDir}`,
      `Deliverable goal: Reverse-engineer the end-to-end 4-byte payload transformation from the Electron UI/IPC boundary through the main process into the actually invoked native helper executable, and verify your recovered rule via an IG5 root investigation bound to the active host goal.`,
      `1. Load skill "ig5-reverse-agent" and switch IG5 toolset to "full".`,
      `2. Create a root investigation with deliverable kind="electron-native-chain", requiredObservations=["static-locate", "dynamic-runtime-observation", "parent-to-helper-handoff"], holdoutRequired=true.`,
      `3. Use ig5_package(action="js_app", target="${spec.appDir}", input={path:"${spec.appDir}"}) and read main.js/preload.js to reconstruct the JS/IPC preprocessing and identify which native helper binary is actually spawned on the live IPC route (watch out for any unused legacy decoy binary or parent memoization cache).`,
      `4. Open and decompile the live native helper PE64 in Ghidra (with research={id:rootId,key:"..."}) to recover its exact byte transformation.`,
      `5. Register components ({componentId:"comp-app",path:"${spec.appDir}",role:"electron-app"} and {componentId:"comp-helper",path:"<live helper path>",role:"helper-pe"}) and via-parent scenarios ({scenarioId,componentId:"comp-app",launchMode:"via-parent",cwd:"${spec.appDir}",inputSpec:{kind:"ipc",ipcPayload:"<8-char hex>",encoding:"hex",isHoldout:false|true}}). Do NOT register standalone scenarios on helper-pe.`,
      `6. Run discovery and post-precommit holdout experiments (select kind="dynamic-breakpoint-read" or "holdout-verify") via ig5_app_observe(action="electron_scenario", target="${spec.appDir}", payload="<8-char hex>", bypass_cache:true, research={...researchBinding,key:"...",step:0}) — omit electron_binary so IG5 uses its configured Electron runtime. Use outputSpec={kind:"app-output",channel:"electron-ipc",byteLength:4}.`,
      ...commonFooter,
    ].join('\n');
  }

  if (spec.branch === 'M4-B') {
    return [
      `Autonomous host-loaded stateful ASLR DLL reverse-engineering task (blind workspace):`,
      `Host runner binary: ${spec.hostPath}`,
      `Companion DLL in workspace: ${spec.dllPath}`,
      `Deliverable goal: Reverse-engineer how the host executable loads, initializes, and invokes the companion DLL on a 4-byte CLI input, recover the exact initialized 4-byte transformation rule and output buffer RVA inside the DLL, and verify it across live ASLR relocation via an IG5 root investigation bound to the active host goal.`,
      `1. Load skill "ig5-reverse-agent" and switch IG5 toolset to "full".`,
      `2. Create a root investigation with deliverable kind="dll-host-transform", requiredObservations=["static-locate", "dynamic-runtime-observation", "aslr-module-rebasing"], holdoutRequired=true.`,
      `3. Register both components ({componentId:"comp-host",path:"${spec.hostPath}",role:"main-pe"} and {componentId:"comp-dll",path:"${spec.dllPath}",role:"dll"}).`,
      `4. Statically analyze BOTH binaries in Ghidra (passing research={id:rootId,key:"..."}) to discover the host CLI flags/prefix, the initialization seed passed to the DLL before transformation, the DLL transformation algorithm, and the 4-byte output buffer RVA inside the DLL.`,
      `5. Select and run dynamic experiments on comp-host under headless x64dbg (ig5_dbg op="start" -> cont -> bpt after DLL transform returns -> cont -> readmem on the loaded DLL output buffer runtime EA -> op="stop"). Note that the host forces ASLR relocation away from the DLL's preferred base; x64dbg context automatically records module, moduleBase, RVA, and moduleSha256 when you read the loaded DLL's runtime EA!`,
      `6. Pre-commit candidate with outputSpec={kind:"module-memory",module:"calc_engine.dll",rva:"0x...",byteLength:4} BEFORE selecting and running an unseen holdout input, stop all debuggers, attach testVectors, assess, and complete the goal.`,
      ...commonFooter,
    ].join('\n');
  }

  if (spec.branch === 'M4-C' || (spec.branch === 'M4-D' && !spec.useSubagents)) {
    return [
      `Autonomous multi-process chain (Entry -> Broker -> Multi-Worker) reverse-engineering task (blind workspace):`,
      `Process chain directory: ${spec.chainDir}`,
      `Entry executable: ${spec.entryExePath}`,
      `Deliverable goal: Reverse-engineer the end-to-end 4-byte transformation across entry_app.exe -> chain_broker.exe -> worker_stage1.exe -> worker_stage2.exe, and verify your composite rule via an IG5 root investigation bound to the active host goal.`,
      `1. Load skill "ig5-reverse-agent" and switch IG5 toolset to "full".`,
      `2. Create a root investigation with deliverable kind="process-chain-transform", requiredObservations=["static-locate", "dynamic-runtime-observation", "multi-process-lineage"], holdoutRequired=true.`,
      `3. Register components: entry_app.exe (componentId:"comp-entry", role:"main-pe"), chain_broker.exe (componentId:"comp-broker", role:"broker-pe"), worker_stage1.exe (componentId:"comp-w1", role:"worker-pe"), and worker_stage2.exe (componentId:"comp-w2", role:"worker-pe").`,
      `4. Statically analyze worker_stage1.exe and worker_stage2.exe in Ghidra (with research={id:rootId,key:"..."}) to recover Stage 1 and Stage 2 byte transformations and how they chain together.`,
      `5. Register via-parent scenarios on entry_app.exe ({scenarioId,componentId:"comp-entry",launchMode:"via-parent",cwd:"${spec.chainDir}",inputSpec:{kind:"ipc",ipcPayload:"<8-char hex>",encoding:"hex",isHoldout:false|true}}) and execute discovery + post-precommit unseen holdout runs using ig5_app_observe(action="process_chain_scenario", target="${spec.entryExePath}", payload_hex="<8-char hex>", corr_id="...", restart_worker1:true, research={...researchBinding,key:"...",step:0}).`,
      `6. Use outputSpec={kind:"app-output",channel:"process-chain",byteLength:4}. Close Ghidra sessions, verify assess="satisfied", and complete the goal.`,
      ...commonFooter,
    ].join('\n');
  }

  // M4-D 3-subagent collaborative run!
  return [
    `Autonomous governed multi-agent reverse-engineering task (blind workspace, 3 bounded subagents):`,
    `Process chain directory: ${spec.chainDir}`,
    `Entry executable: ${spec.entryExePath}`,
    `Worker 1: ${spec.worker1Path}`,
    `Worker 2: ${spec.worker2Path}`,
    `Deliverable goal: Coordinate 3 bounded subagents under a shared IG5 call budget to reverse-engineer the end-to-end 4-byte transformation across entry_app.exe -> chain_broker.exe -> worker_stage1.exe -> worker_stage2.exe and verify it in the root investigation.`,
    `Governance & protocol requirements:`,
    `1. First load skill "ig5-reverse-agent", start a shared parent+child IG5 budget via ig5_profile(collaboration={action:"start",max_calls:${spec.collabMaxCalls || 68}}), and switch toolset to "full".`,
    `2. Create a root investigation (deliverable kind="process-chain-transform", requiredObservations=["static-locate","dynamic-runtime-observation","multi-process-lineage"], holdoutRequired=true) and register all 4 components: comp-entry (role="main-pe"), comp-broker (role="broker-pe"), comp-w1 (role="worker-pe"), comp-w2 (role="worker-pe").`,
    `3. Create two typed child briefs via ig5_workspace(action="delegate-brief", id=rootId, root={childRole:"component-analyst", componentId:"comp-w1"|"comp-w2", objective:"Open and decompile the worker PE64 in Ghidra with research={id:rootId,key:...} to recover its exact 4-byte transform formula and return receiptRefs (_managedExecution.reportId) + targetSha256"}).`,
    `4. Spawn Subagent 1 (for worker_stage1.exe) and Subagent 2 (for worker_stage2.exe) SEQUENTIALLY (wait for each to return) via the host "subagent" tool. Instruct each subagent explicitly: use ONLY read-only IG5 static tools (ig5_profile toolset="full", ig5_open with engine="ghidra", ig5_decompile with engine="ghidra" and research={id:rootId,key:"..."}, ig5_bytes with engine="ghidra", ig5_close with engine="ghidra" — do NOT call ig5_emulate, ig5_dbg, ig5_workspace, or update_goal), and reply with exact JSON containing briefId, componentId, targetSha256, receiptRefs ([_managedExecution.reportId]), and summary.`,
    `5. In the parent session, verify and accept both subagent findings via ig5_workspace(action="accept-child-finding", id=rootId, root={briefId, childReport:{schema:"ig5-delegation-finding-v1", briefId, rootId, componentId, targetSha256, receiptRefs:[...], summary:"..."}}).`,
    `6. Register via-parent scenarios on comp-entry (launchMode:"via-parent", inputSpec:{kind:"ipc",ipcPayload:"<8-char hex>",encoding:"hex",isHoldout:false|true}), run 2 discovery process_chain_scenario experiments via ig5_app_observe(action="process_chain_scenario", target="${spec.entryExePath}", payload_hex=..., restart_worker1:true, research=...), pre-commit the composite executableRule (outputSpec={kind:"app-output",channel:"process-chain",byteLength:4}), then run 1 unseen holdout experiment (isHoldout=true, kind="holdout-verify").`,
    `7. Spawn Subagent 3 (verification auditor) via "subagent" to call ig5_profile(collaboration={action:"status"}) and confirm shared parent+child budget accounting without calling update_goal. Finally, in the parent session, attach testVectors, close any open Ghidra sessions, verify workspace action="assess" is "satisfied", and call update_goal(action="complete").`,
    ...commonFooter,
  ].join('\n');
}

async function runOnlineCase({
  caseKey,
  outSubdir,
  materializeFn,
  extraAllowedTools = ['ig5_package', 'ig5_app_observe'],
  allowedPackageActions = ['js_app', 'apk', 'trace_diff', 'result'],
  policyVersion = 'm3-m4-restricted-allowlist-v1',
  maxTotalToolCalls = 72,
  wallTimeoutMs = 720_000,
}) {
  const outDir = path.join(reviewRoot, outSubdir);
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });

  const hostPaths = resolveHostPaths();
  const stagePluginDir = stageCleanPluginForEval();
  const execRoot = fs.mkdtempSync(path.join(realTmp(), `ig5-online-${caseKey}-`));
  const dshHome = path.join(execRoot, 'dsh-home');
  const ig5Home = path.join(execRoot, 'ig5-home');
  const workspace = path.join(execRoot, 'workspace');
  fs.mkdirSync(path.join(dshHome, 'plugins'), { recursive: true });
  fs.mkdirSync(ig5Home, { recursive: true });
  fs.mkdirSync(workspace, { recursive: true });

  const spec = materializeFn(workspace);
  fs.copyFileSync(path.join(hostPaths.realDshHome, '.credentials.yaml'), path.join(dshHome, '.credentials.yaml'));
  const providerPatchPath = path.join(execRoot, 'provider.patch.yml');
  fs.writeFileSync(providerPatchPath, getProviderBlock(hostPaths.realDshHome), 'utf8');

  execFileSync(hostPaths.electron, ['--expose-internals', hostPaths.cli, '--profile', 'm3m4-eval', '--from-default-profile', 'sdk', '--help'], {
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', DSH_HOME: dshHome, DSH_TELEMETRY_DISABLED: '1' },
    stdio: 'pipe',
  });

  const pluginDest = path.join(dshHome, 'plugins', 'dsh-infinite-gen-5');
  fs.symlinkSync(stagePluginDir, pluginDest, 'junction');
  const profileDir = path.join(dshHome, 'profiles', 'm3m4-eval');
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
            policyVersion,
            extraAllowedTools,
            allowedPackageActions,
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
            terminalControlReserve: 2,
          },
        },
      ],
    },
  ];
  const evalPatchPath = path.join(execRoot, 'eval-overlay.patch.yml');
  fs.writeFileSync(evalPatchPath, JSON.stringify(evalOverlay, null, 2) + '\n', 'utf8');

  const objective = buildOnlinePrompt(spec, workspace);
  const provider = process.env.IG5_EVAL_PROVIDER || 'expr';
  const model = process.env.IG5_EVAL_MODEL || 'deepseek-v4.1-flash-uncensored';

  console.log(`\n>>> Starting Online DSH Autonomous Run [${spec.caseId}] (${spec.branch}) <<<`);
  const child = spawn(hostPaths.electron, [
    '--expose-internals', hostPaths.cli,
    '--profile', 'm3m4-eval',
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
      IG5_RUNTIME_ROOT: donorRuntimes,
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
          console.log(`[${spec.caseId}][tool] ${ev.data?.name} ${(ev.data?.arguments || '').slice(0, 120)}`);
        } else if (ev.type === 'goal/change') {
          console.log(`[${spec.caseId}][goal] op=${ev.data?.operation} phase=${ev.data?.goal?.phase} rev=${ev.data?.goal?.revision}`);
        }
        continue;
      }
      if (msg.method === 'session.query.completed') {
        console.log(`[${spec.caseId}][query.completed] finishReason=${msg.params?.finishReason}`);
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

  const sessionId = `session-${spec.caseId}-${randomUUID()}`;
  const startedAt = Date.now();
  let runError = null;
  let providerResumes = 0;

  const latestGoalPhase = () => {
    let phase = 'active';
    for (const ev of events) {
      if (ev.type === 'goal/change' && ev.data?.goal?.phase) phase = ev.data.goal.phase;
    }
    return phase;
  };

  try {
    await rpc('initialize', { cwd: workspace, provider, model, approvalRequests: true, maxTokens: 8192 });
    const wait1 = waitNextCompleted(wallTimeoutMs);
    await rpc('session/query', {
      sessionId,
      contentBlocks: [{ type: 'text', text: `/goal ${objective.replace(/\s*\n\s*/g, ' ')}` }],
    });
    let qRes = await wait1;
    await rpc('session/wait', { sessionId }, 30_000).catch(() => {});
    while (qRes?.finishReason === 'error' && !['complete', 'completed', 'blocked'].includes(latestGoalPhase()) && providerResumes < 2) {
      const rem = wallTimeoutMs - (Date.now() - startedAt);
      if (rem < 60_000) break;
      providerResumes += 1;
      console.log(`[${spec.caseId}] Transient stream error while goal active; resuming (${providerResumes}/2)...`);
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

  // Archive session logs & ig5-home into outDir
  fs.writeFileSync(path.join(outDir, 'events.jsonl'), events.map((e) => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  fs.writeFileSync(path.join(outDir, 'approvals.json'), JSON.stringify(approvals, null, 2) + '\n', 'utf8');
  fs.writeFileSync(path.join(outDir, 'stderr.log'), stderrChunks.join(''), 'utf8');
  if (fs.existsSync(ig5Home)) {
    fs.cpSync(ig5Home, path.join(outDir, 'ig5-home'), { recursive: true });
  }
  if (fs.existsSync(path.join(dshHome, 'sessions'))) {
    fs.cpSync(path.join(dshHome, 'sessions'), path.join(outDir, 'dsh-sessions'), { recursive: true });
  }

  // Post-shutdown independent offline assessment + 6-vector oracle scoring!
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
        mgr: { analysis: { artifacts }, coordination: coord },
        execution: { agent: { id: sessionId, session: { id: sessionId, header: { id: sessionId } } } },
        hostGoal: null,
      });
    } catch (err) {
      postRunAssess = { error: err.message };
    }
  }

  const observedInputs = (rootTask?.experiments || [])
    .map((e) => e.scenarioSnapshot?.inputHex)
    .filter(Boolean);

  const transformScore = buildTransformScore({
    rule: cand?.executableRule || null,
    outputSpecValidForTarget: Boolean(cand?.outputSpec),
    oracleVectors: ORACLE_VECTORS_6,
    referenceFn: spec.referenceFn,
    observedSessionInputHexes: observedInputs,
    triggerCompletenessStatus: 'passed',
  });

  const subagentToolCalls = events.filter((e) => e.type === 'tool/call' && e.data?.name === 'subagent').length;
  const totalToolCalls = events.filter((e) => e.type === 'tool/call').length;
  const finalGoalPhase = latestGoalPhase();
  const hostGoalCompleted = finalGoalPhase === 'complete' || finalGoalPhase === 'completed';
  const falseCompletion = hostGoalCompleted && !transformScore.transformFiniteVectorCorrect;

  const controlState = coord.controlStatus({ id: sessionId, session: { id: sessionId, header: { id: sessionId } } });
  const cleanup = buildCleanupAssessment({
    processCheck,
    cleanupReservations: controlState?.cleanupReservations || [],
  });

  const summary = {
    schema: 'ig5-m3-m4-online-case-result-v1',
    caseId: spec.caseId,
    branch: spec.branch,
    deliverableKind: spec.deliverableKind,
    sourceTreeIdentity: computeSourceTreeIdentity(repoRoot),
    provider,
    model,
    sessionId,
    elapsedMs,
    providerResumes,
    runError,
    totalToolCalls,
    subagentToolCalls,
    approvalsCount: approvals.length,
    finalGoalPhase,
    hostGoalCompleted,
    deliverableCorrect: transformScore.transformFiniteVectorCorrect,
    falseCompletion,
    cleanupConfirmed: cleanup.cleanupConfirmed,
    cleanup,
    rootInvestigationSummary: rootTask ? {
      rootId: rootTask.rootId,
      componentsCount: rootTask.components?.length || 0,
      experimentsCount: rootTask.experiments?.length || 0,
      receiptsCount: rootTask.receipts?.length || 0,
      counterexamplesCount: rootTask.counterexamples?.length || 0,
      delegatedBriefsCount: rootTask.delegationBriefs?.length || 0,
      acceptedChildFindingsCount: rootTask.childFindings?.length || 0,
    } : null,
    sharedCollaborationBudget: controlState?.budget || null,
    postRunAssess: postRunAssess ? {
      assessment: postRunAssess.assessment,
      cleanup: postRunAssess.cleanup,
      canCompleteHostGoal: postRunAssess.canCompleteHostGoal,
      denialReasons: postRunAssess.denialReasons,
    } : null,
    transformScore,
  };

  fs.writeFileSync(path.join(outDir, 'case-result.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');
  try { await artifacts.dispose(); } catch { /* ignore */ }
  fs.rmSync(execRoot, { recursive: true, force: true });

  console.log(`<<< Finished [${spec.caseId}]: phase=${finalGoalPhase}, deliverableCorrect=${summary.deliverableCorrect}, calls=${totalToolCalls}, subagents=${subagentToolCalls}, cleanup=${summary.cleanupConfirmed} >>>`);
  return summary;
}

const targetArg = process.argv[2] || 'all';
const allRuns = [];

const safeRun = async (opts) => {
  try {
    return await runOnlineCase(opts);
  } catch (err) {
    console.error(`[ONLINE-CASE-ERROR] ${opts.caseKey}:`, err);
    return { caseKey: opts.caseKey, fatalRunnerError: err.message || String(err) };
  }
};

if (targetArg === 'all' || targetArg === 'm3-1') {
  allRuns.push(await safeRun({
    caseKey: 'm3-01',
    outSubdir: path.join('m3-electron', 'online-sealed', 'm3-sealed-01-frame-encoder'),
    materializeFn: materializeM3OnlineCase1,
  }));
}
if (targetArg === 'all' || targetArg === 'm3-2') {
  allRuns.push(await safeRun({
    caseKey: 'm3-02',
    outSubdir: path.join('m3-electron', 'online-sealed', 'm3-sealed-02-ticket-digest'),
    materializeFn: materializeM3OnlineCase2,
  }));
}
if (targetArg === 'all' || targetArg === 'm4b') {
  allRuns.push(await safeRun({
    caseKey: 'm4b-01',
    outSubdir: path.join('m4b-dll', 'online-sealed', 'm4b-online-01-stateful-dll'),
    materializeFn: materializeM4BOnlineCase1,
  }));
}
if (targetArg === 'all' || targetArg === 'm4c') {
  allRuns.push(await safeRun({
    caseKey: 'm4c-01',
    outSubdir: path.join('m4c-process-chain', 'online-sealed', 'm4c-online-01-broker-chain'),
    materializeFn: materializeM4COnlineCase1,
  }));
}
if (targetArg === 'all' || targetArg === 'm4d-single') {
  allRuns.push(await safeRun({
    caseKey: 'm4d-single',
    outSubdir: path.join('m4d-multiagent', 'online-sealed', 'm4d-online-single-agent'),
    materializeFn: (ws) => ({ ...materializeM4DPairedCase(ws, 'single-agent'), useSubagents: false }),
    maxTotalToolCalls: 72,
  }));
}
if (targetArg === 'm4d-3sub-v2') {
  allRuns.push(await safeRun({
    caseKey: 'm4d-3sub-v2',
    outSubdir: path.join('m4d-multiagent', 'online-sealed', 'm4d-online-3subagents-v2'),
    materializeFn: (ws) => ({ ...materializeM4DPairedCase(ws, '3subagents-v2'), useSubagents: true, collabMaxCalls: 68 }),
    extraAllowedTools: ['ig5_package', 'ig5_app_observe', 'subagent', 'send_message'],
    maxTotalToolCalls: 96,
  }));
}

if (targetArg === 'all') {
  fs.writeFileSync(
    path.join(reviewRoot, 'm3-m4-online-summary.json'),
    JSON.stringify({
      schema: 'ig5-m3-m4-online-summary-v1',
      createdAt: new Date().toISOString(),
      runsCount: allRuns.length,
      runs: allRuns,
    }, null, 2) + '\n',
    'utf8',
  );
}
