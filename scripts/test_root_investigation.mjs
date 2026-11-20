import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { DelegationControl } from '../source/delegation_control.js';
import { runManagedToolExecution } from '../source/delegation_execution.js';
import { RootInvestigationStore } from '../source/investigation_root.js';
import { runWorkspace } from '../source/investigation_workflow.js';

function makeEnv(t) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-root-inv-test-'));
  const cfg = {
    projectRoot: path.join(root, 'projects'),
    artifactDir: path.join(root, 'artifacts'),
    host: { id: 'win32-x64', supported: true },
    x64dbg: { available: true },
  };
  const artifacts = new AnalysisArtifacts(path.join(cfg.artifactDir, 'analysis-data'));
  const owner = { id: 'root-agent', session: { header: { id: 'root-agent', cwd: root } } };
  const coordination = new DelegationControl({ root: cfg.projectRoot, getAgent: id => (id === owner.id ? owner : undefined) });
  const rootInvestigations = new RootInvestigationStore({ projectRoot: cfg.projectRoot });

  const mainPe = path.join(root, 'app.exe');
  const helperPe = path.join(root, 'helper.exe');
  const peBuf = Buffer.alloc(256, 0);
  peBuf[0] = 0x4d; peBuf[1] = 0x5a;
  peBuf.writeUInt32LE(0x80, 0x3c);
  peBuf.write('PE\0\0', 0x80, 'ascii');
  peBuf.writeUInt16LE(0x8664, 0x84);
  fs.writeFileSync(mainPe, peBuf);
  peBuf[200] = 0x99;
  fs.writeFileSync(helperPe, peBuf);

  const mgr = {
    analysis: { artifacts },
    coordination,
    rootInvestigations,
    sessions: new Map(),
    debugOwners: new Map(),
    engines: () => [
      { id: 'reverse', provider: 'ghidra', available: true },
      { id: 'x64dbg', provider: 'x64dbg', available: true },
    ],
  };

  t.after(async () => {
    await artifacts.dispose();
    try { fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }); } catch { /* ignore */ }
  });

  const ws = workspace => runWorkspace(mgr, cfg, { workspace }, { agent: owner }).workspace;
  return { root, cfg, mgr, owner, mainPe, helperPe, ws };
}

test('helper IPC scenario guard, secret env guard, and anti-loop preparation budget cap across route renames', async t => {
  const e = makeEnv(t);
  const inv = e.ws({ action: 'root-create', goal: 'Prevent helper scenario substitution and static export loops' });

  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      components: [
        { componentId: 'main', path: e.mainPe, role: 'main-pe' },
        { componentId: 'helper', path: e.helperPe, role: 'helper-pe', parentComponentId: 'main', ipcChannel: 'pipe://ig5-test' },
      ],
    },
  });

  // Helper depending on parent/IPC cannot be launched standalone to fake the runtime scenario
  assert.throws(
    () => e.ws({
      action: 'root-update',
      id: inv.rootId,
      root: { scenario: { componentId: 'helper', launchMode: 'standalone', args: [], cwd: e.root } },
    }),
    err => err.code === 'HELPER_SCENARIO_MISMATCH',
  );

  // Secret-like env variable names are rejected
  assert.throws(
    () => e.ws({
      action: 'root-update',
      id: inv.rootId,
      root: { scenario: { componentId: 'main', args: [], cwd: e.root, envDiff: { SECRET_API_TOKEN: 'xyz' } } },
    }),
    err => err.code === 'SECRET_ENV_FORBIDDEN',
  );

  // When dynamic debug is feasible and no scenario exists yet, planner proposes prepare-runtime-scenario (not bulk static export!)
  const initialPlan = e.ws({ action: 'root-plan', id: inv.rootId });
  assert(initialPlan.candidates.some(c => c.kind === 'prepare-runtime-scenario'), 'Planner must propose preparing runtime scenario when missing');

  // Short route with preparationBudgetCalls = 2
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      route: {
        routeId: 'route-a',
        question: 'Where is transform buffer?',
        targetObservation: 'Transform output buffer RVA and bytes',
        missingPrerequisites: ['target-rva'],
        preparationSteps: ['open', 'funcs'],
        preparationBudgetCalls: 2,
        discriminatingExperiment: 'Break on transform exit and read output buffer',
      },
    },
  });

  // Consume 2 inline preparation calls
  for (let i = 1; i <= 2; i++) {
    await runManagedToolExecution({
      mgr: e.mgr,
      toolName: 'ig5_funcs',
      rawArgs: { target: e.mainPe, research: { id: inv.rootId, key: `prep-${i}`, note: `prep ${i}` } },
      execution: { agent: e.owner },
      runCore: async () => ({ functions: [] }),
    });
  }

  // Attempting to rename/recreate route with higher preparationBudgetCalls (e.g. 6) for the SAME objective cannot enlarge cap!
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      route: {
        routeId: 'route-b-renamed',
        question: 'Where is transform buffer?',
        targetObservation: 'Transform output buffer RVA and bytes',
        missingPrerequisites: ['target-rva'],
        preparationSteps: ['decompile-more'],
        preparationBudgetCalls: 6,
        discriminatingExperiment: 'Break on transform exit and read output buffer',
      },
    },
  });

  assert.throws(
    () => e.ws({
      action: 'select',
      id: inv.rootId,
      root: { kind: 'static-locate', routeId: 'route-b-renamed', isPreparation: true, hypothesis: 'Keep exporting pseudocode' },
    }),
    err => err.code === 'PREPARATION_BUDGET_EXHAUSTED',
  );
});

test('empty observation classification, retained counterexample blocking, and independent artifact-verified holdout satisfaction', async t => {
  const e = makeEnv(t);
  const mainSha = createHash('sha256').update(fs.readFileSync(e.mainPe)).digest('hex');
  const inv = e.ws({ action: 'root-create', goal: 'Recover byte transform and verify holdout' });
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      component: { componentId: 'main', path: e.mainPe, role: 'main-pe' },
      scenarios: [
        { scenarioId: 'scen-untriggered', componentId: 'main', args: ['help'], cwd: e.root, trigger: 'wrong subcommand' },
        {
          scenarioId: 'scen-disc',
          componentId: 'main',
          args: ['enc', '0102'],
          cwd: e.root,
          inputSpec: { kind: 'cli-arg', argIndex: 1, encoding: 'hex', summary: 'disc', sampleHex: '0102', caseId: 'c1', isHoldout: false },
        },
        {
          scenarioId: 'scen-hold',
          componentId: 'main',
          args: ['enc', 'aabb'],
          cwd: e.root,
          inputSpec: { kind: 'cli-arg', argIndex: 1, encoding: 'hex', summary: 'hold', sampleHex: 'aabb', caseId: 'c2', isHoldout: true },
        },
      ],
      route: {
        routeId: 'route-main',
        question: 'What byte transform maps CLI hex input to output?',
        targetObservation: 'Output buffer at breakpoint',
        discriminatingExperiment: 'Run scen-disc and read output memory',
      },
    },
  });

  // Static locate receipt
  const staticOut = await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_decompile',
    rawArgs: { target: e.mainPe, ea: '0x140001000', research: { id: inv.rootId, key: 'stat-1', note: 'Locate transform' } },
    execution: { agent: e.owner },
    runCore: async () => ({ ea: '0x140001000', code: 'out[i] = in[i] ^ 0x55;', _ig5: { sha256: mainSha } }),
  });

  // Experiment 1: unhit breakpoint on scen-untriggered -> cannot be classified as negative-within-verified-scope!
  const sel1 = e.ws({
    action: 'select',
    id: inv.rootId,
    root: { kind: 'dynamic-breakpoint-read', routeId: 'route-main', scenarioId: 'scen-untriggered', observer: 'breakpoint at 0x140001050', hypothesis: 'help triggers transform' },
  });
  await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.mainPe, op: 'cont', research: { ...sel1.researchBinding, key: 'e1-cont', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, op: 'cont', state: 'no-task', reason: 'exit-process' }),
  });

  assert.throws(
    () => e.ws({
      action: 'evaluate',
      id: inv.rootId,
      root: {
        expId: sel1.experiment.expId,
        observationClass: 'negative-within-verified-scope',
        triggerConfirmed: true,
        observerConfirmed: true,
        verdict: 'inconclusive',
        whyNextChanged: 'Try fake negative',
        nextAction: 'none',
      },
    }),
    err => err.code === 'UNVERIFIED_NEGATIVE_SCOPE',
  );

  // Properly classify as not-triggered
  e.ws({
    action: 'evaluate',
    id: inv.rootId,
    root: {
      expId: sel1.experiment.expId,
      observationClass: 'not-triggered',
      verdict: 'inconclusive',
      whyNextChanged: 'Subcommand "help" exited before reaching transform; switch to "enc" scenario',
      nextAction: 'Run scen-disc',
    },
  });

  // Duplicate identical experiment is prevented
  assert.throws(
    () => e.ws({
      action: 'select',
      id: inv.rootId,
      root: { kind: 'dynamic-breakpoint-read', routeId: 'route-main', scenarioId: 'scen-untriggered', observer: 'breakpoint at 0x140001050', hypothesis: 'help triggers transform' },
    }),
    err => err.code === 'DUPLICATE_EXPERIMENT_PREVENTED',
  );

  // Experiment 2: wrong hypothesis ("identity copy") refuted by discovery run (`0102` -> `5457`)
  const sel2 = e.ws({
    action: 'select',
    id: inv.rootId,
    root: { kind: 'dynamic-breakpoint-read', routeId: 'route-main', scenarioId: 'scen-disc', observer: 'breakpoint at 0x140001050', hypothesis: 'Output equals raw input (identity)' },
  });
  await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.mainPe, op: 'start', args: ['enc', '0102'], cwd: e.root, research: { ...sel2.researchBinding, key: 'e2-start', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, op: 'start', state: 'suspended', runId: 'run-disc-1', stopSeq: 0, launchScenario: { argv: ['enc', '0102'], cwd: e.root }, _ig5: { sha256: mainSha } }),
  });
  const discOut = await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.mainPe, op: 'readmem', rva: '0x3000', size: 2, research: { ...sel2.researchBinding, key: 'e2-read', step: 1 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, op: 'readmem', hex: '5457', state: 'suspended', runId: 'run-disc-1', stopSeq: 1, _ig5: { sha256: mainSha } }),
  });
  await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.mainPe, op: 'stop', research: { ...sel2.researchBinding, key: 'e2-stop', step: 2 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, op: 'stop', state: 'no-task', runId: 'run-disc-1' }),
  });
  const eval2 = e.ws({
    action: 'evaluate',
    id: inv.rootId,
    root: {
      expId: sel2.experiment.expId,
      observationClass: 'non-empty',
      verdict: 'refutes',
      newObservations: ['Input 0102 produced 5457 (XOR 0x55), refuting identity'],
      whyNextChanged: 'Identity refuted by counterexample 0102 -> 5457; revise hypothesis to XOR 0x55 and test on holdout aabb',
      nextAction: 'Run holdout scen-hold',
    },
  });
  assert.equal(eval2.counterexample.status, 'unresolved');

  // While counterexample is unresolved and holdout is missing, assess CANNOT be satisfied
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      candidate: {
        summary: 'Premature candidate',
        outputSpec: { kind: 'memory', rva: '0x3000', byteLength: 2 },
        executableRule: {
          schema: 'ig5-bounded-byte-rule-v1',
          outputLength: 2,
          byteExpr: { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, 0x55] },
        },
        staticReceiptIds: [staticOut._managedExecution.reportId],
        testVectors: [{ caseId: 'c1', isHoldout: false, inputHex: '0102', predictedHex: '5457', receiptId: discOut._managedExecution.reportId }],
      },
    },
  });
  const midAssess = e.ws({ action: 'assess', id: inv.rootId });
  assert.equal(midAssess.assessment, 'partial');
  assert(midAssess.denialReasons.some(r => r.includes('unresolved-counterexamples')));
  assert(midAssess.denialReasons.some(r => r.includes('missing-independent-holdout-verification')));

  // Experiment 3: revised hypothesis XOR 0x55 tested on independent holdout `aabb` -> `ffee`, addressing counterexample!
  const sel3 = e.ws({
    action: 'select',
    id: inv.rootId,
    root: { kind: 'holdout-verify', routeId: 'route-main', scenarioId: 'scen-hold', observer: 'breakpoint at 0x140001050', hypothesis: 'Each byte XORs with 0x55 (aabb -> ffee)' },
  });
  await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.mainPe, op: 'start', args: ['enc', 'aabb'], cwd: e.root, research: { ...sel3.researchBinding, key: 'e3-start', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, op: 'start', state: 'suspended', runId: 'run-hold-2', stopSeq: 0, launchScenario: { argv: ['enc', 'aabb'], cwd: e.root }, _ig5: { sha256: mainSha } }),
  });
  const holdOut = await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.mainPe, op: 'readmem', rva: '0x3000', size: 2, research: { ...sel3.researchBinding, key: 'e3-read', step: 1 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, op: 'readmem', hex: 'ffee', state: 'suspended', runId: 'run-hold-2', stopSeq: 1, _ig5: { sha256: mainSha } }),
  });
  await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.mainPe, op: 'stop', research: { ...sel3.researchBinding, key: 'e3-stop', step: 2 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, op: 'stop', state: 'no-task', runId: 'run-hold-2' }),
  });
  e.ws({
    action: 'evaluate',
    id: inv.rootId,
    root: {
      expId: sel3.experiment.expId,
      observationClass: 'non-empty',
      verdict: 'supports',
      resolveCounterexampleId: eval2.counterexample.counterexampleId,
      newObservations: ['Holdout aabb produced ffee as predicted by XOR 0x55'],
      whyNextChanged: 'Both discovery and independent holdout match XOR 0x55',
      nextAction: 'Submit verified candidate and assess',
    },
  });

  // Contradictory caller predictedHex is caught by executable candidate verification!
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      candidate: {
        summary: 'Wrong prediction check',
        rule: 'b ^ 0x55',
        outputSpec: { kind: 'memory', rva: '0x3000', byteLength: 2 },
        executableRule: {
          schema: 'ig5-bounded-byte-rule-v1',
          outputLength: 2,
          byteExpr: { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, 0x55] },
        },
        staticReceiptIds: [staticOut._managedExecution.reportId],
        testVectors: [
          { caseId: 'c1', isHoldout: false, inputHex: '0102', predictedHex: '5457', receiptId: discOut._managedExecution.reportId },
          { caseId: 'c2', isHoldout: true, inputHex: 'aabb', predictedHex: '0000', receiptId: holdOut._managedExecution.reportId },
        ],
      },
    },
  });
  assert.notEqual(e.ws({ action: 'assess', id: inv.rootId }).assessment, 'satisfied');

  // Exact executable candidate rule across discovery + independent holdout -> assessment === 'satisfied'!
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      candidate: {
        summary: 'Bytewise XOR 0x55 verified across discovery and holdout runs',
        rule: 'out[i] = in[i] ^ 0x55',
        outputSpec: { kind: 'memory', rva: '0x3000', byteLength: 2 },
        executableRule: {
          schema: 'ig5-bounded-byte-rule-v1',
          outputLength: 2,
          byteExpr: { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, 0x55] },
        },
        staticReceiptIds: [staticOut._managedExecution.reportId],
        testVectors: [
          { caseId: 'c1', isHoldout: false, inputHex: '0102', predictedHex: '5457', receiptId: discOut._managedExecution.reportId },
          { caseId: 'c2', isHoldout: true, inputHex: 'aabb', predictedHex: 'ffee', receiptId: holdOut._managedExecution.reportId },
        ],
      },
    },
  });
  const finalAssess = e.ws({ action: 'assess', id: inv.rootId });
  assert.equal(finalAssess.assessment, 'satisfied');
  assert.equal(finalAssess.canCompleteHostGoal, true);
});
