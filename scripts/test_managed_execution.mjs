import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { DelegationControl } from '../source/delegation_control.js';
import { runManagedToolExecution } from '../source/delegation_execution.js';
import { RootInvestigationStore } from '../source/investigation_root.js';
import { assessRootInvestigation } from '../source/investigation_assessment.js';
import { runWorkspace } from '../source/investigation_workflow.js';

function makeHarness(t) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-managed-exec-test-'));
  const cfg = {
    projectRoot: path.join(root, 'projects'),
    artifactDir: path.join(root, 'artifacts'),
  };
  const artifacts = new AnalysisArtifacts(path.join(cfg.artifactDir, 'analysis-data'));
  const agents = new Map();
  const makeAgent = (id, parent = null) => {
    const a = { id, session: { header: { id, ...(parent ? { parentSession: parent.id } : {}), cwd: root } } };
    agents.set(id, a);
    return a;
  };
  const owner = makeAgent('root-owner');
  const child = makeAgent('child-worker', owner);
  const coordination = new DelegationControl({ root: cfg.projectRoot, getAgent: id => agents.get(id) });
  const rootInvestigations = new RootInvestigationStore({ projectRoot: cfg.projectRoot });

  const sampleExe = path.join(root, 'sample64.exe');
  const peHeader = Buffer.alloc(256, 0);
  peHeader[0] = 0x4d; peHeader[1] = 0x5a;
  peHeader.writeUInt32LE(0x80, 0x3c);
  peHeader.write('PE\0\0', 0x80, 'ascii');
  peHeader.writeUInt16LE(0x8664, 0x84);
  fs.writeFileSync(sampleExe, peHeader);

  const mgr = {
    analysis: { artifacts },
    coordination,
    rootInvestigations,
    sessions: new Map(),
    debugOwners: new Map(),
    engines: () => [{ id: 'reverse', provider: 'ghidra', available: true }, { id: 'x64dbg', provider: 'x64dbg', available: true }],
  };

  t.after(async () => {
    await artifacts.dispose();
    assert(root.startsWith(fs.realpathSync(os.tmpdir()) + path.sep));
    try { fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }); } catch { /* ignore */ }
  });

  const ws = (workspace, agent = owner) => runWorkspace(mgr, cfg, { workspace }, { agent }).workspace;

  return { root, cfg, artifacts, agents, owner, child, mgr, sampleExe, ws };
}

test('exact retransmission returns saved receipt without re-dispatching even after runId/stopSeq changes; same-key different-args fails with IDEMPOTENCY_CONFLICT', async t => {
  const h = makeHarness(t);
  const inv = h.ws({ action: 'root-create', goal: 'Test idempotency and step locks' });
  h.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      component: { componentId: 'comp-1', path: h.sampleExe },
      scenario: { scenarioId: 'scen-1', componentId: 'comp-1', args: ['alpha'], cwd: h.root },
      route: { routeId: 'route-1', question: 'What is output?', targetObservation: 'buffer bytes', discriminatingExperiment: 'bpt + readmem' },
    },
  });
  const sel = h.ws({
    action: 'select',
    id: inv.rootId,
    root: { kind: 'dynamic-breakpoint-read', routeId: 'route-1', scenarioId: 'scen-1', hypothesis: 'XOR 0x5a' },
  });

  let providerRuns = 0;
  let liveRunId = 'run-epoch-1';
  let liveStopSeq = 1;

  const execDbgRead = (rawArgs) => runManagedToolExecution({
    mgr: h.mgr,
    toolName: 'ig5_dbg',
    rawArgs,
    execution: { agent: h.owner, signal: new AbortController().signal },
    runCore: async (cleanArgs) => {
      providerRuns += 1;
      assert.equal(cleanArgs.research, undefined, 'research binding must be stripped before provider execution');
      if (cleanArgs.expected_run_id !== liveRunId || cleanArgs.expected_stop_seq !== liveStopSeq) {
        throw Object.assign(new Error('Stale runId/stopSeq'), { code: 'ESTATE' });
      }
      return { ok: true, op: 'readmem', hex: '11223344', state: 'suspended', runId: liveRunId, stopSeq: liveStopSeq };
    },
  });

  const firstArgs = {
    target: h.sampleExe,
    op: 'readmem',
    ea: '0x140003000',
    size: 4,
    expected_run_id: 'run-epoch-1',
    expected_stop_seq: 1,
    research: { ...sel.researchBinding, key: 'req-read-1', step: 0 },
  };
  const firstOut = await execDbgRead(firstArgs);
  assert.equal(providerRuns, 1);
  assert.equal(firstOut._managedExecution.replayed, false);
  assert.equal(firstOut.hex, '11223344');

  // Advance live runId/stopSeq AND planRevision — exact retransmission MUST still return the original receipt without calling runCore!
  liveRunId = 'run-epoch-999';
  liveStopSeq = 42;
  h.ws({ action: 'root-update', id: inv.rootId, root: { question: { question: 'New sub-question' } } });

  const replayedOut = await execDbgRead(firstArgs);
  assert.equal(providerRuns, 1, 'Exact retransmission must NOT re-invoke provider');
  assert.equal(replayedOut._managedExecution.replayed, true);
  assert.equal(replayedOut._managedExecution.reportId, firstOut._managedExecution.reportId);
  assert.equal(replayedOut.hex, '11223344');

  // Same key with different arguments must reject with IDEMPOTENCY_CONFLICT
  await assert.rejects(
    () => execDbgRead({ ...firstArgs, size: 8 }),
    err => err.code === 'IDEMPOTENCY_CONFLICT',
  );
  assert.equal(providerRuns, 1);

  // Different key trying to reuse already-consumed step 0 must reject with EXPERIMENT_STEP_ALREADY_CONSUMED
  const refreshed = h.ws({ action: 'root-get', id: inv.rootId });
  await assert.rejects(
    () => execDbgRead({
      ...firstArgs,
      research: { ...sel.researchBinding, rev: refreshed.planRevision, key: 'req-read-duplicate-step', step: 0 },
    }),
    err => err.code === 'EXPERIMENT_STEP_ALREADY_CONSUMED',
  );
  assert.equal(providerRuns, 1);
});

test('inline exploration is allowed only on low-impact read tools and rejected on dynamic/write tools', async t => {
  const h = makeHarness(t);
  const inv = h.ws({ action: 'root-create', goal: 'Inline boundary check' });
  h.ws({ action: 'root-update', id: inv.rootId, root: { component: { componentId: 'c1', path: h.sampleExe } } });

  const funcsOut = await runManagedToolExecution({
    mgr: h.mgr,
    toolName: 'ig5_funcs',
    rawArgs: { target: h.sampleExe, research: { id: inv.rootId, key: 'inline-funcs-1', note: 'List functions' } },
    execution: { agent: h.owner },
    runCore: async () => ({ functions: [{ name: 'entry', ea: '0x140001000' }] }),
  });
  assert.equal(funcsOut._managedExecution.researchLinkStatus, 'linked');

  await assert.rejects(
    () => runManagedToolExecution({
      mgr: h.mgr,
      toolName: 'ig5_dbg',
      rawArgs: { target: h.sampleExe, op: 'start', research: { id: inv.rootId, key: 'illegal-inline-dbg', note: 'Try start without select' } },
      execution: { agent: h.owner },
      runCore: async () => ({ ok: true }),
    }),
    err => err.code === 'INLINE_EXPLORATION_NOT_PERMITTED',
  );

  await assert.rejects(
    () => runManagedToolExecution({
      mgr: h.mgr,
      toolName: 'ig5_run_idapython',
      rawArgs: { target: h.sampleExe, code: 'print(1)', research: { id: inv.rootId, key: 'illegal-inline-py', note: 'Try py without select' } },
      execution: { agent: h.owner },
      runCore: async () => ({ ok: true }),
    }),
    err => err.code === 'INLINE_EXPLORATION_NOT_PERMITTED',
  );
});

test('receipt-pending fault recovery and crash effect-unknown never re-execute native operations', async t => {
  const h = makeHarness(t);
  const inv = h.ws({ action: 'root-create', goal: 'Fault recovery check' });
  h.ws({ action: 'root-update', id: inv.rootId, root: { component: { componentId: 'c1', path: h.sampleExe } } });

  // Inject root-store link failure AFTER artifact save
  h.mgr.rootInvestigations._faultInjectLinkFailure = true;
  let executions = 0;
  const out = await runManagedToolExecution({
    mgr: h.mgr,
    toolName: 'ig5_bytes',
    rawArgs: { target: h.sampleExe, ea: '0x140000000', size: 16, research: { id: inv.rootId, key: 'bytes-fault-1', note: 'Read header' } },
    execution: { agent: h.owner },
    runCore: async () => {
      executions += 1;
      return { hex: '4d5a9000' };
    },
  });
  assert.equal(executions, 1);
  assert.equal(out._managedExecution.researchLinkStatus, 'receipt-pending');
  assert.equal(h.ws({ action: 'root-get', id: inv.rootId }).receipts.length, 0);

  // Assessment flags pendingReceiptsCount > 0
  const preAssess = h.ws({ action: 'assess', id: inv.rootId });
  assert.equal(preAssess.pendingReceiptsCount, 1);

  // Recover pending receipts after simulated restart (new DelegationControl + RootInvestigationStore instances)
  h.mgr.coordination = new DelegationControl({ root: h.cfg.projectRoot, getAgent: id => h.agents.get(id) });
  h.mgr.rootInvestigations = new RootInvestigationStore({ projectRoot: h.cfg.projectRoot });
  const rec = h.ws({ action: 'recover-receipts', id: inv.rootId });
  assert.equal(rec.recoveredCount, 1);
  assert.equal(executions, 1, 'Recovery must link committed receipt without re-running tool');
  assert.equal(h.ws({ action: 'root-get', id: inv.rootId }).receipts.length, 1);

  // Simulate mid-flight crash (operation admitted + dispatching in old epoch, never completed)
  const crashedAdmission = h.mgr.coordination.admitOperation(h.owner, {
    requestKey: 'crashed-dbg-cont',
    tool: 'ig5_dbg',
    cleanArgs: { target: h.sampleExe, op: 'cont' },
    argsDigest: 'a'.repeat(64),
    investigationId: inv.rootId,
  });
  h.mgr.coordination.beginDispatch(h.owner, crashedAdmission.operation.slotKey);

  // Reload DelegationControl with a new epoch -> crashed operation transitions to effect-unknown and blocks auto-replay!
  h.mgr.coordination = new DelegationControl({ root: h.cfg.projectRoot, getAgent: id => h.agents.get(id) });
  await assert.rejects(
    () => runManagedToolExecution({
      mgr: h.mgr,
      toolName: 'ig5_dbg',
      rawArgs: {
        target: h.sampleExe,
        op: 'cont',
        research: { id: inv.rootId, key: 'crashed-dbg-cont', exp: 'exp-x' },
      },
      execution: { agent: h.owner },
      runCore: async () => {
        assert.fail('effect-unknown operation must NEVER re-run');
      },
    }),
    err => err.code === 'IG5_EXECUTION_EFFECT_UNKNOWN' || err.code === 'IDEMPOTENCY_CONFLICT',
  );
  const crashAssess = assessRootInvestigation({
    rootTask: h.mgr.rootInvestigations.get(inv.rootId),
    mgr: h.mgr,
    execution: { agent: h.owner },
  });
  assert.equal(crashAssess.unknownEffectsCount, 1);
  assert.equal(crashAssess.stopReason, 'effect-unknown');
});

test('budget exhaustion pre-reserves owner cleanup slot without enlarging cap, and aborted turn still allows owner stop', async t => {
  const h = makeHarness(t);
  const inv = h.ws({ action: 'root-create', goal: 'Tight budget cleanup reservation' });
  h.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      component: { componentId: 'c1', path: h.sampleExe },
      scenario: { scenarioId: 's1', componentId: 'c1', args: [], cwd: h.root },
    },
  });
  const sel = h.ws({
    action: 'select',
    id: inv.rootId,
    root: { kind: 'dynamic-breakpoint-read', scenarioId: 's1', hypothesis: 'Test cleanup reserve' },
  });

  // Start tight shared budget of 3 calls total:
  // Call 1: ig5_open -> used=1, reserved=0, available=2
  // Call 2: ig5_dbg start -> used=2, reserved=1 (for stop!), available=0
  h.mgr.coordination.budget(h.owner, { action: 'start', max_calls: 3 });

  await runManagedToolExecution({
    mgr: h.mgr,
    toolName: 'ig5_open',
    rawArgs: { target: h.sampleExe, research: { id: inv.rootId, key: 'b-open', note: 'open' } },
    execution: { agent: h.owner },
    runCore: async () => ({ ok: true }),
  });

  await runManagedToolExecution({
    mgr: h.mgr,
    toolName: 'ig5_dbg',
    rawArgs: {
      target: h.sampleExe,
      op: 'start',
      cwd: h.root,
      research: { ...sel.researchBinding, key: 'b-start', step: 0 },
    },
    execution: { agent: h.owner },
    runCore: async () => {
      h.mgr.debugOwners.set(h.sampleExe.toLowerCase(), 'x64dbg');
      return { ok: true, op: 'start', state: 'suspended', runId: 'r1', stopSeq: 1 };
    },
  });

  const midBudget = h.mgr.coordination.budget(h.owner, { action: 'status' });
  assert.equal(midBudget.used, 2);
  assert.equal(midBudget.reserved, 1);
  assert.equal(midBudget.availableForOrdinaryCalls, 0);

  // Ordinary business call is now rejected because the 3rd call is reserved exclusively for owner cleanup!
  await assert.rejects(
    () => runManagedToolExecution({
      mgr: h.mgr,
      toolName: 'ig5_dbg',
      rawArgs: { target: h.sampleExe, op: 'regs', research: { ...sel.researchBinding, key: 'b-regs', step: 1 } },
      execution: { agent: h.owner },
      runCore: async () => ({ ok: true }),
    }),
    err => err.code === 'IG5_SHARED_BUDGET_EXHAUSTED',
  );

  // Smuggled business parameter on op=stop is rejected
  await assert.rejects(
    () => runManagedToolExecution({
      mgr: h.mgr,
      toolName: 'ig5_dbg',
      rawArgs: { target: h.sampleExe, op: 'stop', ea: '0x140001000' },
      execution: { agent: h.owner },
      runCore: async () => ({ ok: true }),
    }),
    err => err.code === 'INVALID_CLEANUP_OPERATION',
  );

  // Non-owner child cannot spend owner's cleanup slot without takeover
  await assert.rejects(
    () => runManagedToolExecution({
      mgr: h.mgr,
      toolName: 'ig5_dbg',
      rawArgs: { target: h.sampleExe, op: 'stop' },
      execution: { agent: h.child },
      runCore: async () => ({ ok: true }),
    }),
    err => err.code === 'CLEANUP_OWNER_REQUIRED',
  );

  // Accept user cancellation AND pass an already-aborted turn signal: owner cleanup STILL succeeds with bounded cleanup signal!
  h.mgr.coordination.acceptCancel(h.owner, 'user-cancelled');
  const abortedController = new AbortController();
  abortedController.abort();

  const stopOut = await runManagedToolExecution({
    mgr: h.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: h.sampleExe, op: 'stop', research: { id: inv.rootId, key: 'b-stop' } },
    execution: { agent: h.owner, signal: abortedController.signal },
    runCore: async (_clean, effectiveSignal) => {
      assert.equal(effectiveSignal.aborted, false, 'Verified owner cleanup receives isolated bounded signal');
      h.mgr.debugOwners.delete(h.sampleExe.toLowerCase());
      return { ok: true, op: 'stop', state: 'no-task' };
    },
  });
  assert.equal(stopOut.state, 'no-task');

  const finalBudget = h.mgr.coordination.budget(h.owner, { action: 'status' });
  assert.equal(finalBudget.limit, 3, 'Budget cap must never be enlarged');
  assert.equal(finalBudget.used, 3);
  assert.equal(finalBudget.reserved, 0);

  const postAssess = assessRootInvestigation({
    rootTask: h.mgr.rootInvestigations.get(inv.rootId),
    mgr: h.mgr,
    execution: { agent: h.owner },
  });
  assert.equal(postAssess.cleanup, 'confirmed');
  assert.equal(postAssess.workState, 'stopped');
  assert.equal(postAssess.stopReason, 'user-cancelled');
  assert.equal(postAssess.assessment, 'partial');
});
