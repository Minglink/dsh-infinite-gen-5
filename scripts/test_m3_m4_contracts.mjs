// Offline deterministic unit & contract regressions for M3 & M4 capabilities.
// Pure Node (< 1s): starts zero native engines, debuggers, emulators, or LLM calls.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { PINNED_REA_MJS_SHA256, resolveReaCliPath } from '../source/native_rea_bridge.js';
import { verifyOrRepairDexIntegrity, diagnoseAndroidSymptom } from '../source/native_android_bridge.js';
import { diffTraces } from '../source/analysis_trace_diff.js';
import { RootInvestigationStore } from '../source/investigation_root.js';
import { assessRootInvestigation } from '../source/investigation_assessment.js';
import { runWorkspace } from '../source/investigation_workflow.js';
import { installAutonomyHost } from '../source/autonomy_host.js';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { DelegationControl } from '../source/delegation_control.js';

const sha256 = (b) => createHash('sha256').update(b).digest('hex');

test('Pinned rea@6.4.0 vendor provenance verifies exact SHA-256 and rejects tampered CLI', () => {
  const repoRoot = path.resolve(import.meta.dirname, '..');
  const vendorCopy = path.join(repoRoot, 'vendor', 'rea', 'rea.mjs');
  assert.equal(sha256(fs.readFileSync(vendorCopy)), PINNED_REA_MJS_SHA256);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-rea-pin-'));
  try {
    const fakeRea = path.join(tmp, 'rea.mjs');
    fs.writeFileSync(fakeRea, '// tampered\n', 'utf8');
    const prev = process.env.IG5_REA_CLI;
    process.env.IG5_REA_CLI = fakeRea;
    try {
      assert.throws(() => resolveReaCliPath(tmp), (err) => err.code === 'REA_PIN_MISMATCH');
    } finally {
      if (prev === undefined) delete process.env.IG5_REA_CLI;
      else process.env.IG5_REA_CLI = prev;
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('DEX integrity verifier enforces strict SHA-1 ([32..N)) -> Adler-32 ([12..N)) order', () => {
  const dex = Buffer.alloc(128, 0);
  dex.write('dex\n035\0', 0, 'ascii');
  dex.writeUInt32LE(128, 32);
  dex.writeUInt32LE(0x70, 36);
  for (let i = 40; i < 128; i++) dex[i] = (i * 7 + 3) & 0xff;

  const before = verifyOrRepairDexIntegrity(dex, { repair: false });
  assert.equal(before.valid, false);

  const repaired = verifyOrRepairDexIntegrity(dex, { repair: true });
  assert.equal(repaired.valid, true);
  assert.equal(repaired.repaired, true);

  const recheck = verifyOrRepairDexIntegrity(repaired.buffer, { repair: false });
  assert.equal(recheck.valid, true);

  const sym = diagnoseAndroidSymptom('DEX_CHECKSUM_INVALID_AFTER_EDIT');
  assert.equal(sym.stopSignal, true);
  assert.match(sym.diagnosis, /SHA-1/i);
});

test('Differential trace alignment rebases ASLR addresses and rejects target mismatch or raw ASLR pointers', () => {
  const targetSha = 'a'.repeat(64);
  const aligned = diffTraces(
    {
      targetSha256: targetSha,
      runId: 'run-1',
      moduleBase: '0x7ff610000000',
      events: [
        { pc: '0x7ff610001000', regs: { rax: '0x10' } },
        { pc: '0x7ff610001020', regs: { rax: '0x20' } },
      ],
    },
    {
      targetSha256: targetSha,
      runId: 'run-2',
      moduleBase: '0x7ff790000000',
      events: [
        { pc: '0x7ff790001000', regs: { rax: '0x10' } },
        { pc: '0x7ff790001044', regs: { rax: '0x99' } },
      ],
    },
  );
  assert.equal(aligned.divergentRegionsCount, 1);
  assert.equal(aligned.firstDivergence.eventIndexA, 1);

  assert.throws(
    () => diffTraces(
      { targetSha256: 'a'.repeat(64), runId: 'r1', events: [{ rva: '0x1000' }] },
      { targetSha256: 'b'.repeat(64), runId: 'r2', events: [{ rva: '0x1000' }] },
    ),
    (err) => err.code === 'TRACE_BUILD_MISMATCH',
  );

  assert.throws(
    () => diffTraces(
      { targetSha256: targetSha, runId: 'r1', aslrActive: true, events: [{ pc: '0x7ff610001000' }] },
      { targetSha256: targetSha, runId: 'r2', aslrActive: true, events: [{ pc: '0x7ff790001000' }] },
    ),
    (err) => err.code === 'UNREBASED_ASLR_TRACE_REFUSED',
  );

  const sameRunWarn = diffTraces(
    { targetSha256: targetSha, runId: 'same-run', events: [{ rva: '0x1000' }] },
    { targetSha256: targetSha, runId: 'same-run', events: [{ rva: '0x1000' }] },
  );
  assert(sameRunWarn.provenance.warnings.some((w) => w.includes('SAME_RUN_TRACE_WARNING')));
});

test('M3/M4 cross-layer verifiers & M4-D child governance enforce provenance and completion boundaries', async () => {
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-m3m4-unit-'));
  const cfg = { projectRoot: path.join(tmp, 'projects'), artifactDir: path.join(tmp, 'artifacts') };
  const artifacts = new AnalysisArtifacts(path.join(tmp, 'artifacts'));
  const rStore = new RootInvestigationStore({ projectRoot: cfg.projectRoot });
  const coord = new DelegationControl({ root: cfg.projectRoot });
  const mgr = {
    rootInvestigations: rStore,
    coordination: coord,
    analysis: { artifacts },
    sessions: new Map(),
  };

  try {
    let registeredGuard = null;
    const rootAgent = { id: 'root-sess', session: { id: 'root-sess', header: { id: 'root-sess' } } };
    const childAgent = { id: 'child-sess', owner: rootAgent, session: { id: 'child-sess', header: { id: 'child-sess', parentSession: 'root-sess' } } };
    const ctx = {
      tools: { guard: (fn) => { registeredGuard = fn; return () => {}; } },
      on: () => () => {},
      get: (n) => (n === 'agents' ? { roots: () => [rootAgent], get: (id) => (id === 'root-sess' ? rootAgent : childAgent) } : undefined),
      inject: () => ({ dispose() {} }),
      effect: (fn) => fn(),
    };
    const autonomy = installAutonomyHost(ctx, { cfg, getManager: () => mgr });
    const gateDecision = autonomy.beforePreExecute({ name: 'update_goal', arguments: { action: 'complete' }, agent: childAgent });
    assert.equal(gateDecision?.kind, 'deny');
    assert.match(gateDecision.reason, /Subagents cannot complete the root host goal/i);
    assert.match(registeredGuard({ name: 'update_goal', arguments: { action: 'complete' }, agent: childAgent }), /Subagents cannot complete the root host goal/i);

    const appDir = path.join(tmp, 'electron-app');
    fs.mkdirSync(appDir, { recursive: true });
    fs.writeFileSync(path.join(appDir, 'main.js'), 'console.log(1);\n', 'utf8');
    const helperPath = path.join(appDir, 'helper.exe');
    const helperBytes = Buffer.from('MZ_HELPER_SYNTHETIC_BYTES');
    fs.writeFileSync(helperPath, helperBytes);

    const created = runWorkspace(mgr, cfg, {
      workspace: JSON.stringify({
        action: 'root-create',
        goal: 'Unit test M3/M4 workflow',
        root: {
          deliverables: [{
            id: 'd1',
            kind: 'electron-native-chain',
            requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'parent-to-helper-handoff'],
            holdoutRequired: true,
          }],
        },
      }),
    }, { agent: rootAgent });
    const rootId = created.workspace.rootId;

    runWorkspace(mgr, cfg, {
      workspace: {
        action: 'root-update',
        id: rootId,
        root: {
          components: [
            { componentId: 'comp-app', path: appDir, role: 'electron-app' },
            { componentId: 'comp-helper', path: helperPath, role: 'helper-pe' },
          ],
        },
      },
    }, { agent: rootAgent });

    assert.throws(
      () => runWorkspace(mgr, cfg, {
        workspace: {
          action: 'root-update',
          id: rootId,
          root: {
            scenario: {
              scenarioId: 'bad-standalone',
              componentId: 'comp-helper',
              launchMode: 'standalone',
              args: ['A'],
              inputSpec: { kind: 'cli-arg', argIndex: 0 },
            },
          },
        },
      }, { agent: rootAgent }),
      (err) => err.code === 'HELPER_SCENARIO_MISMATCH',
    );

    const briefOut = runWorkspace(mgr, cfg, {
      workspace: {
        action: 'delegate-brief',
        id: rootId,
        root: { childRole: 'component-analyst', componentId: 'comp-helper', objective: 'Check helper' },
      },
    }, { agent: rootAgent });
    assert.equal(briefOut.workspace.authorityLimits.canCompleteHostGoal, false);

    assert.throws(
      () => runWorkspace(mgr, cfg, {
        workspace: {
          action: 'accept-child-finding',
          id: rootId,
          root: {
            briefId: briefOut.workspace.briefId,
            childReport: {
              schema: 'ig5-delegation-finding-v1',
              briefId: briefOut.workspace.briefId,
              rootId,
              componentId: 'comp-helper',
              targetSha256: sha256(helperBytes),
              receiptRefs: [],
              summary: 'No receipts',
            },
          },
        },
      }, { agent: rootAgent }),
      (err) => err.code === 'UNBACKED_CHILD_FINDING_REJECTED',
    );

    // dynamic-device-hook is now a supported P2 obligation (unverified without device receipts);
    // genuinely unknown obligations still deterministically return unsupported.
    const dynDeviceRoot = rStore.create({
      rootSessionId: 'root-sess',
      goal: 'Device hook obligation contract check',
      deliverables: [{
        id: 'd-dev',
        kind: 'apk-jni-chain',
        requiredObservations: ['static-locate', 'dynamic-device-hook'],
        holdoutRequired: true,
      }],
    });
    const dynDevAssess = assessRootInvestigation({ rootTask: dynDeviceRoot, mgr, execution: { agent: rootAgent } });
    assert.equal(dynDevAssess.assessment, 'unverified');
    assert.equal(dynDevAssess.canCompleteHostGoal, false);

    const unsupportedRoot = rStore.create({
      rootSessionId: 'root-sess',
      goal: 'Unsupported obligation test',
      deliverables: [{
        id: 'd-unsup',
        kind: 'apk-jni-chain',
        requiredObservations: ['static-locate', 'kernel-hypervisor-hook'],
        holdoutRequired: true,
      }],
    });
    const unsupAssess = assessRootInvestigation({ rootTask: unsupportedRoot, mgr, execution: { agent: rootAgent } });
    assert.equal(unsupAssess.assessment, 'unsupported');
    assert.equal(unsupAssess.canCompleteHostGoal, false);
  } finally {
    await artifacts.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
