import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import * as ig5Plugin from '../index.js';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { DelegationControl } from '../source/delegation_control.js';
import { runManagedToolExecution, hashCanonical, parseAndStripResearch } from '../source/delegation_execution.js';
import { RootInvestigationStore } from '../source/investigation_root.js';
import { runWorkspace } from '../source/investigation_workflow.js';
import { installAutonomyHost } from '../source/autonomy_host.js';
import { installApprovalGate } from '../source/approval_gate.js';
import { evaluateBoundedTransform, validateExecutableRule } from '../source/investigation_verifier.js';

function makeOfflineEnv(t, prefix = 'ig5-audit-reg-') {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), prefix));
  const cfg = {
    projectRoot: path.join(dir, 'projects'),
    artifactDir: path.join(dir, 'artifacts'),
    host: { id: 'win32-x64', supported: true },
    x64dbg: { available: true },
  };
  const artifacts = new AnalysisArtifacts(path.join(cfg.artifactDir, 'analysis-data'));
  const owner = { id: 'audit-owner', session: { header: { id: 'audit-owner', cwd: dir } } };
  const subagent = { id: 'audit-child', session: { header: { id: 'audit-child', parentSession: owner.id, cwd: dir } } };
  const coordination = new DelegationControl({
    root: cfg.projectRoot,
    getAgent: id => (id === owner.id ? owner : id === subagent.id ? subagent : undefined),
  });
  const rootInvestigations = new RootInvestigationStore({ projectRoot: cfg.projectRoot });
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
  const dummy = path.join(dir, 'dummy64.exe');
  const pe = Buffer.alloc(256, 0);
  pe[0] = 0x4d; pe[1] = 0x5a;
  pe.writeUInt32LE(0x80, 0x3c);
  pe.write('PE\0\0', 0x80, 'ascii');
  pe.writeUInt16LE(0x8664, 0x84);
  fs.writeFileSync(dummy, pe);

  t.after(async () => {
    await artifacts.dispose();
    try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }); } catch { /* ignore */ }
  });

  const ws = (workspace, agent = owner) => runWorkspace(mgr, cfg, { workspace }, { agent }).workspace;
  return { dir, cfg, artifacts, owner, subagent, coordination, rootInvestigations, mgr, dummy, ws };
}

test('[P1 #3] unsupported deliverable kinds, empty obligations, and unknown obligations never satisfy assessment', async t => {
  for (const [label, kind, requiredObservations] of [
    ['empty-custom', 'custom', []],
    ['empty-io-transform', 'io-transform', []],
    ['unknown-requirement', 'protocol-behavior', ['verify-protocol-state-machine']],
    ['unknown-kind', 'does-not-exist', ['unknown-verifier']],
    ['mixed-unknown-obligation', 'io-transform', ['static-locate', 'nonexistent-check']],
  ]) {
    const e = makeOfflineEnv(t, `ig5-p1-3-${label}-`);
    const root = e.ws({
      action: 'root-create',
      goal: `Test ${label}`,
      root: { deliverables: [{ kind, requiredObservations, holdoutRequired: true }] },
    });
    e.ws({
      action: 'root-update',
      id: root.rootId,
      root: { candidate: { summary: 'Claim only; zero receipts' } },
    });
    const assessment = e.ws({ action: 'assess', id: root.rootId });
    assert.notEqual(assessment.assessment, 'satisfied', `${label} must NOT be satisfied`);
    assert.equal(assessment.canCompleteHostGoal, false, `${label} must NOT allow completing host goal`);
    assert.equal(assessment.deliverables[0].status, 'unsupported');
  }
});

test('[P1 #2] relabeling same-scenario / same-run receipts as distinct or holdout inputs is rejected', async t => {
  const e = makeOfflineEnv(t, 'ig5-p1-2-');
  const root = e.ws({
    action: 'root-create',
    goal: 'Recover 4-byte transform',
    root: { deliverables: [{ kind: 'io-transform', requiredObservations: ['dynamic-runtime-observation'], minDistinctInputs: 2, holdoutRequired: true }] },
  });
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      component: { componentId: 'main', path: e.dummy, role: 'main-pe' },
      scenario: {
        scenarioId: 'only-real-scenario',
        componentId: 'main',
        args: ['ABCD'],
        cwd: e.dir,
        inputSpec: { kind: 'cli-arg', summary: 'Only actual input', sampleHex: '41424344', caseId: 'c1', isHoldout: false },
      },
    },
  });
  const sel = e.ws({
    action: 'select',
    id: root.rootId,
    root: { kind: 'dynamic-breakpoint-read', scenarioId: 'only-real-scenario', observer: 'Read 4-byte output at 0x1000', hypothesis: 'Observe output' },
  });

  const emitRead = async (key, step) => {
    const out = await runManagedToolExecution({
      mgr: e.mgr,
      toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 4, research: { ...sel.researchBinding, key, step } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId: 'same-synthetic-run', stopSeq: 1, hex: '41424344' }),
    });
    return out._managedExecution.reportId;
  };
  const r1 = await emitRead('read-one', 0);
  const r2 = await emitRead('read-two', 1);

  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'Attempt relabeling second read of same run as holdout',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 4 },
        executableRule: { schema: 'ig5-bounded-byte-rule-v1', outputLength: 4, byteExpr: { op: 'in', index: { op: 'i' } } },
        testVectors: [
          { caseId: 'disc', scenarioId: 'only-real-scenario', inputHex: '41424344', isHoldout: false, receiptId: r1 },
          { caseId: 'fake-hold', scenarioId: 'scenario-does-not-exist', inputHex: '31323334', isHoldout: true, receiptId: r2 },
        ],
      },
    },
  });
  const assessment = e.ws({ action: 'assess', id: root.rootId });
  assert.notEqual(assessment.assessment, 'satisfied');
  assert.equal(assessment.canCompleteHostGoal, false);
  assert(assessment.denialReasons.some(r => r.includes('vector-scenario-mismatch')));
});

test('[P1 #1] candidate rule is independently executed over fixed outputSpec; wrong rule, 1-byte prefix, and unrelated rsp register all fail', async t => {
  const e = makeOfflineEnv(t, 'ig5-p1-1-');
  const root = e.ws({
    action: 'root-create',
    goal: 'Recover exact 4-byte XOR 0x55 transform',
    root: { deliverables: [{ kind: 'io-transform', requiredObservations: ['dynamic-runtime-observation'], minDistinctInputs: 2, holdoutRequired: true }] },
  });
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      component: { componentId: 'main', path: e.dummy, role: 'main-pe' },
      scenarios: [
        { scenarioId: 'disc', componentId: 'main', args: ['ABCD'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'disc', sampleHex: '41424344', caseId: 'disc', isHoldout: false } },
        { scenarioId: 'hold', componentId: 'main', args: ['1234'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'hold', sampleHex: '31323334', caseId: 'hold', isHoldout: true } },
      ],
    },
  });

  const dummySha = createHash('sha256').update(fs.readFileSync(e.dummy)).digest('hex');
  const memReceipts = [];
  const regReceipts = [];
  for (const [idx, scenId] of ['disc', 'hold'].entries()) {
    const argv = idx === 0 ? ['ABCD'] : ['1234'];
    const sel = e.ws({
      action: 'select',
      id: root.rootId,
      root: {
        kind: idx === 0 ? 'dynamic-breakpoint-read' : 'holdout-verify',
        scenarioId: scenId,
        observer: 'Output buffer at RVA 0x3100',
        hypothesis: 'Observe output',
      },
    });
    await runManagedToolExecution({
      mgr: e.mgr,
      toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'start', args: argv, cwd: e.dir, research: { ...sel.researchBinding, key: `st-${idx}`, step: 0 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId: `run-${idx}`, stopSeq: 0, launchScenario: { argv, cwd: e.dir }, _ig5: { sha256: dummySha } }),
    });
    const expectedHex = idx === 0 ? '14171611' : '64676661'; // 'ABCD' ^ 0x55, '1234' ^ 0x55
    const mOut = await runManagedToolExecution({
      mgr: e.mgr,
      toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 4, research: { ...sel.researchBinding, key: `m-${idx}`, step: 1 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId: `run-${idx}`, stopSeq: 1, hex: expectedHex, _ig5: { sha256: dummySha } }),
    });
    memReceipts.push(mOut._managedExecution.reportId);

    const rOut = await runManagedToolExecution({
      mgr: e.mgr,
      toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'regs', research: { ...sel.researchBinding, key: `r-${idx}`, step: 2 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId: `run-${idx}`, stopSeq: 1, regs: { rax: '0x0', rsp: idx ? '0x0012ffb0' : '0x0012ffa0' }, _ig5: { sha256: dummySha } }),
    });
    regReceipts.push(rOut._managedExecution.reportId);

    await runManagedToolExecution({
      mgr: e.mgr,
      toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'stop', research: { ...sel.researchBinding, key: `sp-${idx}`, step: 3 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'no-task', runId: `run-${idx}` }),
    });
  }

  // Variant A: Prose-only rule with copied outputs (no executableRule) -> rejected!
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'Prose only',
        rule: 'out = 00000000 for every input',
        testVectors: [
          { caseId: 'disc', scenarioId: 'disc', inputHex: '41424344', predictedHex: '14171611', isHoldout: false, receiptId: memReceipts[0] },
          { caseId: 'hold', scenarioId: 'hold', inputHex: '31323334', predictedHex: '64676661', isHoldout: true, receiptId: memReceipts[1] },
        ],
      },
    },
  });
  assert.equal(e.ws({ action: 'assess', id: root.rootId }).canCompleteHostGoal, false);

  // Variant B: Constant-zero executableRule ('00000000') -> independently executed and rejected!
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'Wrong constant zero executableRule',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 4 },
        executableRule: { schema: 'ig5-bounded-byte-rule-v1', outputLength: 4, byteExpr: 0 },
        testVectors: [
          { caseId: 'disc', scenarioId: 'disc', receiptId: memReceipts[0] },
          { caseId: 'hold', scenarioId: 'hold', receiptId: memReceipts[1] },
        ],
      },
    },
  });
  const wrongRuleAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.equal(wrongRuleAssess.canCompleteHostGoal, false);
  assert(wrongRuleAssess.denialReasons.some(r => r.includes('candidate-execution-mismatch')));

  // Variant C: 1-byte prefix ('14' / '64') against 4-byte memory read -> rejected by exact width check!
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'One-byte prefix rule against 4-byte read',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 1 },
        executableRule: {
          schema: 'ig5-bounded-byte-rule-v1',
          outputLength: 1,
          byteExpr: { op: 'xor', args: [{ op: 'in', index: 0 }, 0x55] },
        },
        testVectors: [
          { caseId: 'disc', scenarioId: 'disc', receiptId: memReceipts[0] },
          { caseId: 'hold', scenarioId: 'hold', receiptId: memReceipts[1] },
        ],
      },
    },
  });
  const prefixAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.equal(prefixAssess.canCompleteHostGoal, false);
  assert(prefixAssess.denialReasons.some(r => r.includes('width-mismatch') || r.includes('size-arg-mismatch') || r.includes('holdout-consumed')));

  // Variant D: Trying to bind stack pointer rsp as outputSpec -> rejected at validation!
  assert.throws(
    () => e.ws({
      action: 'root-update',
      id: root.rootId,
      root: {
        candidate: {
          summary: 'Unrelated stack pointer',
          outputSpec: { kind: 'register', register: 'rsp', byteLength: 4 },
          executableRule: { schema: 'ig5-bounded-byte-rule-v1', outputLength: 4, byteExpr: 0 },
          testVectors: [{ caseId: 'disc', receiptId: regReceipts[0] }],
        },
      },
    }),
    err => err.code === 'INVALID_ARGUMENT',
  );

  // Also verify holdout anti-overfitting: since candidateRevision is now >= 2, reusing the old holdout run is blocked
  // until a fresh unseen holdout scenario is executed!
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      scenario: { scenarioId: 'hold-fresh', componentId: 'main', args: ['WXYZ'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'fresh holdout', sampleHex: '5758595a', caseId: 'hold2', isHoldout: true } },
      candidate: {
        summary: 'True bytewise XOR 0x55 rule',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 4 },
        executableRule: {
          schema: 'ig5-bounded-byte-rule-v1',
          outputLength: 4,
          byteExpr: { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, 0x55] },
        },
        testVectors: [
          { caseId: 'disc', scenarioId: 'disc', receiptId: memReceipts[0] },
          { caseId: 'hold', scenarioId: 'hold', receiptId: memReceipts[1] },
        ],
      },
    },
  });
  const reusedHoldoutAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.equal(reusedHoldoutAssess.canCompleteHostGoal, false);
  assert(reusedHoldoutAssess.denialReasons.some(r => r.includes('holdout-consumed-by-prior-candidate-revision')));

  // Run the fresh unseen holdout scenario bound to the current candidate revision -> satisfied!
  const selFresh = e.ws({
    action: 'select',
    id: root.rootId,
    root: { kind: 'holdout-verify', scenarioId: 'hold-fresh', observer: 'Output buffer at RVA 0x3100', hypothesis: 'Verify XOR 0x55 on unseen WXYZ' },
  });
  await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'start', args: ['WXYZ'], cwd: e.dir, research: { ...selFresh.researchBinding, key: 'st-fresh', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'run-fresh-holdout', stopSeq: 0, launchScenario: { argv: ['WXYZ'], cwd: e.dir }, _ig5: { sha256: dummySha } }),
  });
  const freshMem = await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 4, research: { ...selFresh.researchBinding, key: 'm-fresh', step: 1 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'run-fresh-holdout', stopSeq: 1, hex: '020d0c0f', _ig5: { sha256: dummySha } }), // 'WXYZ' (5758595a) ^ 0x55 = 020d0c0f
  });
  await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'stop', research: { ...selFresh.researchBinding, key: 'sp-fresh', step: 2 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'no-task', runId: 'run-fresh-holdout' }),
  });
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'True bytewise XOR 0x55 rule verified on unseen holdout',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 4 },
        executableRule: {
          schema: 'ig5-bounded-byte-rule-v1',
          outputLength: 4,
          byteExpr: { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, 0x55] },
        },
        testVectors: [
          { caseId: 'disc', scenarioId: 'disc', receiptId: memReceipts[0] },
          { caseId: 'hold-fresh', scenarioId: 'hold-fresh', receiptId: freshMem._managedExecution.reportId },
        ],
      },
    },
  });
  const finalAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.equal(finalAssess.assessment, 'satisfied');
  assert.equal(finalAssess.canCompleteHostGoal, true);
});

test('[M2 address-space] managed receipts preserve RVA aliases and reject address-space confusion', async t => {
  const cases = [
    ['explicit RVA alias', { ea: '0x00003100', address_space: 'rva' }, 'rva', true],
    ['rva takes priority over ea and database space', { rva: '0x3100', ea: '0x4100', address_space: 'database' }, 'rva', true],
    ['mismatching rva cannot fall back to matching ea', { rva: '0x4100', ea: '0x3100', address_space: 'rva' }, 'rva', false],
    ['invalid rva cannot fall back to matching ea', { rva: null, ea: '0x3100', address_space: 'rva' }, 'rva', false],
    ['legacy bare ea is not an RVA', { ea: '0x3100' }, 'rva', false],
    ['runtime ea is not an RVA', { ea: '0x3100', address_space: 'runtime' }, 'rva', false],
    ['database ea is not an RVA', { ea: '0x3100', address_space: 'database' }, 'rva', false],
    ['unknown address space is not an RVA', { ea: '0x3100', address_space: 'unknown' }, 'rva', false],
    ['RVA alias is not same-number runtime ea', { ea: '0x3100', address_space: 'rva' }, 'ea', false],
    ['rva takes priority over same-number runtime ea', { rva: '0x3100', ea: '0x3100', address_space: 'runtime' }, 'ea', false],
    ['database ea is not same-number runtime ea', { ea: '0x3100', address_space: 'database' }, 'ea', false],
    ['unknown address space is not runtime ea', { ea: '0x3100', address_space: 'unknown' }, 'ea', false],
    ['null address space is not default runtime ea', { ea: '0x3100', address_space: null }, 'ea', false],
    ['explicit runtime ea remains valid', { ea: '0x3100', address_space: 'runtime' }, 'ea', true],
    ['default runtime ea remains valid', { ea: '0x3100' }, 'ea', true],
  ];
  for (const [label, addressArgs, specAddress, accepted] of cases) {
    await t.test(label, async t => {
      const e = makeOfflineEnv(t, 'ig5-m2-address-');
      const root = e.ws({
        action: 'root-create', goal: 'Verify explicit memory address semantics',
        root: { deliverables: [{ kind: 'io-transform', requiredObservations: ['dynamic-runtime-observation'], minDistinctInputs: 2, holdoutRequired: true }] },
      });
      const inputs = ['ABCD', 'WXYZ'];
      const candidate = {
        summary: 'Identity transformation',
        outputSpec: { kind: 'memory', [specAddress]: '0x3100', byteLength: 4 },
        executableRule: { schema: 'ig5-bounded-byte-rule-v1', outputLength: 4, byteExpr: { op: 'in', index: { op: 'i' } } },
      };
      e.ws({
        action: 'root-update', id: root.rootId,
        root: {
          component: { componentId: 'main', path: e.dummy },
          scenarios: inputs.map((input, i) => ({
            scenarioId: `s-${i}`, componentId: 'main', args: [input], cwd: e.dir,
            inputSpec: { kind: 'cli-arg', summary: `input ${i}`, sampleHex: Buffer.from(input).toString('hex'), isHoldout: Boolean(i) },
          })),
          candidate,
        },
      });
      const sha256 = createHash('sha256').update(fs.readFileSync(e.dummy)).digest('hex');
      const vectors = [];
      for (const [i, input] of inputs.entries()) {
        const selected = e.ws({
          action: 'select', id: root.rootId,
          root: { kind: i ? 'holdout-verify' : 'dynamic-breakpoint-read', scenarioId: `s-${i}`, hypothesis: 'Identity transformation' },
        });
        const runId = `address-run-${i}`;
        const invoke = (op, step, args, output) => runManagedToolExecution({
          mgr: e.mgr, toolName: 'ig5_dbg',
          rawArgs: { target: e.dummy, backend: 'x64dbg', op, ...args, research: { ...selected.researchBinding, key: `${op}-${i}`, step } },
          execution: { agent: e.owner },
          runCore: async () => ({ ok: true, runId, _ig5: { sha256 }, ...output }),
        });
        await invoke('start', 0, { args: [input], cwd: e.dir }, {
          state: 'suspended', stopSeq: 0, launchScenario: { argv: [input], cwd: e.dir },
        });
        const observed = await invoke('readmem', 1, { ...addressArgs, size: 4 }, {
          state: 'suspended', stopSeq: 1, hex: Buffer.from(input).toString('hex'),
        });
        const receiptId = observed._managedExecution.reportId;
        const saved = JSON.parse(fs.readFileSync(path.join(e.cfg.artifactDir, 'analysis-data', 'records', `${receiptId}.json`), 'utf8'));
        assert.equal(saved.action, 'ig5_dbg:readmem');
        assert.equal(saved.outcome, 'success');
        for (const key of ['ea', 'rva', 'address_space']) {
          assert.equal(saved.result.cleanArgsSummary[key], addressArgs[key], `${key} must survive actual receipt persistence`);
        }
        await invoke('stop', 2, {}, { state: 'no-task' });
        vectors.push({ caseId: `case-${i}`, scenarioId: `s-${i}`, receiptId });
      }
      e.ws({ action: 'root-update', id: root.rootId, root: { candidate: { testVectors: vectors } } });
      const assessment = e.ws({ action: 'assess', id: root.rootId });
      assert.equal(assessment.canCompleteHostGoal, accepted);
      if (accepted) {
        assert.equal(assessment.assessment, 'satisfied');
      } else {
        assert.notEqual(assessment.assessment, 'satisfied');
        assert(assessment.denialReasons.some(reason => reason.includes(`memory-${specAddress}-mismatch`)), JSON.stringify(assessment.denialReasons));
      }
    });
  }
});

test('[P1 #4, #5, #6] status human message keeps cancel latch; 256+ compaction retains consumed step & key; public gate allows cancelled owner cleanup', async t => {
  // #4: Ordinary human message MUST NOT clear cancellation
  const e = makeOfflineEnv(t, 'ig5-p1-456-');
  const listeners = new Map();
  const mockCtx = {
    on: (name, fn) => listeners.set(name, fn),
    get: name => (name === 'agents' ? { get: id => (id === e.owner.id ? e.owner : undefined), roots: () => [e.owner] } : undefined),
  };
  const autonomy = installAutonomyHost(mockCtx, {
    cfg: e.cfg,
    getManager: () => e.mgr,
  });
  e.mgr.autonomyHost = autonomy;

  e.coordination.acceptCancel(e.owner, 'user-cancelled');
  assert.equal(e.coordination.controlStatus(e.owner).cancelled, true);

  // Inject human message "现在进展怎么样？先不要继续执行。"
  listeners.get('session/event')({ id: e.owner.id }, {
    type: 'user/message',
    data: { source: { kind: 'user' }, content: [{ type: 'text', text: '现在进展怎么样？先不要继续执行。' }] },
  });
  assert.equal(e.coordination.controlStatus(e.owner).cancelled, true, 'Status-only human message must NOT clear cancel latch');
  assert.throws(
    () => e.coordination.admitOperation(e.owner, { requestKey: 'after-msg', tool: 'ig5_status', cleanArgs: {}, argsDigest: 'a'.repeat(64) }),
    err => err.code === 'IG5_CANCELLED_BEFORE_DISPATCH',
  );

  // Subagent cannot invoke explicit resume
  assert.throws(
    () => e.ws({ action: 'root-control', root: { controlAction: 'resume' } }, e.subagent),
    err => err.code === 'RESUME_REQUIRES_DIRECT_HUMAN',
  );

  // Explicit resume on direct-human root turn lifts cancellation
  const resumed = e.ws({ action: 'root-control', root: { controlAction: 'resume' } }, e.owner);
  assert.equal(resumed.resumed, true);
  assert.equal(e.coordination.controlStatus(e.owner).cancelled, false);
  autonomy.dispose();

  // #6: 256+ operation compaction retains request-key replay AND permanent step lock
  const root = e.ws({ action: 'root-create', goal: 'Compaction retention check' });
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      component: { componentId: 'c1', path: e.dummy },
      scenario: { scenarioId: 's1', componentId: 'c1', cwd: e.dir, args: ['A'], inputSpec: { kind: 'cli-arg', summary: 'A', sampleHex: '41' } },
    },
  });
  const sel = e.ws({
    action: 'select',
    id: root.rootId,
    root: { kind: 'dynamic-breakpoint-read', scenarioId: 's1', hypothesis: 'Test step lock retention across >256 ops' },
  });

  const origRaw = { target: e.dummy, op: 'cont', research: { ...sel.researchBinding, key: 'orig-step-0', step: 0 } };
  const origDigest = hashCanonical({
    tool: 'ig5_dbg',
    args: { target: e.dummy, op: 'cont' },
    researchScope: { id: root.rootId, exp: sel.experiment.expId, step: 0 },
  });
  let providerCalls = 0;
  const invokeOrig = () => runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: origRaw,
    execution: { agent: e.owner, signal: new AbortController().signal },
    runCore: async () => { providerCalls += 1; return { ok: true, state: 'suspended', runId: 'r1', stopSeq: 1 }; },
  });

  const first = await invokeOrig();
  assert.equal(providerCalls, 1);

  for (let i = 0; i < 260; i++) {
    const row = e.coordination.admitOperation(e.owner, { requestKey: `filler-${i}`, tool: 'ig5_status', cleanArgs: {}, argsDigest: 'c'.repeat(64) });
    e.coordination.beginDispatch(e.owner, row.operation.slotKey);
    e.coordination.completeOperation(e.owner, row.operation.slotKey, { outcome: 'success', researchLinkStatus: 'not-applicable' });
  }

  const afterTrimLookup = e.coordination.inspectOperation(e.owner, { requestKey: 'orig-step-0', tool: 'ig5_dbg', argsDigest: origDigest });
  assert.equal(afterTrimLookup?.status, 'result-recorded');
  assert.equal(afterTrimLookup?.operationId, first._managedExecution.operationId);

  const second = await invokeOrig();
  assert.equal(second._managedExecution.replayed, true);
  assert.equal(second._managedExecution.operationId, first._managedExecution.operationId);
  assert.equal(providerCalls, 1, 'Compacted operation must replay from saved receipt without re-invoking provider');
  assert.equal(e.ws({ action: 'root-get', id: root.rootId }).receipts.filter(r => r.stepIndex === 0).length, 1);

  await assert.rejects(
    () => runManagedToolExecution({
      mgr: e.mgr,
      toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'cont', research: { ...sel.researchBinding, key: 'different-key-same-step-0', step: 0 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true }),
    }),
    err => err.code === 'EXPERIMENT_STEP_ALREADY_CONSUMED',
  );

  // #5: Full public plugin pre-execute + execute pipeline allows cancelled owner cleanup with aborted signal
  const pubDir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-pub-cleanup-'));
  const pubTools = new Map();
  const pubEvents = new Map();
  const pubEffects = [];
  let approvalSignals = [];
  const pubAgent = { id: 'pub-owner', session: { header: { id: 'pub-owner', cwd: pubDir } } };
  const pubCtx = {
    tools: { register: def => { pubTools.set(def.name, def); return () => pubTools.delete(def.name); }, get: n => pubTools.get(n) },
    get: name => {
      if (name === 'tools') return pubCtx.tools;
      if (name === 'approval') return { request: async req => { approvalSignals.push(req.signal.aborted); return 'allowed-once'; } };
      if (name === 'agents') return { get: id => (id === pubAgent.id ? pubAgent : undefined), roots: () => [pubAgent] };
      return undefined;
    },
    on: (name, fn) => { pubEvents.set(name, fn); return () => pubEvents.delete(name); },
    inject: (names, cb) => { const d = names.every(n => pubCtx.get(n)) ? cb({ get: pubCtx.get, tools: pubCtx.tools }) : undefined; if (typeof d === 'function') pubEffects.push(d); return { dispose: async () => {} }; },
    effect: fn => { const d = fn(); if (typeof d === 'function') pubEffects.push(d); },
  };
  try {
    ig5Plugin.apply(pubCtx, {
      artifactDir: path.join(pubDir, 'artifacts'),
      projectRoot: path.join(pubDir, 'projects'),
      stateRoot: path.join(pubDir, 'state'),
      toolset: 'full',
    });
    const publicInvoke = async (name, args, signal = new AbortController().signal) => {
      const pre = pubEvents.get('tools/pre-execute');
      let enteredNext = false;
      const gate = await pre({ name, arguments: args, agent: pubAgent, callId: 'c1', signal }, async () => { enteredNext = true; return { kind: 'allow' }; });
      if (gate.kind !== 'allow' || !enteredNext) {
        throw Object.assign(new Error(`Blocked at pre-execute: ${gate.kind}`), { code: `GATE_${gate.kind.toUpperCase()}` });
      }
      return pubTools.get(name).execute(args, { agent: pubAgent, callId: 'c1', signal });
    };

    await publicInvoke('ig5_profile', { collaboration: { action: 'start', max_calls: 2 } });
    // Intercept inner performDebug on WorkerManager? No need: test pre-execute passage directly + verify non-owner/business is cancelled!
    // Acquire reservation in DelegationControl via ig5_capture_control or inspect pre-execute on active reservation:
    // Let's inspect the coordination ledger created by ig5Plugin.apply:
    const coord = new DelegationControl({ root: path.join(pubDir, 'projects'), getAgent: () => pubAgent });
    const adm = coord.admitOperation(pubAgent, { requestKey: 'acq', tool: 'ig5_dbg', cleanArgs: { target: e.dummy, op: 'start' }, argsDigest: 'b'.repeat(64) });
    coord.beginDispatch(pubAgent, adm.operation.slotKey);
    coord.completeOperation(pubAgent, adm.operation.slotKey, { outcome: 'success' });
    coord.acceptCancel(pubAgent, 'user-cancelled');

    const abortedSig = AbortSignal.abort('user-cancelled');
    // Business write tool (`ig5_dbg op=regs`) MUST be cancelled at public pre-execute!
    await assert.rejects(
      () => publicInvoke('ig5_dbg', { target: e.dummy, op: 'regs' }, abortedSig),
      err => err.code === 'GATE_CANCEL',
    );
    // Strict owner cleanup (`ig5_dbg op=stop`) MUST pass public pre-execute with isolated non-aborted approval signal!
    let stopEnteredNext = false;
    const stopGate = await pubEvents.get('tools/pre-execute')(
      { name: 'ig5_dbg', arguments: { target: e.dummy, op: 'stop' }, agent: pubAgent, callId: 'c-stop', signal: abortedSig },
      async () => { stopEnteredNext = true; return { kind: 'allow' }; },
    );
    assert.equal(stopGate.kind, 'allow');
    assert.equal(stopEnteredNext, true);
    assert.deepEqual(approvalSignals, [false]);
  } finally {
    for (const fn of pubEffects.reverse()) { try { await fn(); } catch { /* ignore */ } }
    try { fs.rmSync(pubDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }); } catch { /* ignore */ }
  }
});

test('[P1 #7] every executable planner candidate passes production runWorkspace verbatim; templates declare missingParameters', async t => {
  const e = makeOfflineEnv(t, 'ig5-p1-7-');
  const inv = e.ws({ action: 'root-create', goal: 'Verify planner request contracts across all stages' });

  // Stage 1: No components yet -> register-target-component is a template (operationExecutableNow=false), assess-deliverables is executable
  const plan1 = e.ws({ action: 'root-plan', id: inv.rootId });
  const regCand = plan1.candidates.find(c => c.kind === 'register-target-component');
  assert.equal(regCand.operationExecutableNow, false);
  assert.equal(regCand.request, null);
  assert(regCand.missingParameters.includes('workspace.root.component.path'));
  for (const c of plan1.candidates.filter(x => x.operationExecutableNow && x.request?.tool === 'ig5_workspace')) {
    assert.doesNotThrow(() => e.ws(c.request.workspace));
  }

  // Stage 2: Component + scenario + route registered -> select-discriminating-experiment MUST execute verbatim!
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      component: { componentId: 'c1', path: e.dummy },
      scenario: { scenarioId: 's1', componentId: 'c1', args: ['ABCD'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'ABCD', sampleHex: '41424344' } },
      route: { routeId: 'r1', question: 'What is output?', targetObservation: '4-byte buffer at 0x3100', discriminatingExperiment: 'Break and read 0x3100' },
    },
  });
  const plan2 = e.ws({ action: 'root-plan', id: inv.rootId });
  const selectCand = plan2.candidates.find(c => c.kind === 'select-discriminating-experiment');
  assert(selectCand, 'Expected select-discriminating-experiment candidate');
  assert.equal(selectCand.operationExecutableNow, true);

  // Execute planner's select request VERBATIM without any modification!
  const selected = e.ws(selectCand.request.workspace);
  assert(selected.experiment.expId);

  // Stage 3: Record a receipt -> evaluate-active-experiment is a template with valid nested root.expId
  await runManagedToolExecution({
    mgr: e.mgr,
    toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 4, research: { ...selected.researchBinding, key: 'obs-1', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'r-plan', stopSeq: 1, hex: '01020304' }),
  });
  const plan3 = e.ws({ action: 'root-plan', id: inv.rootId });
  const evalCand = plan3.candidates.find(c => c.kind === 'evaluate-active-experiment');
  assert.equal(evalCand.operationExecutableNow, false);
  assert.equal(evalCand.request, null);
  assert.equal(evalCand.requestTemplate.workspace.root.expId, selected.experiment.expId);
  for (const c of plan3.candidates.filter(x => x.operationExecutableNow && x.request?.tool === 'ig5_workspace')) {
    assert.doesNotThrow(() => e.ws(c.request.workspace));
  }
});

test('[R2 P1 #1] typed input channel derivation rejects same-argv divergent sampleHex and unobserved channels while accepting verified CLI/file bindings', async t => {
  const e = makeOfflineEnv(t, 'ig5-r2-p1-1-');
  const dummySha = createHash('sha256').update(fs.readFileSync(e.dummy)).digest('hex');
  const root = e.ws({
    action: 'root-create',
    goal: 'Verify actual input channel provenance',
    root: { deliverables: [{ kind: 'io-transform', requiredObservations: ['dynamic-runtime-observation'], minDistinctInputs: 2, holdoutRequired: true }] },
  });

  // Counterexample: two scenarios both pass actual argv ['ABCD'], second claims sampleHex '31323334'
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      component: { componentId: 'main', path: e.dummy, role: 'main-pe' },
      scenarios: [
        { scenarioId: 'disc', componentId: 'main', args: ['ABCD'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'UTF-8 arg 0', sampleHex: '41424344', isHoldout: false } },
        { scenarioId: 'fake-hold', componentId: 'main', args: ['ABCD'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'Claimed 1234', sampleHex: '31323334', isHoldout: true } },
        { scenarioId: 'unobserved-stdin', componentId: 'main', args: [], cwd: e.dir, inputSpec: { kind: 'stdin', summary: 'Unobserved stdin', sampleHex: '31323334', isHoldout: true } },
      ],
    },
  });

  const copiedRule = {
    schema: 'ig5-bounded-byte-rule-v1',
    outputLength: 4,
    constants: { copied: '41424344' },
    byteExpr: { op: 'const', name: 'copied', index: { op: 'i' } },
  };
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: { candidate: { summary: 'Constant ABCD', outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 4 }, executableRule: copiedRule } },
  });

  const runScen = async (scenId, argv, holdout, idx, outHex) => {
    const sel = e.ws({
      action: 'select',
      id: root.rootId,
      root: { kind: holdout ? 'holdout-verify' : 'dynamic-breakpoint-read', scenarioId: scenId, observer: 'RVA 0x3100', hypothesis: 'Test input provenance' },
    });
    const runId = `r2-p1-1-run-${idx}`;
    await runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'start', args: argv, cwd: e.dir, research: { ...sel.researchBinding, key: `s-${idx}`, step: 0 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId, stopSeq: 0, launchScenario: { argv, cwd: e.dir }, _ig5: { sha256: dummySha } }),
    });
    const rd = await runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 4, research: { ...sel.researchBinding, key: `r-${idx}`, step: 1 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId, stopSeq: 1, hex: outHex, _ig5: { sha256: dummySha } }),
    });
    await runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'stop', research: { ...sel.researchBinding, key: `x-${idx}`, step: 2 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'no-task', runId }),
    });
    return rd._managedExecution.reportId;
  };

  const rDisc = await runScen('disc', ['ABCD'], false, 0, '41424344');
  const rFakeHold = await runScen('fake-hold', ['ABCD'], true, 1, '41424344');
  const rStdin = await runScen('unobserved-stdin', [], true, 2, '31323334');

  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'Constant ABCD',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 4 },
        executableRule: copiedRule,
        testVectors: [{ caseId: 'd', receiptId: rDisc }, { caseId: 'fh', receiptId: rFakeHold }],
      },
    },
  });
  const badAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.notEqual(badAssess.assessment, 'satisfied');
  assert.equal(badAssess.canCompleteHostGoal, false);
  assert(badAssess.denialReasons.some(r => r.includes('unverified-input-provenance') && r.includes('claimed-sampleHex-contradicts-channel')));

  // Unobserved stdin channel also remains unverified
  const idRule = { schema: 'ig5-bounded-byte-rule-v1', outputLength: 4, byteExpr: { op: 'in', index: { op: 'i' } } };
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'Identity',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 4 },
        executableRule: idRule,
        testVectors: [{ caseId: 'd', receiptId: rDisc }, { caseId: 'st', receiptId: rStdin }],
      },
    },
  });
  const stdinAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.equal(stdinAssess.canCompleteHostGoal, false);
  assert(stdinAssess.denialReasons.some(r => r.includes('unverified-input-channel(stdin)')));

  // Positive control: file-channel holdout bound to argv[0] with real file bytes ('1234') + pre-committed identity rule -> satisfied!
  const holdFile = path.join(e.dir, 'holdout-payload.bin');
  fs.writeFileSync(holdFile, Buffer.from('1234', 'ascii'));
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      scenario: {
        scenarioId: 'file-hold',
        componentId: 'main',
        args: [`--in=${holdFile}`],
        cwd: e.dir,
        inputSpec: { kind: 'file', filePath: holdFile, argIndex: 0, prefix: '--in=', summary: 'File payload 1234', isHoldout: true },
      },
    },
  });
  const rFileHold = await runScen('file-hold', [`--in=${holdFile}`], true, 3, '31323334');
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'Identity',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 4 },
        executableRule: idRule,
        testVectors: [{ caseId: 'd', receiptId: rDisc }, { caseId: 'fh-ok', receiptId: rFileHold }],
      },
    },
  });
  const okAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.equal(okAssess.assessment, 'satisfied');
  assert.equal(okAssess.canCompleteHostGoal, true);
});

test('[R2 P1 #2] first candidate memorizing already-observed holdout is rejected; pre-committed candidate on unseen holdout succeeds', async t => {
  const e = makeOfflineEnv(t, 'ig5-r2-p1-2-');
  const dummySha = createHash('sha256').update(fs.readFileSync(e.dummy)).digest('hex');
  const root = e.ws({
    action: 'root-create',
    goal: 'Prevent post-hoc first candidate memorization',
    root: { deliverables: [{ kind: 'io-transform', requiredObservations: ['dynamic-runtime-observation'], minDistinctInputs: 2, holdoutRequired: true }] },
  });
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      component: { componentId: 'main', path: e.dummy, role: 'main-pe' },
      scenarios: [
        { scenarioId: 'disc-A', componentId: 'main', args: ['A'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'A', sampleHex: '41', isHoldout: false } },
        { scenarioId: 'hold-B', componentId: 'main', args: ['B'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'B', sampleHex: '42', isHoldout: true } },
        { scenarioId: 'hold-B-rerun', componentId: 'main', args: ['B'], cwd: e.dir, trigger: 'rerun exposed B', inputSpec: { kind: 'cli-arg', summary: 'B again', sampleHex: '42', isHoldout: true } },
        { scenarioId: 'hold-C', componentId: 'main', args: ['C'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'C', sampleHex: '43', isHoldout: true } },
      ],
    },
  });

  const runOne = async (scenId, arg, holdout, idx) => {
    const sel = e.ws({
      action: 'select',
      id: root.rootId,
      root: { kind: holdout ? 'holdout-verify' : 'dynamic-breakpoint-read', scenarioId: scenId, observer: 'RVA 0x3100', hypothesis: `Run ${scenId}` },
    });
    const runId = `r2-p1-2-run-${idx}`;
    const outHex = Buffer.from([arg.charCodeAt(0) ^ 0x55]).toString('hex');
    await runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'start', args: [arg], cwd: e.dir, research: { ...sel.researchBinding, key: `s-${idx}`, step: 0 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId, stopSeq: 0, launchScenario: { argv: [arg], cwd: e.dir }, _ig5: { sha256: dummySha } }),
    });
    const rd = await runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 1, research: { ...sel.researchBinding, key: `r-${idx}`, step: 1 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId, stopSeq: 1, hex: outHex, _ig5: { sha256: dummySha } }),
    });
    await runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'stop', research: { ...sel.researchBinding, key: `x-${idx}`, step: 2 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'no-task', runId }),
    });
    return rd._managedExecution.reportId;
  };

  // Observe BOTH A and holdout B BEFORE committing any candidate!
  const rA = await runOne('disc-A', 'A', false, 0);
  const rB = await runOne('hold-B', 'B', true, 1);

  const table = Buffer.alloc(256); table[0x41] = 0x14; table[0x42] = 0x17;
  const memorizedRule = {
    schema: 'ig5-bounded-byte-rule-v1',
    outputLength: 1,
    constants: { memorized: table.toString('hex') },
    byteExpr: { op: 'const', name: 'memorized', index: { op: 'in', index: 0 } },
  };
  assert.notEqual(evaluateBoundedTransform(memorizedRule, '43'), '16');

  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'Lookup table memorizing A and B after observing B',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 1 },
        executableRule: memorizedRule,
        testVectors: [{ caseId: 'A', receiptId: rA }, { caseId: 'B', receiptId: rB }],
      },
    },
  });
  const postHocAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.notEqual(postHocAssess.assessment, 'satisfied');
  assert.equal(postHocAssess.canCompleteHostGoal, false);
  assert(postHocAssess.denialReasons.some(r => r.includes('holdout-not-bound-to-precommitted-candidate')));

  // Now commit the true XOR 0x55 rule, and try to re-run already-exposed input B ('42') as holdout -> MUST reject!
  const xorRule = { schema: 'ig5-bounded-byte-rule-v1', outputLength: 1, byteExpr: { op: 'xor', args: [{ op: 'in', index: 0 }, 0x55] } };
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: { candidate: { summary: 'True XOR 0x55', outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 1 }, executableRule: xorRule } },
  });
  const rBRerun = await runOne('hold-B-rerun', 'B', true, 2);
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'True XOR 0x55',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 1 },
        executableRule: xorRule,
        testVectors: [{ caseId: 'A', receiptId: rA }, { caseId: 'B2', receiptId: rBRerun }],
      },
    },
  });
  const exposedAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.equal(exposedAssess.canCompleteHostGoal, false);
  assert(exposedAssess.denialReasons.some(r => r.includes('holdout-input-previously-exposed')));

  // Run genuinely unseen holdout C ('43' -> '16') AFTER xorRule was committed -> satisfied!
  const rC = await runOne('hold-C', 'C', true, 3);
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'True XOR 0x55',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 1 },
        executableRule: xorRule,
        testVectors: [{ caseId: 'A', receiptId: rA }, { caseId: 'C', receiptId: rC }],
      },
    },
  });
  const okAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.equal(okAssess.assessment, 'satisfied');
  assert.equal(okAssess.canCompleteHostGoal, true);
});

test('[R2 P1 #3] foreign target receipts and un-witnessed debugger reads are rejected at dispatch and assessment', async t => {
  const e = makeOfflineEnv(t, 'ig5-r2-p1-3-');
  const otherExe = path.join(e.dir, 'other64.exe');
  const otherBuf = fs.readFileSync(e.dummy);
  otherBuf[240] = 0xee;
  fs.writeFileSync(otherExe, otherBuf);
  const dummySha = createHash('sha256').update(fs.readFileSync(e.dummy)).digest('hex');
  const otherSha = createHash('sha256').update(otherBuf).digest('hex');

  const root = e.ws({
    action: 'root-create',
    goal: 'Bind dynamic receipts to registered component and launch witness',
    root: { deliverables: [{ kind: 'io-transform', requiredObservations: ['dynamic-runtime-observation'], minDistinctInputs: 2, holdoutRequired: true }] },
  });
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      component: { componentId: 'main', path: e.dummy, role: 'main-pe' },
      scenarios: [
        { scenarioId: 'disc', componentId: 'main', args: ['A'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'A', sampleHex: '41', isHoldout: false } },
        { scenarioId: 'hold', componentId: 'main', args: ['B'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'B', sampleHex: '42', isHoldout: true } },
      ],
    },
  });
  const idRule = { schema: 'ig5-bounded-byte-rule-v1', outputLength: 1, byteExpr: { op: 'in', index: 0 } };
  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: { candidate: { summary: 'Identity', outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 1 }, executableRule: idRule } },
  });

  // Start otherExe without research (valid standalone call), then try binding readmem(target=otherExe) to root's experiment -> MUST fail at dispatch!
  await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: otherExe, op: 'start', args: ['A'], cwd: e.dir },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'foreign-run-1', launchScenario: { argv: ['A'], cwd: e.dir }, _ig5: { sha256: otherSha } }),
  });
  const selDisc = e.ws({ action: 'select', id: root.rootId, root: { kind: 'dynamic-breakpoint-read', scenarioId: 'disc', hypothesis: 'Try foreign read' } });
  await assert.rejects(
    () => runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: otherExe, op: 'readmem', rva: '0x3100', size: 1, research: { ...selDisc.researchBinding, key: 'foreign-read', step: 0 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId: 'foreign-run-1', hex: '41', _ig5: { sha256: otherSha } }),
    }),
    err => err.code === 'EXPERIMENT_TARGET_MISMATCH',
  );
  await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: otherExe, op: 'stop' },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'no-task', runId: 'foreign-run-1' }),
  });

  // Even if target=e.dummy is passed on readmem WITHOUT a linked ig5_dbg:start launch witness, assessment MUST reject!
  const unWitnessedRead = await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 1, research: { ...selDisc.researchBinding, key: 'no-start-read', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'unwitnessed-run', stopSeq: 1, hex: '41', _ig5: { sha256: dummySha } }),
  });
  const selHold = e.ws({ action: 'select', id: root.rootId, root: { kind: 'holdout-verify', scenarioId: 'hold', hypothesis: 'Try unwitnessed holdout' } });
  const unWitnessedHold = await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 1, research: { ...selHold.researchBinding, key: 'no-start-hold', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'unwitnessed-hold', stopSeq: 1, hex: '42', _ig5: { sha256: dummySha } }),
  });

  e.ws({
    action: 'root-update',
    id: root.rootId,
    root: {
      candidate: {
        summary: 'Identity',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 1 },
        executableRule: idRule,
        testVectors: [
          { caseId: 'd', receiptId: unWitnessedRead._managedExecution.reportId },
          { caseId: 'h', receiptId: unWitnessedHold._managedExecution.reportId },
        ],
      },
    },
  });
  const unwitnessedAssess = e.ws({ action: 'assess', id: root.rootId });
  assert.notEqual(unwitnessedAssess.assessment, 'satisfied');
  assert.equal(unwitnessedAssess.canCompleteHostGoal, false);
  assert(unwitnessedAssess.denialReasons.some(r => r.includes('missing-verified-launch-witness')));
});

test('[R2 P1 #4] completion gate binds exact hostGoalId and contract revision across goal switches, dual investigations, and edits', async t => {
  const e = makeOfflineEnv(t, 'ig5-r2-p1-4-');
  const dummySha = createHash('sha256').update(fs.readFileSync(e.dummy)).digest('hex');
  let liveGoal = { id: 'goal-A', revision: 1, objective: 'Recover identity transformation', phase: 'active' };
  const listeners = new Map();
  const ctx = {
    on: (name, fn) => listeners.set(name, fn),
    get: name => (name === 'goals' ? { get: () => liveGoal } : name === 'agents' ? { get: () => e.owner, roots: () => [e.owner] } : undefined),
  };
  const host = installAutonomyHost(ctx, { cfg: e.cfg, getManager: () => e.mgr });
  e.mgr.autonomyHost = host;
  t.after(() => host.dispose());

  const gate = (args = { action: 'complete' }) => host.beforePreExecute({ name: 'update_goal', arguments: args, agent: e.owner });

  // Build genuinely satisfied rootA for goal-A (rev 1)
  const rootA = e.ws({
    action: 'root-create',
    goal: liveGoal.objective,
    root: { deliverables: [{ kind: 'io-transform', requiredObservations: ['dynamic-runtime-observation'], minDistinctInputs: 2, holdoutRequired: true }] },
  });
  e.ws({
    action: 'root-update',
    id: rootA.rootId,
    root: {
      component: { componentId: 'main', path: e.dummy },
      scenarios: ['ABCD', '1234'].map((inp, i) => ({
        scenarioId: `s-${i}`,
        componentId: 'main',
        args: [inp],
        cwd: e.dir,
        inputSpec: { kind: 'cli-arg', summary: `arg ${i}`, sampleHex: Buffer.from(inp).toString('hex'), isHoldout: Boolean(i) },
      })),
    },
  });
  const idCand = {
    summary: 'Identity transformation',
    outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 4 },
    executableRule: { schema: 'ig5-bounded-byte-rule-v1', outputLength: 4, byteExpr: { op: 'in', index: { op: 'i' } } },
  };
  e.ws({ action: 'root-update', id: rootA.rootId, root: { candidate: idCand } });
  const vectors = [];
  for (const [i, inp] of ['ABCD', '1234'].entries()) {
    const sel = e.ws({ action: 'select', id: rootA.rootId, root: { kind: i ? 'holdout-verify' : 'dynamic-breakpoint-read', scenarioId: `s-${i}`, hypothesis: 'Identity' } });
    const runId = `goalA-run-${i}`;
    await runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'start', args: [inp], cwd: e.dir, research: { ...sel.researchBinding, key: `gs-${i}`, step: 0 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId, stopSeq: 0, launchScenario: { argv: [inp], cwd: e.dir }, _ig5: { sha256: dummySha } }),
    });
    const obs = await runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 4, research: { ...sel.researchBinding, key: `gr-${i}`, step: 1 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId, stopSeq: 1, hex: Buffer.from(inp).toString('hex'), _ig5: { sha256: dummySha } }),
    });
    await runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: e.dummy, op: 'stop', research: { ...sel.researchBinding, key: `gx-${i}`, step: 2 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'no-task', runId }),
    });
    vectors.push({ caseId: `c-${i}`, receiptId: obs._managedExecution.reportId });
  }
  e.ws({ action: 'root-update', id: rootA.rootId, root: { candidate: { ...idCand, testVectors: vectors } } });
  assert.equal(gate(), undefined, 'Satisfied rootA must allow completing goal-A at revision 1');

  // 1) Switch host to goal-B (no root investigation for goal-B yet) -> MUST deny!
  liveGoal = { id: 'goal-B', revision: 1, objective: 'Different unfinished goal', phase: 'active' };
  assert.equal(gate()?.kind, 'deny', 'Goal B without investigation must be denied despite satisfied Goal A');

  // 2) Create unverified rootB for goal-B, then touch rootA so rootA is latest -> Goal B MUST STILL be denied!
  const rootB = e.ws({ action: 'root-create', goal: liveGoal.objective });
  assert.equal(rootB.origin.hostGoalId, 'goal-B');
  assert.equal(gate()?.kind, 'deny');
  e.ws({ action: 'root-update', id: rootA.rootId, root: { hostGoalBinding: { hostGoalId: 'goal-A', hostGoalRevision: 1 } } });
  assert.equal(gate()?.kind, 'deny', 'Touching old rootA must NOT allow unverified Goal B to complete');

  // 3) Attempting to rebind rootA from goal-A to goal-B MUST fail!
  assert.throws(
    () => e.ws({ action: 'root-update', id: rootA.rootId, root: { hostGoalBinding: { hostGoalId: 'goal-B', hostGoalRevision: 1 } } }),
    err => err.code === 'HOST_GOAL_REBIND_FORBIDDEN',
  );

  // 4) Switch back to goal-A, then edit/revise goal-A contract (revision 2, expanded objective) -> MUST deny until re-verified!
  liveGoal = { id: 'goal-A', revision: 2, objective: 'Recover identity transformation AND second stage', phase: 'active' };
  const afterEditGate = gate();
  assert.equal(afterEditGate?.kind, 'deny');
  assert.match(afterEditGate.reason, /host-goal-revision-mismatch|host-goal-objective-changed/);

  // Advancing hostGoalBinding to revision 2 marks deliverables contractRevisedRequiresUpdate -> still denied until candidate re-verified!
  e.ws({ action: 'root-update', id: rootA.rootId, root: { hostGoalBinding: { hostGoalId: 'goal-A', hostGoalRevision: 2 } } });
  const afterBindOnlyGate = gate();
  assert.equal(afterBindOnlyGate?.kind, 'deny');
  assert.match(afterBindOnlyGate.reason, /goal-contract-revised-requires-candidate-reverification/);
});

test('[R2 P2 #1, #2, #3] ledger saturation still allows public owner cleanup & cancel; multi-component planner targets active component; legacy fallback revokes authority on turn/end', async t => {
  const e = makeOfflineEnv(t, 'ig5-r2-p2-');

  // P2 #1a: 256 pre-dispatch cancelled calls must NOT block public owner stop or root-control cancel!
  {
    const agent = { id: 'sat-pending', session: { header: { id: 'sat-pending' } } };
    const coord = new DelegationControl({ root: path.join(e.dir, 'sat-pending'), getAgent: id => (id === agent.id ? agent : undefined) });
    const mgr = { coordination: coord };
    coord.budget(agent, { action: 'start', max_calls: 1000 });
    const target = path.join(e.dir, 'sat-pending.exe');
    await runManagedToolExecution({
      mgr, toolName: 'ig5_dbg', rawArgs: { target, op: 'start' },
      execution: { agent, signal: new AbortController().signal },
      runCore: async () => ({ ok: true, state: 'suspended', runId: 'sat-run-1' }),
    });
    for (let i = 0; i < 256; i++) {
      await assert.rejects(
        () => runManagedToolExecution({
          mgr, toolName: 'ig5_status', rawArgs: {},
          execution: { agent, signal: AbortSignal.abort('pre-dispatch') },
          runCore: async () => ({ ok: true }),
        }),
        err => err.code === 'IG5_CANCELLED_BEFORE_DISPATCH',
      );
    }
    const listeners = new Map();
    installApprovalGate(
      { on: (n, fn) => listeners.set(n, fn), get: n => (n === 'approval' ? { request: async () => 'allowed-once' } : undefined) },
      { artifactDir: path.join(e.dir, 'gate-1') },
      { isAuthorizedOwnerCleanup: exec => coord.hasActiveOwnerCleanup(exec.agent, exec.name, parseAndStripResearch(exec.arguments).cleanArgs) },
    );
    let stopRan = 0;
    const stopRes = await listeners.get('tools/pre-execute')(
      { name: 'ig5_dbg', arguments: { target, op: 'stop' }, agent, signal: AbortSignal.abort() },
      () => runManagedToolExecution({
        mgr, toolName: 'ig5_dbg', rawArgs: { target, op: 'stop' },
        execution: { agent, signal: AbortSignal.abort() },
        runCore: async () => { stopRan++; return { ok: true, state: 'no-task' }; },
      }),
    );
    assert.equal(stopRes.ok, true);
    assert.equal(stopRan, 1);

    const cancelRes = await runManagedToolExecution({
      mgr, toolName: 'ig5_workspace',
      rawArgs: { workspace: { action: 'root-control', root: { controlAction: 'cancel' } } },
      execution: { agent, signal: new AbortController().signal },
      runCore: cleanArgs => runWorkspace(mgr, { projectRoot: path.join(e.dir, 'sat-pending') }, cleanArgs, { agent }),
    });
    assert.equal(cancelRes.workspace.cancelled, true);
  }

  // P2 #1b: Synthetic 4096 compacted + 256 live keyed rows still allows public owner stop & root-control cancel without dropping compacted history!
  {
    const agent = { id: 'sat-hist', session: { header: { id: 'sat-hist' } } };
    const coord = new DelegationControl({ root: path.join(e.dir, 'sat-hist'), getAgent: id => (id === agent.id ? agent : undefined) });
    const mgr = { coordination: coord };
    const target = path.join(e.dir, 'sat-hist.exe');
    await runManagedToolExecution({
      mgr, toolName: 'ig5_status', rawArgs: {},
      execution: { agent, signal: new AbortController().signal },
      runCore: async () => ({ ok: true }),
    });
    coord.transaction(agent, state => {
      const template = Object.values(state.operations)[0];
      state.operations = {};
      for (let i = 0; i < 255; i++) {
        const slot = `${agent.id}:cap-${i}`;
        state.operations[slot] = { ...template, operationId: `cap-${i}`, slotKey: slot, requestKey: `cap-${i}` };
      }
      state.compactedOperations = {};
      for (let i = 0; i < 4096; i++) {
        const slot = `${agent.id}:hist-${i}`;
        state.compactedOperations[slot] = { ...template, operationId: `hist-${i}`, slotKey: slot, requestKey: `hist-${i}` };
      }
    });
    coord.budget(agent, { action: 'start', max_calls: 3 });
    await runManagedToolExecution({
      mgr, toolName: 'ig5_dbg', rawArgs: { target, op: 'start' },
      execution: { agent, signal: new AbortController().signal },
      runCore: async () => ({ ok: true, state: 'suspended', runId: 'sat-hist-run' }),
    });
    let stopRan = 0;
    const stopRes = await runManagedToolExecution({
      mgr, toolName: 'ig5_dbg', rawArgs: { target, op: 'stop' },
      execution: { agent, signal: AbortSignal.abort() },
      runCore: async () => { stopRan++; return { ok: true, state: 'no-task' }; },
    });
    assert.equal(stopRes.ok, true);
    assert.equal(stopRan, 1);
    assert.equal(coord.inspectOperation(agent, { requestKey: 'hist-0', tool: 'ig5_status', argsDigest: hashCanonical({ tool: 'ig5_status', args: {}, researchScope: null }) })?.operationId, 'hist-0');

    const cancelRes = await runManagedToolExecution({
      mgr, toolName: 'ig5_workspace',
      rawArgs: { workspace: { action: 'root-control', root: { controlAction: 'cancel' } } },
      execution: { agent, signal: new AbortController().signal },
      runCore: cleanArgs => runWorkspace(mgr, { projectRoot: path.join(e.dir, 'sat-hist') }, cleanArgs, { agent }),
    });
    assert.equal(cancelRes.workspace.cancelled, true);
  }

  // P2 #2: Multi-component planner selects & cleans up the actual second component (`running`), not `components[0]`!
  {
    const secondExe = path.join(e.dir, 'second-running.exe');
    const b = fs.readFileSync(e.dummy); b[210] = 0x77; fs.writeFileSync(secondExe, b);
    const inv = e.ws({ action: 'root-create', goal: 'Multi-component select and cleanup accuracy' });
    e.ws({
      action: 'root-update',
      id: inv.rootId,
      root: {
        components: [{ componentId: 'first', path: e.dummy }, { componentId: 'running', path: secondExe }],
        scenario: { scenarioId: 'run-second', componentId: 'running', args: ['ABCD'], cwd: e.dir, inputSpec: { kind: 'cli-arg', summary: 'ABCD', sampleHex: '41424344' } },
        route: { routeId: 'r-multi', question: 'Second component output?', targetObservation: '4 bytes', discriminatingExperiment: 'Run second' },
      },
    });
    assert.throws(
      () => e.ws({ action: 'select', id: inv.rootId, root: { kind: 'dynamic-breakpoint-read', scenarioId: 'run-second', componentId: 'first', hypothesis: 'Mismatched component' } }),
      err => err.code === 'SCENARIO_COMPONENT_MISMATCH',
    );
    const plan = e.ws({ action: 'root-plan', id: inv.rootId });
    const selCand = plan.candidates.find(c => c.kind === 'select-discriminating-experiment');
    assert.equal(selCand.request.workspace.root.componentId, 'running');
    const selected = e.ws(selCand.request.workspace);
    assert.equal(selected.experiment.componentId, 'running');

    await runManagedToolExecution({
      mgr: e.mgr, toolName: 'ig5_dbg',
      rawArgs: { target: secondExe, op: 'start', args: ['ABCD'], cwd: e.dir, research: { ...selected.researchBinding, key: 'mc-start', step: 0 } },
      execution: { agent: e.owner },
      runCore: async () => ({ ok: true, state: 'suspended', runId: 'mc-run-1', launchScenario: { argv: ['ABCD'], cwd: e.dir } }),
    });
    e.coordination.acceptCancel(e.owner, 'user-cancelled');
    const cPlan = e.ws({ action: 'root-plan', id: inv.rootId });
    const cleanupCand = cPlan.candidates.find(c => c.kind === 'cleanup-owned-resource');
    assert.equal(cleanupCand.request.target, secondExe);
    assert.equal(e.coordination.hasActiveOwnerCleanup(e.owner, 'ig5_dbg', { target: cleanupCand.request.target, op: 'stop' }), true);
  }

  // P2 #3: Legacy host fallback without snapshotEvents/turnBoundaryOf revokes direct-human authority on turn/end!
  {
    const fbAgent = { id: 'fb-agent', session: { header: { id: 'fb-agent' } } };
    const fbCoord = new DelegationControl({ root: path.join(e.dir, 'fb'), getAgent: () => fbAgent });
    const fbListeners = new Map();
    const fbMgr = { coordination: fbCoord };
    const fbHost = installAutonomyHost(
      { on: (n, fn) => fbListeners.set(n, fn), get: n => (n === 'agents' ? { get: () => fbAgent, roots: () => [fbAgent] } : undefined) },
      { cfg: { projectRoot: path.join(e.dir, 'fb') }, getManager: () => fbMgr },
    );
    fbMgr.autonomyHost = fbHost;
    fbListeners.get('session/event')({ id: fbAgent.id }, { type: 'turn/start', data: { turn: 1 } });
    fbListeners.get('session/event')({ id: fbAgent.id }, { type: 'user/message', data: { source: { kind: 'user' }, content: [{ type: 'text', text: '只看状态' }] } });
    assert.equal(fbHost.hasDirectHumanTurnAuthority(fbAgent), true);
    fbListeners.get('session/event')({ id: fbAgent.id }, { type: 'turn/end', data: { reason: { kind: 'complete' } } });
    assert.equal(fbHost.hasDirectHumanTurnAuthority(fbAgent), false);
    fbCoord.acceptCancel(fbAgent, 'user-cancelled');
    assert.throws(
      () => runWorkspace(fbMgr, { projectRoot: path.join(e.dir, 'fb') }, { workspace: { action: 'root-control', root: { controlAction: 'resume' } } }, { agent: fbAgent }),
      err => err.code === 'RESUME_REQUIRES_DIRECT_HUMAN',
    );
    fbHost.dispose();
  }
});

test('[M2 Smoke Regressions] cross-experiment same-runId witness, holdout start chronology, id aliases, and planner pre-commit order', async t => {
  const e = makeOfflineEnv(t, 'ig5-m2-smoke-reg-');
  const dummySha = createHash('sha256').update(fs.readFileSync(e.dummy)).digest('hex');

  const inv = e.ws({
    action: 'root-create',
    goal: 'Verify cross-experiment live runId continuation without weakening holdout pre-commitment',
    root: { deliverables: [{ id: 'deliv-1', kind: 'io-transform', requiredObservations: ['dynamic-runtime-observation'], minDistinctInputs: 2, holdoutRequired: true }] },
  });

  // 1. Register component & scenarios using `id` alias and single-component scenario auto-binding
  const updated = e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      components: [{ id: 'comp-exe', path: e.dummy }],
      scenarios: [
        { id: 'scn-disc', args: ['X=AB'], cwd: e.dir, inputSpec: { kind: 'cli-arg', argIndex: 0, prefix: 'X=', encoding: 'ascii', isHoldout: false } },
        { id: 'scn-hold-early', args: ['X=CD'], cwd: e.dir, inputSpec: { kind: 'cli-arg', argIndex: 0, prefix: 'X=', encoding: 'ascii', isHoldout: true } },
      ],
      route: { routeId: 'r-main', deliverableId: 'deliv-1', question: '2-byte XOR?', targetObservation: '2 bytes at RVA 0x3100', discriminatingExperiment: 'x64dbg readmem' },
    },
  });
  assert.equal(updated.updated.components[0].componentId, 'comp-exe');
  assert.equal(updated.updated.scenarios[0].scenarioId, 'scn-disc');
  assert.equal(updated.updated.scenarios[0].componentId, 'comp-exe');
  assert.equal(updated.updated.scenarios[0].inputSpec.canonicalInputHex, '4142');

  // 2. Discovery run spans exp-1 (start + cont hitting maxSteps=2) and exp-2 (readmem + stop on same runId)
  const sel1 = e.ws({
    action: 'select',
    id: inv.rootId,
    root: { kind: 'dynamic-breakpoint-read', routeId: 'r-main', scenarioId: 'scn-disc', hypothesis: 'Start discovery run', maxSteps: 2 },
  });
  await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'start', args: ['X=AB'], cwd: e.dir, research: { ...sel1.researchBinding, key: 'd-start', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'live-run-disc', stopSeq: 0, launchScenario: { argv: ['X=AB'], cwd: e.dir }, _ig5: { sha256: dummySha } }),
  });
  await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'cont', research: { ...sel1.researchBinding, key: 'd-cont1', step: 1 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'live-run-disc', stopSeq: 1, _ig5: { sha256: dummySha } }),
  });
  e.ws({
    action: 'evaluate',
    id: inv.rootId,
    root: { expId: sel1.experiment.expId, observationClass: 'window-insufficient', verdict: 'inconclusive', whyNextChanged: 'Paused at EntryPoint', nextAction: 'Continue same live run in exp-2' },
  });

  // Planner now sees only scn-hold-early unevaluated, and MUST require candidate pre-commitment before holdout select!
  const planBeforeCommit = e.ws({ action: 'root-plan', id: inv.rootId });
  assert(planBeforeCommit.candidates.some(c => c.kind === 'precommit-candidate-before-holdout'));
  assert(!planBeforeCommit.candidates.some(c => c.kind === 'select-discriminating-experiment'));

  const sel2 = e.ws({
    action: 'select',
    id: inv.rootId,
    root: { kind: 'dynamic-breakpoint-read', routeId: 'r-main', scenarioId: 'scn-disc', hypothesis: 'Continue live discovery run to read output', maxSteps: 4 },
  });
  const discRead = await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 2, research: { ...sel2.researchBinding, key: 'd-read', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'live-run-disc', stopSeq: 2, hex: '5152', _ig5: { sha256: dummySha } }),
  });
  await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'stop', research: { ...sel2.researchBinding, key: 'd-stop', step: 1 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'no-task', runId: 'live-run-disc' }),
  });
  e.ws({
    action: 'evaluate',
    id: inv.rootId,
    root: { expId: sel2.experiment.expId, observationClass: 'non-empty', verdict: 'supports', whyNextChanged: 'Observed 5152 = AB ^ 0x10', nextAction: 'Commit candidate' },
  });

  // 3. Adversarial check: pre-launch holdout BEFORE committing candidate, then readmem in a post-commit experiment -> MUST REJECT!
  const selEarlyHold = e.ws({
    action: 'select',
    id: inv.rootId,
    root: { kind: 'holdout-verify', routeId: 'r-main', scenarioId: 'scn-hold-early', hypothesis: 'Pre-launch holdout before candidate commit', maxSteps: 2 },
  });
  await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'start', args: ['X=CD'], cwd: e.dir, research: { ...selEarlyHold.researchBinding, key: 'he-start', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'live-run-hold-early', stopSeq: 0, launchScenario: { argv: ['X=CD'], cwd: e.dir }, _ig5: { sha256: dummySha } }),
  });
  e.ws({
    action: 'evaluate',
    id: inv.rootId,
    root: { expId: selEarlyHold.experiment.expId, observationClass: 'window-insufficient', verdict: 'inconclusive', whyNextChanged: 'Paused early', nextAction: 'Commit then read' },
  });

  const xor10Rule = { schema: 'ig5-bounded-byte-rule-v1', outputLength: 2, byteExpr: { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, 0x10] } };
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: { candidate: { explanation: 'XOR 0x10 rule', outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 2 }, executableRule: xor10Rule } },
  });

  const selLateRead = e.ws({
    action: 'select',
    id: inv.rootId,
    root: { kind: 'holdout-verify', routeId: 'r-main', scenarioId: 'scn-hold-early', hypothesis: 'Read pre-launched holdout after commit', maxSteps: 3 },
  });
  const earlyHoldRead = await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 2, research: { ...selLateRead.researchBinding, key: 'he-read', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'live-run-hold-early', stopSeq: 1, hex: '5354', _ig5: { sha256: dummySha } }),
  });
  await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'stop', research: { ...selLateRead.researchBinding, key: 'he-stop', step: 1 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'no-task', runId: 'live-run-hold-early' }),
  });
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      candidate: {
        explanation: 'XOR 0x10 rule',
        outputSpec: { kind: 'memory', rva: '0x3100', byteLength: 2 },
        executableRule: xor10Rule,
        testVectors: [
          { caseId: 'disc', receiptId: discRead._managedExecution.reportId },
          { caseId: 'hold-early', receiptId: earlyHoldRead._managedExecution.reportId },
        ],
      },
    },
  });
  const rejectPreLaunched = e.ws({ action: 'assess', id: inv.rootId });
  assert.equal(rejectPreLaunched.canCompleteHostGoal, false);
  assert(rejectPreLaunched.denialReasons.some(r => r.includes('holdout-not-bound-to-precommitted-candidate') || r.includes('holdout-input-previously-exposed')));

  // 4a. Verify expected_task_revision CAS check on root-update (mismatch rejected, exact revision accepted)
  const curTask = e.ws({ action: 'root-get', id: inv.rootId });
  assert.throws(
    () => e.ws({
      action: 'root-update',
      id: inv.rootId,
      expected_task_revision: curTask.revision + 99,
      root: { question: { questionId: 'q-cas', question: 'Stale revision check' } },
    }),
    err => err.code === 'TASK_REVISION_MISMATCH',
  );
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    expected_task_revision: curTask.revision,
    root: {
      scenario: {
        id: 'scn-hold-fresh',
        args: ['X=EF'],
        cwd: e.dir,
        inputSpec: { kind: 'cli-arg', argIndex: 0, prefix: 'X=', encoding: 'ascii', isHoldout: true },
      },
    },
  });
  const selFreshHold = e.ws({
    action: 'select',
    id: inv.rootId,
    root: { kind: 'holdout-verify', routeId: 'r-main', scenarioId: 'scn-hold-fresh', hypothesis: 'Fresh post-commit holdout', maxSteps: 4 },
  });
  await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'start', args: ['X=EF'], cwd: e.dir, research: { ...selFreshHold.researchBinding, key: 'hf-start', step: 0 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'live-run-hold-fresh', stopSeq: 0, launchScenario: { argv: ['X=EF'], cwd: e.dir }, _ig5: { sha256: dummySha } }),
  });
  const freshHoldRead = await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'readmem', rva: '0x3100', size: 2, research: { ...selFreshHold.researchBinding, key: 'hf-read', step: 1 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'suspended', runId: 'live-run-hold-fresh', stopSeq: 1, hex: '5556', _ig5: { sha256: dummySha } }),
  });
  await runManagedToolExecution({
    mgr: e.mgr, toolName: 'ig5_dbg',
    rawArgs: { target: e.dummy, op: 'stop', research: { ...selFreshHold.researchBinding, key: 'hf-stop', step: 2 } },
    execution: { agent: e.owner },
    runCore: async () => ({ ok: true, state: 'no-task', runId: 'live-run-hold-fresh' }),
  });

  // 4b. Attach testVectors ONLY (omitting summary/outputSpec/executableRule) -> preserves pre-committed rule & chronology!
  e.ws({
    action: 'root-update',
    id: inv.rootId,
    root: {
      candidate: {
        testVectors: [
          { caseId: 'disc', receiptId: discRead._managedExecution.reportId },
          { caseId: 'hold-fresh', receiptId: freshHoldRead._managedExecution.reportId },
        ],
      },
    },
  });
  const okAssess = e.ws({ action: 'assess', id: inv.rootId });
  assert.equal(okAssess.assessment, 'satisfied');
  assert.equal(okAssess.canCompleteHostGoal, true);

  // 4c. Verify unrolled per-byte AST array form in executableRule.byteExpr (smoke-04 #44 shape) & wrong-length rejection
  const unrolledRule = validateExecutableRule({
    schema: 'ig5-bounded-byte-rule-v1',
    outputLength: 4,
    constants: { tbl: '5aa533cc' },
    byteExpr: [
      { op: 'add', args: [{ op: 'xor', args: [{ op: 'in', index: 0 }, { op: 'const', name: 'tbl', index: 0 }] }, 3] },
      { op: 'add', args: [{ op: 'xor', args: [{ op: 'in', index: 1 }, { op: 'const', name: 'tbl', index: 1 }] }, 10] },
      { op: 'add', args: [{ op: 'xor', args: [{ op: 'in', index: 2 }, { op: 'const', name: 'tbl', index: 2 }] }, 17] },
      { op: 'add', args: [{ op: 'xor', args: [{ op: 'in', index: 3 }, { op: 'const', name: 'tbl', index: 3 }] }, 24] },
    ],
  });
  assert.equal(evaluateBoundedTransform(unrolledRule, '41423132'), '1ef11316');
  assert.equal(evaluateBoundedTransform(unrolledRule, '7778797a'), '30e75bce');
  assert.throws(
    () => validateExecutableRule({
      schema: 'ig5-bounded-byte-rule-v1',
      outputLength: 4,
      byteExpr: [1, 2, 3],
    }),
    err => err.code === 'INVALID_ARGUMENT' && err.message.includes('array length'),
  );

  // 4d. Post-compaction brief navigation & stray top-level args guard on ig5_workspace
  const briefRes = e.ws({ action: 'root-brief', id: inv.rootId });
  assert.match(briefRes.brief, /resumeHint:/);
  assert.match(briefRes.brief, /workspaceSyntax:/);
  assert.throws(
    () => runWorkspace(e.mgr, e.cfg, { action: 'evaluate', root: '{"expId":"exp-1"}', workspace: { action: 'evaluate', id: inv.rootId } }, { agent: e.owner }),
    err => err.code === 'INVALID_ARGUMENT' && err.message.includes('nest all workspace fields inside args.workspace'),
  );
});
