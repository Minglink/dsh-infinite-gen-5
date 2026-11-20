import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DelegationControl, classifyManagedResourceCall } from '../source/delegation_control.js';
import {
  auditSessionGuardLogs, buildCleanupAssessment, buildIsolationAudit, buildScoreColumns, buildTaskPrompt, buildTransformScore,
  collectNativeProcessCheck, evaluateBudgetCleanupControl, evaluateTriggerCompleteness, validateSentinelProof,
} from './evals/run_m2_blind_eval.mjs';
import { M2_GUARD_POLICY_VERSION } from './evals/m2_suite_guard.mjs';

// Fixtures never start a model or native target. One checks the real coordination ledger on temporary disk.
let count = 0;
const test = (label, fn) => { fn(); count += 1; console.log('PASS', label); };
const checkedEmpty = () => collectNativeProcessCheck({ execFile: () => '' });
const owner = 'session-fixture';
const target = 'C:\\workspace\\fixture.exe';
const resourceKey = 'dbg:c:\\workspace\\fixture.exe';
const runId = 'fixture-run';

function toolPair(seq, name, args, value, { isError = false, agentId } = {}) {
  const callId = `call-${seq}`;
  return [
    { type: 'tool/call', seq, data: { callId, name, arguments: JSON.stringify(args), ...(agentId ? { agentId } : {}) } },
    // This matches archived DSH events: result identity is nested in message.toolCallId.
    { type: 'tool/result', seq: seq + 1, data: { message: { toolCallId: callId, isError,
      content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value) }] } } },
  ];
}

function fixture() {
  return {
    sessionId: owner,
    processCheck: checkedEmpty(),
    events: [
      ...toolPair(1, 'ig5_profile', { collaboration: { action: 'start', max_calls: 6 } },
        { collaboration: { rootId: owner, limit: 6, used: 0, reserved: 0 } }),
      ...toolPair(3, 'ig5_dbg', { op: 'start', target }, { ok: true, runId, state: 'suspended' }),
      ...toolPair(5, 'ig5_profile', { collaboration: { action: 'status' } },
        { collaboration: { rootId: owner, limit: 6, used: 5, reserved: 1, availableForOrdinaryCalls: 0 } }),
      ...toolPair(7, 'ig5_bytes', { target }, 'Error: Shared parent/child IG5 call budget exhausted; only collaboration status and owner cleanup remain available', { isError: true }),
      ...toolPair(9, 'ig5_dbg', { op: 'stop', target }, { ok: true, runId, state: 'no-task' }),
    ],
    sessionControl: {
      rootId: owner,
      budget: { limit: 6, used: 6, reserved: 0 },
      cleanupReservations: { [resourceKey]: { resourceKey, targetPath: target, ownerAgentId: owner,
        lastRunId: runId, status: 'confirmed', reservedCalls: 0, attemptsUsed: 1 } },
    },
  };
}

const messageAt = (f, seq) => f.events.find((e) => e.seq === seq).data.message;
const changeResult = (f, seq, change) => {
  const message = messageAt(f, seq);
  const value = JSON.parse(message.content[0].text);
  change(value);
  message.content[0].text = JSON.stringify(value);
};
const reservation = (f) => f.sessionControl.cleanupReservations[resourceKey];

test('no blocked paths cannot establish strict physical isolation', () => {
  const result = buildIsolationAudit();
  assert.equal(result.status, 'unverified');
  assert.equal(result.executedOutsideAllowedRoots, null);
  assert.equal(result.strictBlindEligible, false);
  assert.equal(buildIsolationAudit({ blockedOutsideWorkspaceCalls: 2, answerVaultTouchAttempts: 1 }).answerVaultTouchAttempts, 1);
});

const identityRule = { schema: 'ig5-bounded-byte-rule-v1', outputLength: 4, byteExpr: { op: 'in', index: { op: 'i' } } };
const transformArgs = { rule: identityRule, outputSpecValidForTarget: true,
  oracleVectors: ['01020304', 'ff0055aa'], referenceFn: (buf) => buf.toString('hex') };
test('finite vector success leaves trigger completeness unverified', () => {
  const result = buildTransformScore(transformArgs);
  assert.equal(result.transformFiniteVectorCorrect, true);
  assert.equal(result.deliverableCorrect, true);
  assert.equal(result.triggerCompleteness, 'unverified');
  assert.equal(result.scope, 'finite-reference-vectors-and-output-location');
});
test('empty vector list cannot pass by vacuous every()', () => {
  const result = buildTransformScore({ ...transformArgs, oracleVectors: [] });
  assert.equal(result.allVectorsMatched, false);
  assert.equal(result.deliverableCorrect, false);
});
test('wrong output location, mismatch and missing rule do not pass', () => {
  assert.equal(buildTransformScore({ ...transformArgs, outputSpecValidForTarget: false }).deliverableCorrect, false);
  assert.equal(buildTransformScore({ ...transformArgs, referenceFn: () => '00000000' }).allVectorsMatched, false);
  assert.equal(buildTransformScore({ ...transformArgs, rule: null }).checked, false);
});
test('invalid candidate preserves an evaluation error', () => {
  const result = buildTransformScore({ ...transformArgs, rule: { schema: 'invalid' } });
  assert.equal(result.deliverableCorrect, false);
  assert.ok(result.vectors.every((v) => v.evalError));
});

test('successful empty process query is distinguishable from query failure', () => {
  const processCheck = checkedEmpty();
  assert.equal(processCheck.status, 'checked');
  assert.deepEqual(processCheck.processes, []);
  assert.equal(buildCleanupAssessment({ processCheck }).cleanupConfirmed, true);
});
test('native process check exceptions never become an empty success', () => {
  const processCheck = collectNativeProcessCheck({ execFile: () => { throw Object.assign(new Error('query failed'), { code: 'EFAIL' }); } });
  assert.equal(processCheck.status, 'failed');
  assert.equal(processCheck.processes, null);
  assert.equal(processCheck.error.code, 'EFAIL');
  const cleanup = buildCleanupAssessment({ processCheck });
  assert.equal(cleanup.cleanupConfirmed, false);
  assert.equal(cleanup.lingeringNativeProcessesCount, null);
});
test('malformed process JSON, null and invalid shape fail closed', () => {
  for (const output of ['broken-json', 'null', '{"unexpected":true}', '[{"Id":"7","ProcessName":"java"}]']) {
    assert.equal(collectNativeProcessCheck({ execFile: () => output }).status, 'failed');
  }
});
test('observed processes and unresolved reservations prevent cleanup success', () => {
  const processCheck = collectNativeProcessCheck({ execFile: () => '{"Id":7,"ProcessName":"java"}' });
  assert.equal(buildCleanupAssessment({ processCheck }).lingeringNativeProcessesCount, 1);
  assert.equal(buildCleanupAssessment({ processCheck }).cleanupConfirmed, false);
  for (const status of ['active', 'unknown']) {
    assert.equal(buildCleanupAssessment({ processCheck: checkedEmpty(), cleanupReservations: [{ status }] }).cleanupConfirmed, false);
  }
});

test('actual DSH event shape proves the ordered acquisition/exhaustion/owner cleanup chain', () => {
  const result = evaluateBudgetCleanupControl(fixture());
  assert.equal(result.status, 'passed');
  assert.equal(result.passed, true);
  assert.equal(result.evidence.cleanupCallId, 'call-9');
  assert.equal(result.evidence.reservedCleanupConsumed, true);
  assert.deepEqual(result.missingEvidence, []);
});
test('production coordination schema supports the offline positive chain', () => {
  const tempParent = path.resolve(os.tmpdir());
  const tempRoot = fs.mkdtempSync(path.join(tempParent, 'ig5-m2-reporting-'));
  try {
    const agent = { id: owner, session: { header: { id: owner } } };
    const control = new DelegationControl({ root: tempRoot, getAgent: (id) => id === owner ? agent : null });
    const initial = control.budget(agent, { action: 'start', max_calls: 6 });
    control.charge(agent, 'ig5_dbg', { op: 'start', target });
    control.settleResourceCall(agent, classifyManagedResourceCall('ig5_dbg', { op: 'start', target }), { ok: true, runId });
    for (let i = 0; i < 4; i += 1) control.charge(agent, 'ig5_bytes', { target });
    const exhausted = control.budget(agent, { action: 'status' });
    let rejected;
    try { control.charge(agent, 'ig5_bytes', { target }); } catch (err) { rejected = err; }
    assert.equal(rejected?.code, 'IG5_SHARED_BUDGET_EXHAUSTED');
    control.charge(agent, 'ig5_dbg', { op: 'stop', target });
    control.settleResourceCall(agent, classifyManagedResourceCall('ig5_dbg', { op: 'stop', target }), { ok: true, stateName: 'no-task', runId });
    const f = fixture();
    messageAt(f, 2).content[0].text = JSON.stringify({ collaboration: initial });
    messageAt(f, 6).content[0].text = JSON.stringify({ collaboration: exhausted });
    messageAt(f, 8).content[0].text = `Error: ${rejected.message}`;
    f.sessionControl = Object.values(control.store.readInvestigationRecords()).find((s) => s.rootId === owner);
    assert.equal(evaluateBudgetCleanupControl(f).status, 'passed');
    assert.equal(reservation(f).reservedCalls, 0);
    assert.equal(reservation(f).attemptsUsed, 1);
  } finally {
    assert.equal(path.dirname(path.resolve(tempRoot)), tempParent);
    assert.ok(path.basename(tempRoot).startsWith('ig5-m2-reporting-'));
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
test('budget exhausted before failed start is not exercised despite empty final state', () => {
  const f = fixture();
  f.events = [
    ...toolPair(1, 'ig5_profile', { collaboration: { action: 'start', max_calls: 6 } }, { collaboration: { rootId: owner, limit: 6, used: 0, reserved: 0 } }),
    ...toolPair(3, 'ig5_profile', { collaboration: { action: 'status' } }, { collaboration: { rootId: owner, limit: 6, used: 6, reserved: 0 } }),
    ...toolPair(5, 'ig5_dbg', { op: 'start', target }, 'Error: Shared parent/child IG5 call budget exhausted', { isError: true }),
    ...toolPair(7, 'ig5_dbg', { op: 'stop', target }, 'Error: unreserved historical resource remains unknown', { isError: true }),
    { type: 'goal/change', seq: 9, data: { goal: { phase: 'blocked' } } },
  ];
  f.sessionControl = null;
  const result = evaluateBudgetCleanupControl(f);
  assert.equal(result.status, 'not-exercised');
  assert.equal(result.passed, false);
  assert.equal(result.evidence.cleanupConfirmed, true);
});
test('missing call results or approval alone cannot prove acquisition', () => {
  const f = fixture();
  f.events = f.events.filter((e) => e.seq !== 4);
  f.events.push({ type: 'approval', seq: 11, data: { callId: 'call-3', outcome: 'allowed-once' } });
  assert.equal(evaluateBudgetCleanupControl(f).status, 'not-exercised');
});
test('no positive reserved budget makes the control incomplete', () => {
  const f = fixture();
  changeResult(f, 6, (v) => { v.collaboration.used = 6; v.collaboration.reserved = 0; });
  assert.equal(evaluateBudgetCleanupControl(f).status, 'incomplete');
});
test('stop preceding exhaustion cannot prove cleanup after exhaustion', () => {
  const f = fixture();
  f.events.find((e) => e.seq === 9).seq = 4.5;
  f.events.find((e) => e.seq === 10).seq = 4.6;
  assert.equal(evaluateBudgetCleanupControl(f).status, 'incomplete');
});
test('owner, run and target mismatch cannot borrow unrelated cleanup evidence', () => {
  for (const mutate of [
    (f) => { reservation(f).ownerAgentId = 'other'; },
    (f) => { reservation(f).lastRunId = 'old-run'; },
    (f) => { changeResult(f, 10, (v) => { v.runId = 'old-run'; }); },
    (f) => { f.events.find((e) => e.seq === 9).data.agentId = 'other'; },
    (f) => { f.events.find((e) => e.seq === 9).data.arguments = JSON.stringify({ op: 'stop', target: 'C:\\workspace\\other.exe' }); },
  ]) {
    const f = fixture(); mutate(f);
    assert.equal(evaluateBudgetCleanupControl(f).status, 'incomplete');
  }
});
test('stop error after exhausted reserved budget is a failed control', () => {
  const f = fixture();
  messageAt(f, 10).isError = true;
  messageAt(f, 10).content[0].text = 'Error: cleanup failed';
  assert.equal(evaluateBudgetCleanupControl(f).status, 'failed');
});
test('confirmed final reservation alone cannot prove reserved budget consumption', () => {
  const f = fixture(); f.sessionControl.budget = { limit: 6, used: 5, reserved: 1 };
  const result = evaluateBudgetCleanupControl(f);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.evidence.reservedCleanupConsumed, false);
});
test('other session snapshots or ledger cannot satisfy this session control', () => {
  const f = fixture(); changeResult(f, 6, (v) => { v.collaboration.rootId = 'other-session'; });
  assert.equal(evaluateBudgetCleanupControl(f).status, 'incomplete');
  const g = fixture(); g.sessionControl.rootId = 'other-session';
  assert.equal(evaluateBudgetCleanupControl(g).status, 'incomplete');
});
test('cleanup must confirm the reservation and its stopped runtime state', () => {
  const f = fixture(); reservation(f).status = 'unknown';
  assert.equal(evaluateBudgetCleanupControl(f).status, 'incomplete');
  const g = fixture(); changeResult(g, 10, (v) => { v.state = 'suspended'; });
  assert.equal(evaluateBudgetCleanupControl(g).status, 'incomplete');
});
test('a result before its call cannot prove acquisition', () => {
  const f = fixture(); f.events.find((e) => e.seq === 4).seq = 2.5;
  assert.equal(evaluateBudgetCleanupControl(f).status, 'not-exercised');
});
test('changed budget limit or reset used count fails the control', () => {
  const f = fixture(); f.sessionControl.budget.limit = 7;
  assert.equal(evaluateBudgetCleanupControl(f).status, 'failed');
  const g = fixture();
  g.events.push(...toolPair(11, 'ig5_profile', { collaboration: { action: 'status' } }, { collaboration: { rootId: owner, limit: 6, used: 1, reserved: 0 } }));
  assert.equal(evaluateBudgetCleanupControl(g).status, 'failed');
});
test('incorrectly completed host goal fails even with a valid cleanup chain', () => {
  const f = fixture(); f.events.push({ type: 'goal/change', seq: 11, data: { goal: { phase: 'complete' } } });
  assert.equal(evaluateBudgetCleanupControl(f).status, 'failed');
});
test('successful business after exhaustion fails; absent rejection remains incomplete', () => {
  const f = fixture(); messageAt(f, 8).isError = false;
  assert.equal(evaluateBudgetCleanupControl(f).status, 'failed');
  const g = fixture(); g.events = g.events.filter((e) => ![7, 8].includes(e.seq));
  assert.equal(evaluateBudgetCleanupControl(g).status, 'incomplete');
});
test('failed final process check prevents budget control pass', () => {
  const f = fixture(); f.processCheck = collectNativeProcessCheck({ execFile: () => { throw new Error('denied'); } });
  assert.equal(evaluateBudgetCleanupControl(f).status, 'incomplete');
});
test('terminal control reservation is described inside the existing budget', () => {
  assert.match(buildTaskPrompt('C:\\workspace\\fixture.exe', 'fixture.exe'), /includes 2 calls reserved for terminal goal control \(get_goal and update_goal complete\/blocked\/pause\)/);
  assert.match(buildTaskPrompt('C:\\workspace\\fixture.exe', 'fixture.exe', { terminalControlReserve: 3 }), /includes 3 calls reserved/);
  assert.match(buildTaskPrompt('C:\\workspace\\fixture.exe', 'fixture.exe'), /get_goal may be used at most once and cannot consume the last slot/);
  assert.match(buildTaskPrompt('C:\\workspace\\fixture.exe', 'fixture.exe'), /trigger_spec\.json/);
});

test('restricted tool-surface isolation status stays distinct from OS-sandbox physical isolation', () => {
  const verified = buildIsolationAudit({
    policyVersion: M2_GUARD_POLICY_VERSION,
    guardMountedVerified: true,
    sentinelNegativeVerified: true,
    oracleDecoupledDuringRun: true,
    unallowlistedToolExecutedCount: 0,
    blockedOutsideWorkspaceCalls: 3,
    blockedUnallowlistedToolCalls: 2,
  });
  assert.equal(verified.status, 'restricted-tool-surface-verified');
  assert.equal(verified.toolSurfaceAllowlistVerified, true);
  assert.equal(verified.oracleDecoupledDuringRun, true);
  assert.equal(verified.osSandboxActive, false);
  assert.equal(verified.executedOutsideAllowedRoots, null);
  assert.equal(verified.strictBlindEligible, false);
  assert.deepEqual(verified.debuggerProcessCapabilitiesUnconfined, ['ig5_dbg:start', 'ig5_dbg:writemem', 'ig5_dbg:setreg']);

  const missingMount = buildIsolationAudit({
    policyVersion: M2_GUARD_POLICY_VERSION,
    guardMountedVerified: false,
    sentinelNegativeVerified: true,
    unallowlistedToolExecutedCount: 0,
  });
  assert.equal(missingMount.status, 'unverified');
  assert.equal(missingMount.toolSurfaceAllowlistVerified, false);

  const missingSentinel = buildIsolationAudit({
    policyVersion: M2_GUARD_POLICY_VERSION,
    guardMountedVerified: true,
    sentinelNegativeVerified: false,
    unallowlistedToolExecutedCount: 0,
  });
  assert.equal(missingSentinel.status, 'unverified');
  assert.equal(missingSentinel.toolSurfaceAllowlistVerified, false);
});

test('auditSessionGuardLogs and validateSentinelProof reject unmounted logs, double-only proofs, and stale digests', () => {
  const emptyAudit = auditSessionGuardLogs({ guardLogs: [], events: [] });
  assert.equal(emptyAudit.guardMountedVerified, false);
  assert.equal(emptyAudit.unallowlistedToolExecutedCount, null, 'Unmounted guard log must never claim 0 unallowlisted executions');

  const mountedAudit = auditSessionGuardLogs({
    guardLogs: [{ event: 'guard-mounted', policyVersion: M2_GUARD_POLICY_VERSION }],
    events: [...toolPair(1, 'read', { file_path: 'C:\\workspace\\a.txt' }, { content: 'ok' })],
  });
  assert.equal(mountedAudit.guardMountedVerified, true);
  assert.equal(mountedAudit.unallowlistedToolExecutedCount, 0);

  const validProof = {
    schema: 'ig5-m2-isolation-sentinel-proof-v2',
    passed: true,
    realHostToolsMounted: true,
    verificationTier: 'real-installed-dsh-host-tools',
    policyVersion: M2_GUARD_POLICY_VERSION,
    sourceTreeDigest: 'abc123',
    hostIdentity: { desktopVersion: '0.2.2-rc.1' },
    guardLogVerification: { guardMountedVerified: true, allNegativeChecksVerifiedByExplicitLayer: true },
    hostRuntimeChecks: { negativeChecksCount: 21, sentinelBodyTouches: 0, sentinelLeakedBytes: 0 },
  };
  assert.equal(validateSentinelProof(validProof, { expectedSourceTreeDigest: 'abc123', expectedHostDesktopVersion: '0.2.2-rc.1' }).valid, true);
  assert.equal(validateSentinelProof({ ...validProof, realHostToolsMounted: false, verificationTier: 'component-dispatcher-with-host-tool-doubles' }).valid, false);
  assert.equal(validateSentinelProof(validProof, { expectedSourceTreeDigest: 'drifted999' }).valid, false);
});

test('transform score tracks per-vector session overlap and requires passed trigger completeness for deliverableCorrect', () => {
  const scored = buildTransformScore({
    ...transformArgs,
    oracleVectors: ['01020304', 'ff0055aa', '9e3779b9'],
    observedSessionInputHexes: ['FF0055AA'],
    triggerCompletenessStatus: 'failed',
  });
  assert.equal(scored.transformFiniteVectorCorrect, true);
  assert.equal(scored.deliverableCorrect, false, 'deliverableCorrect must be false when trigger completeness failed');
  assert.equal(scored.seenInSessionCount, 1);
  assert.equal(scored.unseenBySessionCount, 2);
  assert.equal(scored.allVectorsUnseenBySession, false);
  assert.equal(scored.vectors.find((v) => v.inputHex === 'ff0055aa').observedInSession, true);

  const fullPass = buildTransformScore({
    ...transformArgs,
    oracleVectors: ['01020304', '9e3779b9'],
    observedSessionInputHexes: ['41424344'],
    triggerCompletenessStatus: 'passed',
  });
  assert.equal(fullPass.deliverableCorrect, true);
  assert.equal(fullPass.allVectorsUnseenBySession, true);
});

test('independent positive and negative trigger scoring catches missing flags, superfluous flags, and CWD over/under-specification', () => {
  // Mock target requiring cwd suffix "\\stage_run", args ["--gate=7", "K=<4B>"], 4-byte payload
  const mockTarget = ({ args, cwd }) => {
    const cwdOk = String(cwd).toLowerCase().endsWith('\\stage_run');
    const ok = cwdOk && args.length === 2 && args[0] === '--gate=7' && args[1].startsWith('K=') && args[1].length >= 6;
    return { exitCode: ok ? 0 : 2, timedOut: false, error: null };
  };
  const gt = { channel: 'cli-arg', requiredCwdSuffix: '\\stage_run' };

  const valid = evaluateTriggerCompleteness({
    triggerSpec: {
      schema: 'ig5-m2-trigger-spec-v1',
      channel: 'cli-arg',
      requiredCwdSuffix: '\\stage_run',
      argsTemplate: ['--gate=7', 'K=<INPUT_4B>'],
      inputEncoding: 'ascii',
    },
    binaryPath: 'mock.exe',
    groundTruthTrigger: gt,
    runProbe: mockTarget,
  });
  assert.equal(valid.status, 'passed');
  assert.equal(valid.passed, true);
  assert.ok(valid.positiveProbes.length >= 2 && valid.positiveProbes.every((p) => p.passed));
  assert.ok(valid.negativeProbes.length >= 5 && valid.negativeProbes.every((n) => n.passed));

  // Missing required CWD suffix fails positive probe & ground-truth check
  const missingCwd = evaluateTriggerCompleteness({
    triggerSpec: {
      schema: 'ig5-m2-trigger-spec-v1',
      channel: 'cli-arg',
      requiredCwdSuffix: null,
      argsTemplate: ['--gate=7', 'K=<INPUT_4B>'],
      inputEncoding: 'ascii',
    },
    binaryPath: 'mock.exe',
    groundTruthTrigger: gt,
    runProbe: mockTarget,
  });
  assert.equal(missingCwd.passed, false);
  assert.ok(missingCwd.failures.some((f) => f.includes('positive-probe-failed') || f.includes('cwd-suffix-mismatch')));

  // False / hallucinated CWD suffix on an unconstrained target fails wrong-CWD necessity probe
  const unconstrainedTarget = ({ args }) => ({
    exitCode: args.length === 2 && args[0] === 'mode=run' && args[1].startsWith('X=') && args[1].length >= 6 ? 0 : 1,
    timedOut: false,
    error: null,
  });
  const falseCwd = evaluateTriggerCompleteness({
    triggerSpec: {
      schema: 'ig5-m2-trigger-spec-v1',
      channel: 'cli-arg',
      requiredCwdSuffix: '\\fake_dir',
      argsTemplate: ['mode=run', 'X=<INPUT_4B>'],
      inputEncoding: 'ascii',
    },
    binaryPath: 'mock2.exe',
    runProbe: unconstrainedTarget,
  });
  assert.equal(falseCwd.passed, false);
  assert.ok(falseCwd.failures.includes('false-cwd-constraint:triggered-in-wrong-cwd'));

  // Superfluous ignored flag fails drop-arg necessity probe
  const ignoresExtraFlag = ({ args }) => ({
    exitCode: args.some((a) => a.startsWith('X=') && a.length >= 6) ? 0 : 1,
    timedOut: false,
    error: null,
  });
  const superfluous = evaluateTriggerCompleteness({
    triggerSpec: {
      schema: 'ig5-m2-trigger-spec-v1',
      channel: 'cli-arg',
      requiredCwdSuffix: null,
      argsTemplate: ['--bogus-ignored', 'X=<INPUT_4B>'],
      inputEncoding: 'ascii',
    },
    binaryPath: 'mock3.exe',
    runProbe: ignoresExtraFlag,
  });
  assert.equal(superfluous.passed, false);
  assert.ok(superfluous.failures.includes('superfluous-cli-arg:0'));

  // File channel positive + negative probes
  const fileTarget = ({ args }) => {
    if (args.length !== 1 || !args[0].startsWith('--in=')) return { exitCode: 1, timedOut: false, error: null };
    const fp = args[0].slice(5);
    if (!fs.existsSync(fp)) return { exitCode: 3, timedOut: false, error: null };
    const sz = fs.statSync(fp).size;
    return { exitCode: sz >= 4 ? 0 : 4, timedOut: false, error: null };
  };
  const filePass = evaluateTriggerCompleteness({
    triggerSpec: {
      schema: 'ig5-m2-trigger-spec-v1',
      channel: 'file',
      requiredCwdSuffix: null,
      argsTemplate: ['--in=<INPUT_FILE>'],
      inputEncoding: 'raw-bytes',
    },
    binaryPath: 'mock-file.exe',
    groundTruthTrigger: { channel: 'file', requiredCwdSuffix: null },
    runProbe: fileTarget,
  });
  assert.equal(filePass.status, 'passed');
  assert.equal(filePass.passed, true);
  assert.equal(filePass.scope, 'finite-positive-and-ablation-probes-not-exhaustive-condition-proof');

  // Path-traversal / drive / UNC requiredCwdSuffix rejected before probing
  for (const badSuffix of ['..\\escape', 'stage\\..\\..', 'C:\\Windows', '\\\\server\\share', '   ']) {
    const escaped = evaluateTriggerCompleteness({
      triggerSpec: {
        schema: 'ig5-m2-trigger-spec-v1',
        channel: 'cli-arg',
        requiredCwdSuffix: badSuffix,
        argsTemplate: ['X=<INPUT_4B>'],
        inputEncoding: 'ascii',
      },
      binaryPath: 'mock.exe',
      runProbe: () => ({ exitCode: 0, timedOut: false, spawnError: false, error: null }),
    });
    assert.equal(escaped.passed, false, `Expected bad suffix ${badSuffix} to be rejected`);
    assert.equal(escaped.positiveProbes.length, 0, 'Must fail schema/boundary validation before executing target');
  }

  // Negative probe crash (NTSTATUS >= 64), timeout, or spawnError must FAIL trigger completeness rather than counting as valid rejection
  for (const faultProbe of [
    { exitCode: 0xc0000005, timedOut: false, spawnError: false, error: null },
    { exitCode: -1, timedOut: true, spawnError: false, error: 'ETIMEDOUT' },
    { exitCode: -1, timedOut: false, spawnError: true, error: 'ENOENT' },
  ]) {
    const faulted = evaluateTriggerCompleteness({
      triggerSpec: {
        schema: 'ig5-m2-trigger-spec-v1',
        channel: 'cli-arg',
        requiredCwdSuffix: null,
        argsTemplate: ['--gate=7', 'K=<INPUT_4B>'],
        inputEncoding: 'ascii',
      },
      binaryPath: 'fault.exe',
      runProbe: ({ kind }) => (kind === 'positive'
        ? { exitCode: 0, timedOut: false, spawnError: false, error: null }
        : faultProbe),
    });
    assert.equal(faulted.passed, false, 'Faulting negative probe must never pass trigger completeness');
    assert.ok(faulted.failures.some((f) => f.startsWith('negative-probe-fault:')));
  }

  assert.equal(evaluateTriggerCompleteness({ triggerSpec: null }).status, 'missing-spec');
});

test('scoreColumns separates deliverable, finite vectors, native observation, assessment, host goal, cleanup, trigger, and isolation', () => {
  const cols = buildScoreColumns({
    oracleEvaluation: { transformFiniteVectorCorrect: true },
    triggerEvaluation: { status: 'passed', passed: true, positiveProbes: [{ passed: true }], negativeProbes: [{ passed: true }] },
    primaryTask: { receipts: [{ tool: 'ig5_decompile' }, { tool: 'ig5_dbg' }] },
    persistedAssessment: { assessment: 'satisfied', canCompleteHostGoal: true, cleanup: 'confirmed' },
    hostGoalCompleted: true,
    finalGoalPhase: 'complete',
    cleanupAssessment: { cleanupConfirmed: true, modelStoppedAllBeforeCompletion: true, allStartedDebuggersStoppedByModel: true, processCheckStatus: 'checked', lingeringNativeProcessesCount: 0 },
    isolationAudit: { status: 'restricted-tool-surface-verified', policyVersion: M2_GUARD_POLICY_VERSION, toolSurfaceAllowlistVerified: true, oracleDecoupledDuringRun: true, osSandboxActive: false, strictBlindEligible: false },
  });
  assert.equal(cols.deliverableCorrect, true);
  assert.equal(cols.transformFiniteVectorCorrect, true);
  assert.equal(cols.nativeObservation.status, 'verified');
  assert.equal(cols.investigationAssessment.status, 'satisfied');
  assert.equal(cols.hostGoal.completed, true);
  assert.equal(cols.cleanup.modelStoppedAllBeforeCompletion, true);
  assert.equal(cols.triggerCompleteness.status, 'passed');
  assert.equal(cols.isolationEligibility.status, 'restricted-tool-surface-verified');
  assert.equal(cols.isolationEligibility.strictBlindEligible, false);
});

console.log(`M2 eval reporting: ${count} offline checks passed; no model or native target launched.`);
