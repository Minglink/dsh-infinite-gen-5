import assert from 'node:assert/strict';
import {
  classifyPromptGuidance,
  analyzeTokenUsage,
  analyzeCallAndErrorPartitions,
  buildTransparentCleanupReport,
  auditRootContractAgainstSpec,
  buildMultiDimensionalOutcome,
} from './evals/eval_metrics_and_contracts.mjs';

// 1. Token accounting: cacheReadTokens & unknown fields & dedup by message id
{
  const dshSessionObjects = [
    {
      id: 'row-1',
      message: {
        id: 'msg-1',
        usage: {
          inputTokens: 1200,
          outputTokens: 300,
          cacheReadTokens: 45000,
          cacheWriteTokens: 500,
          totalTokens: 47000,
          experimentalFutureField: 42,
        },
      },
    },
    // Duplicate replay of msg-1 must be ignored
    {
      id: 'row-2',
      message: {
        id: 'msg-1',
        usage: {
          inputTokens: 1200,
          outputTokens: 300,
          cacheReadTokens: 45000,
          cacheWriteTokens: 500,
          totalTokens: 47000,
        },
      },
    },
  ];
  const tok = analyzeTokenUsage({ dshSessionObjects });
  assert.equal(tok.usageRecordsCount, 1);
  assert.equal(tok.uncachedInputTokens, 1200);
  assert.equal(tok.cacheReadTokens, 45000);
  assert.equal(tok.cacheWriteTokens, 500);
  assert.equal(tok.outputTokens, 300);
  assert.equal(tok.reportedTotalTokens, 47000);
  assert.equal(tok.sumMatchesReportedTotal, true);
  assert.deepEqual(tok.unknownUsageFields, ['experimentalFutureField']);
}

// 2. Call & error partitions: e.data.message.isError, guard denied vs host round threshold vs tool error, dedup
{
  const sessionEvents = [
    { type: 'tool/call', data: { callId: 'c1', turn: 1, step: 1, name: 'ig5_workspace', arguments: '{"workspace":{"action":"root-get"}}' } },
    { type: 'tool/result', data: { message: { toolCallId: 'c1', isError: true, content: [{ type: 'text', text: 'Error: missing id' }] } } },
    // Duplicate tool/result event for c1 must not double-count
    { type: 'tool/result', data: { message: { toolCallId: 'c1', isError: true, content: [{ type: 'text', text: 'Error: missing id' }] } } },

    { type: 'tool/call', data: { callId: 'c2', turn: 1, step: 2, name: 'ig5_close', arguments: '{"target":"a.exe"}' } },
    { type: 'tool/result', data: { message: { toolCallId: 'c2', isError: false, content: [{ type: 'text', text: '{"ok":true}' }] } } },

    { type: 'tool/call', data: { callId: 'c3', turn: 1, step: 3, name: 'update_goal', arguments: '{"action":"blocked","goal_id":"g1","revision":1}' } },
    { type: 'tool/result', data: { message: { toolCallId: 'c3', isError: true, content: [{ type: 'text', text: 'Error: blocked requires at least 3 consecutive goal rounds; current round is 1' }] } } },

    { type: 'tool/call', data: { callId: 'c4', turn: 2, step: 1, name: 'update_goal', arguments: '{"action":"blocked","goal_id":"g1","revision":1}' } },
    { type: 'tool/result', data: { message: { toolCallId: 'c4', isError: true, content: [{ type: 'text', text: 'Error: Evaluation ordinary tool-call budget exhausted' }] } } },
  ];
  const guardEntries = [
    { event: 'allowed', toolName: 'ig5_workspace' },
    { event: 'allowed', toolName: 'ig5_close' },
    { event: 'allowed', toolName: 'update_goal' },
    { event: 'denied-budget', toolName: 'update_goal' },
  ];

  const part = analyzeCallAndErrorPartitions({ sessionEvents, guardEntries, ordinaryCallLimit: 70 });
  assert.equal(part.attemptedCalls, 4);
  assert.equal(part.guardAllowedCalls, 3);
  assert.equal(part.guardDeniedCalls, 1);
  assert.equal(part.guardAllowedByRole.allowedOrdinaryCalls, 1);
  assert.equal(part.guardAllowedByRole.allowedCleanupCalls, 1);
  assert.equal(part.guardAllowedByRole.allowedTerminalCalls, 1);
  assert.equal(part.executionAndErrors.actuallyDispatchedCalls, 2); // c1 + c2 (c3 was host goal threshold error, c4 guard denied)
  assert.equal(part.executionAndErrors.totalErrorResults, 3);
  assert.equal(part.executionAndErrors.toolExecutionErrors, 1);
  assert.equal(part.executionAndErrors.hostGoalGateOrThresholdErrors, 1);
  assert.equal(part.executionAndErrors.guardDeniedErrorResults, 1);
  assert.equal(part.budgetCompliant, false); // deniedBudget === 1
}

// 3. Contract downgrade detection: omitting nonCooperativeRequired AND non-cooperative-ui-trigger MUST fail contractFullyEnforced
{
  const downgradedRoot = {
    deliverables: [{
      id: 'deliv-1',
      kind: 'structured-frame-transform',
      nonCooperativeRequired: false,
      holdoutRequired: true,
      requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'multi-process-lineage'],
    }],
    components: [{ role: 'main-pe' }, { role: 'broker-pe' }, { role: 'worker-pe' }],
  };
  const audit = auditRootContractAgainstSpec(downgradedRoot, {
    allowedDeliverableKinds: ['structured-frame-transform', 'process-chain-transform'],
    requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'multi-process-lineage'],
    holdoutRequired: true,
    mustRejectFixtureOnlyProtocol: true,
    requiredComponentRoles: [{ role: 'main-pe', minCount: 1 }, { role: 'worker-pe', minCount: 1 }],
  });
  assert.equal(audit.effectiveNonCooperativeGateActive, false);
  assert.equal(audit.contractFullyEnforced, false);
  assert(audit.issues.some((i) => i.includes('non-cooperative-fixture-rejection-not-enforced')));

  // Electron case where nonCooperativeRequired=false BUT non-cooperative-ui-trigger IS present
  const electronRoot = {
    deliverables: [{
      id: 'deliv-1',
      kind: 'structured-frame-transform',
      nonCooperativeRequired: false,
      holdoutRequired: true,
      requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'parent-to-helper-handoff', 'non-cooperative-ui-trigger'],
    }],
    components: [{ role: 'electron-app' }, { role: 'helper-pe' }],
  };
  const elAudit = auditRootContractAgainstSpec(electronRoot, {
    allowedDeliverableKinds: ['structured-frame-transform', 'electron-native-chain'],
    requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'parent-to-helper-handoff', 'non-cooperative-ui-trigger'],
    holdoutRequired: true,
    mustRejectFixtureOnlyProtocol: true,
  });
  assert.equal(elAudit.effectiveNonCooperativeGateActive, true);
  assert.equal(elAudit.contractFullyEnforced, true);
}

// 4. Negative-case multi-dimensional outcome: timeout or runnerTerminated NEVER collapses into autonomous closure!
{
  const cleanup = buildTransparentCleanupReport({
    processCheck: { status: 'checked', processes: [] },
    ephemeralJobContainersAutoReclaimedCount: 8,
    explicitCleanupCallsCount: 0,
    runnerFallbackKillUsed: true,
  });
  assert.equal(cleanup.cleanupConfirmed, true);
  assert.equal(cleanup.primaryCleanupSource, 'runner-fallback-kill');

  const negTimedOut = buildMultiDimensionalOutcome({
    isNegativeControl: true,
    finalGoalPhase: 'active',
    postRunAssess: { canCompleteHostGoal: false },
    contractAudit: { contractFullyEnforced: true },
    callPartitions: { budgetCompliant: false },
    cleanupReport: cleanup,
    timedOut: true,
    runnerTerminated: false,
  });
  assert.equal(negTimedOut.truthfulRejection, true);
  assert.equal(negTimedOut.falseCompletion, false);
  assert.equal(negTimedOut.hostStoppedLegally, false);
  assert.equal(negTimedOut.timeout, true);
  assert.equal(negTimedOut.strictEndToEndAutonomousClosure, false);

  const negRunnerStopped = buildMultiDimensionalOutcome({
    isNegativeControl: true,
    finalGoalPhase: 'blocked',
    postRunAssess: { canCompleteHostGoal: false },
    contractAudit: { contractFullyEnforced: true },
    callPartitions: { budgetCompliant: true },
    cleanupReport: cleanup,
    timedOut: false,
    runnerTerminated: true,
  });
  assert.equal(negRunnerStopped.hostStoppedLegally, false);
  assert.equal(negRunnerStopped.runnerTerminated, true);
  assert.equal(negRunnerStopped.strictEndToEndAutonomousClosure, false);
}

// 5. Prompt guidance classification
{
  const purePrompt = 'Target directory: C:\\ws\\app1\nBusiness goal: Recover the binary packet framing transformation from user input to output.';
  const hintedPrompt = 'Target directory: C:\\ws\\app1\nVerify via IG5 with nonCooperativeRequired=true.';
  const namedContractPrompt = 'Audit ingest_runner.exe across stage_alpha.exe and stage_beta.exe with deliverable kind="process-chain-transform" and worker-pe.';
  assert.equal(classifyPromptGuidance(purePrompt).guidanceLevel, 'pure-business-only');
  assert.equal(classifyPromptGuidance(hintedPrompt).guidanceLevel, 'contract-hinted');
  assert.equal(classifyPromptGuidance(namedContractPrompt).guidanceLevel, 'named-components-and-contract');
}

console.log('test_eval_metrics_and_contracts.mjs: ALL 5 OFFLINE SUITES PASSED');
