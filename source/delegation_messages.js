// Structured multi-agent research delegation envelopes (`M4-D`) bound to rootId, componentId,
// scenarioId, targetSha256, and verified receipt references.
// Enforces parent-only host goal completion, shared DelegationControl root budget, single-owner
// debugger/resource locks, and rejection of cross-root, wrong-SHA-256, or stale-revision child reports.

import { createHash, randomUUID } from 'node:crypto';

const SHA256_RE = /^[a-f0-9]{64}$/i;

function fail(code, message, extra = {}) {
  throw Object.assign(new Error(message), { code, retryable: false, ...extra });
}

function sha256Json(v) {
  return createHash('sha256').update(JSON.stringify(v)).digest('hex');
}

export function createChildResearchBrief({
  rootTask,
  parentAgentId,
  childRole, // 'component-analyst' | 'runtime-verifier' | 'static-auditor'
  componentId,
  scenarioId = null,
  objective,
}) {
  if (!rootTask || rootTask.kind !== 'root-investigation') {
    fail('INVALID_ROOT_TASK', 'Valid root investigation required to issue a child delegation brief');
  }
  if (!['component-analyst', 'runtime-verifier', 'static-auditor'].includes(childRole)) {
    fail('INVALID_CHILD_ROLE', `Unsupported childRole "${childRole}"`);
  }
  const comp = rootTask.components.find((c) => c.componentId === componentId);
  if (!comp) {
    fail('COMPONENT_NOT_FOUND', `Component "${componentId}" is not registered in root investigation "${rootTask.rootId}"`);
  }
  let scenario = null;
  if (scenarioId) {
    scenario = rootTask.scenarios.find((s) => s.scenarioId === scenarioId);
    if (!scenario || scenario.componentId !== componentId) {
      fail('SCENARIO_COMPONENT_MISMATCH', `Scenario "${scenarioId}" does not belong to component "${componentId}"`);
    }
  }
  const brief = {
    schema: 'ig5-delegation-brief-v1',
    briefId: `brief-${randomUUID()}`,
    issuedAt: new Date().toISOString(),
    rootId: rootTask.rootId,
    rootSessionId: rootTask.rootSessionId,
    parentAgentId: String(parentAgentId),
    planRevisionAtIssue: rootTask.planRevision,
    contractRevisionAtIssue: rootTask.contractRevision || 1,
    childRole,
    componentId: comp.componentId,
    targetPath: comp.path,
    targetSha256: comp.sha256,
    scenarioId: scenario?.scenarioId || null,
    scenarioDigest: scenario?.scenarioDigest || null,
    objective: String(objective || '').trim(),
    authorityLimits: {
      canCompleteHostGoal: false,
      canResetOrEnlargeBudget: false,
      mustCiteSystemReceipts: true,
    },
  };
  brief.briefDigest = sha256Json(brief);
  return brief;
}

/**
 * Validate and ingest a child subagent's structured finding report into the parent root investigation,
 * verifying exact rootId, componentId, targetSha256, contractRevision, and system receipt provenance!
 */
export function verifyAndAcceptChildFinding({
  rootTask,
  brief,
  childReport,
  artifacts,
}) {
  if (!brief || brief.schema !== 'ig5-delegation-brief-v1') {
    fail('INVALID_BRIEF', 'Valid ig5-delegation-brief-v1 required');
  }
  if (!childReport || childReport.schema !== 'ig5-delegation-finding-v1') {
    fail('INVALID_CHILD_REPORT_SCHEMA', 'Child report must have schema="ig5-delegation-finding-v1"');
  }
  if (childReport.rootId !== rootTask.rootId || brief.rootId !== rootTask.rootId) {
    fail('CROSS_ROOT_REPORT_REJECTED', `Child report rootId "${childReport.rootId}" does not match active root "${rootTask.rootId}"`);
  }
  if (childReport.briefId !== brief.briefId) {
    fail('BRIEF_ID_MISMATCH', `Child report briefId "${childReport.briefId}" does not match issued brief "${brief.briefId}"`);
  }
  if ((rootTask.contractRevision || 1) !== brief.contractRevisionAtIssue) {
    fail('STALE_CONTRACT_REVISION_REJECTED', `Child brief was issued at contractRevision ${brief.contractRevisionAtIssue}, current is ${rootTask.contractRevision}`);
  }
  const comp = rootTask.components.find((c) => c.componentId === childReport.componentId);
  if (!comp || childReport.componentId !== brief.componentId) {
    fail('CHILD_COMPONENT_MISMATCH', `Child report componentId "${childReport.componentId}" does not match brief component "${brief.componentId}"`);
  }
  if (!childReport.targetSha256 || !SHA256_RE.test(childReport.targetSha256) || childReport.targetSha256.toLowerCase() !== comp.sha256.toLowerCase()) {
    fail('CHILD_TARGET_SHA256_MISMATCH', `Child report targetSha256 "${childReport.targetSha256}" does not match registered component SHA-256 "${comp.sha256}"`);
  }
  if (brief.scenarioId && childReport.scenarioId && childReport.scenarioId !== brief.scenarioId) {
    fail('CHILD_SCENARIO_MISMATCH', `Child report scenarioId "${childReport.scenarioId}" does not match brief scenario "${brief.scenarioId}"`);
  }

  const receiptRefs = Array.isArray(childReport.receiptRefs) ? childReport.receiptRefs : [];
  if (receiptRefs.length === 0) {
    fail('UNBACKED_CHILD_FINDING_REJECTED', 'Child report must cite at least one verified system receiptRef');
  }

  const verifiedReceiptIds = [];
  for (const rId of receiptRefs) {
    const inRoot = rootTask.receipts.find((r) => r.reportId === rId && r.outcome === 'success');
    if (!inRoot) {
      fail('UNVERIFIED_CHILD_RECEIPT', `Child cited receipt "${rId}" is not a successful receipt in root "${rootTask.rootId}"`);
    }
    if (artifacts?.get) {
      const rec = artifacts.get(rId);
      const evSha = rec?.result?.runtimeIdentity?.evidence?.sha256
        || rec?.result?.replayOutput?.targetSha256
        || rec?.result?.replayOutput?._ig5?.sha256
        || null;
      if (evSha && evSha.toLowerCase() !== comp.sha256.toLowerCase()) {
        fail('CHILD_RECEIPT_HASH_CONFLICT', `Receipt "${rId}" SHA-256 "${evSha}" conflicts with component "${comp.sha256}"`);
      }
    }
    verifiedReceiptIds.push(rId);
  }

  return {
    accepted: true,
    findingId: `finding-${randomUUID()}`,
    acceptedAt: new Date().toISOString(),
    briefId: brief.briefId,
    childAgentId: String(childReport.childAgentId || 'unknown-child'),
    childRole: brief.childRole,
    componentId: comp.componentId,
    targetSha256: comp.sha256,
    scenarioId: childReport.scenarioId || brief.scenarioId || null,
    verifiedReceiptIds,
    summary: String(childReport.summary || '').slice(0, 1024),
    structuredClaims: childReport.structuredClaims || {},
  };
}
