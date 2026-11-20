import { RootInvestigationStore, renderDeterministicRootBrief } from './investigation_root.js';
import { assessRootInvestigation } from './investigation_assessment.js';

const HOST_NOTICE_SOURCES = new Set([
  'runtime-context',
  'time-context',
  'repeat-tool-reminder',
  'model-selection',
  'tool-goal',
  'agent-message',
  'subagent-settled',
]);

function isRootAgent(ctx, agent) {
  if (!agent) return false;
  try {
    const roots = ctx.get?.('agents')?.roots?.();
    if (Array.isArray(roots)) return roots.includes(agent);
  } catch { /* fallback to durable header */ }
  return !agent.session?.header?.parentSession && agent.owner === undefined;
}

export function classifyUserMessageEvent(ctx, agent, event) {
  if (!event || event.type !== 'user/message') return null;
  const source = event.data?.source;
  const kind = source?.kind || 'unknown';
  const root = isRootAgent(ctx, agent);
  if (kind === 'user' && root) {
    return { category: 'direct-human', sourceKind: 'user', root: true };
  }
  if (kind === 'goal') {
    return {
      category: 'goal-continuation',
      sourceKind: 'goal',
      root,
      goalId: source.goalId || null,
      revision: source.revision ?? null,
      round: source.round ?? null,
    };
  }
  if (HOST_NOTICE_SOURCES.has(kind)) {
    return { category: 'host-notice', sourceKind: kind, root };
  }
  return { category: root ? 'non-human-input' : 'delegated-input', sourceKind: kind, root };
}

export function readLiveHostGoal(ctx, agent) {
  if (!agent?.ctx && !ctx) return null;
  try {
    const goals = agent?.ctx?.get?.('goals') ?? ctx?.get?.('goals');
    if (typeof goals?.get !== 'function') return null;
    const g = goals.get(agent);
    if (!g) return null;
    return {
      goalId: g.id,
      revision: g.revision,
      goal: g.objective,
      status: g.phase,
      phase: g.phase,
      activation: g.activation,
      roundsStarted: g.roundsStarted,
      maxGoalRounds: g.maxGoalRounds,
      blockedReason: g.blockedReason || null,
    };
  } catch {
    return null;
  }
}

export function installAutonomyHost(ctx, { cfg, getManager }) {
  const agentsBySession = new Map();
  const lastMessageBySession = new Map();
  const openHumanTurnBySession = new Map();
  const registeredBriefDisposers = new Map();
  const hostGoalDivergenceBySession = new Map();

  const resolveAgentBySession = session => {
    if (!session?.id) return undefined;
    try {
      const live = ctx.get?.('agents')?.get?.(session.id);
      if (live) return live;
    } catch { /* fallback */ }
    return agentsBySession.get(session.id);
  };

  const resolveRootStore = mgr => {
    if (!mgr) return new RootInvestigationStore({ projectRoot: cfg.projectRoot });
    return (mgr.rootInvestigations ||= new RootInvestigationStore({ projectRoot: cfg.projectRoot }));
  };

  const checkGoalCompletionGate = exec => {
    const goalAction = exec?.name === 'update_goal' ? exec?.arguments?.action : null;
    if (goalAction !== 'complete' && goalAction !== 'blocked') return undefined;
    const mgr = getManager();
    const agent = exec?.agent;
    if (!mgr || !agent) return undefined;
    if (!isRootAgent(ctx, agent)) {
      return {
        kind: 'deny',
        reason: `Subagents cannot ${goalAction === 'complete' ? 'complete' : 'block'} the root host goal; return structured findings and receipt refs to the parent session.`,
      };
    }

    let rootSessionId = agent.id;
    try {
      if (mgr.coordination) {
        rootSessionId = mgr.coordination.resolveRootSubject(agent, {
          allowLocalFallback: agent.session === undefined,
        }).rootId;
      }
    } catch { /* keep agent.id */ }

    const rStore = resolveRootStore(mgr);
    const hostGoal = readLiveHostGoal(ctx, agent);
    const targetGoalId = exec?.arguments?.goal_id || hostGoal?.goalId || null;
    const effectiveHostGoal = hostGoal || (targetGoalId ? {
      goalId: targetGoalId,
      revision: Number.isSafeInteger(exec?.arguments?.revision) ? exec.arguments.revision : null,
      goal: null,
      status: 'active',
      phase: 'active',
    } : null);

    let rootTask = null;
    if (targetGoalId) {
      const lookup = rStore.findForHostGoal(rootSessionId, targetGoalId);
      if (lookup.ambiguousIds.length > 1 && goalAction === 'complete') {
        return {
          kind: 'deny',
          reason: `Multiple active IG5 root investigations (${lookup.ambiguousIds.join(', ')}) claim host goal "${targetGoalId}"; supersede or specify a single investigation before completing.`,
        };
      }
      rootTask = lookup.task;
    } else {
      rootTask = rStore.latestForSession(rootSessionId);
    }

    if (goalAction === 'blocked') {
      if (rootTask) {
        const assessment = assessRootInvestigation({
          rootTask,
          mgr,
          execution: { agent },
          hostGoal: effectiveHostGoal,
        });
        if (assessment.cleanup === 'pending' || assessment.cleanup === 'unknown') {
          return {
            kind: 'deny',
            reason: `IG5 resource cleanup is still ${assessment.cleanup} (${assessment.pendingCleanup.map(r => r.resourceKey).join(', ')}); stop owned resources before calling update_goal(action="blocked").`,
          };
        }
        const blockedReasonText = String(exec?.arguments?.blocked_reason || '');
        const claimsNegativeFalsification = rootTask.terminalFinding?.classification === 'contract-obligation-falsified'
          || /\b(forged|fabricat|falsif|fake|decoy|did not spawn|never spawned)\b|伪造|虚假|未派生|未执行子进程/i.test(blockedReasonText);
        if (claimsNegativeFalsification) {
          const dynamicToolNames = new Set(['ig5_dbg', 'ig5_emulate', 'ig5_capture', 'ig5_api_trace', 'ig5_app_observe']);
          const artifactStore = mgr.analysis?.artifacts || mgr.artifacts || null;
          const hasStaticReceipt = rootTask.receipts.some(r => !r.isCleanup && r.outcome === 'success' && !dynamicToolNames.has(r.tool));
          const hasHealthyDynamicReceipt = rootTask.receipts.some(r => {
            if (r.isCleanup || r.outcome !== 'success' || !dynamicToolNames.has(r.tool)) return false;
            let fullRec = null;
            try { fullRec = artifactStore?.get?.(r.reportId); } catch { fullRec = null; }
            let out = fullRec?.result?.replayOutput ?? fullRec?.data?.output;
            if (out === undefined && fullRec?.result?.replayBlobRef && artifactStore?.read) {
              try { out = JSON.parse(artifactStore.read(fullRec.result.replayBlobRef).data.toString('utf8')); } catch { out = null; }
            }
            out = out || {};
            if (['missing', 'truncated', 'corrupt'].includes(out.observerLogIntegrity)) return false;
            if (out.cleanup?.enumerationStatus === 'enumeration-failed'
              || out.cleanup?.cleanupEnumerationStatus === 'enumeration-failed'
              || out.cleanupEnumerationStatus === 'enumeration-failed') return false;
            return true;
          });
          if (!hasStaticReceipt || !hasHealthyDynamicReceipt) {
            return {
              kind: 'deny',
              reason: 'OBSERVER_FAILED_CANNOT_CLAIM_NEGATIVE: Claiming negative contract falsification requires at least 1 static receipt and 1 healthy dynamic observation receipt (broken observer logs or failed process enumeration only prove observer failure, not target falsification).',
            };
          }
        }
      } else {
        const control = mgr.coordination?.controlStatus?.(agent, { allowLocalFallback: agent.session === undefined });
        const pendingCleanup = (control?.cleanupReservations || []).filter(r => r.status === 'active' || r.status === 'unknown');
        if (pendingCleanup.length > 0) {
          return {
            kind: 'deny',
            reason: `IG5 resource cleanup is still ${pendingCleanup.some(r => r.status === 'unknown') ? 'unknown' : 'pending'} (${pendingCleanup.map(r => r.resourceKey).join(', ')}); stop owned resources before calling update_goal(action="blocked").`,
          };
        }
        const sessionInvestigations = rStore.list({ rootSessionId });
        const hasIg5Management = sessionInvestigations.length > 0 || Boolean(control?.hasHistory) || (mgr.sessions?.size || 0) > 0;
        if (hasIg5Management && targetGoalId) {
          return {
            kind: 'deny',
            reason: `Host goal "${targetGoalId}" has no bound IG5 root investigation in this session. Create a goal-bound root investigation via ig5_workspace (action="root-create"), attach your static/dynamic receipts, and record terminalFinding before calling update_goal(action="blocked").`,
          };
        }
      }

      const minRounds = Number.isSafeInteger(hostGoal?.minRoundsForBlocked) ? hostGoal.minRoundsForBlocked : 3;
      if (hostGoal && Number.isSafeInteger(hostGoal.roundsStarted) && hostGoal.roundsStarted < minRounds) {
        return {
          kind: 'deny',
          reason: `HOST_GOAL_ROUND_THRESHOLD_NOT_MET: DSH host requires at least ${minRounds} consecutive goal rounds before update_goal(action="blocked") is accepted (current round is ${hostGoal.roundsStarted}/${minRounds}). Stop calling tools in this round and reply with a concise factual status summary so the host automatically advances to round ${hostGoal.roundsStarted + 1}; once round >= ${minRounds}, call update_goal(action="blocked").`,
        };
      }
      return undefined;
    }

    if (rootTask) {
      const assessment = assessRootInvestigation({
        rootTask,
        mgr,
        execution: { agent },
        hostGoal: effectiveHostGoal,
      });
      if (!assessment.canCompleteHostGoal) {
        return {
          kind: 'deny',
          reason: `IG5 root investigation "${rootTask.rootId}" is not verified for completion (assessment=${assessment.assessment}, cleanup=${assessment.cleanup}; blockers: ${assessment.denialReasons.join(', ')}). Complete required dynamic/holdout verification and owner resource cleanup before calling update_goal(action="complete").`,
        };
      }
      return undefined;
    }

    // Check if this session is managed by IG5 (has prior investigations, IG5 operations, or open sessions):
    // if so, completing a host goal without a verified goal-bound root investigation MUST be denied!
    const control = mgr.coordination?.controlStatus?.(agent, { allowLocalFallback: agent.session === undefined });
    const pendingCleanup = (control?.cleanupReservations || []).filter(r => r.status === 'active' || r.status === 'unknown');
    if (pendingCleanup.length > 0) {
      return {
        kind: 'deny',
        reason: `IG5 resource cleanup is still ${pendingCleanup.some(r => r.status === 'unknown') ? 'unknown' : 'pending'} (${pendingCleanup.map(r => r.resourceKey).join(', ')}); stop owned resources before completing the goal.`,
      };
    }
    const sessionInvestigations = rStore.list({ rootSessionId });
    const hasIg5Management = sessionInvestigations.length > 0 || Boolean(control?.hasHistory) || (mgr.sessions?.size || 0) > 0;
    if (hasIg5Management && targetGoalId) {
      return {
        kind: 'deny',
        reason: `Host goal "${targetGoalId}" has no bound and verified IG5 root investigation in this session (other investigations cannot substitute for the active goal). Create and verify a root investigation for "${targetGoalId}" before calling update_goal(action="complete").`,
      };
    }
    return undefined;
  };

  const registerBriefForAgent = agent => {
    if (!agent?.id || registeredBriefDisposers.has(agent.id)) return;
    const sysPrompt = agent.ctx?.get?.('systemPrompt') ?? agent.ctx?.systemPrompt;
    if (typeof sysPrompt?.context !== 'function') return;
    try {
      const dispose = sysPrompt.context({
        name: 'ig5:investigation-brief',
        order: 220,
        interpolate: false,
        text: () => {
          const mgr = getManager();
          if (!mgr) return '';
          let rootSessionId = agent.id;
          try {
            if (mgr.coordination) {
              rootSessionId = mgr.coordination.resolveRootSubject(agent, {
                allowLocalFallback: agent.session === undefined,
              }).rootId;
            }
          } catch { return ''; }
          const rStore = resolveRootStore(mgr);
          const hostGoal = readLiveHostGoal(ctx, agent);
          const rootTask = hostGoal?.goalId
            ? rStore.findForHostGoal(rootSessionId, hostGoal.goalId).task
            : rStore.latestForSession(rootSessionId);
          if (!rootTask) return '';
          const assessment = assessRootInvestigation({ rootTask, mgr, execution: { agent }, hostGoal });
          return renderDeterministicRootBrief(rootTask, assessment);
        },
      });
      if (typeof dispose === 'function') registeredBriefDisposers.set(agent.id, dispose);
    } catch {
      // Optional context registration must never break agent creation.
    }
  };

  ctx.on('agent/created', ({ agent }) => {
    if (!agent?.id) return;
    agentsBySession.set(agent.id, agent);
    registerBriefForAgent(agent);
  });

  ctx.on('session/event', (session, event) => {
    if (!session?.id || !event) return;
    const agent = resolveAgentBySession(session);
    const mgr = getManager();

    if (event.type === 'turn/start') {
      openHumanTurnBySession.set(session.id, false);
      return;
    }

    if (event.type === 'user/message') {
      const classified = classifyUserMessageEvent(ctx, agent, event);
      lastMessageBySession.set(session.id, classified);
      if (classified?.category === 'direct-human') {
        openHumanTurnBySession.set(session.id, true);
      }
      // Ordinary human messages (e.g. "what is the status? do not continue") MUST NOT clear
      // an active cancellation latch. Cancellation is cleared only by explicit resume actions.
      return;
    }

    if (event.type === 'turn/end') {
      openHumanTurnBySession.set(session.id, false);
      const reason = event.data?.reason;
      const abortedKind = reason?.kind === 'aborted' ? (reason.reason?.kind || 'user') : null;
      if (abortedKind && ['user', 'parent'].includes(abortedKind) && agent && mgr?.coordination) {
        try { mgr.coordination.acceptCancel(agent, `turn-aborted-${abortedKind}`); } catch { /* ignore */ }
      }
      return;
    }

    if (event.type === 'goal/change') {
      const op = event.data?.operation;
      if (['pause', 'clear'].includes(op) && agent && mgr?.coordination) {
        try { mgr.coordination.acceptCancel(agent, `host-goal-${op}`); } catch { /* ignore */ }
      } else if (['resume', 'create'].includes(op) && agent && mgr?.coordination) {
        try { mgr.coordination.resumeControlGeneration(agent, `host-goal-${op}`); } catch { /* ignore */ }
        if (op === 'resume' && event.data?.goal?.id && mgr) {
          try {
            const rStore = resolveRootStore(mgr);
            const { task: bound } = rStore.findForHostGoal(agent.id, event.data.goal.id);
            if (bound) {
              rStore.bindHostGoal(bound.rootId, {
                hostGoalId: event.data.goal.id,
                hostGoalRevision: event.data.goal.revision,
                syncLifecycleRevisionOnly: true,
              }, { goalId: event.data.goal.id, goal: event.data.goal.objective });
            }
          } catch { /* ignore */ }
        }
      } else if (op === 'complete' && agent && mgr) {
        // Direct ctx.goals.complete(agent, ref) bypasses ToolsService; detect and record alignment state.
        try {
          const rStore = resolveRootStore(mgr);
          const completedGoalId = event.data?.goal?.id || null;
          const rootTask = completedGoalId
            ? rStore.findForHostGoal(agent.id, completedGoalId).task
            : rStore.latestForSession(agent.id);
          if (rootTask) {
            const assessment = assessRootInvestigation({
              rootTask,
              mgr,
              execution: { agent },
              hostGoal: {
                status: 'complete',
                phase: 'complete',
                goalId: completedGoalId,
                revision: event.data?.goal?.revision,
                goal: event.data?.goal?.objective || null,
              },
            });
            hostGoalDivergenceBySession.set(session.id, {
              aligned: assessment.goalAssessmentAligned,
              hostGoalState: 'complete',
              investigationAssessment: assessment.assessment,
              cleanup: assessment.cleanup,
              observedAt: new Date().toISOString(),
            });
          } else if (rStore.list({ rootSessionId: agent.id }).length > 0) {
            hostGoalDivergenceBySession.set(session.id, {
              aligned: false,
              hostGoalState: 'complete',
              investigationAssessment: 'unverified',
              cleanup: 'not-needed',
              observedAt: new Date().toISOString(),
            });
          }
        } catch { /* ignore */ }
      }
    }
  });

  // Also register ctx.tools.guard when exposed by DSH 0.2.2+ ToolsService (returns string reason | undefined).
  let guardDispose = null;
  if (typeof ctx.tools?.guard === 'function') {
    try {
      guardDispose = ctx.tools.guard(exec => checkGoalCompletionGate(exec)?.reason);
    } catch { /* optional guard API */ }
  }

  const hasDirectHumanTurnAuthority = agent => {
    if (!agent || !isRootAgent(ctx, agent)) return false;
    try {
      const agentsSvc = ctx.get?.('agents');
      if (typeof agent.session?.snapshotEvents === 'function' && typeof agentsSvc?.turnBoundaryOf === 'function') {
        const boundary = agentsSvc.turnBoundaryOf(agent.session);
        if (boundary?.openTurnStartSeq === null || boundary?.openTurnStartSeq === undefined) return false;
        const events = agent.session.snapshotEvents();
        for (let seq = boundary.openTurnStartSeq + 1; seq < events.length; seq += 1) {
          if (events[seq]?.type === 'user/message' && events[seq]?.data?.source?.kind === 'user') return true;
        }
        return false;
      }
    } catch {
      return false;
    }
    return openHumanTurnBySession.get(agent.id) === true;
  };

  return {
    beforePreExecute: checkGoalCompletionGate,
    currentGoalForAgent: agent => readLiveHostGoal(ctx, agent),
    lastMessageSource: agent => (agent?.id ? lastMessageBySession.get(agent.id) || null : null),
    hasDirectHumanTurnAuthority,
    goalAlignmentStatus: agent => (agent?.id ? hostGoalDivergenceBySession.get(agent.id) || null : null),
    registerBriefForAgent,
    dispose() {
      if (typeof guardDispose === 'function') guardDispose();
      for (const fn of registeredBriefDisposers.values()) {
        try { fn(); } catch { /* ignore */ }
      }
      registeredBriefDisposers.clear();
    },
  };
}
