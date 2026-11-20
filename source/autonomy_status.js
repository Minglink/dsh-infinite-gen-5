/** Inspect the caller's host goal surface without creating or driving work. */
export function autonomyStatus(ctx, execution, mgr = null) {
  const agent = execution?.agent;
  const hostMeta = mgr?.autonomyHost ? {
    completionGateInstalled: true,
    directGoalCompleteInterceptable: false,
    lastMessageSource: mgr.autonomyHost.lastMessageSource(agent),
    goalAlignment: mgr.autonomyHost.goalAlignmentStatus(agent),
  } : {};
  const baseline = {
    skill: 'ig5-reverse-agent', continuation: 'DSH Goal Rounds',
    goalTools: [], goalServiceAvailable: false, goal: null,
    continuationEligible: false, driverVerifiedByThisQuery: false,
    queryStartsWork: false,
    ...hostMeta,
  };
  if (!agent?.ctx) return { ...baseline, scopeAvailable: false };
  try {
    const tools = agent.ctx.tools;
    const goalTools = typeof tools?.get === 'function'
      ? ['get_goal', 'create_goal', 'update_goal'].filter(name => !!tools.get(name, agent)) : [];
    const goals = agent.ctx.get?.('goals') ?? ctx.get?.('goals');
    if (typeof goals?.get !== 'function') return { ...baseline, scopeAvailable: true, goalTools };
    // The native service authenticates this exact live Agent; an id string or
    // global registry lookup is never substituted for the execution subject.
    const current = goals.get(agent);
    const goal = current ? Object.fromEntries([
      'id', 'revision', 'objective', 'phase', 'activation', 'roundsStarted', 'maxGoalRounds',
    ].filter(key => current[key] !== undefined).map(key => [key, current[key]])) : null;
    return { ...baseline, scopeAvailable: true, goalTools, goalServiceAvailable: true, goal,
      continuationEligible: !!current && current.phase === 'active' && current.activation === 'armed'
        && current.roundsStarted < current.maxGoalRounds };
  } catch (error) {
    return { ...baseline, scopeAvailable: true, inspectionError: error?.code || 'HOST_GOAL_INSPECTION_FAILED' };
  }
}
