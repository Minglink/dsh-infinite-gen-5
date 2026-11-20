import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

export const name = 'ig5-m2-suite-guard';
export const inject = ['tools'];

export const M2_GUARD_POLICY_VERSION = 'm2-restricted-allowlist-v2';

// Exact stopping actions supported by DSH 0.2.2-rc.1 @deepseek-ai/dsh-tool-goal update_goal.
// Invalid/non-stopping actions ('paused', 'edit', 'resume') are excluded so they cannot burn terminal reserve.
export const M2_TERMINAL_GOAL_ACTIONS = Object.freeze(['complete', 'blocked', 'pause']);

export const M2_ALLOWED_HOST_TOOLS = Object.freeze([
  'working_directory',
  'read',
  'write',
  'edit',
  'glob',
  'grep',
  'skill',
  'todo_write',
  'job_output',
  'job_list',
  'job_kill',
  'get_goal',
  'create_goal',
  'update_goal',
]);

// Audited IG5 evaluation toolset: excludes ig5_run_idapython (arbitrary Python OS I/O),
// ig5_package, ig5_capture, ig5_protocol, ig5_recovery, ig5_patch_bytes, ig5_export_diff,
// ig5_sync, and ig5_bindiff. ig5_capture_control is admitted solely for action="stop" cleanup.
export const M2_ALLOWED_IG5_TOOLS = Object.freeze([
  'ig5_doctor',
  'ig5_open',
  'ig5_status',
  'ig5_close',
  'ig5_profile',
  'ig5_workspace',
  'ig5_funcs',
  'ig5_strings',
  'ig5_decompile',
  'ig5_xrefs',
  'ig5_calls',
  'ig5_bytes',
  'ig5_search',
  'ig5_listing',
  'ig5_scan',
  'ig5_cfg',
  'ig5_slice',
  'ig5_fingerprint',
  'ig5_stack',
  'ig5_switches',
  'ig5_vtables',
  'ig5_microcode',
  'ig5_ir',
  'ig5_crypto',
  'ig5_rename',
  'ig5_comment',
  'ig5_analyze',
  'ig5_set_type',
  'ig5_undo',
  'ig5_struct',
  'ig5_switch_repair',
  'ig5_emulate',
  'ig5_dbg',
]);

export const M2_BLOCKED_EVAL_TOOLS = Object.freeze([
  'ig5_run_idapython',
  'ig5_package',
  'ig5_capture',
  'ig5_app_observe',
  'ig5_protocol',
  'ig5_recovery',
  'ig5_patch_bytes',
  'ig5_export_diff',
  'ig5_sync',
  'ig5_bindiff',
  'apply_patch',
  'read_image',
  'subagent',
  'present',
  'pwsh',
  'bash',
  'web_search',
  'web_fetch',
]);

const ALLOWED_TOOL_SET = new Set([...M2_ALLOWED_HOST_TOOLS, ...M2_ALLOWED_IG5_TOOLS]);

function normPath(p) {
  const resolved = path.resolve(String(p));
  const realNative = fs.realpathSync.native || fs.realpathSync;
  try {
    return realNative(resolved).toLowerCase();
  } catch {
    let cur = resolved;
    const tail = [];
    while (true) {
      const parent = path.dirname(cur);
      if (parent === cur) break;
      tail.unshift(path.basename(cur));
      cur = parent;
      try {
        return path.join(realNative(cur), ...tail).toLowerCase();
      } catch { /* walk up */ }
    }
    return resolved.toLowerCase();
  }
}

function isUnder(targetPath, rootPath) {
  const t = normPath(targetPath);
  const r = normPath(rootPath);
  if (t === r) return true;
  const prefix = r.endsWith(path.sep) ? r : r + path.sep;
  return t.startsWith(prefix);
}

const PATH_KEY_RE = /^(path|file_path|filepath|target|cwd|cd|dir|directory|workdir|root|output_dir|report_path|script_path|app_dir|entry_path|apk_path|dex_path|electron_binary|output_apk_path)$/i;

function collectPathCandidates(args, baseCwd) {
  const out = [];
  function walk(val, key = '') {
    if (!val) return;
    if (typeof val === 'string') {
      if (PATH_KEY_RE.test(key)) {
        out.push(path.resolve(baseCwd, val));
      }
      return;
    }
    if (Array.isArray(val)) {
      for (const item of val) walk(item, key);
      return;
    }
    if (typeof val === 'object') {
      for (const [k, v] of Object.entries(val)) walk(v, k);
    }
  }
  walk(args);
  return out;
}

function extractCliArgPathCandidates(argsArray, baseCwd) {
  if (!Array.isArray(argsArray)) return [];
  const candidates = [];
  for (const rawItem of argsArray) {
    if (typeof rawItem !== 'string') continue;
    const tokens = [rawItem];
    const eqIdx = rawItem.indexOf('=');
    if (eqIdx > 0) tokens.push(rawItem.slice(eqIdx + 1));
    const colonIdx = rawItem.indexOf(':');
    if (colonIdx > 1 && !/^[a-zA-Z]:[\\/]/.test(rawItem)) tokens.push(rawItem.slice(colonIdx + 1));
    for (const tok of tokens) {
      if (!tok) continue;
      if (tok.includes('..') || tok.includes('/') || tok.includes('\\') || /^[a-zA-Z]:/.test(tok)) {
        candidates.push(path.resolve(baseCwd, tok));
      }
    }
  }
  return candidates;
}

function hasUnsafeSearchPattern(pat) {
  if (typeof pat !== 'string') return false;
  return pat.includes('..') || pat.includes(':') || pat.startsWith('/') || pat.startsWith('\\');
}

export function apply(ctx, config) {
  const workspaceRoot = normPath(config.workspaceRoot);
  const allowedRoots = (config.allowedRoots || [config.workspaceRoot]).map((r) => normPath(r));
  const pluginInternalRoots = (config.pluginInternalRoots || []).map((r) => normPath(r));
  const blockedPluginSubdirs = (config.blockedPluginSubdirs || []).map((r) => normPath(r));
  const readAllowedRoots = config.readOnlyRoots
    ? [workspaceRoot, ...config.readOnlyRoots.map((r) => normPath(r))]
    : allowedRoots.filter((r) => !pluginInternalRoots.some((pi) => isUnder(r, pi)));
  const searchAllowedRoots = config.searchAllowedRoots
    ? config.searchAllowedRoots.map((r) => normPath(r))
    : readAllowedRoots;
  const logPath = config.logPath;
  const maxTotalToolCalls = Number.isSafeInteger(config.maxTotalToolCalls) ? config.maxTotalToolCalls : 72;
  // Reserve terminal controls inside the existing cap; this does not grant more
  // analysis calls or bypass the downstream IG5 completion/owner checks.
  const terminalControlReserve = config.terminalControlReserve ?? Math.min(2, maxTotalToolCalls);
  if (!Number.isSafeInteger(maxTotalToolCalls) || maxTotalToolCalls < 1
      || !Number.isSafeInteger(terminalControlReserve) || terminalControlReserve < 0
      || terminalControlReserve > maxTotalToolCalls) {
    throw new Error('Invalid M2 total-call cap or terminal-control reserve');
  }
  const ordinaryCallLimit = maxTotalToolCalls - terminalControlReserve;
  const extraAllowedTools = Array.isArray(config.extraAllowedTools) ? config.extraAllowedTools.map(String) : [];
  const allowedPackageActions = Array.isArray(config.allowedPackageActions) ? new Set(config.allowedPackageActions.map(String)) : null;
  const effectiveAllowedToolSet = new Set([...ALLOWED_TOOL_SET, ...extraAllowedTools]);
  const effectiveBlockedEvalTools = M2_BLOCKED_EVAL_TOOLS.filter((n) => !effectiveAllowedToolSet.has(n));
  const policyVersion = config.policyVersion || M2_GUARD_POLICY_VERSION;

  const controlMode = config.controlMode || 'none'; // 'none' | 'pause-after-first-dbg-stop' | 'cancel-after-first-dbg-start'
  const minGoalRoundsForBlocked = Number.isSafeInteger(config.minGoalRoundsForBlocked) ? config.minGoalRoundsForBlocked : 3;

  let attemptedCalls = 0;
  let ordinaryAllowedCount = 0;
  let cleanupAllowedCount = 0;
  let terminalReserveUsed = 0;
  let terminalQueryUsed = false;
  let controlTriggered = false;
  let postCancelBusinessAttempts = 0;
  let postCancelBusinessExecuted = 0;
  const agentCwds = new Map();
  const restrictedAgents = new WeakSet();
  const restrictDisposers = [];

  const appendLog = (entry) => {
    try {
      fs.appendFileSync(logPath, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n', 'utf8');
    } catch { /* best-effort */ }
  };

  const getAgentCwd = (agent) => {
    const id = agent?.id;
    if (id && agentCwds.has(id)) return agentCwds.get(id);
    const metaCwd = agent?.session?.meta?.cwd || agent?.session?.header?.cwd;
    if (metaCwd && isUnder(metaCwd, workspaceRoot)) return normPath(metaCwd);
    return workspaceRoot;
  };

  const isBlockedPath = (candidate) => blockedPluginSubdirs.some((b) => isUnder(candidate, b))
    || pluginInternalRoots.some((pi) => isUnder(candidate, pi));

  appendLog({
    event: 'guard-mounted',
    policyVersion,
    workspaceRoot,
    readAllowedRoots,
    searchAllowedRoots,
    pluginInternalRoots,
    blockedPluginSubdirs,
    allowedToolCount: effectiveAllowedToolSet.size,
    extraAllowedTools,
    maxTotalToolCalls,
    terminalControlReserve,
    ordinaryCallLimit,
    controlMode,
  });

  if (typeof ctx.effect === 'function') {
    ctx.effect(() => () => {
      while (restrictDisposers.length) restrictDisposers.pop()?.();
    });
  }

  ctx.on('agent/created', ({ agent }) => {
    if (!agent?.ctx?.tools?.restrict || restrictedAgents.has(agent)) return;
    restrictedAgents.add(agent);
    try {
      const globalSchemas = ctx.tools?.schemas?.() || [];
      const globalNames = new Set(globalSchemas.map((s) => s.name));
      const denyList = effectiveBlockedEvalTools.filter((n) => globalNames.has(n));
      if (denyList.length > 0) {
        const dispose = agent.ctx.tools.restrict({ deny: denyList });
        if (typeof dispose === 'function') restrictDisposers.push(dispose);
        appendLog({ event: 'agent-global-tools-restricted', agentId: agent.id || null, deniedGlobals: denyList });
      }
    } catch { /* best-effort host restriction; pre-execute remains authoritative */ }
  }, { global: true });

  function validateToolContainment(toolName, rawArgs, agentCwd) {
    const isCleanupCaptureStop = toolName === 'ig5_capture_control' && rawArgs?.action === 'stop';
    const isCleanupAppObserveStop = toolName === 'ig5_app_observe'
      && ['stop', 'android_session_stop'].includes(rawArgs?.action)
      && effectiveAllowedToolSet.has('ig5_app_observe');
    if (!effectiveAllowedToolSet.has(toolName) && !isCleanupCaptureStop && !isCleanupAppObserveStop) {
      return {
        ok: false,
        event: 'denied-unallowlisted-tool',
        candidate: null,
        reason: `Blind evaluation capability policy (${policyVersion}) denies tool "${toolName}". Unconstrained script/patch/subagent/archive/capture channels are disabled; use audited IG5 static/emulation/debugger/workspace tools and workspace file tools only.`,
      };
    }

    if (toolName === 'ig5_package' && allowedPackageActions && !allowedPackageActions.has(String(rawArgs?.action || ''))) {
      return {
        ok: false,
        event: 'denied-unallowlisted-tool',
        candidate: null,
        reason: `Evaluation policy (${policyVersion}) denies ig5_package action "${rawArgs?.action}"; allowed static actions: ${[...allowedPackageActions].join(', ')}.`,
      };
    }

    if (rawArgs && typeof rawArgs === 'object' && (rawArgs.sandbox_permissions !== undefined || rawArgs.justification !== undefined)) {
      return {
        ok: false,
        event: 'denied-sandbox-escalation',
        candidate: null,
        reason: 'Blind evaluation policy denies sandbox_permissions escalation.',
      };
    }

    // Host write/edit: strictly confined to workspaceRoot only (skills/docs/spills/ig5Home are non-writable).
    if (toolName === 'write' || toolName === 'edit') {
      if (typeof rawArgs?.file_path !== 'string' || !rawArgs.file_path.trim()) {
        return { ok: false, event: 'denied-invalid-schema', candidate: null, reason: `${toolName} requires a non-empty string file_path inside workspace.` };
      }
      const candidate = path.resolve(agentCwd, rawArgs.file_path);
      if (isBlockedPath(candidate) || !isUnder(candidate, workspaceRoot)) {
        return {
          ok: false,
          event: 'denied-path-escape',
          subReason: 'write-outside-workspace',
          candidate,
          reason: `Blind evaluation write policy confines "${toolName}" strictly to workspace "${config.workspaceRoot}"; denied "${candidate}".`,
        };
      }
    }

    // Host read: confined to workspaceRoot + readAllowedRoots (never ig5Home or blockedPluginSubdirs).
    if (toolName === 'read') {
      if (typeof rawArgs?.file_path !== 'string' || !rawArgs.file_path.trim()) {
        return { ok: false, event: 'denied-invalid-schema', candidate: null, reason: 'read requires a non-empty string file_path.' };
      }
      const candidate = path.resolve(agentCwd, rawArgs.file_path);
      const allowed = !isBlockedPath(candidate) && readAllowedRoots.some((r) => isUnder(candidate, r));
      if (!allowed) {
        return {
          ok: false,
          event: 'denied-path-escape',
          subReason: 'read-outside-allowed-roots',
          candidate,
          reason: `Blind evaluation read policy denies access to "${candidate}".`,
        };
      }
    }

    // Host working_directory: cd must remain strictly inside workspaceRoot.
    if (toolName === 'working_directory' && rawArgs?.cd !== undefined) {
      if (typeof rawArgs.cd !== 'string' || !rawArgs.cd.trim()) {
        return { ok: false, event: 'denied-invalid-schema', candidate: null, reason: 'working_directory cd must be a non-empty string.' };
      }
      const candidate = path.resolve(agentCwd, rawArgs.cd);
      if (isBlockedPath(candidate) || !isUnder(candidate, workspaceRoot)) {
        return {
          ok: false,
          event: 'denied-path-escape',
          subReason: 'cd-outside-workspace',
          candidate,
          reason: `Blind evaluation policy confines working_directory strictly to "${config.workspaceRoot}"; denied "${candidate}".`,
        };
      }
    }

    // Host glob / grep: reject pattern traversal ('..', drive letters, root slashes) and confine search path.
    if (toolName === 'glob' || toolName === 'grep') {
      if ((toolName === 'glob' && hasUnsafeSearchPattern(rawArgs?.pattern))
          || (toolName === 'grep' && hasUnsafeSearchPattern(rawArgs?.glob))) {
        const badPat = toolName === 'glob' ? rawArgs?.pattern : rawArgs?.glob;
        return {
          ok: false,
          event: 'denied-path-escape',
          subReason: 'search-pattern-traversal',
          candidate: path.resolve(agentCwd, String(badPat)),
          reason: `Blind evaluation search policy rejects parent/drive/root pattern "${badPat}".`,
        };
      }
      const searchBase = rawArgs?.path !== undefined ? path.resolve(agentCwd, String(rawArgs.path)) : agentCwd;
      const allowed = !isBlockedPath(searchBase) && searchAllowedRoots.some((r) => isUnder(searchBase, r));
      if (!allowed) {
        return {
          ok: false,
          event: 'denied-path-escape',
          subReason: 'search-outside-allowed-roots',
          candidate: searchBase,
          reason: `Blind evaluation search policy denies searching "${searchBase}".`,
        };
      }
    }

    // IG5 profile: block guest VM profiles or non-read knowledge actions.
    if (toolName === 'ig5_profile') {
      if (rawArgs?.guest_debug !== undefined) {
        return { ok: false, event: 'denied-unallowlisted-tool', candidate: null, reason: 'ig5_profile guest_debug is disabled in M2 blind evaluation.' };
      }
      if (rawArgs?.knowledge?.action !== undefined && !['search', 'read', 'documents'].includes(rawArgs.knowledge.action)) {
        return { ok: false, event: 'denied-unallowlisted-tool', candidate: null, reason: `ig5_profile knowledge action "${rawArgs.knowledge.action}" is disabled in M2 blind evaluation.` };
      }
    }

    // IG5 debugger & workspace: enforce strict workspace containment on all nested scenario/component/inputSpec paths & CLI args.
    if (toolName === 'ig5_dbg') {
      const dbgBaseCwd = typeof rawArgs?.cwd === 'string' && rawArgs.cwd.trim()
        ? path.resolve(agentCwd, rawArgs.cwd)
        : agentCwd;
      if (rawArgs?.cwd !== undefined && (isBlockedPath(dbgBaseCwd) || !isUnder(dbgBaseCwd, workspaceRoot))) {
        return {
          ok: false,
          event: 'denied-path-escape',
          subReason: 'dbg-cwd-outside-workspace',
          candidate: dbgBaseCwd,
          reason: `Blind evaluation policy confines ig5_dbg cwd strictly to "${config.workspaceRoot}"; denied "${dbgBaseCwd}".`,
        };
      }
      for (const cliCand of extractCliArgPathCandidates(rawArgs?.args, dbgBaseCwd)) {
        if (isBlockedPath(cliCand) || !isUnder(cliCand, workspaceRoot)) {
          return {
            ok: false,
            event: 'denied-path-escape',
            subReason: 'dbg-cli-arg-outside-workspace',
            candidate: cliCand,
            reason: `Blind evaluation policy denies CLI argument referencing path outside workspace: "${cliCand}".`,
          };
        }
      }
    }

    if (toolName === 'ig5_app_observe') {
      const appBaseCwd = typeof rawArgs?.cwd === 'string' && rawArgs.cwd.trim()
        ? path.resolve(agentCwd, rawArgs.cwd)
        : agentCwd;
      if (rawArgs?.cwd !== undefined && (isBlockedPath(appBaseCwd) || !isUnder(appBaseCwd, workspaceRoot))) {
        return {
          ok: false,
          event: 'denied-path-escape',
          subReason: 'app-observe-cwd-outside-workspace',
          candidate: appBaseCwd,
          reason: `Blind evaluation policy confines ig5_app_observe cwd strictly to "${config.workspaceRoot}"; denied "${appBaseCwd}".`,
        };
      }
      for (const cliCand of extractCliArgPathCandidates(rawArgs?.args, appBaseCwd)) {
        if (isBlockedPath(cliCand) || !isUnder(cliCand, workspaceRoot)) {
          return {
            ok: false,
            event: 'denied-path-escape',
            subReason: 'app-observe-cli-arg-outside-workspace',
            candidate: cliCand,
            reason: `Blind evaluation policy denies ig5_app_observe CLI argument referencing path outside workspace: "${cliCand}".`,
          };
        }
      }
    }

    if (toolName === 'ig5_workspace') {
      const rootObj = rawArgs?.workspace?.root;
      if (rootObj && typeof rootObj === 'object') {
        if (Array.isArray(rootObj.prepareInputs)) {
          for (const prep of rootObj.prepareInputs) {
            if (prep && typeof prep === 'object' && prep.path !== undefined) {
              const fp = path.resolve(agentCwd, String(prep.path));
              if (isBlockedPath(fp) || !isUnder(fp, workspaceRoot)) {
                return {
                  ok: false,
                  event: 'denied-path-escape',
                  subReason: 'prepare-input-outside-workspace',
                  candidate: fp,
                  reason: `Blind evaluation policy confines root.prepareInputs.path strictly to "${config.workspaceRoot}"; denied "${fp}".`,
                };
              }
            }
          }
        }
        const scenarios = [
          ...(rootObj.scenario ? [rootObj.scenario] : []),
          ...(Array.isArray(rootObj.scenarios) ? rootObj.scenarios : []),
        ];
        for (const sc of scenarios) {
          if (!sc || typeof sc !== 'object') continue;
          const scCwd = typeof sc.cwd === 'string' && sc.cwd.trim() ? path.resolve(agentCwd, sc.cwd) : agentCwd;
          if (sc.cwd !== undefined && (isBlockedPath(scCwd) || !isUnder(scCwd, workspaceRoot))) {
            return {
              ok: false,
              event: 'denied-path-escape',
              subReason: 'scenario-cwd-outside-workspace',
              candidate: scCwd,
              reason: `Blind evaluation policy confines scenario.cwd strictly to "${config.workspaceRoot}"; denied "${scCwd}".`,
            };
          }
          if (sc.inputSpec?.filePath !== undefined) {
            const fp = path.resolve(scCwd, String(sc.inputSpec.filePath));
            if (isBlockedPath(fp) || !isUnder(fp, workspaceRoot)) {
              return {
                ok: false,
                event: 'denied-path-escape',
                subReason: 'scenario-input-file-outside-workspace',
                candidate: fp,
                reason: `Blind evaluation policy confines scenario.inputSpec.filePath strictly to "${config.workspaceRoot}"; denied "${fp}".`,
              };
            }
          }
          for (const cliCand of extractCliArgPathCandidates(sc.args, scCwd)) {
            if (isBlockedPath(cliCand) || !isUnder(cliCand, workspaceRoot)) {
              return {
                ok: false,
                event: 'denied-path-escape',
                subReason: 'scenario-cli-arg-outside-workspace',
                candidate: cliCand,
                reason: `Blind evaluation policy denies scenario CLI argument referencing path outside workspace: "${cliCand}".`,
              };
            }
          }
        }
      }
    }

    // Generic path-key scan across all arguments:
    // For IG5 tools, every target/path/cwd must stay strictly inside workspaceRoot.
    // For host tools, any additional path field must stay within readAllowedRoots (or workspaceRoot for mutating tools).
    const candidates = collectPathCandidates(rawArgs, agentCwd);
    const strictWorkspaceOnly = toolName.startsWith('ig5_') || toolName === 'write' || toolName === 'edit' || toolName === 'working_directory';
    for (const candidate of candidates) {
      const inAllowed = !isBlockedPath(candidate) && (strictWorkspaceOnly
        ? isUnder(candidate, workspaceRoot)
        : readAllowedRoots.some((r) => isUnder(candidate, r)));
      if (!inAllowed) {
        return {
          ok: false,
          event: 'denied-path-escape',
          subReason: strictWorkspaceOnly ? 'outside-workspace' : 'outside-allowed-roots',
          candidate,
          reason: `Blind evaluation isolation policy denies access outside the case workspace: "${candidate}". Operate only on files inside "${config.workspaceRoot}".`,
        };
      }
    }

    return { ok: true };
  }

  ctx.on('tools/pre-execute', async (exec, next) => {
    const toolName = exec?.name || 'unknown';
    const rawArgs = exec?.arguments ?? {};
    const argsSha256 = createHash('sha256').update(JSON.stringify(rawArgs)).digest('hex');
    const isCleanupCall = (toolName === 'ig5_dbg' && rawArgs?.op === 'stop')
      || (toolName === 'ig5_capture_control' && rawArgs?.action === 'stop')
      || (toolName === 'ig5_app_observe' && ['stop', 'android_session_stop'].includes(rawArgs?.action) && effectiveAllowedToolSet.has('ig5_app_observe'))
      || toolName === 'ig5_close';
    const isTerminalControl = toolName === 'get_goal'
      || (toolName === 'update_goal' && M2_TERMINAL_GOAL_ACTIONS.includes(rawArgs?.action));

    attemptedCalls += 1;
    const callSeq = attemptedCalls;

    if (controlMode === 'cancel-after-first-dbg-start' && controlTriggered && !isCleanupCall) {
      postCancelBusinessAttempts += 1;
    }

    // 1. Closed per-tool capability allowlist + separated read/write/CLI-arg path containment.
    // Validate containment first so path/allowlist rejections do not consume ordinary or terminal reserve slots.
    const agentCwd = getAgentCwd(exec?.agent);
    const containment = validateToolContainment(toolName, rawArgs, agentCwd);
    if (!containment.ok) {
      appendLog({
        event: containment.event,
        ...(containment.subReason ? { subReason: containment.subReason } : {}),
        ...(containment.candidate ? { candidate: containment.candidate } : {}),
        callSeq,
        ordinaryAllowedCount,
        cleanupAllowedCount,
        terminalReserveUsed,
        toolName,
        argsSha256,
      });
      return { kind: 'deny', reason: containment.reason };
    }

    // 2. Host 3-round gate coordination for update_goal(action="blocked"):
    // If DSH's live goal is still in round < minGoalRoundsForBlocked (default 3), deny pre-execute
    // WITHOUT consuming ordinary budget or terminal reserve so the model can yield the turn and advance rounds.
    if (toolName === 'update_goal' && rawArgs?.action === 'blocked') {
      let liveGoal = null;
      try {
        const goalsSvc = exec?.agent?.ctx?.get?.('goals') ?? ctx?.get?.('goals');
        liveGoal = typeof goalsSvc?.get === 'function' ? goalsSvc.get(exec?.agent) : null;
      } catch { /* optional in offline harnesses without goals service */ }
      if (liveGoal && Number.isSafeInteger(liveGoal.roundsStarted) && liveGoal.roundsStarted < minGoalRoundsForBlocked) {
        appendLog({
          event: 'denied-host-round-threshold-not-met',
          callSeq,
          toolName,
          currentRound: liveGoal.roundsStarted,
          minGoalRoundsForBlocked,
          ordinaryAllowedCount,
          cleanupAllowedCount,
          terminalReserveUsed,
          argsSha256,
        });
        return {
          kind: 'deny',
          reason: `Host goal "blocked" requires at least ${minGoalRoundsForBlocked} consecutive goal rounds; current round is ${liveGoal.roundsStarted}/${minGoalRoundsForBlocked}. Neither ordinary budget nor terminal reserve was consumed by this check. Stop calling tools in this round and reply with a concise factual status summary so DSH advances to round ${liveGoal.roundsStarted + 1}; once round >= ${minGoalRoundsForBlocked}, call update_goal(action="blocked") with goal_id, revision, and blocked_reason.`,
        };
      }
    }

    // 3. Ordinary calls stop at ordinaryCallLimit; cleanup calls never consume ordinary or terminal reserve;
    // denied calls never increment ordinaryAllowedCount or replenish exhausted reserve.
    let usesTerminalReserve = false;
    if (isCleanupCall) {
      cleanupAllowedCount += 1;
    } else if (ordinaryAllowedCount < ordinaryCallLimit) {
      ordinaryAllowedCount += 1;
    } else {
      // A repeated status query must not spend the last terminal-commit slot.
      const canUseReserve = isTerminalControl && terminalReserveUsed < terminalControlReserve
        && (toolName !== 'get_goal' || (!terminalQueryUsed && terminalReserveUsed < terminalControlReserve - 1));
      if (canUseReserve) {
        terminalReserveUsed += 1;
        if (toolName === 'get_goal') terminalQueryUsed = true;
        usesTerminalReserve = true;
      } else {
        appendLog({
          event: 'denied-budget',
          callSeq,
          toolName,
          argsSha256,
          ordinaryCallLimit,
          ordinaryAllowedCount,
          cleanupAllowedCount,
          terminalReserveUsed,
          terminalControlReserve,
        });
        return {
          kind: 'deny',
          reason: `Evaluation ordinary tool-call budget (${ordinaryCallLimit} of ${maxTotalToolCalls}, with ${terminalControlReserve} reserved terminal controls) exhausted. Resource cleanup remains available. Reserved terminal calls remaining: ${terminalControlReserve - terminalReserveUsed}; get_goal is allowed at most once and cannot spend the last commit slot. Valid update_goal terminal actions: ${M2_TERMINAL_GOAL_ACTIONS.join(', ')}. Do not resume analysis or reset the budget; use update_goal to conclude, completing only if the bound IG5 investigation is verified. All original completion and owner gates still apply.`,
        };
      }
    }

    appendLog({
      event: 'allowed',
      callSeq,
      toolName,
      isCleanupCall,
      isTerminalControl,
      usesTerminalReserve,
      ordinaryAllowedCount,
      cleanupAllowedCount,
      terminalReserveUsed,
      controlTriggered,
      postCancelBusinessAttempts,
      argsSha256,
    });
    return next();
  }, { global: true });

  ctx.on('tools/post-execute', async (exec, result, next) => {
    const toolName = exec?.name || 'unknown';
    const rawArgs = exec?.arguments ?? {};
    const isError = result?.isError === true;
    const isCleanupCall = (toolName === 'ig5_dbg' && rawArgs?.op === 'stop')
      || (toolName === 'ig5_capture_control' && rawArgs?.action === 'stop')
      || (toolName === 'ig5_app_observe' && ['stop', 'android_session_stop'].includes(rawArgs?.action) && effectiveAllowedToolSet.has('ig5_app_observe'))
      || toolName === 'ig5_close';

    if (toolName === 'working_directory' && !isError && typeof rawArgs?.cd === 'string' && exec?.agent?.id) {
      const nextCwd = path.resolve(getAgentCwd(exec.agent), rawArgs.cd);
      if (isUnder(nextCwd, workspaceRoot)) agentCwds.set(exec.agent.id, normPath(nextCwd));
    }

    if (controlMode === 'cancel-after-first-dbg-start' && controlTriggered && !isCleanupCall && !isError && toolName.startsWith('ig5_') && !['ig5_status', 'ig5_doctor', 'ig5_profile', 'ig5_workspace'].includes(toolName)) {
      postCancelBusinessExecuted += 1;
    }

    const outText = isError ? String(result?.error?.message || '') : JSON.stringify(result?.value ?? '');
    appendLog({
      event: 'post-execute',
      toolName,
      op: rawArgs?.op || rawArgs?.workspace?.action || null,
      isError,
      postCancelBusinessExecuted,
      outputBytes: Buffer.byteLength(outText, 'utf8'),
    });

    // Pre-registered deterministic control hooks
    if (!controlTriggered && !isError && exec?.agent) {
      if (controlMode === 'cancel-after-first-dbg-start' && toolName === 'ig5_dbg' && rawArgs?.op === 'start') {
        controlTriggered = true;
        appendLog({ event: 'control-cancel-fired', reason: 'post-first-ig5_dbg-start' });
        setImmediate(() => {
          try {
            const goals = ctx.get?.('goals');
            const g = goals?.get?.(exec.agent);
            if (g && g.phase === 'active') {
              goals.pause(exec.agent, { id: g.id, revision: g.revision });
            }
          } catch { /* best-effort */ }
          try { exec.agent.cancel?.({ kind: 'user' }); } catch { /* best-effort */ }
        });
      } else if (controlMode === 'pause-after-first-dbg-stop' && toolName === 'ig5_dbg' && rawArgs?.op === 'stop') {
        controlTriggered = true;
        appendLog({ event: 'control-pause-for-compaction-fired', reason: 'post-first-ig5_dbg_stop' });
        setImmediate(() => {
          try {
            const goals = ctx.get?.('goals');
            const g = goals?.get?.(exec.agent);
            if (g && g.phase === 'active') {
              goals.pause(exec.agent, { id: g.id, revision: g.revision });
            }
          } catch { /* best-effort */ }
          try { exec.agent.cancel?.({ kind: 'user' }); } catch { /* best-effort */ }
        });
      }
    }

    return next();
  }, { global: true });
}
