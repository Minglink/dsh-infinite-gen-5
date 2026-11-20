import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { diagAppend } from './diag_log.js';

// ── M1-B 审批门：写工具 pre-execute 弹 ui-approval；post-execute 留痕 ────────
export const IG5_WRITE_TOOLS = new Set([
  'ig5_rename', 'ig5_patch_bytes', 'ig5_comment', 'ig5_analyze', 'ig5_set_type',
  'ig5_undo', 'ig5_run_idapython', 'ig5_dbg', 'ig5_struct',
  'ig5_switch_repair', 'ig5_emulate',
  'ig5_sync',
  'ig5_capture_control',
  'ig5_app_observe',
]);

// 审批人必须能看到全部载荷。展示内容不截断；超过此上限的操作直接拒绝（失败即关闭），要求拆分后重试。
// ig5_run_idapython 的 code 最长 64 KiB，上限留有余量。
export const APPROVAL_DISPLAY_LIMIT = 131072;
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
  : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
    : JSON.stringify(value) ?? 'null';

/**
 * 审批人必须看到将要执行的真实载荷（脚本源码、补丁字节、命令参数），而不只是目标路径。
 * 不截断：complete=false 表示内容超过 APPROVAL_DISPLAY_LIMIT，调用方必须拒绝而不是只展示一部分。
 * ig5_capture_control 的请求体可能含凭据，只展示与审计一致的脱敏摘要。
 */
export function describeOperation(name, args) {
  const shown = name === 'ig5_capture_control'
    ? { action: args?.action, id: args?.id, session_id: args?.session_id, scope: args?.scope, port: args?.port, tls: args?.tls,
      ...(args?.request ? { request: { redacted: true, method: args.request.method,
        headerNames: Object.keys(args.request.headers || {}), bodyProvided: args.request.body !== undefined } } : {}) }
    : (args ?? {});
  const sha256 = createHash('sha256').update(canonical(args ?? {})).digest('hex');
  const blocks = [];
  for (const [key, value] of Object.entries(shown)) {
    if (value === undefined) continue;
    if (typeof value === 'string' && (value.length > 80 || value.includes('\n'))) blocks.push(`${key}（${value.length} 字符）:\n${value}`);
    else blocks.push(`${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`);
  }
  const detail = blocks.join('\n');
  return { detail, sha256, complete: detail.length <= APPROVAL_DISPLAY_LIMIT };
}

export function installApprovalGate(ctx, cfg, options = {}) {
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (typeof options.beforePreExecute === 'function') {
      const intercept = await options.beforePreExecute(exec);
      if (intercept) return intercept;
    }
    if (!IG5_WRITE_TOOLS.has(exec?.name)) return next();
    const args = exec?.arguments ?? {};
    const destination = args.guest_profile !== undefined ? ` guest=${args.guest_profile} binding=${args.guest_binding_sha256 || '[missing]'}` : '';
    const what = (args?.plan_id ?? args?.ea ?? args?.name ?? args?.target ?? '') + destination;
    const { detail, sha256, complete } = describeOperation(exec.name, args);
    if (!complete)
      return { kind: 'deny', reason: `IG5 ${exec.name} payload exceeds the ${APPROVAL_DISPLAY_LIMIT}-character approval display limit and cannot be reviewed in full; split the operation. Nothing was dispatched.` };
    const payload = `\n--- 将执行的参数（SHA-256 ${sha256}）---\n${detail}`;
    const request = {
      reason: `IG5 写操作待批准: ${exec.name} @ ${what}${payload}`,
      displayReason: {
        en: `IG5 operation "${exec.name}" needs one-time approval before mutation or execution.\n--- Arguments to be executed (SHA-256 ${sha256}) ---\n${detail}`,
        zh: `IG5 操作「${exec.name}」（${what}）涉及修改或执行，需要你批准一次。${payload}`,
      },
    };
    // Resolve the public approval seam here. Some host builds turn a rejected
    // `ask` into an allow; a plugin-owned deny must remain a deny.
    let isOwnerCleanup = false;
    try {
      if (typeof options.isAuthorizedOwnerCleanup === 'function') {
        isOwnerCleanup = options.isAuthorizedOwnerCleanup(exec) === true;
      } else {
        const coord = options.coordination || ctx.get?.('ig5Coordination');
        if (typeof coord?.hasActiveOwnerCleanup === 'function') {
          const cleanArgs = args && typeof args === 'object' && args.research !== undefined
            ? (() => { const copy = { ...args }; delete copy.research; return copy; })()
            : args;
          isOwnerCleanup = coord.hasActiveOwnerCleanup(exec?.agent, exec?.name, cleanArgs, {
            allowLocalFallback: exec?.agent?.session === undefined,
          }) === true;
        }
      }
    } catch {
      isOwnerCleanup = false;
    }
    const approvalSignal = isOwnerCleanup && exec?.signal?.aborted
      ? AbortSignal.timeout(10_000)
      : exec?.signal;
    if (!isOwnerCleanup && exec?.signal?.aborted) return { kind: 'cancel' };
    let approval;
    try { approval = ctx.get('approval'); } catch { /* uncomposed host */ }
    if (!exec?.agent || typeof approval?.request !== 'function')
      return { kind: 'deny', reason: `IG5 ${exec.name} requires an active agent and an available approval service.` };
    let outcome;
    try {
      outcome = await approval.request({ agent: exec.agent, toolName: exec.name,
        callId: exec.callId, ...request, signal: approvalSignal });
    } catch {
      if (approvalSignal?.aborted) return { kind: 'cancel' };
      return { kind: 'deny', reason: `IG5 ${exec.name} approval could not be confirmed; operation was not dispatched.` };
    }
    if (approvalSignal?.aborted || outcome === 'cancelled') return { kind: 'cancel' };
    if (outcome !== 'allowed-once')
      return { kind: 'deny', reason: `IG5 ${exec.name} approval was ${outcome === 'rejected' ? 'rejected' : 'unavailable'}; operation was not dispatched.` };
    return next();
  });
  ctx.on('tools/post-execute', async (exec, result, next) => {
    if (!IG5_WRITE_TOOLS.has(exec?.name)) return next();
    try {
      fs.mkdirSync(cfg.artifactDir, { recursive: true });
      const rec = {
        ts: new Date().toISOString(),
        tool: exec.name,
        args: exec.name === 'ig5_capture_control' ? {
          action: exec.arguments?.action, id: exec.arguments?.id, session_id: exec.arguments?.session_id,
          scope: exec.arguments?.scope, port: exec.arguments?.port, tls: exec.arguments?.tls,
          ...(exec.arguments?.request ? { request: { redacted: true, method: exec.arguments.request.method,
            headerNames: Object.keys(exec.arguments.request.headers || {}), bodyProvided: exec.arguments.request.body !== undefined } } : {}),
        } : exec.arguments,
        isError: result?.isError === true,
        detail: result?.isError ? result?.error?.message : result?.value,
      };
      fs.appendFileSync(path.join(cfg.artifactDir, 'approvals.jsonl'), JSON.stringify(rec) + '\n', 'utf8');
    } catch (error) {
      // 审计失败不能破坏结果路径，但必须留下痕迹：该操作已执行而审计行没有落盘。
      try { diagAppend(cfg, `audit: 审计行写入失败，操作已执行但无记录 tool=${exec.name} callId=${exec.callId ?? ''} code=${error?.code ?? 'unknown'}`); } catch { /* diagnostics are best-effort */ }
    }
    return next();
  });
  diagAppend(cfg, `host: 审批门已挂载（${[...IG5_WRITE_TOOLS].join(', ')}）`);
}
