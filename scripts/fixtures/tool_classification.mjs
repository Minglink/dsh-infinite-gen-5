// 工具分类的唯一事实来源（测试侧）。新增或改名任何公开工具时，必须在这里明确归入"需审批"或"不需审批"，
// 否则 test_tool_classification 与 test_public_tool_catalog 会失败——这样不会再有工具悄悄漏出审批闸门。
// 产品侧的名单是 source/approval_gate.js 的 IG5_WRITE_TOOLS；二者由 test_tool_classification 对账。
const prefix = names => names.map(name => `ig5_${name}`);

/** 修改数据库、执行样本/脚本或控制网络采集，必须经过一次性人工审批。 */
export const APPROVAL_GATED = prefix([
  'rename', 'patch_bytes', 'comment', 'analyze', 'set_type', 'undo', 'run_idapython', 'dbg', 'struct',
  'switch_repair', 'emulate', 'sync', 'capture_control', 'app_observe',
]);

/** 已评审、有意不设审批门的工具。 */
export const NOT_GATED = prefix([
  'doctor', 'open', 'status', 'funcs', 'strings', 'decompile', 'xrefs', 'calls', 'bytes', 'search', 'listing', 'scan',
  'export_diff', 'cfg', 'slice', 'fingerprint', 'close', 'profile', 'workspace', 'recovery', 'stack', 'switches',
  'vtables', 'microcode', 'bindiff', 'ir', 'crypto', 'protocol', 'package', 'capture',
]);

/** 不是纯只读、但有意不设审批的工具及理由；评审时应复核这些理由是否仍成立。 */
export const NOT_GATED_RATIONALE = {
  ig5_open: '加载样本建立数据库，不执行样本（AGENTS.md：load 不执行）。',
  ig5_close: '释放会话与租约。',
  ig5_export_diff: '仅向 artifactDir 写导出文件，输入来自已审计的补丁记录，不修改数据库。',
  ig5_capture: '读取已保存的抓包历史，不启动监听、不发请求（工具描述）；其 materialize 动作会把完整字节按 SHA 固定路径写入文件，不执行也不打开引擎。启动、停止与重放走 ig5_capture_control（需审批）。',
  ig5_profile: '读取配置与能力信息；部分动作如 memory 会写入本会话记忆存储。',
  ig5_package: '只做静态包/目录/轨迹解析：apk/firmware/js_app/trace_diff 只读输入文件、已验证静态前端（如固定清单的 rea-agents@6.4.0）或已保存报告，不执行样本、不开引擎、不发网络；unpack 仅把清洗过路径名的解包文件写到 artifactDir 下新的随机根目录（不建链接/设备节点，受大小/数量/深度预算限制），不修改目标数据库。P3 起为无目标执行静态前端，评审时请复核 unpack 的写入范围。',
  ig5_workspace: '只维护调用方任务笔记、系统证据引用与已保存的分析报告；会更新本会话任务存储并写不可变报告，但不执行目标、不加审批门。P2 拆分自 ig5_profile。',
  ig5_recovery: '只读取有界恢复案例/已提交录制并写不可变报告；不执行目标、不加审批门。P2 拆分自 ig5_profile。',
};

export const ALL_TOOLS = [...APPROVAL_GATED, ...NOT_GATED];
