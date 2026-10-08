---
name: ig5-patch-and-sign
description: "使用 IG5 对已确定的补丁实施 expected 字节核验、审批写入、当前数据库导出及回滚验证，按需用版本差异定位和已授权函数仿真复核。"
---

选择静态后端 `engine=reverse|ghidra`，先从 `ig5_status` 核对路径、engine、projectId/artifactId 与 dbRevision；结果保留来源，不能把两引擎数据库当成一致内存。路径相同不保证内容相同，地址用十六进制字符串并区分静态 VA、RVA、文件偏移和运行时 VA。Ghidra 分析预算到期的 partial 结果只能作为部分证据，不称完整分析。

确认用户期望、目标函数、EA 与实际文件偏移。先用 `ig5_bytes` 读取原始字节，并通过反编译、控制流或反汇编证据说明拟改字节为何实现预期行为。记录原始字节和预期替换，工作流优先显式传入可选 `expected` 以触发前置比较；发现目标字节与依据不一致时先重新定位，不盲写旧偏移或未加载区域。需要高级工具时先调用 `ig5_profile toolset=full`，用户也可用 `/ig5 toolset full`。切换是实例级非持久配置，不授权样本执行，也不改变审批要求。

通过普通工具调用提交 `ig5_patch_bytes`，由宿主审批后执行；不要使用直接 Worker RPC、工作台 HTTP、任意 Python 或旁路文件写入来绕开审批。审批取消或工具失败后停止该写入，保留诊断及已完成的只读证据。写后重新读取字节并核验相关代码行为，动态验证仅在已授权运行该样本时进行。

跨版本补丁先用 `ig5_bindiff left=<旧目标> right=<新目标>` 取得启发式候选，再核查新版本字节、控制流和调用证据；评分不证明语义等价或漏洞，不能直接复用旧地址。只有用户已授权该目标的函数仿真或动态验证，才通过审批用 `ig5_emulate` 复核；仿真不提供 OS/import/TLS，不能把工具启用等同于运行授权。若涉及 switch 修复，先 preview 并明确其 apply 不在 Undo 范围内。

使用 `ig5_export_diff` 按当前数据库状态导出副本与报告。检查报告包含实际 EA、文件偏移、修改前后字节及导出路径；不要把有数据库地址的补丁默认当成可映射文件补丁。需要回滚验证时用审批工具 `ig5_undo`，随后再次读字节并核验重新导出的副本，确认导出尊重 Undo；依赖项目操作日志，不假设引擎自动记录全部 Undo。

交付原件与导出件的实际 SHA-256 及验证结果；未执行哈希不得编造。校验清单属于工件签收，只有使用有效证书签名且验证通过后才声称数字签名。商业引擎称 Reverse，开源结果保留 Ghidra/x64dbg 来源。

补丁调用显式 target/engine，优先传 `expected_revision` 绑定当前数据库。跨引擎复制同一文件修改只通过 `ig5_sync` 的显式 RVA preview→审阅前后值及 digest→apply；preview 也经审批，hash/revision/原值不一致时重新取证，已尝试计划不可重放。报告目的引擎的 applied/remaining 与 atomic=false，不宣称全局 Undo。`ig5_sync` 不能迁移不同 hash 版本，也不自动复制类型；跨版本仍逐项重新定位。
