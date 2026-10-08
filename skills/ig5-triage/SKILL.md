---
name: ig5-triage
description: "使用 IG5 对新二进制样本进行只读侦察，结合入口、可疑 API、加密常量、栈帧、跳转表与虚表线索选择优先分析函数。"
---

选择静态后端 `engine=reverse|ghidra`，先从 `ig5_status` 核对路径、engine、projectId/artifactId 与 dbRevision；结果保留来源，不能把两引擎数据库当成一致内存。路径相同不保证内容相同，地址用十六进制字符串并区分静态 VA、RVA、文件偏移和运行时 VA。Ghidra 分析预算到期的 partial 结果只能作为部分证据，不称完整分析。

先用 `ig5_profile`、`ig5_status` 确认当前工具面及目标；未打开样本时用 `ig5_open`。后台分析以实际作业结果为准，不能将已提交作业当作分析完成。若所需高级工具未启用，先调用 `ig5_profile toolset=full`；用户也可用 `/ig5 toolset full`。切换影响插件实例的所有会话且不持久化，只配置工具面，不授予样本执行权限或改变审批要求。

按问题选取 `ig5_funcs`、`ig5_strings`、`ig5_listing kind=imports|exports|segments`、`ig5_scan`、`ig5_fingerprint`。函数枚举优先 `user_only=true`，必要时再查看库函数；扫描命中只是线索，常量或 API 名称不能单独证明恶意行为。把有意义的字符串和导入用 `ig5_xrefs` 连到调用位置，再对少量候选函数使用 `ig5_decompile style=llm`。

按候选特征使用 `ig5_stack` 读取汇编级栈帧，`ig5_switches` 核验已识别跳转表，`ig5_vtables` 检视虚表/RTTI 及继承线索。虚调用需要显式表地址与字节偏移，不能自动归因寄存器来源。此 runbook 为只读侦察，不因发现可疑线索自动启动调试、仿真或写入修复。

给出目标架构、分析状态、可复核的函数地址、主要线索及下一步假设。对每项判断区分观察与推测，说明哪个调用关系、字节或伪代码片段能证实或证伪。将精力用于与用户问题相关的假设，不穷举全部函数或字符串。商业引擎称 Reverse，开源结果明确标 Ghidra/x64dbg。

按实际 capabilities 选择工具，不为能力不足静默换引擎。Ghidra 函数需要 IR 时用只读 `ig5_ir level=raw|high`，Reverse 使用 `ig5_microcode`；二者 IR 层级不互相等同。静态 open 不运行样本；该 runbook 不触发 `ig5_sync` 写回或启动 x64dbg。
