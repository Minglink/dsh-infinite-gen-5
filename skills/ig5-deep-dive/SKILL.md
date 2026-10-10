---
name: ig5-deep-dive
description: "使用 IG5 深入解释函数或输入处理路径，结合调用关系、栈帧、跳转表、虚表、微码和变量切片验证假设，按授权进行函数仿真或审批修改。"
---

选择静态后端 `engine=reverse|ghidra`，先从 `ig5_status` 核对路径、engine、projectId/artifactId 与 dbRevision；结果保留来源，不能把两引擎数据库当成一致内存。路径相同不保证内容相同，地址用十六进制字符串并区分静态 VA、RVA、文件偏移和运行时 VA。Ghidra 分析预算到期的 partial 结果只能作为部分证据，不称完整分析。

确认目标与函数地址，使用 `ig5_decompile style=llm` 建立输入、输出、全局状态和关键分支的初步解释。沿 `ig5_calls`、`ig5_xrefs` 追踪影响结论的调用者或被调函数；用 `ig5_cfg` 核验分支与循环结构，用 `ig5_bytes` 核验影响结论的常量或指令。若所需高级工具未启用，先调用 `ig5_profile toolset=full`，也保留用户 `/ig5 toolset full` 入口。切换作用于整个插件实例且不持久化，不构成执行授权或审批豁免。

`ig5_slice` 返回局部变量信息及按变量匹配的代码行，不能把文本命中当成完备的定义使用链或微代码污点证明。用局部赋值、别名、参数传递和调用上下文交叉核验。结构体偏移解释先用 `ig5_struct action=list|get` 检查已有类型；类型假设与已验证布局分别陈述。

按问题使用 `ig5_stack` 核对帧偏移，`ig5_switches` 检查 case/default，`ig5_vtables` 读取 RTTI/虚槽；显式表地址加偏移的解析不能代替寄存器来源证明。`ig5_microcode` 可读取不同成熟度的真实 IR，或优化临时 IR；受限 `xor-self/sub-self` 规则必须检查实际 `rule_hits` 与前后 IR，命中为零时不声称改写，不宣传通用去平坦化。`ig5_switch_repair` 先 preview，应用必须审批且不在 Undo 范围内。

只有用户已授权该目标的仿真或动态验证，才通过审批调用 `ig5_emulate` 验证实际 provider 支持的 x86/x64 或 Ghidra ARM64 函数、明确 ABI、整数参数与内存缓冲区；ARM64 使用 AAPCS64，已在 Windows CPU 仿真验证，不代表手机原生移植。它没有 OS/import/TLS 环境，fault、系统指令中止或超时不能单独证明真实程序行为。没有执行授权时继续完成上述只读证据，不扩大到任意程序执行。涉及解密/配置或报文解析时，按 `ig5-crypto` / `ig5-protocol` 建立显式参数、数据变换与独立验证证据；扫描命中不是算法确认。

当用户需要沉淀理解时，通过正常工具调用提交 `ig5_rename`、`ig5_comment`、`ig5_set_type` 或 `ig5_struct action=define|apply`，每个写操作必须通过宿主审批。不可通过工作台 HTTP、直接 Worker RPC 或任意 Python 绕过审批。给出地址、证据、尚未确认的别名或类型，以及修改后的重新反编译结果。商业引擎称 Reverse，开源结果保留 Ghidra/x64dbg 来源。

Ghidra 的低层证据用 `ig5_ir level=raw|high`，不能请求 Reverse 微码成熟度或把 p-code 当作去混淆证明。不支持的栈帧/虚表/修复能力先报告实际 capabilities；仅在用户需要且允许另一静态来源时显式打开，分别引用结果。写操作优先带本次证据的 `expected_revision`。需跨引擎保存选中名称/注释/字节时用 `ig5_sync` preview→审阅 digest→apply，两步仍审批；仅同 hash、显式 RVA，部分失败不声称原子回滚。
