---
name: ig5-debug-live
description: "使用 IG5 调试车道验证已授权样本的断点、寄存器、单步和异常上下文，结合静态栈帧或显式虚槽定位，区分原生调试与受限函数仿真。"
---

默认静态后端为 `engine=reverse`、`reverseProvider=bundled`，随包服务的实际 `provider=ghidra`，无需本机商业安装；显式 `engine=ghidra` 使用独立车道，商业扩展仅在显式配置 `reverseProvider=commercial` 时使用。先从 `ig5_status` 核对路径、engine、provider、capabilities、projectId/artifactId 与 dbRevision；结果保留来源，不能把两引擎数据库当成一致内存。路径相同不保证内容相同，地址用十六进制字符串并区分静态 VA、RVA、文件偏移和运行时 VA。Ghidra 分析预算到期的 partial 结果只能作为部分证据，不称完整分析。

明确运行的目标、后端与验证问题。`ig5_dbg` 的参数是 `op`，不是 `action`；所有调试操作使用普通工具调用并经过宿主审批。不要通过 Worker RPC、工作台 HTTP 或任意 Python 绕开审批。需要高级工具时先调用 `ig5_profile toolset=full`，也保留用户 `/ig5 toolset full` 入口；按返回的 `toolsetScope` 判断作用域：支持作用域的宿主仅切换当前 agent，旧宿主明确返回 `plugin-instance` 时才影响插件实例。两种切换均不持久化，不授权程序执行或改变审批。只有用户授权运行相应样本后才启动它。

已打开静态目标时，用 `ig5_profile target=... workspace={action:create,goal:...}` 建立调查任务，或用 `workspace={action:get,id:...}` 恢复；更新以本次返回的 `taskRevision` 作为 `expected_task_revision`，冲突后重新读取。待验证函数优先用 `ig5_decompile style=dossier task_id=...` 获取反编译、CFG、调用者/被调函数和栈帧，检查章节 ok/truncated/unsupported/error、provenance、partial 与 stale。dossier 是静态快照，不捕获新暂停事件；正文响应预算不等于全部后端计算预算。任务仅持久分析元数据，不写 IDB、不授权运行，status/conclusion 是调用者陈述；重开或修订变化的旧快照不能当新证据。

`load` 只证明调试器加载；在设置 `bpt`、调用 `start` 后检查真实返回事件与任务状态，再使用 `regs`、`step|stepover`、`readmem` 验证假设。遇到 `no-task`、启动返回失败或没有暂停事件时，不声称寄存器读取、断点命中或单步通过；报告失败阶段与实际诊断，不把外部模拟器路径猜测成唯一根因。不得自动切换到可能直接执行样本的其他车道。

断点地址核对运行时模块基址与 RVA，不能直接把数据库绝对地址当成 ASLR 后地址。按问题用只读 `ig5_stack`、`ig5_switches`、`ig5_vtables` 为断点和异常上下文提供静态依据；显式虚槽解析不能替代寄存器来源证据。没有可用调试任务时仍可完成这些只读检查。`ig5_emulate` 是受限 CPU 仿真，架构与 ABI 按当前 provider、capabilities 和目标核验，不能仅凭 engine 名称推断 x86/x64/ARM64 支持；ARM64 使用 AAPCS64。仿真无 OS/import/TLS；只有目标的仿真已获授权时才通过审批使用，不将它自动替代失败调试或外推真实进程行为。ARM64 Windows 仿真通过不代表手机原生执行已移植。

记录地址、事件类型、暂停状态以及实际寄存器或内存值，只有观测支持时才描述动态行为。`writemem`、继续执行和运行配置修改分别通过审批；验证结束后通过 `stop` 释放任务，并确认实际停止状态。将有用结论通过审批的注释或命名工具回写；商业引擎称 Reverse，动态证据标明实际后端。

x64dbg 使用自建 ig5-native SDK/NamedPipe headless bridge（不依赖 automate/ZeroMQ）。内置 Reverse 与显式 Ghidra 默认使用随包 x64dbg；明确选择该后端时传 `backend=x64dbg`。native win32 仅在显式商业扩展且实际能力支持时使用，不能由 Reverse 标签推断可用。headless 仍会真实执行程序，运行失败不能自动换后端。`load` 不执行，`start` 后以实际暂停、模块与 regs 建立 runId/stopSeq；执行控制优先携带 `expected_run_id/expected_stop_seq`，跨 agent 控制必须显式审批 takeover，不能偷用另一会话控制权。运行地址按已加载模块 base+RVA 映射并核对 epoch，拒绝旧 run/stop 地址；受限 trace 仍属执行操作。工作台 debug_state 只读缓存可辅助看证据，但不替代新暂停事件或真实 regs。x64/x86 已分别有真实 headless 闭环和四槽硬件断点证据，商业扩展 Bochs 历史仅 load/bpt；对当前样本仍实际验证，不外推任意程序。捕获解密或协议缓冲区后保留暂停身份和范围，再交给 `ig5_crypto` / `ig5_protocol` 数据层验证，不用数据工具执行目标函数或改变进程状态。
