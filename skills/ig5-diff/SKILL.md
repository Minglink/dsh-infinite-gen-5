---
name: ig5-diff
description: "使用 IG5 bindiff 多特征启发式比较版本函数和变更块，结合调用关系、常量、虚表、跳转表及微码核验补丁候选，保留歧义与截断信息。"
---

默认静态后端为 `engine=reverse`、`reverseProvider=bundled`，随包服务的实际 `provider=ghidra`，无需本机商业安装；显式 `engine=ghidra` 使用独立车道，商业扩展仅在显式配置 `reverseProvider=commercial` 时使用。先从 `ig5_status` 核对路径、engine、provider、capabilities、projectId/artifactId 与 dbRevision；结果保留来源，不能把两引擎数据库当成一致内存。路径相同不保证内容相同，地址用十六进制字符串并区分静态 VA、RVA、文件偏移和运行时 VA。Ghidra 分析预算到期的 partial 结果只能作为部分证据，不称完整分析。

分别确认旧、新目标的路径与分析状态，必要时各自 `ig5_open`。单目标调用显式传入 `target`，`ig5_bindiff` 明确传入 `left`、`right`，防止混用两个版本。保存比较依据；地址漂移、不同编译选项或分析缺失不能直接当作业务逻辑改变。需要高级工具时先调用 `ig5_profile toolset=full`，用户也可用 `/ig5 toolset full`；按返回的 `toolsetScope` 判断作用域：支持作用域的宿主仅切换当前 agent，旧宿主明确返回 `plugin-instance` 时才影响插件实例。两种切换均不持久化，不授权执行或免除审批。

旧、新目标各自用 `ig5_profile target=... workspace={action:create,goal:...}` 建立调查任务，或用 `workspace={action:get,id:...}` 恢复各自任务；不要复用另一目标的绑定。更新以本次返回的 `taskRevision` 作为 `expected_task_revision`，冲突后重新读取。hypothesis/conclusion 与 status 是调用者陈述，不是匹配验证；任务不写 IDB、不授权执行。重开或数据库修订变化后检查旧系统快照的 stale，不把旧版本证据当新版本证据。

用 `ig5_bindiff left=<旧目标> right=<新目标>` 取得基于规范化指令、CFG 邻域、常量与调用特征的函数匹配和变更块；保留歧义、候选评分、未匹配及截断信息。用 `ig5_funcs`、字符串、导入与调用者交叉核对，比较时优先用户代码。对重要候选各自优先读取 `ig5_decompile style=dossier task_id=...`，聚合反编译、CFG、调用者/被调函数和栈帧；检查章节 ok/truncated/unsupported/error、provenance 与分析 partial，再补查缺项。正文响应预算不等于全部后端计算预算，不为全部候选无差别生成 dossier。必要时用 `ig5_xrefs`、`ig5_calls` 解释上下文，并按问题比较 `ig5_stack`、`ig5_switches`、`ig5_vtables` 或同一实际阶段的 `ig5_microcode`。仅凭名称、大小或评分不能确认同一函数、语义等价或漏洞；证据不足时列出候选与置信依据。

输出旧函数 EA、新函数 EA、匹配理由、行为差异与仍待核验的问题。`ig5_export_diff` 导出当前数据库中的字节补丁状态并尊重 Undo，不是两个版本的匹配器；版本候选使用 `ig5_bindiff`。补丁迁移重新读取新版本原字节并传 `expected`，走宿主审批，不复用旧版本绝对地址直接写入。未经目标执行授权不启动仿真或调试；商业引擎称 Reverse，开源结果保留 Ghidra/x64dbg 来源。

跨引擎对同 hash 交叉检视与跨版本比较是不同任务：前者按实际 provider 与 capabilities 读取 IR，`provider=ghidra` 的内置 Reverse 与显式 Ghidra 均可在能力支持时读 raw/high p-code；微码入口保留实际 stage 与兼容 maturity 映射，不能由 engine 标签推断专属微码能力。后者需独立 artifact 与各自静态地址。IR 表示不同不单独证明行为变化；当前没有 BSim 集成。`ig5_sync` 只复制同 hash 的显式名称/行尾注释/字节，不能用来直接把旧版本补丁同步到新版本。
