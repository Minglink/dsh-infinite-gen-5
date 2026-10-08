# DeepSeek Harness Plugin — 无限五代 / dsh-infinite-gen-5（v1.0.0）

统一 Reverse / Ghidra 静态分析与 x64dbg 无头调试工作台。完整目录为 36 个工具（22 只读、12 审批、2 生命周期/配置），默认注册 Core 8。插件不注入系统提示词；指导载体为工具描述、会话流卡片和五个原生技能。

## 接入架构

| 层 | 内容 |
|---|---|
| 宿主 | `index.js` 基于 Cordis 注册工具、独立引擎会话和后台分析作业；`installApprovalGate` 统一写操作审批及审计 |
| Reverse | `worker/ig5_worker.py`：独立 Python 子进程，stdio 单行 JSON-RPC、UTF-8 及日志隔离；仅使用用户已有本机授权商业安装，不随包、不称自研 |
| Ghidra | `adapters/ghidra/worker.py`：插件内 `runtimes/ghidra` 提供 Ghidra/JDK/Python；可写持久项目另存，提供真实 raw/high p-code |
| x64dbg | `adapters/x64dbg/adapter.py` 与自建 `ig5-native` SDK/NamedPipe bridge：headless 调试；不依赖 automate/ZeroMQ |
| 身份与路由 | `engine_runtime.js` 解析 runtime manifest；`source/project_store.js` 持久化工程、样本哈希、数据库 attachment/revision；`source/address_ref.js` 做显式地址映射 |
| 跨引擎 | `integration_tools.js` 提供 `ig5_ir` 与审批工具 `ig5_sync`；数据库独立，仅显式 changeset 传递选中的修改 |
| 内部端点 | `/ig5-diag` 诊断、`/ig5-jobs` 作业与会话快照、`/ig5-data` 工作台只读数据与调试缓存 |
| 原生界面 | `client.js` 注册工作台、输入徽章与原生 `openView` 焦点；使用 `--dsw-alias-*` CSS 变量；`ig5dash` 投影汇总工具状态 |
| 工作流 | `workflow.js` 注册五个 skills、`/ig5` 命令和 Core/Full 生命周期 |

## 工具面与审批

| 类别 | 工具 |
|---|---|
| 只读（22） | `ig5_doctor`、`ig5_open`、`ig5_status`、`ig5_funcs`、`ig5_strings`、`ig5_decompile`、`ig5_xrefs`、`ig5_calls`、`ig5_bytes`、`ig5_search`、`ig5_listing`、`ig5_scan`、`ig5_export_diff`、`ig5_cfg`、`ig5_slice`、`ig5_fingerprint`、`ig5_stack`、`ig5_switches`、`ig5_vtables`、`ig5_microcode`、`ig5_bindiff`、`ig5_ir` |
| 审批（12） | `ig5_rename`、`ig5_patch_bytes`、`ig5_comment`、`ig5_analyze`、`ig5_set_type`、`ig5_undo`、`ig5_run_idapython`、`ig5_dbg`、`ig5_struct`、`ig5_switch_repair`、`ig5_emulate`、`ig5_sync` |
| 生命周期/配置（2） | `ig5_close`、`ig5_profile` |

Core 8 为 `doctor/open/status/funcs/strings/decompile/close/profile`（均带 `ig5_` 前缀）。模型按需调用 `ig5_profile toolset=full`，用 `toolset=core` 恢复；不传参数只查询。用户入口 `/ig5 toolset full|core` 保持。切换是**插件实例级、非持久**，影响该实例所有会话；重载回到 `config.toolset`（默认 core）。不能把它当成按会话工具隔离或执行授权。

审批按工具名称拦截，要求真实活跃 agent/turn 审批通道；无通道或拒绝时不执行，成功调用后记录 `approvals.jsonl`。因此 `ig5_struct action=get|list`、`ig5_sync action=preview` 仍走工具级审批。工作台 HTTP 不构成写入通道。

`ig5_struct` 参数名是 **action**，调试器是 **op**。写工具可用 `expected_revision` 拒绝过期数据库计划。补丁 `expected` 是可选原字节条件，提供时前置比较并拒绝不匹配，工作流优先显式提供；拒绝未加载区域。Undo 依赖各后端操作日志，不能假设任意写入都有 Undo；switch repair 不在 Reverse `_op_journal` 范围内。导出读取当前数据库，尊重已执行 Undo。

## 三引擎使用与证据身份

静态工具通过 `engine=reverse|ghidra` 路由同一工具 schema；默认优先可用的已授权本机 Reverse，否则使用随包 Ghidra，用户可显式指定。`ig5_ir` 专用于 Ghidra raw/high p-code，Reverse 使用 `ig5_microcode`；两种 IR 不是相同成熟度或相同语义表示。后端能力以 `doctor/status` 的实际 capabilities 为准，不支持的能力明确拒绝。Ghidra 默认 `analysis_profile=interactive`，仅跳过批量 Decompiler Parameter ID 分析器，函数反编译仍可用；`full` 需显式选择。`ig5_open analysis_timeout` 设置 1–600 秒分析预算；超时返回 partial，不伪称分析完成。

```text
ig5_open path="C:\samples\app.exe" engine=ghidra analysis_profile=interactive analysis_timeout=120
ig5_profile toolset=full
ig5_decompile target="C:\samples\app.exe" engine=ghidra ea=0x140001000
ig5_ir target="C:\samples\app.exe" engine=ghidra ea=0x140001000 level=high max_instructions=120
ig5_dbg target="C:\samples\app.exe" engine=ghidra backend=x64dbg op=load
```

`open` 和调试 `load` 不启动样本；`start`、继续执行和仿真需要该目标的运行授权及宿主审批。`backend=x64dbg` 可从 Ghidra 静态会话发起独立调试 attachment；同一目标的调试控制有 owner/takeover 和可选 `expected_run_id/expected_stop_seq` 校验，切换 debugger 前先停止已有任务。

样本 SHA-256 决定 `artifactId`，路径移动可关联同一内容；修改后的文件是新 artifact。会话同时标识 `engine/projectId/artifactId/attachmentId/dbRevision`，不能把同路径不同引擎视作一个可写数据库。稳定数据库路径显式复用其持久修订，活跃 attachment 不暗中跨会话共享。64 位地址保持十六进制字符串；static VA/RVA/file offset、runtime VA、stack/register 等地址空间不混用。只有明确 image base、已加载模块和文件映射才转换，BSS 不伪造文件偏移；运行地址还需 runId、模块装载 epoch 和 stopSeq。

v1.0.0 的工程锁使用原子发布的完整 owner、PID/进程创建身份与 nonce；仅确认死亡或 PID 被复用时恢复，活锁及未知旧格式锁拒绝写入。释放和恢复保留同 nonce 非空 `.projects-stale-lock-*` 小目录，当前不自动删除；只可在宿主和相关 worker 全部停止后维护清理。未知 `projects.lock` 先人工确认无所有者再移走。物理数据库硬链接、目录别名维持同一修订及排他 attachment，未创建路径仍可注册；冲突历史记录拒绝猜测合并。file/RVA 映射来源和目的都须唯一，重叠区域拒绝转换。

Ghidra 全程序 `partial/analysisComplete` 与本次 `scopePartial/scopeComplete` 分开：范围分析完成不升级全程序完成状态或替换既有 profile。写入的 `committed` 表示内存事务已完成，`saved` 表示原生数据库保存已确认。rename/comment/patch 每次保存并用显式逆操作做会话 Undo；类型、结构体、分析写入为 `persistence=session-only`，用原生 Undo，正常 close 保存，后续保存可能使其原生 Undo 失效。

Ghidra 原生保存、intent、revision sidecar 与审计不是跨文件原子事务。`partial_commit`/`recoveryRequired` 必须连同 `committed/saved/stage/durableRevision` 解释，不能把错误当作未写入或自动回滚。强杀/硬超时可能丢失 session-only 修改；重开依据原生数据库 marker 对账并返回 recovery，不自动重放写入。恢复前检查数据库及未保存状态，不能直接重试同一变更。

## 显式跨引擎 changeset

仅支持**同一文件哈希**在 Reverse/Ghidra 数据库间按显式 RVA 单向复制名称、行尾注释与有限字节；不自动同步全部分析结果或结构体。两个目标均先打开。preview 保存前后值、数据库 attachment/revision 与 digest，apply 重新检查哈希、修订及所有原值。示例见 [README](README.md#三引擎工程与跨引擎修改计划)。

apply 锁定两个参与数据库的修改队列，逐条记录目的后端操作日志。失败返回已应用项和剩余项，`atomic=false`；remaining 仅表示未确认，失败原语也可能已提交，须核对 `failed.committed/saved/recoveryRequired` 并恢复目的数据库。已尝试计划不可重放，需要重新 preview。没有跨引擎全局原子 Undo；名称相同不证明类型或语义一致。

## 原生命令与工作台

```text
/ig5 status
/ig5 engines
/ig5 open --engine ghidra C:\samples\app.exe
/ig5 export --engine ghidra C:\samples\app.exe
/ig5 toolset [core|full]
```

命令只执行状态、静态打开和导出等分析操作，不能直接发起写工具。五个原生技能为 `ig5-triage`、`ig5-deep-dive`、`ig5-patch-and-sign`、`ig5-diff`、`ig5-debug-live`，随 skills/commands 服务注册并跟随卸载清理；工件哈希签收不是证书数字签名。

工作台静态选择器按 session key + target + engine 区分会话，展示来源和数据库修订，排除 x64dbg 调试会话。函数、调用、xref 与字符串引用使用原生 `openView` 焦点跳转，绑定样本身份；旧目标/引擎/修订响应不能覆盖当前视图。SVG CFG 支持缩放、拖拽、分支/回边和双击读取反汇编，最多绘制 300 块并提示截断。点击变量请求 focused slice 并高亮匹配行，不能把文本过滤当成完整数据流证明。

结构体新增/修改只生成包含 target/engine 的可编辑 composer 草稿，使用原生 `captureInsertion/insertText/persistDraft`，不 submit、不覆盖已有草稿；用户发送并审批后才生效。无原生接口时提供复制入口。审计使用真实 `args/detail/ts/isError`，按目标与引擎分页、刷新，sync 归属目的引擎，所有字段以文本渲染。Ghidra IR 页显示实际 p-code；运行态页只展示最近 x64dbg 缓存，不发起执行 RPC，切换目标/artifact/attachment 立即隐藏旧快照并拒绝迟到响应。

## 安装与便携 runtime

完整发行包默认在插件根目录包含 `runtimes/ghidra`、`runtimes/x64dbg`，运行不依赖外部 `.dsh/ig5/runtimes`。直接执行 `.\install.ps1` 离线校验、暂存并安装整包，备份已有插件和更新 profile；缺件或哈希不符时拒绝安装。`-RuntimeSource` 保留为显式导入其他已校验包的维护入口，用户无需另跑 setup。`.\uninstall.ps1` 卸载插件。

Ghidra runtime 包含自身 Ghidra/JDK/Python，x64dbg runtime 包含 x86/x64 debugger/Python/native bridge；不修改 Reverse 安装、全局 Python 或引擎 site-packages。`scripts/setup_ghidra_runtime.ps1`、`scripts/setup_x64dbg_runtime.ps1` 是维护者联网重建资产的脚本，不是默认安装前置依赖。`scripts/package_portable.ps1` 生成自包含目录及文件大小/SHA-256 清单；不附带 DSH、商业 Reverse 程序、用户项目或缓存，用户项目需单独备份；`-IncludeProjects` 明确拒绝。当前远端仓库尚未发布这些本轮资产，不能把原 GitHub 下载当作已包含完整运行件的发行包。

`third_party/sources/ghidra-master`、`x64dbg-development` 保留桌面原档主体，`x64dbg-runtime` 另存运行版固定提交及递归 gitlinks。来源、archive/hash、逐文件校验、materialize 的相对链接和已知缺件见 [源码清单](third_party/sources/manifest.json)。桌面 Ghidra 是 12.3 DEV，运行版是官方 12.1.4；development 的原提交及 gitlinks 未知，其固定补充来源明确记录，均不冒称由这些桌面源码编译运行包。IG5 适配上游 Java/C++ 引擎，不是重写；完整源码归档也不意味着随包包含全部离线重编工具链、构建缓存或已暴露上游每项功能。

分发保留[第三方许可清单](THIRD_PARTY_NOTICES.txt)与各依赖许可证。项目自有代码采用 CC BY-NC-SA 4.0，第三方源码/运行组件继续适用各自许可，不受项目 NC 条款覆盖。

| 配置 | 用途 |
|---|---|
| `reverse` | `false` 可关闭 Reverse，Ghidra-only 模式无需商业安装 |
| `defaultEngine` | 默认静态后端 `reverse` 或 `ghidra` |
| `defaultDebugger` | 默认调试路由，可显式选 `x64dbg`；不隐式运行样本 |
| `runtimeRoot` / `IG5_RUNTIME_ROOT` | 显式覆盖 runtimes 根目录；未覆盖时使用插件内 `runtimes` |
| `ghidraRuntime` / `IG5_GHIDRA_RUNTIME` | Ghidra runtime.json 路径 |
| `x64dbgRuntime` / `IG5_X64DBG_RUNTIME` | x64dbg runtime.json 路径 |
| `projectRoot` | 项目身份、修订与 changesets；默认 `~\.dsh\ig5\projects` |
| `idaDir` / `IG5_IDA_DIR` | 已有 Reverse 安装目录，内部兼容名称 |
| `pythonExe` | Reverse Worker 使用的 Python 可执行文件 |
| `requestTimeoutMs` / `openTimeoutMs` | 普通/打开任务超时，默认 240000 / 1800000 毫秒 |
| `maxSessions` / `artifactDir` | 默认 3 个会话；产物默认 `~\.dsh\ig5\artifacts` |
| `backgroundOpen` / `autoOpenHint` | 默认 true；后台打开与提示 |
| `toolset` | 启动工具面，默认 core，可设 full |

## 开发与验证 SOP

所有修改在 `C:\Users\Administrator\Desktop\无限五代\dsh-infinite-gen-5` 源码目录完成，禁止修改运行副本。依次执行全部项目 JS 语法检查、全部 Python 编译检查、`node scripts/test_new_tools.mjs`、Robocopy 镜像同步、重启宿主及本次启动日志核查。完整命令和 npm 回归范围见 [README](README.md#开发验证与同步-sop)。日志是 `~\.dsh\ig5\artifacts\ig5-diag.log`；核对三个端点、审批门和客户端挂载。

## 已验证范围

- **Ghidra/集成**：真实 Ghidra-only doctor/open/函数/只读 HTTP/p-code、写入持久化/缓存失效、过期修订拒绝、同修订并发写入与重开数据库修订；同 hash 双引擎独立数据库，changeset 名称/注释/字节、digest/重复/过期拒绝、导出及 Undo 回归通过。真实 notepad interactive 分析约 85 秒、853 函数、无超时，分析后 decompile 子进程数为 0；不是任意样本性能保证。分析预算到期时明确标记 partial，仍可读取已完成结果；没有 BSim 集成或跨引擎语义等价证明。
- **x64dbg**：原生 SDK+NamedPipe headless bridge 已通过中文路径生成 PE 的 start、ASLR/RVA 断点、regs/readmem/modules、step/setreg、5 步受限 trace、RIP=0 的结构化访问违规；公开工具链已通过 owner/takeover/过期 run/stop 拒绝、缓存 HTTP、stop/dispose。x64/x86 均已分别通过真实 headless 完整闭环；14 项 fake 回归、命名管道 DACL、取消/超时/强杀清理均通过。生成 PE 的证据不外推任意样本。
- **Reverse 调试**：native win32 在 notepad 副本完成 start→ASLR 入口断点→寄存器读写→step→注释/Undo→故意访问违规→恢复→stop。Bochs 仍仅 load/bpt 通过，不能声称真实运行闭环通过。
- **微码**：原生 filter 管线与构造真实临时 MBA 的受限 xor-self/sub-self 改写已验证；自然夹具仍 rule_hits=0，未实现通用去平坦化。
- **RTTI/diff/仿真**：MSVC64 与 Itanium class/SI/VMI 字节布局已在生成 PE 验证，非原生 Linux ELF 验证；虚槽要求显式 table+offset。bindiff 为带歧义/截断的启发式与变更块，不是语义等价/漏洞证明。Unicorn 2.1.4 仅 x86/x64、最多复制 64 MiB，无 OS/import/TLS，报告返回/内存/超时/fault；保留 [NOTICE](worker/vendor/NOTICE.txt) 及 [依赖锁定](worker/requirements-emulation.txt)。
- **身份/前端**：store 20 项、address 11 项与 client 24 项回归通过，含真进程活锁/崩溃/竞争恢复、确定性延迟恢复、硬链接/目录别名、双向映射重叠与运行态快照切换；三项恢复竞争用例连续五轮通过，真实 Ghidra-only 与双静态引擎集成回归通过。使用安装版 DSH React 的浏览器 fixture 已通过，fixture 不替代真实调试证据。

对外商业引擎统一称 **Reverse**，不输出其版本或带版本安装路径；保留 `ig5_run_idapython`、`IG5_IDA_DIR` 等兼容 API/配置名。Schema 必填放父级 `required: [...]`，不得在 property 写 `required: true`。
