# DeepSeek Harness Plugin — 无限五代 / dsh-infinite-gen-5（v0.9.0）

纯逆向插件：Reverse 无头引擎、34 个 `ig5_*` 工具的完整目录、后台分析作业、五个原生技能包与六标签逆向工作台。默认注册 Core 8 工具，Full 模式注册全部 34。插件不注入系统提示词；指导载体为工具描述、会话流卡片与原生技能。

## 接入架构

| 层 | 内容 |
|---|---|
| 宿主 | `index.js` 基于 Cordis 注册工具；`WorkerManager` 管理会话池与后台作业，`installApprovalGate` 统一处理写操作审批和审计 |
| 引擎 | `worker/ig5_worker.py` 为每个目标运行独立 Python 子进程；使用 stdio 单行 JSON-RPC、UTF-8 通信及日志隔离；大伪代码落盘 artifacts |
| 内部端点 | `/ig5-diag`：诊断日志；`/ig5-jobs`：后台作业进度；`/ig5-data`：工作台只读数据 |
| 会话投影 | `ig5dash` 汇总 `tool/call` 与 `tool/result`，提供调用状态和计数 |
| 客户端 | `client.js` 注册逆向工作台与输入框状态徽章，使用 DSH 原生 `--dsw-alias-*` CSS 变量 |
| 工作流 | `workflow.js` 注册五个 skills 与 `/ig5` 原生命令，管理 Core/Full 工具面和卸载清理 |
| 高级分析 | `advanced_tools.js`、`semantic_diff.js` 与 Worker 分析模块提供栈帧、跳转表、RTTI、微码、差异与函数仿真 |

## 34 个工具与审批规则

| 类别 | 工具 |
|---|---|
| 只读分析（21） | `ig5_doctor`、`ig5_open`、`ig5_status`、`ig5_funcs`、`ig5_strings`、`ig5_decompile`、`ig5_xrefs`、`ig5_calls`、`ig5_bytes`、`ig5_search`、`ig5_listing`、`ig5_scan`、`ig5_export_diff`、`ig5_cfg`、`ig5_slice`、`ig5_fingerprint`、`ig5_stack`、`ig5_switches`、`ig5_vtables`、`ig5_microcode`、`ig5_bindiff` |
| 写操作审批门（11） | `ig5_rename`、`ig5_patch_bytes`、`ig5_comment`、`ig5_analyze`、`ig5_set_type`、`ig5_undo`、`ig5_run_idapython`、`ig5_dbg`、`ig5_struct`、`ig5_switch_repair`、`ig5_emulate` |
| 生命周期/配置（2） | `ig5_close`、`ig5_profile` |

审批门按工具名称拦截上述 11 个工具，执行前请求一次批准，执行后写入 `approvals.jsonl`。`ig5_struct` 使用 **`action=define|get|list|apply`**，不要写 `op`；其中 `get`、`list` 的分析含义是只读，但仍经过工具级审批门。结构体示例：

```text
ig5_struct action=define decl="struct Packet { int id; char payload[32]; };"
ig5_struct action=get name=Packet
ig5_struct action=list filter=Packet
ig5_struct action=apply name=Packet ea=0x140010000
```

Undo 依赖 `_op_journal` 自管操作日志；switch repair 不在该回滚范围。`ig5_patch_bytes` 提供可选 `expected` 时先比较并拒绝不匹配，工作流优先显式提供；始终拒绝未加载区域。`ig5_export_diff` 读取当前数据库中的补丁状态，尊重已完成的 Undo，runtime 回归已覆盖该行为。

## Core / Full 与原生工作流

Core 的 8 个入口为 `ig5_doctor`、`ig5_open`、`ig5_status`、`ig5_funcs`、`ig5_strings`、`ig5_decompile`、`ig5_close`、`ig5_profile`。模型按需先调用 `ig5_profile toolset=full` 注册完整 34 个工具，`ig5_profile toolset=core` 恢复 Core；不传 `toolset` 只查询。用户 `/ig5 toolset full|core` 切换和 `/ig5 toolset` 查询入口保持可用。真实回归已覆盖 full→core8（写工具注销）→full34。

此切换属于**插件实例**，影响该实例的所有会话；不按会话隔离，不持久化到 `cordis.yml`。重载时回到 `config.toolset` 指定值（默认 `core`）。它只配置工具面，不构成样本执行授权，不改变任何写工具的宿主审批要求。

原生 `/ig5` 命令支持：

```text
/ig5 status
/ig5 open <样本绝对路径>
/ig5 export [目标绝对路径]
/ig5 toolset [core|full]
```

`export` 未给路径时要求恰有一个活跃目标。命令仅直接执行状态、打开和导出等只读分析操作，不能直接发起写工具。原生技能 `ig5-triage`、`ig5-deep-dive`、`ig5-patch-and-sign`、`ig5-diff`、`ig5-debug-live` 已实现，随 skills/commands 服务可用时注册，并跟随插件生命周期清理。`patch-and-sign` 的工件哈希签收不等于证书数字签名。

## 工作台交互

- CFG 使用无 CDN 依赖的原生 SVG，展示基本块、分支和回边，支持缩放、拖拽及双击基本块读取 `type=disasm`；Mermaid 源码仍可复制。图形绘制上限为 300 块，超限提示截断。
- 点击局部变量调用带 `var` 的 focused slice，高亮标识符匹配行；函数/目标切换使旧请求结果失效。匹配行过滤不等于完整数据流证明。
- 结构体新增/修改表单加载 C 声明并生成可编辑 `ig5_struct` 草稿；通过原生 composer 的 `captureInsertion/insertText/persistDraft` 插入，不调用 `submit`。用户仍需发送并通过审批门；接口不可用时提供复制草稿。`/ig5-data` 仅允许结构体 `list/get`，无写入旁路。
- 审计使用真实 `args/detail/ts/isError`，按当前目标过滤、分页和刷新，正确显示偏移 `0`，所有内容以文本渲染。

上述交互已通过使用安装版 DSH 内置 React 的真实浏览器 fixture 预览，并有客户端 renderer/异步竞态回归；只读分析后端另有真实引擎集成回归。`ig5_fingerprint` 与 `ig5_funcs user_only=true` 继续提供 ABI 信息和库函数过滤。

## 引擎引导与配置

保留现有配置标识，用户可通过 `config.idaDir` 或 `IG5_IDA_DIR` 指定 Reverse 安装目录；未指定时 Worker 启动配置会尝试发现本机安装。Python 优先使用 `config.pythonExe`，其次使用安装目录中的 `python311\python.exe`，最后尝试 `python`。插件通过 `IDADIR` 和 Python 搜索路径引导引擎库，不修改引擎安装目录。

`cordis.yml` 插件行可配置：

| 配置项 | 默认/用途 |
|---|---|
| `idaDir` | Reverse 安装目录；可由 `IG5_IDA_DIR` 或自动探测提供 |
| `pythonExe` | Python 可执行文件绝对路径 |
| `requestTimeoutMs` | `240000`，普通请求超时 |
| `openTimeoutMs` | `1800000`，打开/长任务超时 |
| `maxSessions` | `3`，会话池上限 |
| `artifactDir` | `~\.dsh\ig5\artifacts`，日志与交付物 |
| `backgroundOpen` | `true`，默认后台打开并分析 |
| `autoOpenHint` | `true`，自动打开提示 |
| `toolset` | `core`，启动时注册 8 个入口；`full` 注册完整 34 工具 |

## 安装与开发 SOP

首次安装运行 `.\install.ps1`，卸载运行 `.\uninstall.ps1`。安装脚本写入宿主插件目录和 profile 配置，重启 Harness 后生效。

所有修改必须在 `C:\Users\Administrator\Desktop\无限五代\dsh-infinite-gen-5` 源码目录完成。每次调整后严格执行：

1. 对项目全部 `.js/.mjs/.cjs` 运行 `node --check`，使用宿主配置的 Python 对全部项目 `.py` 运行 `-m py_compile`。
2. 运行 `node scripts/test_new_tools.mjs`，失败则停止发布。
3. 核对绝对路径后，通过 `robocopy /MIR /FFT /Z /NP` 镜像源码到 `C:\Users\Administrator\.dsh\plugins\dsh-infinite-gen-5`，仅接受退出码 `0–7`。
4. 重启 DeepSeek Harness，重新加载插件。
5. 检查 `C:\Users\Administrator\.dsh\ig5\artifacts\ig5-diag.log` 本次启动的三个端点、审批门及客户端挂载记录。

完整 PowerShell 命令见 [README.md 的开发验证与同步 SOP](README.md#开发验证与同步-sop)。测试样本为 `C:\Users\Administrator\Desktop\无限五代\_research\fixtures\notepad.exe`。安装后可先调用 `ig5_doctor`，再使用 `ig5_open` 打开样本，核对工作台作业进度、工具卡与数据展示。

## 验证状态与能力边界

- **原生调试**：native win32 已在 notepad 副本上完成真实 `start`、ASLR 入口断点、寄存器读写、`step`、注释回写与 Undo、故意访问违规的结构化异常上下文、恢复和 `stop` 闭环。`scripts/test_debug_runtime.mjs` 默认验证 win32；指定 `IG5_DEBUG_BACKEND=bochs` 才验证 Bochs。Bochs 仍仅 `load/bpt` 通过，尚无真实 `start` 闭环，不能混用两个后端的验证结论。
- **微码**：原生 filter 管线、多级真实 IR 与临时 IR optimize 已验证，optinsn 仅支持受限 `xor-self/sub-self` 规则。隔离构造的真实临时 MBA 对两种规则各命中 1 次，生成 `mov #0`、清空源并保留目的；原生优化、verify 与 finally 规则清理通过，IDB 字节不变。自然夹具自定义规则仍 `rule_hits=0`，不能声称自然函数发生规则改写；未实现通用去平坦化。
- **虚表与 RTTI**：MSVC64 继承和 Itanium class/SI/VMI 的真实字节布局已在生成 PE 夹具中验证，未验证原生 Linux ELF 装载。调用解析使用显式 `table+offset`，不自动推导寄存器来源。
- **差异分析**：`ig5_bindiff` 是多特征启发式，输出变更块、歧义及截断信息；生成 PE 夹具中的 `[rcx+4]` → `[rcx+8]` 已验证 matched+changed 和变更块。不证明语义等价或自动确认漏洞。
- **仿真**：插件 vendored Unicorn 2.1.4 仅支持 x86/x64，内存复制上限 64 MiB，提供返回值、内存捕获和超时/fault；无 OS/import/TLS 仿真，不修改引擎 site-packages。Windows x64 wheel 与哈希见 [requirements-emulation.txt](worker/requirements-emulation.txt)，随插件保留的上游许可证见 [NOTICE.txt](worker/vendor/NOTICE.txt)。
- **跳转表修复**：默认 preview，`apply=true` 走审批门；变更不在 `_op_journal` Undo 范围内，应用前核对所有分支目标。

回归命令和具体范围见 [README.md 的回归命令概览](README.md#回归命令概览)。真实引擎/仿真/调试测试使用生成 PE 或 notepad 副本，不能将 fixture 通过扩大为任意样本或格式均通过。

对外引擎称谓统一为 **Reverse**；不得在界面或工具说明中输出底层商业引擎版本。`ig5_run_idapython` 等 API 名称与 `IG5_IDA_DIR` 等配置名保持兼容。Schema 属性内不得使用 `required: true`，必填参数放在父级 `required: [...]` 数组中。
