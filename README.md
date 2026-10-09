# ⚒️ DeepSeek Harness AI 驱动专业逆向工作台（无限五代 ∞ IG5）v1.0.0
（本工具仅限用于合法授权的软件逆向工程、安全审计与学术研究）

本轮重构继续保持 **1.0.0**：抽出公共 worker 通信与内存仿真核心，维护固定版本的 Ghidra / x64dbg 源码构建，增加真实硬件断点回归，并优化手机宽度下的工作台。完整 Windows 包包含本地运行依赖，无需用户另行安装 Java、Python 或调试器。

首次使用：解压完整包 → `plugin/install.ps1` → 重启 DSH → `/ig5 engines` → `/ig5 open --engine ghidra <路径>`。高级功能通过 `/ig5 toolset full` 展开。仓库源码、便携发行包和手机原生执行包是不同交付物；当前已验证的发行平台为 **Windows x64**。

- [重构后的模块与能力边界](docs/ARCHITECTURE.md)
- [固定源码构建、验证与部署](docs/BUILD.md)
- [Android / iOS 本地离线运行的实际进度](docs/MOBILE.md)

<p align="center">
  <img src="assets/banner.png" alt="无限五代 IG5 · AI 驱动的专业逆向工作台" width="100%" />
</p>

<p align="center">
  <a href="#local-install">
    <img src="https://img.shields.io/badge/DeepSeek%20Harness-📦%20本地自包含安装-10B981?style=for-the-badge&logo=deepseek&logoColor=white" alt="本地自包含安装" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/开源协议-CC%20BY--NC--SA%204.0-brightgreen?style=for-the-badge" alt="CC BY-NC-SA 4.0 协议" />
  </a>
  <img src="https://img.shields.io/badge/项目性质-非盈利开源公益-blue?style=for-the-badge" alt="非盈利开源公益项目" />
</p>

> 🌐 **插件生态市场**：[DeepSeek Harness Hub - DeepSeek 官方与开源生态市场 | 插件发现与一键安装](https://deepseek.stream/)

> ## 💬 DeepSeek 交流群 & 社区
>
> ### 👉 **红队安全交流 9 群：`338431075`**
> ### 👉 **腾讯频道技术交流社区：`pd86424753`**
>
> 🔥 欢迎进群交流 AI 辅助逆向工程心得、二进制安全审计经验、软件漏洞分析基准与大模型逆向工具生态共建！

---

## 🚀 项目定位与五代革命性升级

**无限五代（dsh-infinite-gen-5 / IG5）** 是专为 **DeepSeek Harness (DSH)** 桌面客户端打造的高性能、无头**纯逆向分析插件与可视化工作台系统**。

完整本地发行包内含 Ghidra、x64dbg 的可运行依赖、固定上游源码、IG5 维护补丁与源码构建证据，安装后无需再运行 setup 或安装全局 Java/Python。本轮实际重建 Ghidra 12.1.4 的完整 Java 框架、PyGhidra、原生反编译 / Sleigh 组件，以及 x64dbg x86 / x64 无头核心。Ghidra 来自固定 12.1.4 tag 的本地 DEV 发行构建；保留的预编译第三方依赖与工具链边界见 BUILD 文档。IG5 的宿主、工作台、身份模型、审批与两引擎的执行协议统一维护。Reverse 使用用户已有的本机授权安装，程序和许可证不随包提供；DeepSeek Harness 仍需另行安装。

与上一代以提示词注入为主的形态不同，五代彻底实现了从“脚本封装”向**“专业级全功能 Agent 逆向工作站”**的本质蜕变：
* **零提示词常驻占领**：不侵占全局系统提示词，彻底杜绝大模型在日常对话中的偏见与输出畸变；
* **36 项专业逆向工具面**：覆盖从二进制快速侦察、CFG 拓扑、符号与结构体、微代码与 Ghidra p-code，到受限函数仿真、x64dbg 原生调试和跨引擎修改计划；
* **双模式动态降噪**：默认仅加载 **Core 8 核心工具**，减少常驻工具描述开销；高级场景按需展开为 **Full 36 全景工具**；
* **人机协作安全审批门**：写操作（打补丁、重命名、写回数据库）强制弹窗由人工确认，自建操作日志覆盖部分数据库修改，具体 Undo 范围以各后端为准；
* **现代化交互式工作台**：原生注入 DSH 桌面端，包含富交互 SVG CFG（平移/缩放/双击汇编跳转）、局部变量切片高亮、在线 C 结构体声明草稿箱与真实审计时间线。

---

> ### ⚖️ 严正法律免责与合规使用声明（Strict Legal & Compliance Disclaimer）
>
> **【合规与合法使用严正申明】**：本项目坚决反对并严禁任何形式的违法犯罪行为！本项目开发者绝不支持、不鼓励、不协助任何未授权漏洞挖掘、黑灰产破解、非法获取计算机信息系统数据或破坏计算机信息系统的活动。
>
> 1. **合法受控范围限定**：本项目定位为面向安全研究员、逆向工程师、高校师生及企事业单位的**辅助逆向工程科研工具与防御性软件安全审计套件**。使用本工具必须严格遵守《中华人民共和国网络安全法》、《中华人民共和国数据安全法》、《中华人民共和国计算机软件保护条例》及相关司法解释。**严禁在未经软件著作权人或资产所有者合法书面授权的目标、商业软件或生产系统上运行本项目**。一切逆向与调试行为必须严格限制在自有软件、授权网络安全演练靶标、开源软件审计及合规教学科研环境中进行。
> 2. **严禁违法恶意用途**：使用者严禁利用本项目直接或间接从事：
>    - 破解侵犯正版软件版权、绕过数字版权管理（DRM）或商业授权验证机制；
>    - 分析、提取或利用漏洞编写武器化恶意载荷、病毒木马或勒索软件；
>    - 逆向分析特定受保护的关键信息基础设施系统并实施未授权入侵或窃密；
>    - 违反相关大模型提供商的《服务条款（Terms of Service）》与《滥用政策（Usage Policy）》。
> 3. **开源协议与严格非商用限制（CC BY-NC-SA 4.0）**：本项目依据 **CC BY-NC-SA 4.0（署名-非商业性使用-相同方式共享 4.0 国际开源协议）** 及严禁商用特别条款“按现状（AS-IS）”提供。**严禁任何个人、企业或第三方将本项目（或二次开发衍生版本）用于商业售卖、付费倒卖、商业培训封装或黑灰产牟利，二次开发商用属于严重违法违规行为**。使用者应对自身的所有下载、部署、运行、修改、传播行为以及由此产生的全部输入与输出后果承担独立、完全的法律责任。项目作者与贡献团队绝不承担任何因使用者滥用导致的直接、间接或连带责任。
> 4. **第三方独立性声明**：本项目属于完全独立的开源逆向辅助工具研究项目，与 DeepSeek 官方或其关联主体无任何隶属、商业合作或官方背书关系。

---

## 🧰 工具面与能力矩阵（22 只读 + 12 审批 + 2 配置）

五代提供完整的 36 项逆向工具，并采用 **Core / Full 智能分级机制**：

| 类别 | 数量 | 工具清单 | 典型功能说明 |
| :--- | :---: | :--- | :--- |
| **只读分析面** | 22 | `ig5_doctor`, `ig5_open`, `ig5_status`, `ig5_funcs`, `ig5_strings`, `ig5_decompile`, `ig5_xrefs`, `ig5_calls`, `ig5_bytes`, `ig5_search`, `ig5_listing`, `ig5_scan`, `ig5_export_diff`, `ig5_cfg`, `ig5_slice`, `ig5_fingerprint`, `ig5_stack`, `ig5_switches`, `ig5_vtables`, `ig5_microcode`, `ig5_bindiff`, `ig5_ir` | 覆盖段熵扫描、反编译、交叉引用、控制流拓扑、局部变量切片、虚表RTTI解析、微代码IR提取、跳转表恢复与多特征启发式差异比对 |
| **写操作审批门** | 12 | `ig5_rename`, `ig5_patch_bytes`, `ig5_comment`, `ig5_analyze`, `ig5_set_type`, `ig5_undo`, `ig5_run_idapython`, `ig5_dbg`, `ig5_struct`, `ig5_switch_repair`, `ig5_emulate`, `ig5_sync` | 上述工具按名称经过宿主审批（含 sync preview），执行后登记审计；拒绝或无审批通道时不执行；包含 NOP/字节补丁、C 结构体应用、内存仿真与调试交互 |
| **生命周期/配置** | 2 | `ig5_close`, `ig5_profile` | 会话安全关闭与工具集热切换（Core 8 ↔ Full 36） |

### 💡 Core 8 与 Full 36 动态降噪架构
* **Core 8 默认模式**：日常对话中仅注册 `ig5_doctor`、`ig5_open`、`ig5_status`、`ig5_funcs`、`ig5_strings`、`ig5_decompile`、`ig5_close`、`ig5_profile` 8 个工具，减少模型常驻工具上下文。
* **Full 36 展开模式**：遇到深水区分析时，模型可自动调用 `ig5_profile toolset=full`，或由用户在聊天框直接输入命令切换：
  ```text
  /ig5 toolset full   # 展开为全量 36 个专业工具
  /ig5 toolset core   # 恢复为轻量 8 工具省 Token 模式
  ```

---

## 🌟 核心高阶技术亮点

### 1. 交互式 SVG 控制流图 (CFG) 与变量切片
* **富交互画布**：工作台内置高性能原生 SVG 渲染引擎，支持鼠标平移（Pan）、滚轮缩放（Zoom），清晰标明分支与回边。
* **双击汇编跳转**：在流程图上双击任意基本块，即可直接呼出该块的只读反汇编指令检视窗。
* **局部变量切片**：点击变量读取匹配代码行并高亮标识符；这是焦点行过滤，不代表完备的定义使用链或污点分析。

### 2. 轻量纯内存单函数仿真执行 (`ig5_emulate`)
* **内置 Unicorn 2.1.4 引擎**：无需安装庞大的外部依赖，零环境污染。
* **受限函数执行**：Reverse 与 Ghidra 通过公共内存映像提供器执行 x86/x64，Ghidra 另支持 ARM64 / AAPCS64；内存复制上限 64 MiB，可设置参数和指令/时间预算，捕获返回值、内存和 fault。无 OS/import/TLS 环境，不能外推真实进程行为。ARM64 样本在 Windows 宿主仿真通过，不代表 Android 原生运行包已完成。

### 3. Reverse Win32 与 x64dbg 原生调试车道 (`ig5_dbg`)
* Reverse native win32 与自建 x64dbg SDK/NamedPipe headless bridge 已分别验证真实 start、ASLR/RVA 断点、寄存器读写、step 与结构化异常；两条后端证据分别记录。Bochs 仍只有 load/bpt 通过。
* x64dbg 已分别验证 x64/x86 的真实 headless 闭环，其中 x64 中文路径 PE 覆盖受限 5 步 trace、控制 owner/takeover、过期 run/stop 拒绝、缓存读取与 stop/dispose；不使用 automate/ZeroMQ。load 不启动样本，执行需目标运行授权和审批。

### 4. C++ 虚函数表 (vtables) 与跳转表 (Switches) 恢复
* 支持 MSVC64 与 Itanium class/SI/VMI RTTI 布局检视；已验证生成 PE 夹具，未验证原生 Linux ELF 装载，调用解析要求显式表地址和偏移。
* 读取已识别跳转表的分支信息；修复默认 preview，应用需审批且不在 Reverse 操作日志的 Undo 范围。

---

<a id="local-install"></a>

## ⚡ 本地自包含安装

需要 Windows x64 和已安装的 DeepSeek Harness profile。完整包包含插件、两套开源运行依赖和上游源码；当前远端仓库尚未发布本轮自包含资产，不将原 GitHub/master 下载作为完整发行包入口。

从便携包根目录可直接运行 `.\plugin\install.ps1`；以下步骤从包内 plugin 目录或源码交付根目录执行。

1. 将完整发行包解压到本地，保留同目录的 `runtimes/`、`third_party/sources/` 与清单文件；
2. 打开 PowerShell，进入完整包的 `plugin` 目录（源码交付则进入项目根目录）；
3. 执行一键安装脚本：
   ```powershell
   .\install.ps1
   ```
4. 脚本离线核验完整运行包，暂存插件及内置依赖，备份已有插件并配置 profile；缺件或校验失败时拒绝安装；
5. 重启 DeepSeek Harness；使用 `/ig5 engines` 或 `ig5_doctor` 检查实际引擎可用性。

---

## 三引擎工程与跨引擎修改计划

v1.0.0 保留同一工具面，通过 `engine=reverse|ghidra` 选择静态来源；`backend=x64dbg` 选择独立动态后端。`ig5_ir` 提取 Ghidra raw/high p-code；`ig5_microcode` 提取 Reverse 微码，两种 IR 不当成相同成熟度。先用 `ig5_profile toolset=full` 启用所需高级工具。Core/Full 是插件实例级、非持久切换，影响该实例全部会话；它不授权样本执行，也不豁免写审批。

每个会话返回 engine、projectId、artifactId、attachmentId 与 dbRevision。SHA-256 识别样本内容，路径移动可关联原 artifact；新内容形成新 artifact。两引擎数据库独立，活跃数据库不暗中跨 session 共享。工作台按 session key + 路径 + 引擎选择并显示来源；原生地址跳转还绑定样本身份。64 位 VA/RVA/file/runtime 地址保持十六进制字符串，只有明确基址与已加载映射才转换，BSS 不伪造文件偏移。运行地址还需 runId、moduleLoadEpoch、stopSeq，不能复用旧暂停上下文。

v1.0.0 修复工程锁崩溃恢复、物理数据库别名排他、双向地址映射歧义和运行态页旧快照串目标的问题。文件锁按 PID、进程创建身份与 nonce 核验；活锁或无法确认的旧格式锁保持拒绝写入，不按年龄猜测删除。数据库硬链接与目录别名保持同一修订和排他 attachment，已注册但尚未创建的数据库路径仍受支持。file/RVA 转换要求来源和目的均唯一，重叠映射拒绝转换。

锁的正常释放和崩溃恢复均保留 `.projects-stale-lock-<nonce>/owner.json` 小记录，防止延迟恢复者误移新锁；当前不自动清理。仅在确认宿主及相关 worker 全部停止后维护清理这些历史目录。未知 `projects.lock` 需先核实无存活所有者，再人工移走，不能在运行中直接删除。

以下为同一文件分别打开后的调用示例，地址与计划 ID 需替换为实际证据：

```text
ig5_open path="C:\samples\app.exe" engine=reverse
ig5_open path="C:\samples\app.exe" engine=ghidra analysis_profile=interactive analysis_timeout=120
ig5_ir target="C:\samples\app.exe" engine=ghidra ea=0x140001000 level=high max_instructions=120
ig5_sync action=preview target="C:\samples\app.exe" source_engine=reverse destination_engine=ghidra selections=[{"kind":"rename","rva":"0x1000"},{"kind":"comment","rva":"0x1000"},{"kind":"patch","rva":"0x1010","size":2}]
ig5_sync action=apply target="C:\samples\app.exe" plan_id="<preview返回的ID>" plan_digest="<已审阅digest>"
```

`ig5_sync` 的 preview/apply 都经过宿主审批，只在同 hash 两个数据库间单向复制显式选中的名称、行尾注释和字节，不自动全量同步或同步类型。apply 重新核对 hash、attachment、修订与所有前后值，两个数据库修改队列共同加锁。部分失败返回 applied/remaining、`atomic=false`；remaining 是未确认项，失败项也可能已提交，应查看 `failed.committed/saved/recoveryRequired` 并恢复目的数据库，不能直接重试。已尝试计划不可重放，需要重新 preview，没有跨引擎全局 Undo。普通写工具的 `expected_revision` 可拒绝过期计划；补丁 `expected` 可选，建议显式提供，提供后必须前置比较。

结构体参数使用 `action=define|get|list|apply`，调试使用 `op`。结构编辑器仅插入含 target/engine 的可编辑 composer 草稿，保留现有输入，不自动发送；用户发送并审批后才生效。CFG 双击、字符串引用和调用关系可原生跳转；Ghidra 页显示真实 p-code；运行态页只读最近 x64dbg 缓存，不执行 RPC。审计按目标和引擎分页、刷新，sync 归属目的引擎，文本转义避免 HTML 注入。

### 自包含 runtime、上游源码与离线安装

完整发行包的插件根目录直接包含 `runtimes/ghidra` 与 `runtimes/x64dbg`。Ghidra 包含自身 JDK/Python，x64dbg 包含自身 Python、x86/x64 debugger 与自建 `ig5-native` bridge；默认安装直接带入插件，运行不依赖外部 `~\.dsh\ig5\runtimes`，不改全局 Python、系统 PATH 或引擎 site-packages。默认优先使用可用的已授权本机 Reverse；没有该引擎时选随包 Ghidra，也可显式指定 `engine=ghidra|reverse`。`reverse:false` 可禁用 Reverse。`runtimeRoot`、`ghidraRuntime` / `IG5_GHIDRA_RUNTIME`、`x64dbgRuntime` / `IG5_X64DBG_RUNTIME` 保留显式外置覆盖，`projectRoot` 与可写工程缓存仍与分发资产分开。Reverse 兼容配置 `idaDir` / `IG5_IDA_DIR`、`pythonExe` 保留。完整配置见 [HARNESS_PLUGIN.md](HARNESS_PLUGIN.md#安装与便携-runtime)。

```powershell
# 完整包内直接离线安装，不需要另跑 setup
.\install.ps1
# 维护者重新生成含文件 SHA-256 清单的自包含目录
.\scripts\package_portable.ps1
```

`setup_ghidra_runtime.ps1` 与 `setup_x64dbg_runtime.ps1` 是维护者联网重建运行资产的脚本，不是用户安装前置步骤。`-RuntimeSource` 仅用于显式导入其他已校验运行包。完整包不含 DSH、商业 Reverse 程序、用户项目或缓存；用户工程应单独备份，打包脚本拒绝 `-IncludeProjects`。

上游源码归档位于 `third_party/sources/ghidra-12.1.4`、`ghidra-master`、`x64dbg-development` 与 `x64dbg-runtime`，来源、固定提交/gitlinks、逐文件 SHA-256、符号链接 materialize 记录及已知缺件见 [源码清单](third_party/sources/manifest.json)。随包 Ghidra 来自固定 `Ghidra_12.1.4_build` 源码的本地完整 DEV 构建，包含 Java 分析框架、PyGhidra 与自编译 native 核心；`ghidra_12.1.4_PUBLIC` 目录名仅为兼容别名。桌面原档 `ghidra-master` 是单独保留的 12.3 DEV 研究资料。x64dbg 的 x86/x64 无头核心、bridge、dbg、loaddll 与 TitanEngine 已按固定修订及维护补丁重建；GUI 与列明的链接依赖仍为预编译资产。development 原档缺少提交信息，其补充子模块采用清单中明确记录的固定运行版修订，不冒称原 development gitlinks。构建步骤和证据见 [BUILD](docs/BUILD.md)；用户运行包不承诺包含全部编译器、SDK、Qt 开发环境和传递依赖的离线重编工具链。引擎源码中的功能也不自动成为 IG5 已暴露工具。

分发保留 [第三方许可清单](THIRD_PARTY_NOTICES.txt) 与各组件许可证；第三方代码、运行件和依赖按自身许可分发，不受项目自有代码的 NC 条款覆盖。

## 开发验证与同步 SOP

所有修改在源码目录 `dsh-infinite-gen-5` 完成，运行副本是 `%USERPROFILE%\.dsh\plugins\dsh-infinite-gen-5`。使用与宿主一致的 Python；以下 `$pythonExe` 应设为实际配置路径。顺序为全部 IG5 自有源码语法/编译检查→封存运行资产→回归烟测→镜像→重启→检查本次日志，检查失败停止发布。第三方源码与运行资产按其清单校验，不使用 IG5 的 Node/Python 对整套上游源码混编。以下封存和验收命令面向项目维护，普通安装无需执行；自包含验收会运行生成的临时 PE。

```powershell
$sourceRoot = [IO.Path]::GetFullPath(if ($env:IG5_SOURCE) { $env:IG5_SOURCE } else { (Join-Path $env:USERPROFILE 'Desktop\无限五代\dsh-infinite-gen-5') })
$pluginRoot = [IO.Path]::GetFullPath(Join-Path $env:USERPROFILE '.dsh\plugins\dsh-infinite-gen-5')
$pythonExe = "C:\path\to\configured\python.exe"
Get-ChildItem -LiteralPath $sourceRoot -Recurse -File | Where-Object { $_.Extension -in '.js','.mjs','.cjs' -and $_.FullName -notmatch '[\\/](third_party|runtimes|vendor|node_modules|\.git)[\\/]' } | ForEach-Object {
    & node --check $_.FullName
    if ($LASTEXITCODE -ne 0) { throw "JavaScript 检查失败: $($_.FullName)" }
}
Get-ChildItem -LiteralPath $sourceRoot -Recurse -Filter '*.py' -File | Where-Object { $_.FullName -notmatch '[\\/](third_party|runtimes|vendor|node_modules|\.git)[\\/]' } | ForEach-Object {
    & $pythonExe -m py_compile $_.FullName
    if ($LASTEXITCODE -ne 0) { throw "Python 编译失败: $($_.FullName)" }
}
# 维护者更新/修补运行资产后，重建并验证包内文件 SHA-256 清单
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $sourceRoot 'scripts\seal_runtime_bundle.ps1')
if ($LASTEXITCODE -ne 0) { throw '运行包封存失败，停止发布' }
& node (Join-Path $sourceRoot 'scripts\test_runtime_bundle.mjs')
if ($LASTEXITCODE -ne 0) { throw '运行包结构/路由回归失败' }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $sourceRoot 'scripts\test_install_package.ps1')
if ($LASTEXITCODE -ne 0) { throw '安装/打包隔离回归失败' }
& node (Join-Path $sourceRoot 'scripts\test_self_contained.mjs')
if ($LASTEXITCODE -ne 0) { throw '自包含真实运行验收失败' }
& node (Join-Path $sourceRoot 'scripts\test_new_tools.mjs')
if ($LASTEXITCODE -ne 0) { throw '烟测失败，停止发布' }
# /MIR 会删除目的目录多余文件；先核实这两个解析后的绝对路径
$sourceRoot
$pluginRoot
if ($sourceRoot -eq $pluginRoot -or $pluginRoot -ne (Join-Path $env:USERPROFILE '.dsh\plugins\dsh-infinite-gen-5')) { throw '镜像目录不符合预期' }
& robocopy $sourceRoot $pluginRoot /MIR /FFT /Z /NP /XJ /XD .git __pycache__
if ($LASTEXITCODE -gt 7) { throw "Robocopy 失败: $LASTEXITCODE" }
Get-Process -Name '*DeepSeek*' -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
Start-Process -FilePath (Join-Path $env:LOCALAPPDATA 'Programs\DeepSeek Harness\DeepSeek Harness.exe') -WindowStyle Hidden
Get-Content -LiteralPath (Join-Path $env:USERPROFILE '.dsh\ig5\artifacts\ig5-diag.log') -Tail 30
```

核对本次启动 `/ig5-diag`、`/ig5-jobs`、`/ig5-data`、审批门和客户端挂载；不要把旧日志视为新版本已加载。默认静态样本是上级 `_research\fixtures\notepad.exe`；动态和补丁测试使用副本或生成 PE。

## 回归命令概览

| 命令 | 覆盖 |
|---|---|
| `npm run harness:check`、`npm run test:new-tools` | 基础 JS 检查与真实样本工具烟测；不替代 SOP 全项目检查 |
| `npm run test:host`、`npm run test:data-route`、`npm run test:workflow`、`npm run test:client` | 宿主、只读路由、Core8/Full36 与五技能生命周期、renderer/引擎竞态/原生焦点 |
| `npm run test:projects` | 持久身份、崩溃锁恢复/真进程竞争、物理数据库别名/修订、64 位地址及双向歧义拒绝 |
| `npm run test:runtime-bundle`、`npm run test:self-contained` | 结构/搬移/路由拒绝夹具；清空外部运行配置后的真实包内 Ghidra+x64dbg 验收及运行资产不变性 |
| `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/test_install_package.ps1` | 临时 profile/运行件夹具中的安装、备份/失败回退、缺件与打包过滤；不替代真实引擎验收 |
| `npm run test:engines`、`npm run test:ghidra` | 真实 Ghidra、双引擎 changeset/字节导出/Undo 与修订校验 |
| `npm run test:debug-api`、`npm run test:debug-runtime`、`npm run test:x64dbg` | Mock API；真实 Reverse win32；独立 x64dbg headless（会执行受控测试程序） |
| `npm run test:advanced`、`npm run test:semantic-diff`、`npm run test:patch-runtime` | 高阶分析/受限仿真、差异匹配、补丁前置校验与导出 Undo |

Ghidra 默认 `analysis_profile=interactive`，仅跳过批量 Decompiler Parameter ID 分析器，函数反编译仍可用；需要该批量分析时显式设 `full`。`analysis_timeout` 为 1–600 秒，预算到期保留 partial 和分析状态，工作台显示“部分分析结果”，不能当成完整分析完成。真实 notepad 的 interactive 分析约 85 秒、853 函数、无超时，分析后 decompile 子进程数为 0；这不是任意样本的性能保证。真实 Ghidra-only 与跨引擎公开工具测试通过；x64dbg x64/x86 真实 headless 闭环、14 项 fake 回归、命名管道 DACL、取消/超时/强杀清理均通过。Reverse native win32 的 notepad 副本动态闭环通过，Bochs 仅 load/bpt；不能外推任意样本或所有文件格式。前端浏览器使用真实 DSH React 与明确标注的 mock fixture，不能当成动态后端证据。

Ghidra 的 `partial/analysisComplete` 描述全程序在所选 profile 下的完成状态；`scopePartial/scopeComplete` 描述本次范围分析。范围成功不会把尚未完成的全程序标为完整，也不会改变既有全程序 profile。

Ghidra 写响应中的 `committed=true` 表示原生内存事务完成，`saved=true` 才表示数据库保存已确认。名称、行尾注释和补丁每次保存；类型、结构体与分析写入保留原生会话 Undo，返回 `persistence=session-only`，正常 `ig5_close` 保存。后续保存会使相应原生 Undo 失效。强杀、硬超时或异常退出可能丢失 session-only 修改，重开时应检查 `recovery`、`durableRevision`、`unsavedChanges`。`partial_commit` 与 `recoveryRequired=true` 表示提交/保存/审计持久化链未全部确认，并不表示回滚；先检查数据库与恢复结果，不自动重放写入或盲目重试。原生保存与 sidecar/审计文件不是一个原子事务。

Reverse 微码原生 filter 管线与构造临时 MBA 的 xor-self/sub-self 改写已验，自然函数规则命中仍为 0，未实现通用去平坦化。RTTI 的 MSVC64/Itanium class/SI/VMI 已验证生成 PE 字节布局，非原生 Linux ELF 装载验证；显式 table+offset 不自动推导寄存器来源。bindiff 是保留歧义/截断的启发式匹配和变更块，包含 memoff +4→+8 测试，不是 BSim、语义等价或自动漏洞证明。Unicorn 2.1.4 限 x86/x64、64 MiB、无 OS/import/TLS，捕获返回/内存/fault/超时；依赖锁定见 [requirements](worker/requirements-emulation.txt)，保留 [NOTICE](worker/vendor/NOTICE.txt)。

---

## 🧭 逆向工作台操作与常用指令

在对话框中可直接使用斜杠命令与模型工具调用：

### 1. 快捷斜杠命令（免模型 Token 消耗）
* `/ig5 status`：查看已打开引擎会话、样本身份、数据库修订与当前状态；
* `/ig5 engines`：检查三引擎配置和可用性；
* `/ig5 open --engine ghidra <样本路径>`：显式选静态后端；省略参数使用默认引擎，打开不启动样本；
* `/ig5 toolset full`：展开为 36 个全量逆向分析工具面；
* `/ig5 toolset core`：恢复为 8 工具轻量模式；
* `/ig5 export --engine ghidra <样本路径>`：导出指定数据库当前有效字节补丁副本与报告（尊重 Undo）；多目标时明确路径和来源。

### 2. 5 大原生专家级工作流技能包（Runbooks）
系统预置了 5 套标准逆向分析流程，可在聊天中直接唤起：
* `/ig5-triage`：**新样本 10 分钟快速侦察流**（架构识别 → 熵与加密常量扫描 → 库函数过滤 → 提出关键假设）；
* `/ig5-deep-dive`：**核心算法攻坚流**（关键分支定位 → CFG 拓扑 → 变量切片 → 重建结构体与命名）；
* `/ig5-patch-and-sign`：**补丁实验与哈希签收流**（前置原字节安全校验 → 审批门提交 → 导出副本并校验 SHA-256）；
* `/ig5-diff`：**版本补丁差异比对流**（提取新旧二进制调用图与拓扑结构，定位 Patch 变更块）；
* `/ig5-debug-live`：**动态调试验证流**（断点设置 → 进程挂载 → 命中事件 → 寄存器回读）。

---

## 📁 项目目录结构

```
dsh-infinite-gen-5/
├── 🖼️ assets/
│   ├── banner.png               # 无限五代高分辨率宽屏海报
│   └── community.jpg            # 官方社区与交流群二维码
├── 🚀 一键安装与维护套件
│   ├── install.ps1              # Windows 自动化一键部署脚本
│   └── uninstall.ps1            # 自动化卸载脚本
├── 🧩 核心插件装载面 (Cordis 架构)
│   ├── package.json             # 插件元数据（dsh-infinite-gen-5 v1.0.0）
│   ├── index.js                 # 宿主核心（36工具注册 + 审批门 + 三大 HTTP 诊断端点）
│   ├── client.js                # 工作台前端（SVG CFG + 变量切片 + 结构体草稿箱）
│   ├── advanced_tools.js        # 高阶工具扩展（栈帧 / 跳转表 / 虚表 / 微代码 / 差异比对）
│   ├── semantic_diff.js         # 多特征启发式匹配算法
│   ├── engine_runtime.js        # 独立运行包配置与引擎路由
│   ├── integration_tools.js     # Ghidra IR 与显式跨引擎 changeset
│   ├── source/                 # project_store / address_ref 身份与地址基础
│   ├── adapters/               # Ghidra / x64dbg 独立工作进程
│   ├── runtimes/               # 随包 Ghidra/JDK/Python 与 x64dbg/Python/bridge
│   ├── third_party/sources/    # 上游源码、固定gitlinks与逐文件来源/hash清单
│   ├── workflow.js              # 原生命令与技能包生命周期管理器
│   ├── cordis.patch.yml         # 宿主加载补丁配置
│   └── HARNESS_PLUGIN.md        # 插件技术规范文档
├── 🧠 原生逆向技能包 (skills/)
│   ├── ig5-triage/SKILL.md      # 新样本快速首探 Runbook
│   ├── ig5-deep-dive/SKILL.md   # 单函数深挖 Runbook
│   ├── ig5-patch-and-sign/      # 补丁验证与导出 Runbook
│   ├── ig5-diff/SKILL.md        # 版本差异比对 Runbook
│   └── ig5-debug-live/SKILL.md  # 动态调试交互 Runbook
├── 🐍 后端逆向工作进程 (worker/)
│   ├── ig5_worker.py            # JSON-RPC 核心通信进程（Reverse 引擎封装）
│   ├── advanced_analysis.py     # C++ 虚表/RTTI/微代码/跳转表分析实现
│   ├── execution_analysis.py    # Unicorn 仿真执行核心
│   └── vendor/unicorn/          # 插件内置 Vendored Unicorn 2.1.4 运行时
└── 🧪 自动化测试套件 (scripts/)
    ├── test_new_tools.mjs       # 真实样本基础工具烟测
    ├── test_advanced_runtime.mjs# Unicorn 仿真 / 微代码 / 虚表 / 跳转表回归测试
    ├── test_debug_runtime.mjs   # 原生 Win32 真实进程调试全流程闭环回归
    ├── test_client.mjs          # SVG CFG / 变量切片 / 竞态条件前端自动化测试 (含引擎切换与原生焦点回归)
    ├── test_workflow.mjs        # Core8/Full36 切换与命令生命周期测试
    └── test_patch_runtime.mjs   # 补丁审批与安全回滚测试
```

---

## 💬 官方交流社区

> 📌 **非盈利开源公益项目，严禁任何主体用于商业售卖、付费倒卖或黑灰产牟利，仅供技术研究交流。**

<p align="center">
  <img src="./assets/community.jpg" width="240" alt="DeepSeek 网安逆向技术交流社区" /><br>
  <sub><b>🌐 官方技术交流社区（腾讯频道号：pd86424753 · 红队安全交流 9 群：338431075）</b></sub>
</p>

---

## 📄 开源协议与非商用特别声明（License）

本项目采用 **[CC BY-NC-SA 4.0（署名-非商业性使用-相同方式共享 4.0 国际许可协议）](LICENSE)** 进行开源，并附加以下严格的法律与商业限制条款：

1. 🚫 **严禁直接商业使用**：禁止任何个人、企业或第三方将本项目自有代码、组件、前端界面及文档用于商业售卖、付费倒卖、付费社群、会员增值服务或黑灰产牟利。随包第三方源码、运行件和依赖继续适用各自上游许可，项目 NC 条款不覆盖它们。
2. 🚫 **严禁二次开发商业化**：任何基于本项目的 Fork、修改、重构、二次开发或作为组件嵌入其他软件时，**必须严格继承 CC BY-NC-SA 4.0 协议并完全开源，绝对禁止将任何二次开发或衍生作品用于商业营利**。二开商用属于严重侵权及违法违规行为。
3. ⚖️ **违规终止与法律追责**：任何违反非商业性条款或将本项目用于违法黑产活动的行为将导致开源授权自动且永久终止，原作者保留依法追究侵权方民事赔偿与法律责任的一切权利。
