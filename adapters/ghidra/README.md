# Ghidra 独立适配器

完整发行包在插件内 `runtimes/ghidra` 直接包含运行环境，默认 `install.ps1` 离线校验并复制，无需用户执行 setup，也不依赖全局 Java/Python 或外部 `.dsh/ig5/runtimes`。固定 Ghidra 12.1.4、Temurin JDK 21.0.12.1、Python.org 3.12.10 embedded、同源自编 PyGhidra 3.1.0、JPype1 1.5.2 和 packaging 26.3，目标平台为 Windows AMD64。`scripts/setup_ghidra_runtime.ps1` 是维护者获取基础环境的联网脚本；自有发行件由本页的固定源码构建链生成。运行时清单保留来源、校验依据和许可证位置。

`runtime.json` 中 `pythonExe`、`ghidraHome`、`javaHome` 都相对于运行环境根目录；宿主为可写项目指定独立 `projectRoot`。实际来源与文件哈希清单随运行包保存，整包保持可移动。上游发行包中的 `LICENSE`、`licenses`、JDK `legal`、Python 许可证和 wheel 的 dist-info 许可证一起保留，各自适用上游许可。

`third_party/sources/ghidra-master` 保留桌面 12.3 DEV 源码、工程和许可，[来源清单](../../third_party/sources/manifest.json) 记录逐文件 hash 与已知缺件。该桌面源码不是 12.1.4 运行版的构建输入。固定 `third_party/sources/ghidra-12.1.4` 的 20,149 个 Git blob 全部校验后，已实际完成 703 个 Gradle 任务，编译完整 Windows Java/原生/语言规格/PyGhidra 发行件；[完整构建凭证](../../runtimes/ghidra/licenses/ig5-source-build/full-build-proof.json) 记录 ZIP SHA、工具链、125 个 Maven 锁文件和日志。随包 decompile/sleigh 使用同源 [CMake 原生核心构建](native-core/README.md) 的静态 CRT 版本，另携带自编 C ABI Sleigh 解码库；runtime.json.sourceBuild 标明范围与文件 SHA。完整发行件的 application.release.name 为 DEV，安装目录延续原别名以保持路径兼容，版本为 12.1.4。维护依赖缓存与产物保存在独立 build workspace。

## JPype 中文路径启动修补与维护重建

包内 `python/pylib/org.jpype.jar` 是经过 IG5 修补的 JPype 1.5.2 support JAR，不能标成未修改的上游原件。原始 JAR 来自固定官方 wheel；原始 `JPypeContext.java` 固定到上游 v1.5.2。[jpype-patch](jpype-patch/README.md) 保留原始输入、修改源码、`unicode-bootstrap.patch`、Apache-2.0 LICENSE 与上游/修改 NOTICE。冻结的 `third_party/sources` 上游归档及其哈希不因这项修补而改变。

修补只在 IG5 专用属性启用时，允许固定 `_jpype.cp312-win_amd64.pyd` 文件名，由 Java 的 Unicode `user.dir` 解析本机扩展路径；未启用属性时保留上游路径行为。Worker 以包内相对 JAR classpath 完成单次 JVM 引导，随后恢复临时 Python 元数据与工作目录。它不改全局 Python/Java，不通过外部 ASCII 目录、junction 或复制运行时绕过中文路径；原生 JPype 扩展未重编。

维护者可使用随包 JDK 离线重建，无需系统编译器或下载：

```powershell
& .\scripts\patch_ghidra_jpype.ps1 -RuntimeRoot .\runtimes\ghidra
& .\scripts\seal_runtime_bundle.ps1
```

脚本使用 `runtime.json.javaHome` 下的 `javac --release 8`，仅替换原始 JAR 中 `JPypeContext` 及其内部类条目，并固定新增 ZIP 条目时间。`runtimes/ghidra/runtime.json.jpypeBootstrap` 记录上游 source/JAR、修改后 source/JAR 和 patch 的 SHA-256；`licenses/ig5-jpype-bootstrap/provenance.json` 保留同一来源记录。更新后重新封存 `runtimes/manifest.json`，再执行 README 的维护验收；普通安装不运行上述重建命令。该适配固定到 JPype 1.5.2，升级依赖时须重新验证。

## 启动合同

```text
<runtimeRoot>/python/python.exe -I -B <pluginRoot>/adapters/ghidra/worker.py
```

环境变量：

- `IG5_GHIDRA_HOME`：Ghidra 安装目录。
- `IG5_JAVA_HOME`：独立 JDK 目录。
- `IG5_GHIDRA_PROJECT_ROOT`：宿主指定的项目产物目录。
- `IG5_TARGET`：可选，仅作为 `open.path` 缺省值。

stdout 为 UTF-8 JSONL；Python/JVM/原生诊断进入 stderr。worker 启动发送 `{ig5:"ready",pid,engine:"Ghidra",capabilities:[...]}`，请求格式为 `{id,method,params}`，响应为 `{id,result}` 或 `{id,error:{message,code}}`。分析进度为 `{ig5:"progress",id,payload:{stage,pct,...}}`。不在能力清单的方法返回 `code:"unsupported"`。

worker 串行处理请求，一个实例独占一个项目。宿主负责写操作审批、超时和进程数量预算。Windows worker 在 JVM 启动前加入 kill-on-job-close Job Object，清理其原生反编译子进程；Job Object 不可用时 doctor 明确要求宿主终止整个进程树。宿主正常释放时应先 RPC `close`，再结束 stdin；硬超时使用整个进程树终止。

单个 JVM 的堆上限为 2 GiB，逻辑处理器预算为 2；原生反编译器还使用独立进程内存。每个请求结束时取消其 TaskMonitor 定时器，避免会话积累 Timer 线程。

## 数据库与写入

`open` 根据 `database_key || targetPath`、文件 SHA-256、引擎版本和语言/编译器选项选择独立 Ghidra 项目。宿主传稳定的项目/产物键后，移动样本仍能复用数据库；内容改变则产生另一项目。`fresh:true` 创建独立新项目。`databasePath` 返回实际 `.gpr` 路径，`programPath` 为 `/sample`，VA 使用十六进制字符串，`imageBase` 用于宿主 RVA 映射。

分析结果来自 Ghidra 的真实程序、引用、反编译器、HighFunction 和 BasicBlockModel。`ir` 提供 `raw`/`high` p-code，保留旧文本字段并返回真实 inputs/output varnode、宽度、地址空间、定义序号和来源/修订；最多 10,000 条指令、20,000 个 varnode，截断字段明确区分指令与操作数，精确满页不假报截断；`slice` 提供 HighFunction 符号和 C 文本行过滤，其 scope 明确限定为词法筛选。`semantics` 是带类型操作数、CFG 和调用/字符串证据的启发式快照。库函数标记只依据 external/thunk，不能等同标准库识别。

`open`/`analyze action=reanalyze` 的 `analysis_profile` 支持 `interactive`（默认）与 `full`。interactive 关闭耗时的批量 `Decompiler Parameter ID`，保留按需真实反编译和 HighFunction；full 开启该分析器。响应明确给出 `analysisProfile`、`skippedAnalyzers` 与 `partial`/`analysisComplete`；完成表示所选 profile 已完成。默认分析预算 120 秒，显式 timeout 最多 600 秒，宿主仍负责硬截止。记事本副本的默认完整 Ghidra 分析曾触发 120 秒 partial；不能据此宣称 full 分析已在该预算完成。

写操作在 Ghidra transaction 中执行。rename/comment/patch 每次保存数据库，使用显式逆操作做会话内 Undo；patch 支持 `expected` 前置比较，拒绝未加载范围，清理并重新解码相交 code units 后验证字节。注释默认是 EOL。其他类型/结构体/分析写入使用原生 Undo，并在 close 保存；Ghidra 保存会清空原生 Undo，所以这类记录遇到后续 save/close 会明确报告回滚已失效。

所有成功写入与 Undo 记录在 `<project>-journal.jsonl`，flush/fsync；单调 revision 在 sidecar 中持久化。journal 是审计记录，会话重启后不会自动重放或宣称仍能回滚。未保存的类型/分析修改可能在硬终止时丢失。`status.unsavedChanges` 和写响应的 `saved`、`undoMode` 表示当前耐久状态。`undo action=list` 只读列出会话记录。

`set_type` 支持 C 函数原型、固定长度 1..4096 字节的 C 数据声明和唯一命中的本地 typename；非函数类型不得替换函数入口。`struct` 支持 composite 的 list/get/define/apply，apply 替换相交数据定义；`analyze` 支持 create_function/delete_function/mark_code/undefine/reanalyze。调试、Reverse 微码、任意 Python 执行和高级类型修复仍明确 unsupported。

`emulate` 在 Windows 随包 Unicorn 上执行复制的 Ghidra 内存映像，支持 x86、x64 和 ARM64；通过目标程序的 compiler specification 选择 Win64、SysV64、cdecl 或 AAPCS64，无法确定时要求显式 ABI。它只执行 CPU 指令，不修改数据库，不模拟操作系统、导入、TLS 或完整进程。宿主仍需写操作审批。Linux ARM64 尚未随包构建验证对应 Unicorn 运行库，该平台明确报告不可用，不能据 Windows 主机上的 ARM64 目标测试宣称手机运行通过。

## 验证

```powershell
node scripts/test_ghidra_runtime.mjs
node scripts/test_ghidra_runtime.mjs --notepad
```

回归只写临时样本副本和独立项目，断言 PE 分析、两种 p-code、引用/CFG、类型与事务回滚、原值不匹配拒绝、源码字节不变、中文路径、稳定数据库键和 revision。第二个命令额外分析 `_research/fixtures/notepad.exe` 的副本。

## 维护构建

```powershell
& .\runtimes\ghidra\python\python.exe .\scripts\fetch_ghidra_source.py --cache-root <下载缓存目录>
& .\scripts\build_ghidra_native.ps1 -BuildRoot <原生构建目录>
& .\scripts\build_ghidra.ps1 -BuildRoot <完整构建目录> -UseWindowsTcpPipe
```

源码获取按固定 tag/commit、ZIP SHA-256 和 Git blob 校验，不覆盖内容不同的已有档案。完整构建需要维护机具备 Visual C++、完整 JDK21 和上游支持的 Python/pip，首次在线准备依赖，保存在独立 build workspace；`-Offline` 需要该缓存已准备。发行运行环境无需这些维护工具。完整 Gradle ZIP 的完成凭证写入对应构建目录的 `build-proof.json`，部署审计在 `runtimes/ghidra/licenses/ig5-source-build/full-build-proof.json`；随包原生构建凭证在同目录 `build-proof.json`，准确范围由 `runtime.json.sourceBuild` 指明。

本机 JDK 的 Windows AF_UNIX NIO pipe 在 Gradle 中返回 Invalid argument；可选 `-UseWindowsTcpPipe` 从该 JDK 的 `src.zip` 精确修改一处开关，选择已有 TCP loopback pipe，并将 OpenJDK 来源、补丁 SHA 和 GPL/Classpath 许可记录到维护目录。补丁仅供 Gradle 构建进程，运行包 JDK 和 worker 不携带该修改。

重复构建时，上游 IP 扫描会误把第一次生成的 `gradle.lockfile` 当作没有许可头的源码。维护脚本仅在可丢弃的 workspace 给 IP 扫描增加该生成文件名的排除项，保留实际源码和依赖许可校验，记录补丁 SHA；固定源码树不改。
