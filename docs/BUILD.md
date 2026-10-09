# 固定源码构建与交付

运行目录 `runtimes/` 是用户安装时使用的本地依赖。`third_party/sources/` 保存上游源码和来源证据。`.downloads/` 保存获取、编译、Gradle / MSVC 工具链缓存，已从 Git 与发行包排除。源码快照与编译产物分别记录；快照存在不作为构建通过的证明。

| 组件 | 固定来源 | 本轮构建状态 |
| --- | --- | --- |
| Ghidra 12.1.4 | `Ghidra_12.1.4_build`，`8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc` | 完整 Gradle 发行构建成功，703 个 actionable task 执行；Java framework、PyGhidra 与 native 实际编译，额外提供 Sleigh C ABI 核心 |
| x64dbg | `9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87` 及固定子模块 | 实际编译 x86 / x64 Release 无头核心、bridge、loaddll、TitanEngine；部分依赖仍为固定预编译件 |
| IG5 原生桥 | `adapters/x64dbg/ig5_bridge.cpp` | x86 / x64 编译，与源码核心共同验证 |
| JPype 支持 JAR | 1.5.2 固定来源 | 保留可复现 Unicode 启动补丁，不改全局 Python |
| Unicorn | 固定 2.1.4 Windows x64 wheel | 原生 DLL / Python 绑定未改；移除未使用静态链接档案 |

`ghidra-master` 的桌面快照是 12.3 DEV；仍保留作研究资产，不能用它证明 12.1.4 可复现构建。x64dbg 的桌面 development 快照同样不替代固定 commit 的构建输入。

维护入口：

```powershell
# 固定源码及 native / full 构建，参数说明见脚本头
python scripts/fetch_ghidra_source.py --help
Get-Help scripts/build_ghidra_native.ps1 -Full
Get-Help scripts/build_ghidra.ps1 -Full
Get-Help scripts/build_x64dbg_core.ps1 -Full

# 裁剪 pinned Unicorn wheel 的静态链接档案
./scripts/prepare_unicorn_runtime.ps1
python -B scripts/test_cpu_emulator.py
```

构建脚本需要对应工具链；完整运行包安装不需要这些工具链。每个 build proof 应同时记录固定输入、维护补丁、编译命令、产物 hash、尚未重建的依赖和真实测试结果。包含源码不意味着整个构建工具链可以离线首次获取。

Ghidra 完整源码构建产物为 `ghidra_12.1.4_DEV_20261009_win_x86_64.zip`，568,192,269 字节，SHA-256 `d3a6c4fa5d45bb93ca6ada4855286aaf986f35d785dc7b11ae4caa708a2acd9d`。`application.release.name=DEV` 如实保留；安装目录名为既有兼容别名，不能据目录名将其称为未修改的官方 PUBLIC 包。框架与 PyGhidra 使用源码构建件，native 使用同一固定源码的 `/MT` 产物，避免依赖开发机已安装的 VC 运行库。

完整凭证在 `runtimes/ghidra/licenses/ig5-source-build/full-build-proof.json`，native 凭证在同目录 `build-proof.json`。Gradle 的 Windows pipe 工具链兼容补丁只在构建进程启用；源码、classes、hash 和上游许可随证明保存，随包运行 JDK 未应用该补丁。完整构建仍使用固定下载的第三方依赖，不宣称全部依赖均从源码重编。

部署顺序：

1. 在源码目录修改，运行自有 JS 语法校验、Python 编译校验与 PowerShell parser；不把第三方源码的测试 / 老版本语法作为自有代码失败。
2. 运行受影响回归、`test_new_tools.mjs`、引擎与真实调试验收；校验成功必须包含结果断言。
3. 原生运行件变更后运行 `seal_runtime_bundle.ps1`，再运行 `test_runtime_bundle.mjs` 与自包含安装检查。
4. 创建新便携目录和文件清单，再镜像到 `.dsh/plugins/dsh-infinite-gen-5`；镜像时排除源码根 `.downloads` 与 Git 元数据。校验目标解析后的绝对路径。
5. 正常退出并重新打开 DSH，检查新启动产生的诊断日志。仅磁盘副本一致不能证明已运行的宿主加载了新代码。

## 原生回归要求

x64dbg 的硬件断点必须实际触发，不能仅以设置 API 成功作为验证。维护补丁修复 TitanEngine callback 返回时误删用户刚替换的硬件 slot：返回后只对同一断点身份执行临时删除 / 恢复，新 slot 保留。x86 / x64 使用执行断点暂停→删除→同 slot 写监视→写入 `0x5a` 的相同流程验证，并检查事件类型、地址与读回值。

Windows 上读取、反编译与仿真 ARM64 ELF 是目标架构支持证据；Android 原生 worker 与 iOS App 内执行仍需各自宿主和原生依赖测试。
