# 手机版 DSH 的本地离线适配

桌面端仍是 IG5 的完整执行环境。用户要求手机完全离线独立执行，因此远程连接桌面不作为移动端完成标准。

| 目标 | 本轮已实现 | 尚未完成 |
| --- | --- | --- |
| 桌面 Windows x64 | 本地 Ghidra / x64dbg；源码 native 构建；完整工作台与受限仿真 | 部分 upstream 预编译依赖的完整源码重建 |
| Android ARM64 + Ubuntu / glibc 本地宿主 | worker 协议拆分、Linux ELF / ISA / libc 校验、区分 host 与浏览器、大小写正确的路径身份、窄屏触控界面 | 匹配的 ARM64 Python / JVM / JPype / Ghidra / Unicorn 包及 Android 真机验收 |
| Android Bionic 原生 App | 明确拒绝把 glibc 或 Windows 包当作匹配依赖；已抽出独立 Sleigh C ABI 核心供后续移植 | NDK 构建、App 本地插件宿主、系统权限和调试器适配 |
| iOS | 可复用的触控界面、平台不支持状态、无 Java 的 C ABI 移植基础 | 具体 DSH 插件宿主、iOS native 编译与签名、设备上的文件 / 线程 / 内存边界验收 |

运行可用性以 `ig5_doctor` 与工作台“本机执行环境”为准。浏览器显示 390 px 宽度不证明引擎运行在手机。ARM64 样本在 Windows Unicorn 中执行也不证明 Windows DLL 能在手机加载。

## 参考宿主

- [DSH-APP/DSHA](https://github.com/DSH-APP/DSHA)：本地 Ubuntu ARM64 rootfs / Node / DSH 运行方式，可作为第一条 Android 接入车道。
- [dphmoblie/deepseek-harness-android](https://github.com/dphmoblie/deepseek-harness-android)：Capacitor / Kotlin / PRoot 架构，参考本地 DSH 进程与文件访问。
- [radareorg/r2ghidra](https://github.com/radareorg/r2ghidra)：参考 Ghidra C++ decompiler 单独接入；不等同于移植完整 Java 分析框架。

这两套 Android 宿主尚未实际安装 IG5 做真机验证，iOS 原生 DSH 宿主尚未确认。参考项目实现不作为 IG5 平台支持证据。

## 下一步验收

1. 固定一个 Android 宿主，提供 `runtimes/linux-arm64/ghidra` 与对应 CPU runtime；验证中文路径、进程取消、后台恢复、文件持久化和内存峰值。
2. 用与 Windows 相同的 hash 夹具比较函数 / CFG / 类型 / p-code 结果，明确资源预算和差异；大样本按需分析，避免打开就全量扫描。
3. 将独立 Sleigh 核心编译为 Android / iOS 原生库，先验收本地反汇编，再评估完整 C++ 反编译桥。保留完整桌面后端。
4. 手机无法执行的 Windows 真实调试操作返回平台能力原因，不能静默改为静态分析或声称 x64dbg 已跨平台。

本地分析引擎离线执行与 AI 模型离线推理是独立需求。当前不随 IG5 分发手机大模型权重；使用远端模型的 DSH 宿主仍需要联网调用模型。
