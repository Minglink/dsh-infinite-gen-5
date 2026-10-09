# IG5 Ghidra 原生核心

构建输入固定为 Ghidra 12.1.4，tag `Ghidra_12.1.4_build`，commit `8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc`。完整 Git 源文件逐 blob 验证后放在 `third_party/sources/ghidra-12.1.4`；此前用户提供的 `ghidra-master` 12.3 DEV 档案保持原内容。CMake overlay 不改上游源码，按固定上游 `buildNatives.gradle` 的生产文件清单构建，避免把诊断/测试 main 混入产品。

生成 `decompile`、`sleigh`、`ig5_sleigh_core`、本地 zlib 和 `ig5_sleigh` C ABI。Windows 采用静态 CRT，运行件不依赖维护者机器上的 Visual C++ 运行库。`scripts/build_ghidra_native.ps1` 的输出、SHA-256 与构建范围写入工作目录 `build-proof.json`；发行 runtime 的 `sourceBuild` 记录实际携带文件。原生核心源码保留 Ghidra Apache-2.0 与其 zlib 许可，项目许可不覆盖第三方。

```powershell
& .\scripts\build_ghidra_native.ps1 -BuildRoot <维护构建目录>
& .\runtimes\ghidra\python\python.exe .\adapters\ghidra\test_native_core.py --library <构建目录>\install\bin\ig5_sleigh.dll --ghidra-home .\runtimes\ghidra\ghidra_12.1.4_PUBLIC --compiler <构建目录>\install\bin\sleigh.exe
```

`ig5_sleigh_decode` 输入已验证的随包 `.sla` 内存、样本字节、基址和明确的处理器 context；输出有界 JSON 指令及 raw p-code。输入/输出归调用者所有，没有 Java/Python、网络、文件系统或执行样本的操作。LOAD/STORE 的首操作数被转换为地址空间名/编号，不把原生 `AddrSpace*` 当作目标常量或输出宿主指针。原生异常不跨 C ABI，截断指令、无效规格和输出容量不足有独立返回码。SLA 是可信处理器资产，不能把用户任意规格文件当成安全可加载输入。每个调用顺序解码，不推断函数边界/CFG，也不执行完整 Java 自动分析或高层反编译。

Windows 实际编译与 C ABI 的九项验证覆盖 x64/AArch64 解码、高位 64 位地址、指令限制、截断字节、无效 SLA、容量查询、空指针，以及使用自产 Sleigh 编译器生成小规格并再次解码。它为原生宿主提供可链接基础，不等于已经具备 Android/iOS 执行包或真机兼容。

Linux ARM64 可在真实 ARM64 Ubuntu 环境使用本 CMake overlay 构建。Android 原生应用可使用 NDK 的 CMake toolchain、`ANDROID_ABI=arm64-v8a` 构建解码库；DSHA Ubuntu 则需要 Linux ARM64/glibc 运行包，不能混用 Android/bionic 产物。iOS 在 macOS/Xcode 环境指定 `CMAKE_SYSTEM_NAME=iOS`、`CMAKE_OSX_SYSROOT=iphoneos`、`CMAKE_OSX_ARCHITECTURES=arm64`、`IG5_SLEIGH_SHARED=OFF` 并构建 `ig5_sleigh`，由应用静态链接。以上跨平台构建合同尚未在对应工具链/真机执行；缺少执行包时宿主必须报告 unavailable。

完整 Java 发行链另见 `scripts/build_ghidra.ps1`：维护工作副本、固定 Gradle/JDK、上游校验的非 Maven 依赖、Maven lockfiles 与最终 ZIP 校验。原生 CMake 成功不能冒称该完整 Java 构建也成功。
