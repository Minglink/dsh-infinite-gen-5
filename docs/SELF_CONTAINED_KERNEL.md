# 五代独立内核

本轮为 IG5 增加随源码和完整包分发的原生分析通道。IG5 自有 PE/ELF 加载、地址映射、任务隔离、CFG、局部 IR 优化和 RTTI 算法，接入固定 Ghidra 源码构建的 SLEIGH 解码器与原生 C 反编译管线。商业 Reverse 是另外保留的兼容后端；独立通道不调用它，也不启动 JVM。

## 使用

先运行 `/ig5 toolset full`。独立通道不要求先 `ig5_open`，不创建 IDB 或 Ghidra 项目。

```text
ig5_ir target="C:\samples\app.exe" level=kernel action=info
ig5_ir target="C:\samples\app.exe" level=kernel action=analyze ea=0x140001000 max_code_bytes=256 max_instructions=128 optimize=true
ig5_ir target="C:\samples\app.exe" level=kernel action=decompile ea=0x140001000 max_code_bytes=256 max_instructions=128
ig5_ir target="C:\samples\app.exe" level=kernel action=vtables ea=0x140002508 abi=msvc offset=8
```

`action=decompile` 运行真实原生优化器和 C printer；`code` 是反编译结果。`ea` 是函数入口，`max_code_bytes` 指定允许分析的函数范围上限，不能跨入口所在执行区域。范围不足、指令超限、不可读或未实现指令返回 `ok=false / complete=false / partial=true` 及阶段、原因。成功只表示该范围内原生分析管线完成，不证明程序行为等价或原始函数签名已经恢复。未知原型会保留反编译器的未知类型；输出不是保证可直接编译的源码。

`action=analyze` 输出真实 raw p-code、指令节点 CFG 和有 before/after 证据的局部常量折叠。它没有 SSA 或跨函数去混淆；内部 p-code 分支与外部出口混合时保留可能出口并报告未决，间接目标不伪装成确定函数。`partial` 包含解码、CFG 和输出裁剪状态。

`action=vtables` 使用 IG5 字节算法解析 MSVC x86/x64 与 Itanium RTTI/虚表。独立加载器目前不提供符号表；没有符号证据时 Itanium 类型变体和继承不作猜测。显式虚表地址和槽偏移不等于已求解运行时寄存器来源。Ghidra 后端的 `ig5_vtables` 复用这套算法，并提供默认地址空间内的内存与符号。

## 结构与预算

| 模块 | 责任 |
|---|---|
| `worker/kernel_image.py` | 独立 PE32/PE32+、ELF32/64 大小端加载；精确 64 位地址、R/W/X、显式 BSS，拒绝空洞、重叠和截断 |
| `worker/kernel_analysis.py` | 原生 SLEIGH JSON、可达指令图、位宽保真的局部 IR 规则 |
| `worker/kernel_rtti.py` | MSVC COL/TypeDescriptor/类继承与 Itanium class/SI/VMI、虚表槽 |
| `worker/kernel_decompile.py` | IG5 映射镜像转为原生 C ABI 输入，校验 DLL 构建证明与 SHA-256 |
| `adapters/kernel/native-core/` | 自有 `LoadImage`、C ABI、真实 Ghidra `Funcdata` 优化管线、PrintC |
| `source/kernel_jobs.js` | 隔离单次请求、最多两个自有 worker、超时与幂等回收 |

文件及原生映射总量最多 64 MiB；最多 512 区域。公开入口最多 65,536 代码字节、1,024 条指令。C 输出和诊断各有独立 native 限额，JSON 最多 8 MiB。宿主请求最长 60 秒，默认采用插件请求超时；优化器的硬时限由隔离 worker 外部实施。取消或协议超限仅停止本插件创建的进程，确认退出前保留 owner/capacity；卸载清理有 5 秒等待上限，超时明确报错。样本不执行，原文件不修改。

DLL 为 Windows x64 `/MT` 构建，仅依赖 `KERNEL32.dll`。随包 Python 和处理器规格复用 `runtimes/ghidra` 资产，C 通道不加载 Java/JPype。Windows 上固定 worker CWD 支持中文插件目录；规格目录使用 ASCII 相对路径，非 ASCII 外置覆盖路径明确拒绝。

当前已在 Windows x64 宿主验证 x86 32/64 位 Windows/GCC 与 ARM64 Windows/default 目标。ELF 大小端加载已通过纯字节回归；原生反编译目前只开放小端目标。没有重定位、导入原型、调试符号或自动函数边界恢复；ELF ET_REL 拒绝。Android/iOS 宿主原生执行尚未实现，不能由 ARM64 目标通过推导手机运行通过。

## 构建与许可证

`adapters/kernel/build_native_decompiler.ps1` 使用固定 Ghidra 12.1.4 修订 `8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc` 的未改源码，在独立构建目录生成 `adapters/kernel/native/ig5_decompiler.dll`。不链接 BFD、Java 通信壳或商业内核，不改已封存 `third_party/sources` 和 `runtimes` pins。DLL 的逐源文件 hash、产物大小和 SHA 保存在 `native/build-proof.json`；该证明记录编译事实，实际执行由验收报告另外记录。

自有 C ABI/加载与分析代码遵循项目 CC BY-NC-SA 4.0；Ghidra、zlib 及其它第三方部分保留各自许可，详见 `adapters/kernel/NOTICE` 和随 DLL 安装的许可文本。独立内核不实现 IDAPython 或专属微码 API，`ig5_run_idapython` 与 `ig5_microcode` 仍属于可选商业后端。

## 验证

```powershell
& .\runtimes\ghidra\python\python.exe -I -B scripts/test_kernel_image.py
& .\runtimes\ghidra\python\python.exe -I -B scripts/test_kernel_analysis.py
& .\runtimes\ghidra\python\python.exe -I -B scripts/test_kernel_rtti.py
node scripts/test_kernel_jobs.mjs
node scripts/test_kernel_runtime.mjs
& .\runtimes\ghidra\python\python.exe -I -B adapters/kernel/native-core/selftest.py
```

本轮已通过：加载器 17 组（含 480 次确定性变异）、RTTI 36 项、IR/CFG 40 项、进程生命周期 16 组、公开独立入口 15 项及原生 C ABI 22 项。C ABI 用例分别置于带独立超时的子进程，实际检查未加载 JVM/JPype/商业模块，未执行样本。

完整 Ghidra/x64dbg 公开目录回归通过 35/38 入口及 12 个审批夹具。未通过范围是未实现/未提供的专属微码、IDAPython 与需另一静态数据库的跨引擎同步，不用注册数量冒充功能通过。现有完整包与源码 ZIP 的安装路径均须保留独立内核 DLL、构建证明和许可；旧发行附件不会自动获得本轮实现。
