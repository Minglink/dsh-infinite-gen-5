# 无限五代 1.4.0 · 减重增效与分层发行版

日期：2026-11-20。本版本完成蓝图 Phase 0 → Phase 4 全链路改造：运行态上下文瘦身、工具面 Schema 压缩、内置无依赖 JS/Electron 静态提取、7D12D 纯静态规则与 .NET BSJB 元数据解析，以及 v1.4.0 分层精简运行时供体与伴随合规源码包。

- **版本与工具面**：插件包、DSH 元数据、`index.js`、`client.js` 与 `ig5_profile` 同步为 `1.4.0`（实现标识 `20261120-release-1.4.0`）；保持 Full 44 工具与 14 个审批门契约零变更，不中途动态切工具集以保留 92%+ KV Prefix Cache；通过压缩冗长描述将 Full 44 降至 `< 18,000` tokens、Core 8 降至 `1,890 / 4,000` tokens。
- **上下文防雪崩与主干精简**：`ig5_workspace` 的 `root-create` / `root-update` 默认返回增量摘要（`include_task: true` 可按需返回完整快照）；`skills/ig5-reverse-agent/SKILL.md` 精简至 `< 10 KB`，VM handler 语义下沉至 `references/handler-semantics.md`。
- **内置轻量 `js_app` 后备引擎**：新增 `source/native_js_static.js`（`engines` 层，纯 Node 标准库 `< 25 KB`），支持只读 ASAR Chromium Pickle 解构与 Electron/IPC/子进程拓扑提取；未配置外部 `IG5_REA_ROOT` 时自动回退，消除外部大目录强依赖。
- **静态规则与 .NET BSJB 增强**：扩充 `source/apk_rules.js`（商业加固与跨端运行时规则、Keystore/KeyInfo 审计）、`worker/packer_rules.py`（小写保护器节名与 Go/Zig/MinGW 现代编译器标准节白名单）、`worker/scan_analysis.py` 与 `worker/packer_analysis.py`（纯 Python ECMA-335 `.NET` `BSJB` `#Strings`/`#US`/`TypeDef`/`MethodDef` RVA 解析）、`source/protocol_analysis.js`（`payloadDisguiseCheck`）及 `source/failure_router.js`（`KNOWLEDGE_CARD_HINTS` 卡片推荐指针）。
- **v1.4.0 分层发行包与无损精简供体**：
  - 严格保持历史 `1.0.0` 密封供体与 `1.1.0/1.2.0/1.3.0` 兼容校验零改动（`scripts/distribution.json` 逐字节保留）。
  - 新增 `scripts/build_slim_donor.ps1` 在独立输出目录生成 `1.4.0` 无头精简运行时供体（剔除 JDK `jmods/`、`lib/src.zip`、`lib/ct.sym` 及 Ghidra `docs/`、`Extensions/Ghidra/*.zip`、`Ghidra/Debug/`、`Ghidra/Features/BSim/`、`Ghidra/Features/GhidraServer/`，完整保留 Decompiler/Base/FunctionID/SLEIGH/pyghidra/x64dbg 与全部许可证），并将 `third_party/sources/` 外置归档为伴随合规包 `IG5-1.4.0-sources-compliance.zip` 及校验清单 `companion-sources.json`。
  - `scripts/package_portable.ps1` 默认输出隔离至 `~/.dsh/ig5/releases`，并在 `>= 1.4.0` 便携打包时自动排除 `archive/`、`docs/review/`、`scripts/test_*`、`scripts/accept_*` 及 `tools/ci/sample-specific.json` 所列开发期单样本脚本（源码仓内完整保留以运行 `npm run ci`）；同时在解压根目录生成纯 ASCII + `CRLF` 的一键安装脚本 `install.bat` / `uninstall.bat`，自动处理宿主进程关闭、PowerShell 执行策略绕过与重启动。
- **Ghidra ↔ x64dbg 精准断点与门禁实测**：
  - `adapters/ghidra/worker.py` 在 `ig5_decompile` 返回函数入口 `rva`、`callSites[].returnRva` 与 `returnSites[].rva`，`source/worker_manager.js` 增加 `MID_INSTRUCTION_BREAKPOINT` 预检拦截；`source/investigation_verifier.js` 与 `source/investigation_assessment.js` 补全 `cli-arg` 十六进制字符与 ASCII 等价求值兼容。
  - `npm run ci` 全量门禁 **131/131** 通过；`package.json` 同步声明 `engines.dsh: ">=0.2.0-rc.1 <0.3.0-0"` 并已在桌面端 `DeepSeek Harness 0.2.2`（`dsh-v0.2.2-rc.x`）实测通过 `install.bat` 一键安装与原生 PE 静态 + `x64dbg` 动态闭环。
  - Windows x64 便携发行包 `IG5-1.4.0-Windows-x64-portable.zip`（`433,291,421` 字节 / ~413 MB，SHA-256：`ebfebc785d7044e60f6b7910cf721775c284e11bbeb1cfe`）。
