# IG5 M2–M4 自主逆向能力与验收矩阵（2026-11-18）

> 本文档按三层证据边界（**离线单元/组件门禁**、**预编排真实原生正反例控制实测**、**未见样本真实 DSH 模型在线自主评测**）如实记录 IG5 `1.3.0` 当前已验证能力、未支持/受阻边界与第三方开源归属声明。严禁将静态分析、Unicorn 仿真或模拟测试结果外推为真机动态实测或任意未知软件完备保证。

## 1. 六分支状态与分层证据总表

| 里程碑 / 分支 | 验收状态 | 离线单元与门禁（`128/128`） | 预编排真实原生正反例控制 | 未见样本真实 DSH 在线自主评测 | 未支持 / 明确受阻边界 |
|---|---|---|---|---|---|
| **M2** 单二进制 PE64 自主逆向（`blind3`） | **achieved**（有限测试域内） | `m2-suite-guard`、`m2-eval-reporting`（31/31）、`m2-isolation-sentinel` 全过 | `--real-host` 哨兵 21 负例阻断 + 4 正例放行；`verify_m2_controls_native.mjs`（1A 冷启动 Ghidra `emulate`、1B `rva` 回执验收、1C 触发正反探针、1D 预算耗尽后 owner `stop`）全过 | 全新四例封存集 `blind3`（`sealed-09..12`）：触发完整性 **4/4**，交付正确 **3/4**（`sealed-10/11/12` 均 `6/6`），宿主 `complete` **2/4**（62 次、56 次），错误完成 **0/4**，活跃超时 **0/4**，清理确认 **4/4** | 无 OS 用户/VM 内核隔离（`strictBlindEligible=false`）；`ig5_dbg:start/writemem/setreg` 具非沙箱进程能力 |
| **M3** Electron → Native Helper 端到端业务链 | **achieved** | `test_m3_m4_contracts.mjs`（`rea@6.4.0` SHA-256 锁定、`HELPER_SCENARIO_MISMATCH` 防裸跑保护）通过 | `verify_m3_m4_controls_native.mjs m3`：`rea@6.4.0` 静态图重建、`stdin` `TK` 二进制帧裸跑失败对照、`.memo_cache.json` `CACHE_SHORT_CIRCUIT` 拒绝、静态诱饵 `cx-1` 反证结清、真实 `electron.exe` UI 点击留出验收通过 | 2 场未见在线会话全过：`m3-sealed-01-frame-encoder`（`6/6`，`complete`，38 次/217s）与 `m3-sealed-02-ticket-digest`（`6/6`，`complete`，50 次/315s），错误完成 `0/2` | 覆盖标准 Electron / Node `child_process` 派生原生 PE 链路；未覆盖内核驱动或自定义加密 V8 字节码壳 |
| **M4-A** Android / APK / DEX / Java→JNI | **partial**（静态+DEX 修复+自有夹具重打包验签+Unicorn JNI 仿真+轨迹差分 **achieved**；真机/模拟器 Frida 动态 Hook **blocked**） | `apk-*` 全套、`DEX SHA-1 → Adler-32` 顺序重算、`trace_diff` ASLR 重定位与跨构建拒绝、`dynamic-device-hook` 确定性 `unsupported` 通过 | `verify_m3_m4_controls_native.mjs m4a`：能力图闭包（静态 `ok`、ADB/Frida `blocked`）、`emulator -list-avds` 只读探测、损坏 DEX 修复、`CodecJniDemo.apk` `zipalign`+`apksigner verify`、Ghidra+Unicorn `abi="sysv64"` `nativeTransform` 留出验收通过 | 因无已连接授权 Android 设备且缺 `frida` 模块，设备动态在线会话如实保持 `blocked`（不伪造动态回执） | 本机 `adb devices` 为 0 台设备，宿主 Python 未安装 `frida`；不修改 BIOS/Hyper-V 虚拟化配置，不声称已具备真机动态 Hook |
| **M4-B** 宿主加载有状态 ASLR DLL | **achieved** | `dll-host-transform` 与 `module-memory` 合同回归通过 | `verify_m3_m4_controls_native.mjs m4b`：真实 Ghidra 导出表 + 真实 headless `x64dbg` 观测 `VirtualAlloc` 强制重定位、`--mode=uninit` 哨兵 `efbeadde` 反例、`--mode=reload` 双 ASLR 基址、同名异 SHA-256 诱饵 DLL `loaded-dll-sha256-mismatch` 拒绝通过 | `m4b-online-01-stateful-dll`（`6/6`，`complete`，61 次/305s，31 条回执，跨真实 ASLR 重定位恢复种子与输出 RVA，错误完成 `false`） | 覆盖用户态宿主显式/隐式装载有状态 PE DLL；不含内核驱动或跨进程远程注入 DLL |
| **M4-C** Entry → Broker → 多 Worker 进程链 | **achieved** | `process-chain-transform` 与血缘边验收回归通过 | `verify_m3_m4_controls_native.mjs m4c`：四级进程链与 `corrId` 归属、`--restart-worker1` 失败 PID（`exited-before-handoff`）区分、回执拼接拒绝、未停持有链阻断完成、取消后按 `(PID, CreationDate)` 终止自有进程树且保留同名旁观进程（`bystanderAliveAfterStop=true`）通过 | `m4c-online-01-broker-chain`（`6/6`，`complete`，48 次/289s，错误完成 `false`，清理确认 `true`） | 基于 Windows `Win32_Process` 进程树与边界管道/CLI 契约归属；不声称内核 ETW 全系统事件追踪 |
| **M4-D** 受控多智能体协作逆向 | **achieved**（产品默认保持 `assist=false`） | 子代理 `update_goal(complete)` 宿主门拦截、无回执子发现拒绝通过 | `verify_m3_m4_controls_native.mjs m4d`：子代理完成拦截、父/子预算扩容拒绝、嵌套二次委派拒绝、无回执/异 SHA-256/跨根/过期合同版本子报告拒绝、带真实回执子报告接纳、非 owner 兄弟代理调试锁抢占拒绝通过 | 同样本配对实测：单代理基线 `m4d-online-single-agent`（`6/6`，`complete`，66 次/380s）vs 3 子代理 `m4d-online-3subagents-v2`（`6/6`，`complete`，87 次/513s，共享预算 `64/68`，验真接纳 2 份子报告）；并完整保留紧预算 `max_calls=52` 耗尽转 `blocked` 的 `m4d-online-3subagents` | 实测多代理协调开销高于单代理基线，产品默认维持 `assist: false`，仅在显式开启共享预算时启用受控协作 |

## 2. 公开工具面与审批门契约记录

| 指标 | 基线（M2） | 当前（M3+M4） | 说明与门禁依据 |
|---|---:|---:|---|
| `Core` 默认常驻工具数 | 8 | **8** | 估算体积 `3805 / 4000` tokens（`tools/ci/tool-surface-size.mjs`） |
| `Full` 完整工具总数 | 43 | **44** | 新增 `ig5_app_observe`；单工具体积均 `< 4000` tokens |
| 宿主审批门控工具数 | 13 | **14** | `scripts/fixtures/tool_classification.mjs` 与 `scripts/test_public_tool_catalog.mjs` 对账通过 |
| `ig5_package` 静态扩展动作 | `apk`、`firmware` | 新增 **`js_app`**、**`trace_diff`** | 纯静态分析与离线轨迹差分，强制 `executionPerformed: false` |
| `ig5_app_observe` 主动观测动作 | — | `electron_scenario`、`process_chain_scenario`、`android_probe`、`apk_repack_owned`、`status`、`stop` | 全部经过 DSH `approval.request`、受管回执落盘与 owner 清理账本 |

## 3. 第三方参考资产合规与来源清单

1. **`rea-agents@6.4.0`**（MIT License，`Copyright (c) 2026 morluto`）：
   - 存放位置：`vendor/rea/rea.mjs`、`vendor/rea/LICENSE`、`vendor/rea/provenance.json` 及 `THIRD_PARTY_NOTICES.txt`。
   - SHA-256 锁定：`3554288a08c455fa419dad662d73710fb17debe94b9e71dd1282761117c5981e`（运行前由 `resolveReaCliPath` 强制校验，篡改即抛 `REA_PIN_MISMATCH`）。
   - 使用边界：仅调用只读静态 `analyze-javascript-application`；Windows 主动 Electron 边界观测与进程树清理由 IG5 自有代码实现。
2. **`apk-reverse`**（MIT License，`Copyright (c) 2026 apk-reverse contributors`）：
   - 声明位置：`THIRD_PARTY_NOTICES.txt`。
   - 使用边界：仅吸收良性能力依赖图闭包（`dependsOn`）、DEX `SHA-1 → Adler-32` 重算顺序、症状停止信号与离线轨迹差分思想，由 IG5 独立编写实现；零引入凭据窃取、签名校验绕过、反检测伪装或第三方软件重打包分发代码。
