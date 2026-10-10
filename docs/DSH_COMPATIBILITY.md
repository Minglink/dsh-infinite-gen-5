# DSH 宿主兼容与验收范围

记录日期：2026-10-10。IG5 版本保持 1.0.0。本轮默认 Reverse 使用随包内核，源码副本的实际宿主 SDK 与全部 38 个公开工具验收已通过，无需本机商业引擎。发行附件的下载、安装与功能复验以对应 Release 的验收报告为准；不能把源码结果替代下载副本结果。

## 实际版本与声明范围

本机安装的 DeepSeek Harness `resources/app.asar` 内，桌面包 `@deepseek-ai/dsh-desktop` 和用于兼容判断的 `@deepseek-ai/dsh-app-boot` 版本均为 **`0.2.1-alpha.1`**。实际 tools、scope、skills、commands、session-projection 等 SDK 包也为 `0.2.1-alpha.1`。用户已确认本次要求的“0.2.1 re1”就是该 `0.2.1-alpha.1`；这是本轮真实服务验证的版本，其他构建仍须分别核验。

`package.json` 声明：

```json
{
  "peerDependencies": {
    "@deepseek-ai/dsh": ">=0.2.0-rc.1 <0.3.0-0"
  },
  "peerDependenciesMeta": {
    "@deepseek-ai/dsh": { "optional": true }
  }
}
```

宿主实际兼容 evaluator 使用 semver 的 `includePrerelease: true`。下界允许 `0.2.0-rc.1` 起的相应 0.2 版本；上界 `<0.3.0-0` 连 `0.3.0-alpha.1` 也排除。可选 peer 避免包管理器为插件自动安装另一个宿主。这里的声明不保证未测试构建保留相同 API，也不证明桌面界面或模型 Provider 已验收。

| 版本 | 实际宿主兼容 evaluator 结果 | 服务验收 |
|---|---|---|
| `0.2.1-alpha.1` | 接受 | 本轮使用该安装包的真实 SDK 验证通过 |
| `0.2.0-rc.1`、`0.2.0-rc.2`、`0.2.1-alpha.2`、`0.2.1` | 版本判断接受 | 仅核验 semver 边界，未逐个安装并执行其 SDK |
| `0.1.7-rc.2`、`0.1.9` | 拒绝 | 不声明支持 |
| `0.3.0-alpha.1`、`0.3.0`、`0.3.1` | 拒绝 | 不声明支持 |

兼容 evaluator 的相关函数从实际安装包原样提取，在隔离 VM 中用实际 semver 调用；这不等于导入整个 app-boot 或启动 DSH。

## 工具作用域

已在实际 DSH tools / scope 服务中验证：全局保留 Core8，另外 30 个工具只注册到真实 `agent.ctx`。agent A 展开 Full38 时，agent B 和全局仍为 Core8；之后两个 agent 可独立切换。`ig5_profile` 返回 `toolsetScope=agent`，切换不持久化，也不授予执行或写权限。缺少可用 agent context 时拒绝切换，不凭字符串 id 创建伪作用域。

支持的 Core8 为 `ig5_doctor`、`ig5_open`、`ig5_status`、`ig5_funcs`、`ig5_strings`、`ig5_decompile`、`ig5_close`、`ig5_profile`。新 agent 按 `config.toolset` 初始化，插件和 agent 卸载清理各自注册。旧宿主缺少 scoped API 时，兼容路径明确返回 `toolsetScope=plugin-instance`；本轮没有用每一个旧版本实际安装包验证该回退。

## 12 个工具的明确一次审批

`ig5_rename`、`ig5_patch_bytes`、`ig5_comment`、`ig5_analyze`、`ig5_set_type`、`ig5_undo`、`ig5_run_idapython`、`ig5_dbg`、`ig5_struct`、`ig5_switch_repair`、`ig5_emulate`、`ig5_sync` 按工具名称进入审批门。因此结构体 list/get 和 sync preview 也需要工具级审批。

审批门直接请求宿主公共 `approval.request`，携带真实 agent、toolName、callId、signal 及双语理由。只有明确返回 `allowed-once` 才调用 `next`；后续宿主策略仍可拒绝。拒绝、不可用、未知结果、缺 agent/服务或请求异常均终止为 deny，取消结果或已中止的 signal 返回 cancel。每次调用独立请求，不缓存上一次批准。当前安装包存在把部分 `ask` 结果折算为 allow 的路径，插件不再依赖该路径。

本轮真实 tools registry 验证了全部 12 个工具在拒绝时未 dispatch、未启动原生 worker，以及取消、不可用、未知、异常、缺 agent/服务。明确一次批准到达工具体时使用无打开目标的调用，确保验证审批允许路径时仍不执行样本。审批服务在测试中可控；这证明 registry 与审批协议，不证明桌面人工审批弹窗的外观和点击交互。

`scripts/test_approval_gate.mjs` 另读取实际产品 gate，在隔离 VM 中覆盖 45 组断言，包括 abort 后请求抛异常、一次批准不缓存、下游 deny 与错误传播。该测试不创建 worker、数据库、项目、产物或网络请求。HTTP 工作台仍只提供只读数据及 composer 草稿。

## 严格 JSON 输出

DSH 会在渲染前校验工具结果。IG5 的 `source/json_output.js` 在公开工具输出边界生成普通 JSON 数据：可选对象字段的 `undefined` 省略，`null` 保留；数字必须有限且不能为负零。数组空位/undefined、BigInt、函数、循环引用、accessor、带额外字段的数组及非普通对象明确报错，不通过隐式 stringify 丢失含义。

64 位地址和需要保留精度的整数使用字符串。扫描常量样本的 Shannon 熵在 Python 生产者处由 `-0.0` 规范为 `0.0`；未观察到字节时仍为 `None`/JSON `null`。`test_json_output.mjs` 核验输出契约，`test_scan_analysis.py` 覆盖常量熵符号及 JSON 往返，实际 SDK 验证另确认 status/profile 通过宿主的结果校验。

## 各层证据能证明什么

| 验证入口 | 使用的真实组件 | 证据范围与限制 |
|---|---|---|
| `scripts/test_host_sdk.mjs` | 实际安装包的 Cordis、tools、scope、skills、commands、projection、SlotCore 和兼容 evaluator | 两 agent 隔离、38 schema、七技能加载、命令、投影、审批与结果校验、注册卸载；隔离 context，无桌面 GUI、模型 API、分析/调试 worker。仅允许读取测试进程自身创建身份的 PowerShell 查询 |
| `scripts/test_approval_gate.mjs` | 实际产品审批 hook | 可控公共服务与完整 exec 的允许/拒绝/取消及零下游调用断言；不代替真实 SDK dispatch |
| `scripts/test_client.mjs` | 实际 client 源码 | VM 中的 renderer/HTTP fixture；不是真实浏览器或原生引擎 |
| `scripts/preview_client.mjs` 加浏览器操作记录 | 安装包的真实 React/ReactDOM 与浏览器 | 本轮 8 页、16 项交互检查通过，含 CFG 缩放/拖动/跳转、高亮、草稿保留、审计分页、解密/协议及 390×844 窄屏无横向溢出；HTTP 分析数据为 fixture，不证明实时引擎、调试器或手机原生运行 |
| `scripts/test_public_tool_catalog.mjs` | 插件公开 execute、内置 Reverse/Ghidra 独立数据库车道、随包 Unicorn、x64dbg | 38 工具全部通过，包括真实微码阶段、脚本兼容 API、两车道同步、动态断点/寄存器/单步和 12 个审批门。内置静态数据库服务来源为 Ghidra；使用生成 PE，宿主审批服务可控，实际 SDK 另验，不外推任意样本或专有 API 的完整兼容 |
| 引擎、调试和数据回归 | 对应真实 worker/生成样本或样本副本 | 根据每项断言核验具体能力；fake/mock、单纯 load 和存在工具均不能算运行闭环 |
| 下载归档/安装校验 | 实际 GitHub 附件及隔离安装副本 | 文件大小/hash、完整资产和安装流程；不能单凭归档完整性推断所有功能正常 |

本轮内核重构证据根为 `~/.dsh/ig5/artifacts/kernel-reconstruction-20261010/`，逐工具报告与各次受测源码身份分别保留。早期 `github-consumer-validation-20261010/` 中的 69 项断言、6 项 unsupported 和安装 26 场景是重构前的历史记录；不能用它们说明当前内置能力。历史 `workbench-browser.json` 与截图仍仅证明浏览器 fixture 交互，`download-original-sdk/host-sdk.json` 保留原附件 SDK 问题。最新安装回归覆盖 35 个本地及模拟网络场景；实际公开下载、完整离线安装及安装后的原生复验另记录。下载副本和源码分别记录文件身份，旧远端附件与失败记录不覆盖；模拟网络不能替代实际 GitHub 下载。

## 重验入口

验证另一个 DSH 构建时，必须提供它实际安装包中的 `app.asar`，不可用伪造版本号替代服务测试：

```powershell
node .\scripts\test_host_sdk.mjs --asar "<实际app.asar路径>" --plugin-root "<受测插件目录>" --evidence "<独立证据目录>"
node .\scripts\test_approval_gate.mjs
node .\scripts\test_json_output.mjs
```

纯 gate 和 public catalog 可通过 `IG5_PLUGIN_UNDER_TEST` 指向下载后安装副本。完整 catalog 默认使用 `reverseProvider=bundled` 的内置 Reverse、显式 Ghidra 车道及随包 x64dbg，无需本机商业引擎；使用生成的临时 PE、独立 IG5_HOME/项目/状态/产物并在 finally 清理。原生运行按维护安排串行执行。指定少数引擎或禁用调试只能产生部分覆盖报告，不能作为 38 项全部通过。

已知能力边界继续以 [HARNESS_PLUGIN](../HARNESS_PLUGIN.md#已验证范围)、[SELF_CONTAINED_KERNEL](SELF_CONTAINED_KERNEL.md)、[SCRIPT_API](SCRIPT_API.md) 和各引擎 capabilities 为准。内置微码提供真实 p-code/SSA 与有界优化，脚本提供明确兼容子集，不能冒称完整商业专有 API。可选商业扩展的 Bochs load 不等于运行闭环；生成夹具不保证任意二进制；Android/iOS 尚无本轮真机原生执行证据。
