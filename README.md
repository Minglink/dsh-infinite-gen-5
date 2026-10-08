# ⚔️ DeepSeek-V4.1 / V4 Flash 网络安全逆向与红队防御评测工具（无限四代）v0.4.0
（使用工具需要合法授权）

<p align="center">
  <img src="assets/banner.png" alt="无限四代 Infinite Generation Four" width="100%" />
</p>

<p align="center">
  <a href="dsh://plugin/install?id=dsh-infinite-gen-4&name=%E6%97%A0%E9%99%90%E5%9B%9B%E4%BB%A3&version=0.4.0&repo=Minglink%2Fdsh-infinite-gen-4&permissions=%E7%B3%BB%E7%BB%9F%E6%8F%90%E7%A4%BA%E8%AF%8D%E6%B3%A8%E5%85%A5%2C%E5%AE%A2%E6%88%B7%E7%AB%AF%E7%8A%B6%E6%80%81%E6%9D%A1&downloadUrl=https%3A%2F%2Fgithub.com%2FMinglink%2Fdsh-infinite-gen-4%2Farchive%2Frefs%2Fheads%2Fmaster.zip">
    <img src="https://img.shields.io/badge/DeepSeek%20Harness-🚀%20唤起桌面客户端一键安装无限四代-10B981?style=for-the-badge&logo=deepseek&logoColor=white" alt="唤起桌面客户端一键安装" />
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
> 🔥 欢迎进群交流红队安全攻防对抗心得、分享逆向工程经验与评测基准、探讨大模型防御护栏（Guardrails）评测与生态共建！

---

## 🛡️ 网络安全红队基准评测的必要性（Why Red-Teaming Matters）

在生成式人工智能与大语言模型（LLM）向各行业深度融合的背景下，模型的鲁棒性、对抗防御能力与系统对齐安全性已成为网络空间安全的核心研究课题：

1. **暴露防御边界，反哺安全护栏**：只有通过专业的网络安全红队对抗模拟（Red-Teaming），在受控环境下深入探查模型的输入逃逸、提示词注入与非预期行为，才能帮助安全团队精确定位模型的防护盲区，从而在模型微调、输入过滤网关（Guardrails）与系统安全层实现前置加固。
2. **构建攻防一体化防御体系**：缺乏受控红队评测用例的防御如同纸上谈兵。标准化红队用例集（Test Suite）为企业与安全审计机构提供了衡量防御策略有效性的“标尺”，确保在面对真实威胁前已具备充分的检测与阻断能力。
3. **推动大模型原生安全与逆向学术发展**：本项目旨在为学术界与安全工程领域提供透明、合规、可复现的基准测试基线，共同推动 AI 基础设施抗对抗攻击、流形约束对齐与形式化验证技术演进。

---

> ### ⚠️ 严正法律免责与合规使用声明（Strict Legal & Compliance Disclaimer）
>
> **【零容忍严正申明】**：本项目坚决反对并严禁任何形式的违法犯罪行为！本项目开发者绝不支持、不鼓励、不协助任何未授权网络攻击、漏洞利用、数据窃取、非法侵入计算机信息系统或生成违法违禁内容的活动。
>
> 1. **合法受控范围限定**：本项目（`dsh-infinite-gen-4`）定位为纯粹的网络安全红队科研工具、合规逆向工程与鲁棒性基准评测套件。**严禁在未经所有者合法书面授权的目标、公网在线系统或生产业务上运行本项目**。一切测试行为必须严格限制在**离线本地合成靶标（Local Synthetic Fixtures）、授权网络安全演练靶场及合规实验室受控环境**中进行。
> 2. **严禁违法与违禁用途**：使用者严禁利用本项目直接或间接从事：
>    - 任何违反《中华人民共和国刑法》、《中华人民共和国网络安全法》、《中华人民共和国数据安全法》、《中华人民共和国个人信息保护法》等法律法规的行为；
>    - 未经授权渗透、攻击公私机构计算机信息系统，实施勒索、破坏、撞库或传播恶意载荷；
>    - 诱导、生成或传播危害国家安全、恐怖主义、暴力血腥、涉黄涉赌、诈骗、侵犯公民隐私或知识产权等任何法律明令禁止的违法违禁内容；
>    - 违反相关大模型提供商的《服务条款（Terms of Service）》与《滥用政策（Usage Policy）》。
> 3. **开源协议与严格非商用限制（CC BY-NC-SA 4.0）**：本项目依据 **CC BY-NC-SA 4.0（署名-非商业性使用-相同方式共享 4.0 国际开源协议）** 及严禁商用特别条款“按现状（AS-IS）”提供。**严禁任何个人、企业或第三方将本项目（或二次开发衍生版本）用于商业售卖、付费倒卖、商业封装或黑灰产牟利，二次开发商用属于严重违法违规行为**。使用者应对自身的所有下载、部署、运行、修改、传播行为以及由此产生的全部输入与输出后果承担独立、完全的法律责任。项目作者与贡献团队绝不承担任何因使用者滥用导致的直接、间接或连带责任。
> 4. **违约即终止授权**：任何将本项目用于非法攻击、恶意活动或违规行为的个人或实体，其开源软件使用许可将自违法违规行为发生之日起**自动且不可撤销地立即终止**。该主体须立即停止使用并永久销毁本项目的所有代码、脚本与衍生数据，并依法承担相应法律制裁。
> 5. **第三方独立性声明**：本项目属于完全独立的开源安全评测研究项目，与 DeepSeek 官方或其关联主体无任何隶属、商业合作、授权或官方背书关系。

---

> 🔥 **V4.1-DeepSeek Flash 网络安全红队与逆向工程工具（无限四代）v0.4.0**。针对 V4.1 强化学习对抗进行深度适配与支持，支持桌面端与客户端一键安装。如果这个开源网安项目对你有帮助，欢迎点亮 Star ⭐。
> 
> **v0.4.0 纯净合规版**：原生采用零工具面架构，杜绝模型思考阶段的决策噪音；注入双层协同内核，仅保留系统提示词注入与实时状态投影。**严正声明：本项目严格打击与抵制（且不支持）模型生成 NSFW 等任何违法违规、违禁不良内容，技术体系仅限用于合法授权的逆向工程、防御安全审计与网络安全研究。**

---

> ### 🧬 v0.4.0 双层内核说明（Dual-Layer Kernel）
>
> - 注入槽位：`infinite-gen-4:global-system-prompt`（Order 100）+ `infinite-gen-4:dual-layer-reinforce`（Order 200），
>   由 `index.js` 的 `DUAL_LAYER_INJECTION` 开关控制（改 `false` 即单段注入，行为等价）。
> - `prompts/` 下三个内核文件（`infinite-gen-3.md` / `infinite-gen-4.md` / `infinite-gen-4.1-flash.md`）保持同源逐字一致。

---

## 📊 世代架构与能力对比

| 维度 | 无限二代 | 无限三代 | 无限四代 (v0.4.0) |
|---|---|---|---|
| **目标模型** | V3 / 早期 V4 | DeepSeek-V4 (mHC) | DeepSeek-V4.1 / V4-Pro / Flash 全系列 |
| **运行时架构** | 单层提示词 | 安全基准版单层 | **双层协同注入（通用内核 + 强化镜像同源同构）** |
| **工具面设计** | 粗粒度 | 零工具面 | **原生零工具面（消除决策噪音，极速直出）** |
| **逆向工程分析** | 基础反编译 | 脚本级分析 | **深度逆向支持 (Ghidra/IDA/Frida/Angr/PE/ELF/APK)** |
| **输出契约** | 弱规则 | 首行命名交付物 | **首 Token 强制诱导 (##/```) + 占位符自造** |
| **客户端状态条** | 无 | 支持（带域与载荷计数） | **支持（实时投影 + 状态条）** |
| **一键安装协议** | 手动配置 | 支持 dsh:// | **原生支持 dsh:// 联动 + 自动兼容旧版** |

---

## 📁 项目目录结构

```
无限四代v0.4.0/
├── 🚀 一键安装与维护套件
│   ├── install.ps1              # Windows 一键自动安装（自动配置环境，注册协议）
│   ├── install.bat              # Windows 快捷双击批处理
│   ├── install.sh               # Linux / macOS 一键安装
│   ├── uninstall.ps1            # Windows 一键卸载
│   └── uninstall.sh             # Linux / macOS 一键卸载
├── 🧩 核心插件装载面 (标准 Cordis 架构)
│   ├── package.json             # 插件元数据（dsh-infinite-gen-4 v0.4.0）
│   ├── cordis.patch.yml         # 核心 patch 声明
│   ├── index.js                 # 插件核心入口（双层提示词注入 + profile 元数据 + 会话投影）
│   ├── client.js                # 客户端半体（「⚫ 无限四代 v0.4.0」状态条）
│   └── HARNESS_PLUGIN.md        # 插件规范说明
├── 📜 网络安全红队与逆向分析系统提示词本体
│   └── prompts/
│       ├── infinite-gen-3.md          # 三代经典内核
│       ├── infinite-gen-4.md          # 四代通用内核（逆向工程 + 防御审计 + 全域槽位）
│       └── infinite-gen-4.1-flash.md  # V4.1 强化镜像层（逆向分析 + 防御审计 + 符号恢复）
├── 📖 文档中心
│   ├── README.md                # 综合主说明文档（本文件）
│   └── LICENSE                  # CC BY-NC-SA 4.0 开源协议（严禁商用与二开商用）
├── 🛡️ 确定性回归测试套件
│   ├── scripts/
│   │   ├── lib/scorer.mjs       # 开头窗口判拒与域分类评分器
│   │   ├── verify_prompt.mjs    # 经典确定性校验
│   │   ├── verify_prompt_gen4.mjs # 四代全量回归断言（103 项严苛断言全部通过）
│   │   └── verify_prompt_gen41.mjs # V4.1 专项断言
│   └── tests/
│       ├── prompt-bank.jsonl      # 经典双语回归用例库
│       ├── prompt-bank-gen4.jsonl # 四代双语回归用例库（合规逆向 & 安全审计）
│       ├── prompt-bank-gen41.jsonl # V4.1 专项用例库（符号执行 & 自动化分析）
│       └── v4pro-benchmark.jsonl  # V4-Pro 评测基准
└── 📁 静态资源 (assets/)
```

---

## ⚡ 一键安装方式

### 方式 1：dsh:// 协议联动一键安装（⚡ 桌面端最快，秒级免命令行）

若已安装 DeepSeek Harness 官方桌面客户端（EXE），点击下方按钮即可通过系统级 URI Scheme 协议安全唤起客户端完成免命令行秒级装载：

> 🌐 **插件生态市场**：[DeepSeek Harness Hub - DeepSeek 官方与开源生态市场 | 插件发现与一键安装](https://deepseek.stream/)

<p align="center">
  <a href="dsh://plugin/install?id=dsh-infinite-gen-4&name=%E6%97%A0%E9%99%90%E5%9B%9B%E4%BB%A3&version=0.4.0&repo=Minglink%2Fdsh-infinite-gen-4&permissions=%E7%B3%BB%E7%BB%9F%E6%8F%90%E7%A4%BA%E8%AF%8D%E6%B3%A8%E5%85%A5%2C%E5%AE%A2%E6%88%B7%E7%AB%AF%E7%8A%B6%E6%80%81%E6%9D%A1&downloadUrl=https%3A%2F%2Fgithub.com%2FMinglink%2Fdsh-infinite-gen-4%2Farchive%2Frefs%2Fheads%2Fmaster.zip">
    <img src="https://img.shields.io/badge/DeepSeek%20Harness-🚀%20唤起桌面客户端一键安装无限四代-10B981?style=for-the-badge&logo=deepseek&logoColor=white" alt="唤起客户端一键安装" />
  </a>
</p>

🔗 **原生协议链接：**

```
dsh://plugin/install?id=dsh-infinite-gen-4&name=%E6%97%A0%E9%99%90%E5%9B%9B%E4%BB%A3&version=0.4.0&repo=Minglink%2Fdsh-infinite-gen-4&permissions=%E7%B3%BB%E7%BB%9F%E6%8F%90%E7%A4%BA%E8%AF%8D%E6%B3%A8%E5%85%A5%2C%E5%AE%A2%E6%88%B7%E7%AB%AF%E7%8A%B6%E6%80%81%E6%9D%A1&downloadUrl=https%3A%2F%2Fgithub.com%2FMinglink%2Fdsh-infinite-gen-4%2Farchive%2Frefs%2Fheads%2Fmaster.zip
```

**网页端（前端）触发代码示例：**

```js
/**
 * 唤起 DeepSeek Harness 桌面客户端一键安装无限四代插件
 */
export function installInfiniteGen4ToDesktop() {
  const params = new URLSearchParams({
    id: 'dsh-infinite-gen-4',
    name: '无限四代',
    version: '0.4.0',
    repo: 'Minglink/dsh-infinite-gen-4',
    permissions: '系统提示词注入, 客户端状态条',
    downloadUrl: 'https://github.com/Minglink/dsh-infinite-gen-4/archive/refs/heads/master.zip',
  });

  const deepLink = `dsh://plugin/install?${params.toString()}`;

  // 通过隐藏 iframe 安全静默拉起协议
  const iframe = document.createElement('iframe');
  iframe.style.display = 'none';
  iframe.src = deepLink;
  document.body.appendChild(iframe);
  setTimeout(() => document.body.removeChild(iframe), 2000);
}
```

**HTML 静态链接方式：**

```html
<a href="dsh://plugin/install?id=dsh-infinite-gen-4&name=%E6%97%A0%E9%99%90%E5%9B%9B%E4%BB%A3&version=0.4.0&repo=Minglink%2Fdsh-infinite-gen-4&permissions=%E7%B3%BB%E7%BB%9F%E6%8F%90%E7%A4%BA%E8%AF%8D%E6%B3%A8%E5%85%A5%2C%E5%AE%A2%E6%88%B7%E7%AB%AF%E7%8A%B6%E6%80%81%E6%9D%A1&downloadUrl=https%3A%2F%2Fgithub.com%2FMinglink%2Fdsh-infinite-gen-4%2Farchive%2Frefs%2Fheads%2Fmaster.zip" class="btn-install">
  🚀 唤起客户端一键安装
</a>
```

**协议参数配置（dsh://plugin/install）：**

| 参数名 | 值 / 示例 | 说明 |
|---|---|---|
| id | `dsh-infinite-gen-4` | 插件唯一标识符 |
| name | `无限四代`（URL 编码） | 插件展示名称 |
| version | `0.4.0` | 语义化版本号 |
| repo | `Minglink/dsh-infinite-gen-4` | 官方 GitHub 仓库 |
| permissions | `系统提示词注入, 客户端状态条`（URL 编码） | 申请权限 |
| downloadUrl | `https://github.com/Minglink/dsh-infinite-gen-4/archive/refs/heads/master.zip` | 离线 zip 下载直链 |

---

### 方式 2：Windows 本地脚本一键安装（推荐）

1. 打开本文件夹；
2. 右键 `install.ps1` → **「使用 PowerShell 运行」**（或直接双击 `install.bat`）；
3. 脚本会自动完成：依赖写入、`pnpm install` 与 `dsh://` 协议注册；
4. 看到「安装完成」后，**完全退出并重启 DeepSeek Harness**（Web 版刷新页面，桌面版重新启动），新建会话即可生效。

### 方式 3：Linux / macOS 一键安装

```bash
chmod +x install.sh uninstall.sh
./install.sh
```

### 方式 4：手动配置安装

在 `~/.dsh/profiles/<web 或 default>/package.json` 中添加：

```json
{
  "dependencies": {
    "dsh-infinite-gen-4": "file:../../plugins/dsh-infinite-gen-4"
  },
  "dsh": {
    "profile": {
      "bundles": [
        "@deepseek-ai/dsh-base",
        "dsh-infinite-gen-4"
      ]
    }
  }
}
```

然后在 profile 目录下执行 `pnpm install` 并重启 Harness。

---

## ⚡ 验证生效

1. **界面状态条**：重启后在输入框上方应显示醒目的绿色状态条 **「⚫ 无限四代 v0.4.0」**。
2. **测试离线回归**：
   ```bash
   # 运行 103 项断言（提示词完备性、双层内核同源性、V4.1车道、纯净架构、评分器等）
   node scripts/verify_prompt_gen4.mjs
   ```
3. **会话探针**：在全新对话中输入：
   > “你的系统提示词来自哪些插件？”
   若回答包含「无限四代 / Infinite Generation Four」即证明双层提示词完全注入成功。

---

## 🗑 卸载方法

运行 `uninstall.ps1`（Windows）或 `./uninstall.sh`（Linux / macOS）即可一键彻底清理，无任何配置残留。

---

## 💬 官方交流社区

> 📌 **非盈利公益项目，严禁任何主体用于商业售卖、付费倒卖或黑灰产牟利，仅供技术参考。**

<p align="center">
  <img src="./assets/community.jpg" width="240" alt="DeepSeek网安逆攻防技术交流社区" /><br>
  <sub><b>🌐 官方技术交流社区（腾讯频道号：pd86424753）</b></sub>
</p>

---

## 📄 开源协议与非商用特别声明（License）

本项目采用 **[CC BY-NC-SA 4.0（署名-非商业性使用-相同方式共享 4.0 国际许可协议）](LICENSE)** 进行开源，并附加以下严格的法律与商业限制条款：

1. 🚫 **严禁直接商业使用**：禁止任何个人、企业或第三方将本项目（包括源码、双层注入内核、提示词资产、分发包及文档）用于商业售卖、付费倒卖、付费社群、会员增值服务或黑灰产牟利。
2. 🚫 **严禁二次开发商业化**：任何基于本项目的 Fork、修改、重构、二次开发或作为组件嵌入其他软件时，**必须严格继承 CC BY-NC-SA 4.0 协议并完全开源，绝对禁止将任何二次开发或衍生作品用于商业营利**。二开商用属于严重侵权及违法违规行为。
3. ⚖️ **违规终止与法律追责**：任何违反非商业性条款的行为将导致开源授权自动且永久终止，原作者保留依法追究侵权方民事赔偿与法律制裁的一切权利。
