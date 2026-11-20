# IG5 自主逆向决策架构

状态：v0.2（M0/M1 已有分层验证；M2 首轮真实模型四实例已结束，有限输出评分 4/4、宿主闭环完成 2/4，严格盲测隔离未证；冻结后定点修复已有离线回归，宿主 SDK 门禁仍有缺件失败）。日期：2026-11-18。基线：dsh-infinite-gen-5-master，package 1.3.0。

本版在原文件内替换 v0.1。保留 DSH 单一模型驱动、IG5 现有引擎、公共工具和资源管理；优化决策方式、执行协议与首版范围。本文描述技术研究流程，不承担案件或法律流程。

## 1. 本版的六项关键改进

| v0.1 的薄弱点 | v0.2 的选择 |
|---|---|
| 总选当前可执行动作，容易一直静态导出 | 从交付目标倒推短路线，允许投入必要的动态准备 |
| 有工具调用，却未必触发了业务 | 实验同时描述运行场景、触发、观测健康和判断条件 |
| 每个小操作都 select/evaluate，管理成本高 | 低成本查询可内联登记；重要反馈才重新规划 |
| 模型解释结果，但下一步仍可能不变 | 评估明确提交“哪些前提和候选因此改变” |
| 预算与执行意图分开写入，恢复时可能重复 | 扩展原执行预算账本，统一持有派发资格；研究状态引用回执 |
| 六个模块容易各自维护状态 | 收敛为控制器、版本化研究状态、受管能力三个边界 |

产品目标保持：输入软件和希望得到的成果，系统自行盘点、拆解障碍、组合方法、执行和调整，交付有适用范围及验证依据的结果。

“使用各种方法”体现为能按障碍选择、准备和组合能力。成果可以是行为解释、算法实现、协议模型、可分析映像、可运行重建或指定行为修改，分别验收。只有“分析这个软件”时，先有界盘点并形成可交付选项，关键目标无法推断时再向用户澄清。

## 2. 三个核心边界

~~~mermaid
flowchart TD
    U[软件与交付目标] --> H[DSH：模型运行、续轮、用户控制]
    H --> C[控制器：整理上下文、提议路线、准备操作、评估反馈]
    S[研究状态：目标、组件、场景、问题、证据、验收] <--> C
    M[方法与当前能力目录] --> C
    C --> X[受管执行入口：派发账本、原审批与队列、原资源所有者]
    X --> I[IG5：静态、调试、仿真、数据分析]
    X --> R[REA：JS / Electron]
    X --> A[APK：Android 专项能力]
    I --> E[原始回执与工件]
    R --> E
    A --> E
    E --> S
    C --> V[同一状态派生的交付评估]
    V --> O[成果、范围与未决项]
    V -. 宿主接口验证后接入 .-> H
~~~

| 边界 | 权威职责 | 首版落点 |
|---|---|---|
| 控制器 | 调整研究方向；管理选定路线；核验操作前提；生成上下文和验收视图 | 复用 workspace、planner、failure_router，增加少量执行/验收函数 |
| 研究状态 | 保存目标、观察、解释、依赖与修订；支持恢复 | 扩展 InvestigationStore / ResearchState，原始内容留工件存储 |
| 受管能力 | 真实调用、派发去重、成本、取消、资源身份、实际回执 | index.js 统一包装、DelegationControl、既有 worker/provider |

这三个边界是同一插件内的职责，不要求三个服务。规划、失败评估、验收先作为内部函数，不建设各有状态的独立智能体或通用调度平台。

DSH 是唯一模型运行和续轮来源。IG5 控制器通过工具和正式宿主接口工作，不另外循环调用私有模型 API。模型负责假设、路线选择和语义解释；代码负责结构检查、当前条件、执行记录和可计算的验证。模型同意某个结论不构成独立验证。

## 3. 决策尺度：目标、路线、实验与动作

### 3.1 从交付条件倒推短路线

~~~text
交付要求
  └─ 尚未满足的验收项
       └─ 需要获得的关键观察或产物
            └─ 当前路线：必要准备 → 辨别实验 → 验证
                 └─ 当前具备条件的具体操作
~~~

路线只保存少量里程碑、待满足前提、下一观察点和退出条件。它不预编译整个软件的研究过程，不需要通用 DAG/DSL。

例如，目标是恢复某个转换算法，当前需要知道运行时输入如何进入原生函数。即使断点实验尚不可执行，仍可选择“确认启动参数和输入传递 → 建立可复现触发 → 观察函数”的路线。准备动作必须说明它最终解锁哪项观察。

区分两种就绪：
- 路线可行：关键前提已知如何取得，准备成本在剩余预算内；未知可先做可行性探测。
- 当前操作可执行：此刻的输入、能力、资源、授权和运行身份均满足要求。

未就绪的最终动作保留在路线中；只有当前可执行的一步进入派发。不会因动态分析需要准备，就永久选择现成的静态导出。

### 3.2 选择与换路

候选来自当前问题、方法库、失败记录以及模型提出的探索。选择理由至少回答：
1. 它推进哪个交付条件，能获得什么关键观察？
2. 需要哪些前置准备，当前先做哪一步？
3. 不同结果分别支持什么判断？
4. 成本、干扰和不确定性是否值得？
5. 什么结果或成本边界会使我们暂停或放弃这条路线？

使用可解释的优先级，不伪造成功概率或信息熵评分。允许少量备用路线；主路线在前提未被推翻、仍有合理进展时持续推进，避免每轮随意换工具。

准备也有结束条件：方法前提被反驳、准备预算到达边界、关键资源不可得，或已有更直接的有效路线时，重新比较候选。补工具、读论文、增加脚本不能无限替代目标研究。

准备成本按同一根问题与待解锁观察累计；更换路线 ID、报告名、工具包装或拆成子任务不重置额度。达到边界后，只能依据新的有效证据在原剩余预算内重新评估，不能靠重新命名继续投入。

已有候选产物时，优先考虑是否能做独立对照验证。无需理解软件的每个模块才能验证目标成果。广泛扫描和批量反编译用于寻找入口，达到入口条件后转向定位与验证。

### 3.3 何时重新决策

普通分页读取、同一范围查询可在一个有界实验内继续；以下事件触发重新评估：
- 到达预设观察点；
- 新反例、前提失效、运行组件变化；
- 工具失败、观测异常、无有效增量；
- 成本边界到达；
- 用户修改目标、暂停或取消；
- 候选成果已具备验证条件。

每个步骤仍产生真实回执，但不要求每一步都做完整规划。一次实验通常对应一个问题；探索允许只有目的和范围，不必编造精确假设。

## 4. 研究状态与运行场景

复用既有存储。一套事实按职责保存：研究存储管理问题与解释，原执行预算账本管理派发资格，工件存储管理不可变结果。相互引用，不重复决定同一事实。

| 对象 | 最小内容 | 主要来源 |
|---|---|---|
| 根调查与合同 | 稳定 ID、用户目标来源、交付条件、范围、修订、控制状态、宿主绑定 | 用户意图与状态服务 |
| 组件与关系 | 文件/目录清单身份、格式/架构、父子与加载/IPC关系、数据库或运行引用 | 工具观察；模型关系标为推断 |
| 运行场景 | 构建、参数、工作目录、必要环境差异、输入/触发、观测窗口、重置方式 | 原程序基线和运行观察 |
| 问题与路线 | 关键未知、支持/反对证据、候选解释、前置准备、退出条件 | 模型提议，代码校验引用 |
| 实验与操作引用 | 目的、输入、相关前提、预期区分结果、执行记录引用 | 模型提议与系统回执 |
| 证据与验收 | 原始报告、来源、覆盖、解释、检查结果、产物摘要 | 工具/验证器；解释单独标注 |

运行场景是动态实验的必要输入。例如 helper 依赖父进程、stdin 或 IPC 时，单独执行同名 EXE 不代表同一场景。目录、文件和程序路径只是定位信息，内容摘要与清单范围另行保存。

环境只记录实验必需的差异、资源引用和可复现条件；不复制整份环境变量或秘密材料到模型上下文。不能取得的外部状态、服务器条件和设备状态明确为未知。

### 4.1 根任务与修订

- 根调查不依赖静态数据库打开。组件操作继续核对原 engine/provider、attachment、dbRevision。
- 根身份绑定真实人类目标和宿主根会话；续轮、时间提醒和摘要不能覆盖目标。
- 用户修改成果要求才变更合同；模型可细化路线，不可为了完成而缩小用户要求。
- 保留已撤回解释、反证和旧证据，不自动把旧 caller-declared completed 升级为新验收成功。
- 并行更新按相关对象 CAS；无关组件的新证据不使全局计划过期。

### 4.2 三种变化分别处理

| 变化 | 处理 |
|---|---|
| 尚未执行操作的前提变化，例如 run/stop、目标内容或必要数据库修订 | 阻止派发，刷新相关输入 |
| 新反证或目标变化影响解释/验收 | 标记相关判断需重评，保留原始观察 |
| 历史运行结束 | 不能再控制旧 run；该次运行的历史观察仍有效，范围保持原样 |

前提集合只包含本操作实际依赖的对象。已派发操作即使期间目标改变，仍接收并保存结果，标明属于旧合同，不能因 stale 丢掉实际效果。

## 5. 动态实验：触发、观测与判断必须完整

~~~text
Experiment
  investigation / component / question
  kind: explore | discriminate | reproduce | verify | deliver
  routeRef + intendedObservation
  scenarioRef + relevantPreconditions
  trigger: 输入与操作，怎样证明目标行为已经发生
  observer: 采集方式、范围、健康检查、可能干扰
  predictions: 可能结果如何改变判断
  nextOperation: 公共操作及实际参数
  budgetRef + stopConditions + evidenceRequirements
~~~

先建立原程序的基线场景，再引入观测。无法运行原程序时，保留基线缺失，不把观测后的异常直接归因于保护机制或算法。

空结果必须区分：
- 行为没有触发；
- 观测器没有正常工作；
- 观测窗口或范围不足；
- 在已确认触发和有效覆盖内，确实没有观察到预期事件。

只有最后一种才可能成为范围内的负面证据。断点未命中不能直接推出函数不执行，字符串搜索为空也不能推出行为不存在。

每次比较记录改变了哪些条件。构建、场景或观测器不同导致混杂时，先解释范围，再设计控制组；轨迹差异本身不证明因果或语义等价。

## 6. 实际执行协议与模型调用成本

### 6.1 两种入口，同一执行记录

保持工具数量，扩展现有 workspace 与公共工具的可选研究上下文，属于待评审 schema 增量。

| 使用场景 | 调用方式 |
|---|---|
| 普通手工使用 | 原公共工具，不自动宣称归属某项研究 |
| 有界低影响探索 | 原工具内联 investigation/question 或 purpose；程序登记单步实验 |
| 多步动态实验或明确产物操作 | workspace select 固定实验和相关前提，后续原工具携带绑定 |
| 关键结果解释 | workspace evaluate 引用系统回执，更新判断与下一步 |
| 恢复与交付 | workspace resume / assess |

低影响范围由工具实现的效果分类确定，不能靠模型把动作称为“探索”取得豁免。两种研究入口最终经过同一审批、计费、身份检查与回执协议。

首版允许动态后续步骤继续显式准备绑定；只读查询先减少多余 select/evaluate 调用。以后若工具返回下一步建议，它仍只是建议，不能自动授予派发资格。动态地址与参数必须使用最新真实结果。

建议研究绑定包含根调查、实验、步骤、计划修订与相关前提摘要。模型可提供幂等请求键，但调用者身份和目标/参数摘要由程序核实；同键异参拒绝，同参数的新请求不自动视为重传，因为可能是有意义的复现。

### 6.2 派发资格与预算只由一个账本决定

扩展既有 DelegationControl 的持久事务，记录操作意图和派发资格；ResearchState 只引用操作，不另行维护“是否执行过”的权威标志。

~~~text
认证调用者与结构检查
  → 按请求键和原参数摘要查询：精确重传返回已有状态/回执
  → 仅新操作经过原审批、资源队列与当前前提复核
  → 原账本事务：
      再次检查请求/步骤去重，避免并发重复批准
      核验并扣除调用预算、保留所需清理额度
      写入 admitted 操作记录
  → 在同一串行控制点核对取消代次，转 dispatching 并交接 provider
  → 保存原始回执及工件
  → 操作终态关联回执
  → 研究状态吸收结果，生成反馈
~~~

同一调用者、请求键和相同参数重传只能查询原操作，不获得第二次派发资格；同一实验步骤也只消费一次。普通新公共调用沿用原计费，失败调用不退款。重传状态读取的计费方式需要在接口验收中明确，不开放无界免费业务调用。

精确重传只读取原来有权访问的操作记录，无需旧 run/stop 仍然有效；原动作改变暂停状态后仍能取回其回执。只有新操作检查当前运行前提；同键异参不能借历史查询绕过检查。

预算和 admitted 记录在同一个事务内提交，消除两份存储独立批准执行的风险。原审批仍由原宿主入口负责，准备实验不授予权限。操作持久记录不能在重启后被当成自动重放队列。

### 6.3 崩溃和结果记录失败

- admitted 后、实际调用前后发生崩溃，都可能无法判断效果；在没有确定证据时保守保留 effect-unknown，不退费、不自动重放。
- provider 已有回执而研究入库失败：补入已存在的回执引用，不再运行一次。
- 结果需先保存工件，再关联账本和研究状态；未完成的关联标 receipt-pending，恢复可幂等补记。工件不依靠全文进入聊天。
- 未知清理、部分提交、超时、工具失败、业务无结果和用户取消分别记录。
- 不承诺跨数据库、进程及外部环境的 exactly-once 效果，只保证本系统不因重复请求再批准同一步派发。

### 6.4 执行记录的最小状态

~~~text
admitted → dispatching → result-recorded
    │             └──→ effect-unknown
    └──→ cancelled-before-dispatch
result-recorded → success | failure | cancelled | inconclusive
~~~

状态描述程序实际知道的情况。success 是该操作的局部结果，不是实验或整个调查的完成。读取旧状态不重新派发。

## 7. 反馈必须改变后续决策

每次到达评估点，模型提交一份简短的决策变化，程序核验来源：

~~~text
observed: 新观察及原始回执引用
coverageChange: 范围扩大、重复、未知
interpretation: 支持 / 反驳 / 无法判断，以及理由
prerequisiteChanges: 哪些前提满足或失效
candidateChanges: 哪些动作进入、退出或改变优先级
next: 继续路线 / 改场景 / 换方法 / 验证产物 / 等待
~~~

程序可确定相同内容、采集范围、字段缺失、身份变化和明确检查器结果；语义新颖性及方法价值仍属模型解释，不能伪装成自动证明。

| 障碍 | 优先分辨 |
|---|---|
| 工具或环境缺项 | 具体缺项是否可补齐，准备后解锁什么观察 |
| 启动失败或无命中 | 场景、输入、父进程、模块、地址、触发和窗口 |
| 捕获行为异常 | 原版基线、观测器是否改变目标、健康检查是否通过 |
| 相同结果反复出现 | 是否在扩大覆盖或检验重复性；否则复用原结果并换问题 |
| 假设被反驳 | 保留反例，撤回受影响解释，调整候选 |
| 检查器失败 | 定位首次差异，区分实现错误、样本条件变化和验证器错误 |
| 清理未知 | 原 owner 恢复；其他独立只读研究可继续 |

重复判断绑定组件、方法版本、输入、场景、观测范围和结果。仅修改文件名、报告 UUID、轮次或脚本无关文字，不构成有意义的新实验。

允许重复性和时序研究，但必须说明变化因素或采样目的、次数边界。固定“两次失败”只提示重新诊断，不能替代原因判断。

## 8. 取消、预算与长期资源

取消请求、控制器接受取消、实际停止确认是三个不同时间点。admitted → dispatching 的交接与接受取消经过同一串行控制点，交给 provider 前最后复核控制代次。取消已被接受时，尚未派发的 admitted 操作转 cancelled-before-dispatch，不启动 provider，已扣费用保留；此前进入 dispatching 的操作按在途取消处理，其结果仍需接收。串行控制点只保护派发交接，不等待长操作完成，以免阻塞取消和停止。

资源可以跨多个短实验存活。例如同一 debugger run 可依次定位、观察和验证，不要求每个实验结束都重启程序。资源生命周期由原 provider owner 管理，调查结束、资源作用域关闭或用户取消时清理。

已核实的基线缺口：DelegationControl.charge 在共享预算耗尽后会拒绝公共 stop，index.js 取消前置检查也会拒绝新公开调用。设计需新增原总预算内的清理预留与受限清理信号：
- 取得资源前预留其停止/清理成本，普通研究不能使用；
- 清理只允许作用于原 owner 的停止、状态核对和释放；
- 取消后的清理使用独立有界期限，不允许启动、继续目标业务或扩大作用域；
- 总预算不增加、不重置，历史无预留的运行保持真实未知状态。

清理成本无法在当前额度内合理覆盖时，不批准新的资源获取。资源需要多次恢复才能确认时仍受原边界约束；不能通过“清理”名义无限重试。

REA/APK 的内部子操作、时间与字节成本必须有边界并报告。现有根预算只覆盖 IG5 调用，不等于所有模型 token 或任意 shell 消耗；受管适配器覆盖前，外部执行只能以限定来源导入。

## 9. 验收：事实、解释、产物分别检查

~~~text
workState: active | waiting | paused | stopped | settled
stopReason: completed | user-cancelled | budget-exhausted |
            no-admissible-action | host-stopped | null
assessment: not-assessed | partial | satisfied | not-satisfied | unverified
cleanup: not-needed | pending | confirmed | unknown
~~~

验收来自当前合同、有效证据和检查结果。操作成功、模型回答结束、资源停止、交付完成各自表达。

| 成果 | 验收重点 |
|---|---|
| 行为解释 | 可追溯观察、触发条件、覆盖范围及竞争解释 |
| 算法实现 | 可运行实现、原程序对照、留出/边界输入、适用域 |
| 协议模型 | 真实消息、解析与留出验证、方向和状态范围 |
| 可分析映像 | 映射/缺口、重新装载与分析结果 |
| 重建或行为修改 | 构建、运行、目标功能、相关回归及原版/零改动控制组 |

检查器尽量独立于生成逻辑；模型自己生成的期望值不能单独证明自己的产物正确。有限测试通过保留输入域限制。语义问题无法自动判断时，输出推断和待复核范围。

完整运行交付要求必要验收项满足、产物身份可核实、相关反证已处理、资源结清。结果已验证但清理未知时分别报告，不抹掉成果，也不宣称整个运行完成。

评估记录绑定合同、依赖证据及产物摘要。新反证只使受影响结论重新评估，不废弃全部历史。

## 10. DSH 宿主合同与降级行为

当前源码只能确认 Goal 查询与必要续轮条件、工具注册和 IG5 自身调用包装。不能据此保证轮前注入、完成拦截或真实恢复已可用。

M0 必须验证：
1. 真实根会话/Goal、用户来源和目标修订；
2. 轮前通过正式接口恢复研究 brief；
3. 取消、暂停、恢复及预算停止事件；
4. Goal complete 提交前读取并复核同一验收结果；
5. 子代理身份、工具中间件及重启后的连续性。

支持时，宿主完成与当前合同/验收绑定；不支持时分别显示 hostGoalState 和 investigationAssessment，明确不一致，作为辅助模式。不能靠多写 Skill、伪造人类消息、后台重启 Goal 或另建模型循环声称补齐。

上下文按当前问题组织：目标、当前路线、有效观察、关键反证、未决项、执行与资源状态、剩余成本。大工件分页读取，摘要是导航；关键执行前提从原始来源复核。状态丢失时先恢复身份，不从最近一句聊天猜整个目标。

## 11. 方法、能力扩展与多代理

方法条目最小内容：适用问题、必要前提、第一项辨别检查、可能观察、失败解释、验证方式、来源及版本。检索以当前障碍和缺失观察为入口，单个 Electron/加壳关键词不能覆盖具体组件身份。

能力条目说明实际操作、支持对象、依赖、效果、输入输出、成本和 owner。区分文件存在、依赖齐备、启动验证和当前目标执行结果。

案例只影响同等条件下的方法排序。环境故障不能永久淘汰一种算法；成功案例也不能自动证明新目标。新脚本先做小范围自身验证，再参与目标实验，避免脚本错误被记为目标结论。

融合次序：
- IG5 保留原生静态、x64dbg、仿真和数据能力。
- REA 用固定版本公共 CLI 接 JS/Electron，原 Evidence 经转换后引用；被动 Inspector 和主动 Electron 是不同能力。
- APK 先吸收依赖、症状、反证和轨迹差分，后接 Android 设备能力。
- 自定义脚本/新 provider 使用同一受管执行边界，不能通过普通 shell 绕过成本和回执后再宣称完整验证。

首版单研究者跑通后再引入多代理。独立组件、竞争解释和独立验证适合委派；同一 debugger 或可写数据库保留单 owner。成员返回证据和解释，不能更改根交付条件或宣布根目标完成。冲突形成待验证问题，不以多数同意裁决。

## 12. 首版切片与代码落点

第一版只交付：一个根调查、一个自产 PE、一个可复现场景、一个输入输出问题、一条动态路线、一次受控失败调整，以及独立对照验收。

先实现所需启动参数的公开传递，例如 args/cwd；stdin、attach 等只有当前场景确实需要才接入。底层支持不等于公共入口已可用。首个样本可独立启动，后续多进程场景不能偷换成独立启动测试。

| 现有落点 | 最小改动 |
|---|---|
| InvestigationStore / ResearchState | 版本化根对象、组件关联、轻量问题/路线/场景及证据引用；旧数据保持 |
| investigation_workflow / experiment_planner | root/component 分派，少量候选、select/evaluate/assess，短路线准备 |
| index.js + DelegationControl | 受管调用、原事务中的派发资格/预算、清理预留、回执引用 |
| capability_catalog / failure_router | 当前能力、依赖、症状分类与相关条件 |
| 小型执行/验收模块 | 状态转换、幂等恢复及纯验收投影，避免扩大 index.js |
| autonomy_status 与宿主适配 | M0 验证后接研究摘要、控制事件和完成判定 |

不批量重排文件、不迁入完整 REA/APK、不新建通用图数据库或工作流语言。完整对象关系按真实用例增加。旧手工模式保留，旧 caller-declared 状态不自动升级，assist 默认值暂不改变。

### 12.1 里程碑与可判定退出条件

| 阶段 | 交付 | 退出条件 |
|---|---|---|
| M0 宿主合同 | 实际接口验证与缺口表 | 每个控制点有真实宿主结果；缺口对应明确降级 |
| M1 受管实验 | 人工给定步骤的真实 PE 动态实验 | 公开调用、回执、取消、耗尽预算清理、重复提交和重启边界均可核对 |
| M2 自主研究 | 只给软件和目标的多样本任务 | 自选路线、完成必要准备、面对失败调整、留出输入验证；错误完成可检测 |
| M3 多组件 | Electron→原生 helper 的完整场景 | 真实父子关系、触发与参数交接、观测、验证在同一调查内完成 |
| M4 扩展 | Android、DLL、更复杂进程与多代理 | 每项能力独立验收，不外推已有样本结果 |

M1 证明执行链；M2 才证明自主决策。M0 与 M1 可并行推进独立部分，宿主完成接线缺失时不能宣称强制自主闭环通过。

### 12.2 一个完整反馈例子

目标：恢复自产 Electron 转换软件的输入输出逻辑。

1. 静态发现 JS 调用 helper；这只是候选关系。
2. 记录原版一次成功转换，确认输入、输出、缓存状态和实际子进程参数。
3. helper 依赖父进程 IPC，则保留原场景；不能以“单独启动成功”替代。当前 attach/输入能力不够时，先形成有界能力准备或选择其他可验证观察。
4. 设置观测并检查其健康，再触发相同业务。
5. 无子进程事件：检查业务触发与缓存。已确认 helper 收到输入但无断点：检查构建、映射和窗口。观察反驳算法候选：保留反例并修改假设。
6. 形成可运行候选后，用未用于推导的输入对照；有反例继续定位差异，通过则报告其验证域与未决范围。

### 12.3 评价是否真正改善

同模型、同能力集合、同预算、多样本重复比较旧/新决策流程；新增工具收益另做对照。正确工具序列和关键地址不写入自主任务提示。

主要指标：交付正确率、错误完成率、有效覆盖、无效重复、人工干预、取消接受后新增业务派发、资源遗留。成本指标：时间、调用/token、准备成本和管理调用占比。

必须含：只需静态、确需动态但先要准备、观测器失效、业务未触发、混合组件、错误假设、压缩/恢复、取消和重启。保留未参与方法调试的样本，防止只适配固定夹具。

## 13. 依据与本轮验证范围

主要源码依据：index.js 的 workspace 入口及统一执行包装；investigation_workflow 的静态 scope；InvestigationStore/ResearchState 的版本和声明状态；experiment_planner 的 suggestions-only；autonomy_status 的只读 Goal 查询；DelegationControl 的共享计费和取消边界。

前期审查位于工作区 review/ig5-session-832875d3-2026-11-17 与 review/ig5-fusion-candidates-2026-11-17。旧 1.4.0 会话提供失败反例，不直接认定其特有 bug 存在于 1.3.0。

## 14. M0 宿主包组件集成与 M1 受管原生实验记录（2026-11-17）

### 14.1 M0 本机 DSH（0.2.2-rc.1）宿主包集成核实结果

基于本机安装的 DeepSeek Harness `app.asar`（`@deepseek-ai/dsh-app-boot` `0.2.2-rc.1`）提取宿主包与组件集成测试（`scripts/test_host_autonomy_contract.mjs`；注：该脚本驱动真实宿主包组件与真实 headless `x64dbg`，采用确定性 `MockApprovalService`，不等同于桌面 Electron GUI 真实模型多轮会话）：

| 控制点 | 真实宿主接口 | 实测结论与缺口降级 |
|---|---|---|
| 根会话、消息来源与取消锁存 | `ctx.agents.roots()`、`session.header.parentSession`、`session/event` 中 `user/message` 的 `data.source` | `source.kind === "user"` 为人类直接输入；`source.kind === "goal"`（含 `goalId/revision/round`）为自动续轮；`runtime-context`、`time-context`、`repeat-tool-reminder` 等为宿主通知。**普通人类状态询问消息不会自动解除取消锁存**；仅显式恢复动作（宿主 `goals.resume`/`create` 或人类活跃轮次中的 `ig5_workspace` `root-control: resume`）可解除取消，且兼容无 `turnBoundaryOf` 的宿主在 `turn/end` 后自动撤销当轮人类恢复权限。 |
| 步前研究摘要恢复 | `agent.ctx.systemPrompt.context({ name: "ig5:investigation-brief", order: 220, interpolate: false, text })` | DSH `RuntimeContextProjection` 仅在渲染文本变化时追加快照消息，因此简报渲染去除时间戳与易变字段以保持同修订幂等，并严格按当前宿主 `goalId` 投射对应调查。**宿主缺口**：预设调用 `suppressRuntimeContext()` 可屏蔽非 `required` 上下文；降级为 `ig5_workspace` 的 `root-brief` / `root-resume` 显式拉取。 |
| 取消、耗尽预算/满载公共清理与暂停 | `turn/end`（`reason.kind === "aborted"`）、`goal/change`（`pause/resume/clear`）、`installApprovalGate` `tools/pre-execute` | 用户中止或暂停 Goal 时同步推进 `DelegationControl.acceptCancel`，阻断新增业务派发；公共前置门 `installApprovalGate` 核对 `hasActiveOwnerCleanup`，对合法 owner 清理替换有界超时信号放行；操作账本为 owner 清理与 `root-control` 预留独立应急容量并优先回收派发前取消记录，避免账本或压缩历史满载阻断停止路径。**宿主缺口**：DSH 无跨轮插件累计调用预算，由 `DelegationControl` 持久账本承担。 |
| 工具中间件、Goal 绑定与独立可执行验收 | `tools/pre-execute`（复用 `installApprovalGate` 单一监听器）+ `ctx.tools.guard` | `update_goal(action="complete")` 提交前按精确 `hostGoalId`、合同 `revision` 与 `objective` 哈希核对绑定调查（禁止用最近更新的其他 Goal 调查替代或跨 Goal 重绑；合同修订后强制重新核验候选）。`io-transform` 强制校验：类型化输入通道（`cli-arg`/`file`）字节派生、同实验 `ig5_dbg:start` 启动见证与目标 SHA-256/`runId` 对齐、自第 1 版起候选规则与 `outputSpec` 必须在留出实验选择和观测前提交（禁止事后查表与复用已暴露输入），并在固定 `outputSpec` 上独立求值有界 AST 规则。**宿主缺口**：桌面 UI 直接调用 `@Remote("complete")` 不经过 `ToolsService`；IG5 记录 `goalAssessmentAligned: false` 与 `hostCompletedWithoutInvestigationAcceptance: true`，绝不伪升调查状态。 |

### 14.2 M1 代码落点与分层验证范围

- `source/delegation_control.js`：扩展 schemaVersion 2 单一持久账本，通过 `compactedOperations` 与持久 `stepLocks` 保证超过 256 条操作窗口裁剪后仍保留请求幂等索引与已消费步骤锁；为 owner 清理和 `root-control` 保留独立应急容量并支持回收未派发取消项，保证满载下清理与取消可达；在清理预留上保留精确 `targetPath`。
- `source/delegation_execution.js` 与 `source/approval_gate.js`：公共工具统一受管执行包装 `runManagedToolExecution` 与公共审批前置门贯通取消/耗尽预算/账本满载下的 owner 清理路径，先落盘不可变 `managed-operation-receipt` 工件再关联根调查。
- `source/investigation_verifier.js`、`source/investigation_root.js` 与 `source/investigation_assessment.js`：建立端到端代码校验链 `当前 Goal / 合同修订 → 调查 → 组件哈希 → 实际输入通道字节与哈希 → 启动见证与 runId → 预提交候选与 outputSpec → 独立留出观察 → 验收结果`；未知类型/空义务/未观测输入通道一律拒绝放行。
- `source/investigation_workflow.js`、`source/experiment_planner.js`、`source/capability_catalog.js`、`source/failure_router.js`、`source/autonomy_host.js`、`index.js`、`adapters/x64dbg/adapter.py`：严格区分可执行 `request` 与待补参 `requestTemplate`，多组件场景下按实际场景组件与活跃预留目标生成 `select` 与 `cleanup-owned-resource`，保持 Core 8 与单工具 schema 在 4000 token 门限以内。
- 分层验证脚本与证据边界：
  - 单元/组件与两轮审计反例门禁：`scripts/test_managed_execution.mjs`、`scripts/test_root_investigation.mjs`、`scripts/test_audit_regressions.mjs`（覆盖首轮 7 项 P1 与次轮 4 项 P1 + 3 项 P2 正反例）。
  - M0 宿主包组件集成：`scripts/test_host_autonomy_contract.mjs`（验证本机 DSH `0.2.2-rc.1` 所选宿主包与真实 headless `x64dbg` 公共清理、显式恢复、跨 Goal 切换阻断与完成拦截，保留完整回执与账本证据包）。
  - M1 预编排真实原生实验：`scripts/test_m1_native_experiment.mjs` + `scripts/fixtures/pe64-cli-transform.mjs`（验证自产良性 PE64 经真实 Ghidra 与真实 headless `x64dbg` 的受管静态/动态/预提交留出集实验及公共门禁清理，统一绑定完整源码树清单 `run-manifest.json`；目标地址与步骤由测试给定，自主路线选择留待 M2 盲测验证）。

### 14.3 M2 真实 DSH 模型驱动自主逆向盲测协议与定点改进（2026-11-18）

- **评测复现入口与当前隔离范围**：
  - 基线内复现与守卫入口：`scripts/evals/run_m2_blind_eval.mjs` 与 `scripts/evals/m2_suite_guard.mjs`（支持 `smoke`、`dev`、`controls`、`freeze-sealed`、`sealed`、`case`）。
  - 每个被测会话使用独立临时 `DSH_HOME`、`IG5_HOME` 与初始仅含目标 `.exe` 的 `workspace`；插件副本剔除 `scripts/evals`、`scripts/fixtures` 与 `scripts/test_*`；禁用宿主非受管 shell/web 工具。`m2_suite_guard.mjs` 只约束已识别的路径参数，不是 OS 沙箱，不能限制任意 Python 内部的文件访问。答案库位于这些目录之外并不证明其物理不可读。当前隔离资格为 `unverified`，不能由“未见拒绝/泄漏记录”推导严格盲测成立。
- **基于开发集与控制实测的通用定点改进（封闭盲测冻结前完成，不弱化任何安全或验收不变量）**：
  - 跨短实验延续同一活调试 `runId` 启动见证（`source/investigation_assessment.js`）：允许同一根调查内绑定相同 `scenarioDigest`、`targetSha256` 与 `runId` 的前序显式实验提供 `ig5_dbg:start` 启动见证，同时严格要求 `holdout-verify` 的 `start` 实验选择序号与回执序号均晚于候选预提交序号。
  - 有界 AST 逐字节数组表示与诊断定位（`source/investigation_verifier.js`）：`ig5-bounded-byte-rule-v1` 的 `byteExpr` 同时支持按 `i` 参数化的单 AST 节点与长度等于 `outputLength` 的展开式纯 AST 数组（仍受统一节点数与深度上限约束），且 `canonicalPathKey` 统一使用 `realpathSync.native` 消除 Windows 8.3 短路径（`ADMINI~1`）差异。
  - 预提交候选增量附加测试向量（`source/investigation_root.js`）：留出运行后仅提交 `testVectors` 时保留已冻结的 `executableRule`、`outputSpec`、`candidateRevision`、`candidateCommittedSeq` 与 `committedContractRevision`，不覆盖已提交规则且不绕过宿主合同修订重验门禁。
  - 真实宿主 `/compact` 压缩后确定性恢复导航（`source/investigation_root.js`、`source/investigation_workflow.js`）：`renderDeterministicRootBrief` 增加确定性 `resumeHint` 与 `workspaceSyntax` 指引，`runWorkspace` 对误传在 `args.workspace` 顶层外的参数立即报错，支持 `root-update` 可选 `expected_task_revision` CAS 校验。
- **验证范围声明**：`io-transform` 独立验收与评分向量仅证明候选规则在已观测输入及评测集有限测试域上与目标二进制等价，不声称对任意未测输入空间的完备数学等价；多进程 Electron/IPC 与 Android/APK 留待 M3/M4 独立验收。

### 14.4 M2 blind1 冻结结果与修复边界（2026-11-18）

冻结源码树 `8a8c0ebedae833a704094cea9a285c348785fc783ebaf6790c42774b7c920c82`（1,145 文件）在四场结束前保持一致。使用真实 DSH CLI、同一路由模型、8 Goal rounds、72 次调用阈值和每场 720 秒期限；审批由预登记 harness 自动应答，不等于人工审批体验验证。

| 实例 | 候选有限向量评分 | 宿主最终状态 | 原始清理确认 | 调用尝试 |
| --- | --- | --- | --- | ---: |
| sealed-01-nibblesched | 6/6 | complete | true | 53 |
| sealed-02-filegate | 6/6 | complete | true | 55 |
| sealed-03-dualflag-cwd | 6/6 | blocked | true | 88 |
| sealed-04-cascade-state | 6/6 | active，查询超时 | true | 90 |

候选对归档 oracle 输出的离线回放全部吻合，不是额外 24 次原生执行。前三场分别有 1、1、2 个评分输入与已观察场景重合，不能称所有评分输入均未见。原始 `falseCompletion=false` 仅覆盖有限输出评分及清理，不证明触发条件完整恢复；没有配对基线或重复盲测，不能报告流程收益百分比。

- 第三场合法 `ea + address_space="rva"` 在回执摘要中丢失地址空间，验收因缺 `cleanArgs.rva` 拒绝。冻结后保存该字段并按公开调试接口的 `rva` 优先规则验收；裸 EA、database EA 与未知空间不隐式换算为 RVA，旧回执不回填。
- Ghidra 首次 `emulate` 在共享 worker 路径注册前导入 `cpu_emulator`。冻结后交换 setup/import 顺序；依赖文件实际存在，不归因为漏打包。冷启动离线回归不等于新的真实 Ghidra 仿真通过。
- 第四场第二次 `assess` 已 `satisfied`、清理已确认，随后宿主状态查询及完成调用被评测器总调用门拒绝，目标保持 active 至超时。后续协议在原 72 额度内预留 2 次终态控制：普通阈值 70，预留状态查询最多一次，最后一次额度留给终态提交；所有原完成与 owner 门仍执行。拒绝尝试和清理可使事件总数大于 72，获准非清理调用上限不扩大。该变更只适用于新冻结轮次，不把 blind1 改判通过。
- `budget-cleanup-v1` 在首次 start 前预算已耗尽，没有资源获取或清理预留，属于 `not-exercised`，不能计入“控制 3/3 全过”。取消 v2、压缩恢复 v3 的已有证据分别保留。后续预算控制须证明成功获取、预留、普通额度耗尽、原 owner stop、账本消费的完整顺序。
- 后续汇总分开记录有限变换评分、触发条件完整性、隔离资格、进程检查状态和预算清理控制。无法观察的越界执行数记 null；进程检查失败不得当作零残留。

下一阶段先补齐上述修复的开发/控制实测，再建立可验证的 worker/答案库访问隔离及触发条件正反评分，冻结后使用新封存实例。当前四实例已经暴露，仅可作回归，不再作为新的未见盲测。现阶段不推进 M3/M4 或据此宣布通用软件逆向完成。

冻结后验证：地址审计回归 27/27、Ghidra 启动组件离线回归 18/18（含旧顺序反证）、guard 6 项与评测报告 26 项通过；JS 511/Python 247 语法、单样本登记和源码打包清单检查通过。默认门禁 125/126；未变的 `host-sdk` 测试在提取本机 DSH SDK 时因缺少 `@deepseek-ai/dsh-client-ui-slots` 失败，尚未加载本次修改。普通模块审计无依赖违规，但 9 条审查记录已过期。没有重新运行原生模型评测、生成发行包或安装重载，因此保留这些未验证项。

### 14.5 M2 审计五项补齐与全新未见封存盲测 `blind3`（2026-11-18）

在推进 M3/M4 前，先针对前序 M2 复核的五项缺口完成补齐，并在冻结源码树 `9b2527ba8c78ecd1256a005c32c42cc1aef3224758f561763b2da50a582a6600`（1,149 文件）上执行与 oracle 完全解耦的全新四样本封存盲测 `blind3`（证据归档于 `review/ig5-m2-m3-m4-continuous-2026-11-18/m2-remediated/`）：

1. **真实宿主工具层隔离哨兵（`scripts/test_m2_isolation_sentinel.mjs` v2）**：拆分为纯 Node 门禁层（`component-dispatcher-with-host-tool-doubles`，`realHostToolsMounted=false`）与真实 Electron 宿主层（`--real-host` 在 `ELECTRON_RUN_AS_NODE=1 "DeepSeek Harness.exe"` 内挂载 `app.asar` 中的 `@deepseek-ai/dsh-fs-local`、`dsh-subprocess-local`、`dsh-working-directory`、`dsh-tool-fs`、`dsh-tool-fs-search` 与 `dsh-tool-working-directory`，`realHostToolsMounted=true`）。两层均验证 21 项越界/未授权拒绝与 4 项工作区内正例，哨兵零读取/零泄漏，逐项核对 `guard-log.jsonl` 拒绝记录。同时为 `scripts/test_host_sdk.mjs` 补齐可选 UI 插槽桩，恢复宿主 SDK 门禁全绿。
2. **评测器隔离声明与触发探针加固（`scripts/evals/run_m2_blind_eval.mjs`）**：移除硬编码 `unallowlistedToolExecutedCount: 0`，强制读取真实 `guard-log.jsonl` 与最新匹配 `sourceTreeDigest` 的 `--real-host` 哨兵证明；显式披露非沙箱调试器能力 `debuggerProcessCapabilitiesUnconfined: ["ig5_dbg:start", "ig5_dbg:writemem", "ig5_dbg:setreg"]` 且保持 `strictBlindEligible: false`。`evaluateTriggerCompleteness` 拒绝含 `..`/盘符/UNC/空白的 `requiredCwdSuffix`，且负向消融探针仅接受干净非零退出码 `1..63`（崩溃 NTSTATUS `>= 64`、超时或启动错误一律判失败）。
3. **原生控制实测原始工件归档（`scripts/evals/verify_m2_controls_native.mjs`）**：完整保留 `controls-native/` 下 267 个原始 `ig5-home` 项目/回执文件、`cold-ghidra-emulate` 真实输出、触发正反探针原始记录与 SHA-256 `manifest.json`（`1A`/`1B`/`1C`/`1D` 全过）。
4. **`blind3` 全新四例未见封存盲测结果（运行期不加载 `--corpus-module`，全部原生进程退出后离线评分）**：

| 实例 | 题型特征 | 触发正反探针 | 有限向量评分 | 交付正确 (`deliverableCorrect`) | 宿主终态 | 错误完成 (`falseCompletion`) | 清理确认 |
|---|---|---|---|---|---|---|---|
| `sealed-09-byteshuffle` | 字节重排 + 单标志 | passed | 0/6（普通额度耗尽前未提交留出向量） | false | blocked（经预留终态槽干净收敛） | false | true |
| `sealed-10-cwdfile` | CWD `\batch_slot` + 文件通道 | passed | 6/6 | **true** | **completed**（62 次调用） | false | true |
| `sealed-11-dualflag-cwd` | CWD `\verify_bay` + 双标志 | passed | 6/6 | **true** | **completed**（56 次调用） | false | true |
| `sealed-12-mutator-cascade` | 间接函数指针运行时改表 + 诱饵分支 + 级联（现场使用 `address_space="rva"`） | passed | 6/6 | **true** | blocked（第 70 次普通上限耗尽时 IG5 门禁拒绝未附向量的 `complete`，预留槽干净转 `blocked`，零超时） | false | true |

## 15. M3 跨层业务链与 M4 四分支实施及独立验收记录（2026-11-18）

### 15.1 实现范围、公共工具面与审批边界

- **公共工具面与审批门**：保持 `Core 8`（`3805 / 4000` 估算 token）不变，`Full 43 → Full 44`，审批写入/执行门 `13 → 14`。所有跨层主动运行（Electron UI/IPC 触发、多进程链观测、持有会话清理与自有测试夹具 APK 重打包）统一集中在显式审批工具 `ig5_app_observe`；`ig5_package` 新增的 `js_app`（锁定 SHA-256 `3554288a08c455fa419dad662d73710fb17debe94b9e71dd1282761117c5981e` 的 `rea@6.4.0` CLI）与 `trace_diff` 严格保持零目标执行（`executionPerformed: false`）。
- **M3（Electron → Native Helper）**：`source/native_rea_bridge.js` 集成 `rea@6.4.0` 静态 JS/Electron 重建与 IG5 自有 Windows 主动 Electron 边界观测器（结合 `NODE_OPTIONS` 预加载钩子与 `Win32_Process` `CreationDate` 进程树清理，补齐 `rea@6.4.0` 在 `win32` 下 `listProcesses()` 返回空数组的限制）。`electron-native-chain` 验收器强制核对父进程触发回执、子 Helper PE SHA-256 交接边、进程树清理以及预提交留出向量，自动拒绝 `.memo_cache.json` 缓存短路（`CACHE_SHORT_CIRCUIT`）与裸启动 Helper 替代（`HELPER_SCENARIO_MISMATCH`）。
- **M4-A（Android APK / DEX / Java→JNI）**：`source/native_android_bridge.js` 与 `source/analysis_trace_diff.js` 实现能力依赖图闭包探测、严格按 `SHA-1 ([32..N)) → Adler-32 ([12..N))` 顺序重算的 DEX 完整性校验/修复、症状停止诊断、自有夹具 `zipalign` + `apksigner verify` 重打包验签、跨 ASLR 基址离线轨迹差分，以及 `apk-jni-chain`（`ig5_package:apk` + Ghidra JNI `.so` 反编译 + Unicorn `abi="sysv64"` 仿真，支持 `out.memory` 留出核验）。当前主机 `adb devices` 为 0 台设备且宿主 Python 未装 `frida`，设备动态通路如实保持 `blocked`，请求 `dynamic-device-hook` 义务时确定性返回 `assessment="unsupported"`。
- **M4-B（宿主加载有状态 ASLR DLL）**：`adapters/x64dbg/adapter.py` 在运行态内存/断点上下文中补充磁盘模块 `moduleSha256`；`dll-host-transform` 与 `outputSpec.kind="module-memory"` 强制核对真实重定位 `moduleBase`（拒绝未重定位首选基址假象）、模块名、`RVA` 与已登记 DLL 组件 `sha256`（拒绝同名异哈希诱饵 DLL 与未初始化哨兵态）。
- **M4-C（Entry → Broker → 多 Worker 进程链）**：`process-chain-transform` 与 `NativeAppObserver` 追踪四级进程链与 `corrId`、区分中途退出重启的旧 Worker PID（`exited-before-handoff`）与有效交接 Worker PID，并在取消/耗尽预算清理时严格按 `(PID, CreationDate)` 终止自有进程树，实测同名旁观进程完整存活（`bystanderAliveAfterStop=true`）。
- **M4-D（受控多代理协作）**：`source/autonomy_host.js` 在宿主完成门直接拦截非根会话 `update_goal(action="complete")`；`source/delegation_messages.js` 与 `ig5_workspace`（`delegate-brief` / `accept-child-finding`）对子代理发现强制校验 `rootId`、`briefId`、`contractRevision`、`targetSha256` 与系统回执引用，共享父会话 `DelegationControl` 不可放大预算与单 owner 调试锁；产品默认保持 `assist: false`。

### 15.2 M3 与 M4 真实原生控制及在线 DSH 模型自主评测结果

5 套预编排真实原生正反例控制套件（`scripts/evals/verify_m3_m4_controls_native.mjs all`）与 7 场真实 DSH 模型在线自主评测（`scripts/evals/run_m3_m4_online_eval.mjs`，执行期源码树摘要 `864fccfa3ae2a70ba90ff4b49ffed231701152f35c33c6a84d1afeedcd94bb86`）完整归档于 `review/ig5-m2-m3-m4-continuous-2026-11-18/`：

| 在线运行实例 | 分支 | 任务与机制验证点 | 有限向量评分 | 交付正确 (`deliverableCorrect`) | 宿主终态 | 错误完成 (`falseCompletion`) | 清理确认 | 调用数 / 耗时 |
|---|---|---|---|---|---|---|---|---|
| `m3-sealed-01-frame-encoder` | M3 | Electron UI/IPC 预处理 + CLI Helper + 静态诱饵二进制排他 + 绕过 `.memo_cache.json` | 6/6 | **true** | **complete** | false | true | 38 次 / 217s |
| `m3-sealed-02-ticket-digest` | M3 | Electron UI/IPC + `stdin` `TK` 二进制帧原生 Helper + 级联变换 | 6/6 | **true** | **complete** | false | true | 50 次 / 315s |
| `m4b-online-01-stateful-dll` | M4-B | 宿主 `VirtualAlloc` 强制 ASLR 重定位 + `EngineInit` 种子推导 + `module-memory` RVA 验证 | 6/6 | **true** | **complete** | false | true | 61 次 / 305s |
| `m4c-online-01-broker-chain` | M4-C | 四进程链 `entry_app → chain_broker → worker_stage1 → worker_stage2` + Worker1 重启 PID 轮替 | 6/6 | **true** | **complete** | false | true | 48 次 / 289s |
| `m4d-online-single-agent` | M4-D 对照 | 同一四进程链样本，单代理基线（`assist=false`） | 6/6 | **true** | **complete** | false | true | 66 次 / 380s |
| `m4d-online-3subagents`（保留紧预算耗尽运行） | M4-D | 派生 3 个子代理、共享 `max_calls=52` 耗尽、现场拒绝 `max_calls=64` 扩容尝试 | 0/0 | false | **blocked**（干净阻断，零超时） | false | true | 89 次（含拒绝） / 411s |
| `m4d-online-3subagents-v2` | M4-D | 派生 3 个真实子代理（允许 `send_message` 回传）、共享预算 `64/68`、根调查验真接纳 2 份带回执子报告 | 6/6 | **true** | **complete** | false | true | 87 次 / 513s |

对照结论：在同一 `collab-chain` 四进程样本上，受控 3 子代理协作端到端验证通过（`6/6`、`acceptedChildFindingsCount=2`），但总调用与耗时（87 次 / 513s）高于单研究者基线（66 次 / 380s），且在更紧共享上限（52 次）下会因跨会话协调开销提前耗尽预算；实证支持保持产品默认单研究者 `assist: false`。



