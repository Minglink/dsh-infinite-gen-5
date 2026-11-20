# Handler 语义与组合边界

再次遇到已有handler时，先逐项核对新完整核心、原字节、解码器和证书来源相等，再复用通用局部证明；仅重新计算当前前序状态/写后内存/守卫/字节前提与来源关系。旧查询和同批数值重跑不计新增覆盖。原入口RSI与当前VIP中的RSI不得互换。槽208/137例见../../../docs/CONTEXT208_JOIN.md。

解释上下文槽时追踪保存发生时的完整状态；同名RBP/RSP可能是入口值、当前虚拟指针或后继值，不能互换。验证源字后再连接写后内存；SMT的源字或派发内存cut必须有原LOAD/STORE证书，SAT反例要恢复被切割定义。槽200原RSP与槽120原RBP的固定条件证书见../../../docs/CONTEXT200_JOIN.md；不外推其他输入路径或完整业务。

遇到复制循环，先用discover取得入口到条件边及退出后继，保留原字节和全部读写；若prefix把计数设为常量，使用constant-loop的prefix/body/suffix，不提供次数或删去正文。核对inferredRepeat实际推导、全部STORE进入guard和完整sideExits；重叠复制从每一步写后内存读取。条件未知或预算拒绝保存失败。固定208的32次复制和75→76证书仅作可核验证据，不代表其他目标或所有输入已过，见../../../docs/HANDLER208_RELOCATION.md。

显式sequence/transition-chain可用template_mode=opaque-effects连接原字节严格匹配的入口保守效果，见../../../docs/OPAQUE_COMPOSITION.md。它具有独立schema和逐应用鲜明未知节点；默认严格组合仍拒绝原缺口。宿主representationValidation是结构/来源摘要，不是架构证明；完整内存绑定等式、STORE进入guard和互补出口不得丢弃。

在已确认的 VM 内部控制流停滞、合并 handler 或重复入口状态不明时使用。先恢复可检查的状态转移，再决定如何提升和组合；不预设某一版本的 opcode 表或固定 VIP/VSP 寄存器。

显式 `ig5_ir level=project projection_mode=opaque-effects` 可对完整字节和固定解码同时匹配的 PUSHFQ/RDTSC/未定义16位BSWAP保留新的任意64位值、全部写入和未知别名；这是独立的保守集合模型，不能说未知指令已精确恢复。检查 `opaqueEffects`、`nondeterministicInputs` 与控制/内存根的依赖；即使目的值后来被覆盖，抽象边界仍保留。原严格/guarded/compose规则、原raw预算和活初始flags禁令不变，不能用观察值填未知字。PUSHFQ STORE的原pcodeIndex与replacementPcodeIndex分开。完整接口见../../../docs/OPAQUE_PROJECTION.md，VM机制与整机回放的证据链见../../../docs/VM_MODEL_RESEARCH.md。

## 从记录提取候选

固定目标 SHA、生产器版本依据、录制 run/thread/stop、映像与 trace 摘要。核对每次取 opcode、查表、计算目标与实际转移；表值在已观察读取中相同，只证明这些读取。文件 RX、初始映像相同或候选目标全可执行，均不能证明表在运行期间不可写、始终不变或全部目标可达。

以实际入口和下一派发边界切分路径，对字节及地址进行绑定。用真实解码产生的 raw p-code/SSA 建模；未知调用、硬件效应、条件分支或未观察后继不能从摘要中删除。只能处理直线路径的原型应明确拒绝条件分支，而不是把记录走过的分支当作唯一分支。

公开工具现在提供 `ig5_ir level=project`：传原始 AMD64 PE32+ 文件 `target`、精确首选地址数组 `projection_path`（最多128条）和末态 GPR 名称数组 `projection_registers`。不要同时传 `ea`、`initial_flags`、trace、lift 或 kernel 参数。它验证连续路径，保留全部写入及末条件分支两后继，生成自由初态的表达式 DAG；须读取返回的完整 `reportPath`，预览节点 id 不是可读公式或证明。此入口仅原始文件，重复地址、中途间接转移和未知副作用拒绝，默认strict也拒绝中途条件边；内部循环只有下述完整死写入 BSR/BSF 例外。拒绝 BSR/BSF 时保留缺口，不通过删除该指令重试来冒充原路径。此入口没有独立 SMT 证明；不能把生成 DAG 升级为等价、覆盖或业务恢复通过。

默认 `projection_mode=strict` 保留上述中途分支限制。需要在同一次请求组合跨越条件边的路径时，显式选择 `projection_mode=guarded-path`，给出的下一地址必须只匹配 taken/fallthrough 其中一侧；同目标两侧、中途间接转移和重复地址仍拒绝。保持原始指令，不能按某次记录删分支或注入观察 flags。终点投影仅在 `pathGuard` 非零时成立；另一侧 `sideExits` 是各自 guard 下的分叉时点状态，续程正文仍未分析。

近直接CALL只支持无前缀E8 rel32与同一字节绑定的完整RSP减8/压返回地址/直接控制结构。后续地址须为实际callee入口，不能跳到返回地址当作callee已经执行。终点control带transfer=call、returnAddress字符串，原STORE与path中的directCall元数据须保留；compose也衔接完整压栈状态。它不提供ABI、库调用、间接/远调用摘要，不执行目标，不放宽初始flags或PUSHFQ/RDTSC/未定义BSWAP等独立拒绝。

每条 STORE 按自身进入条件执行，不要用最终 pathGuard 筛掉分叉之前已发生的写入。读取完整 `branchPoints/sideExits`、所需 DAG 依赖、存储链与控制字段；预览最多8个出口，检查总数及 `sideExitPreviewComplete`。flags在同一次raw路径中连续处理，但不导出为可任意续接的出口状态。该入口提供有限路径条件和局部状态，不证明条件可满足、原生可达性或完整 handler 图覆盖。

组合多个闭合模板时使用公开`ig5_ir level=compose`，仅传`target`和`composition_plan`。计划`strategy=sequence`须有`paths`（严格地址路径数组）；`strategy=constant-loop`须有`prefix`、`body`、`suffix`（退出路径数组），不得同时传paths或循环次数。每个模板重新投影全部16GPR并自行定义有效flags，只代入GPR和写后内存；活初始flags仍拒绝，不能跨模板删除活scratch。有限重复只依据自由初态DAG中的确定常量条件，未知/超限不算退出。最多128不同地址、1024显式地址出现、64实际应用、1024逻辑指令/1024访问字节；推导尝试总量另计。展开预算不能把旧project的超限/重复地址请求改记为通过。

计划默认`indirect_mode=reject`；显式`guarded-target`才允许在模板边界按下一入口选择间接/RET续程。续接guard是实际目标表达式==该入口，不等侧保留原动态目标及控制执行后的全部GPR和内存，RET含已弹栈RSP。不能把候选入口或记录目标代入内存/寄存器，也不能据此声称自动发现、可满足性、可达性或目标全覆盖。读取每条STORE的进入guard与全部sideExits，终点仅在pathGuard下有效。源码纯核心报告与公开`ig5-pcode-composition-v1`报告、实际安装副本和DSH模型调用分别验收；参数、工作预算和范围见docs/STATE_COMPOSITION.md。

已有长计划或重复路径数组优先传`composition_plan_ref={path,sha256}`，不要手工重新展开/转抄。它与内联`composition_plan`互斥，只读最多64KiB的稳定普通UTF-8 JSON文件，并使用同一地址计划验证和预算。核对真实响应`compositionInput`的文件摘要、规范化摘要、模板数和地址数；分析拒绝的错误也包含已验证摘要/计数。不能只因拒绝原因相同就把63次调用当64次调用通过；文件引用的新请求与旧调用的失败分别记录。无可验证现成计划时先保存计划数据再获取其真实摘要，不猜哈希、不改已有冻结文件。

compose的`memoryNormalization`仅按同一uint64主体加模常量偏移确定写后读别名；宽窄重叠逐字节保留最新写入和旧内存，未知主体不能当不相交。4096 STORE访问的优化预算耗尽保留LOAD，原raw访问仍计全额预算。`PUSH/RET`同址读回目标可化简为写入值，但存储副作用及弹栈RSP不能删。工具中的`independentSMTProof=false`保持真实：局部数学验证不会由计数或优化自动升级为CPU、原生可达性、全部间接目标或业务证明。

投影报告使用可分页的多行 JSON，每次最多200行并记录已读范围。读取遇到行数上限时继续读取后续行，直到所需 DAG 节点及其依赖、存储和控制字段齐全；用户要求完整读取时须覆盖全文。只读到被截断的行时不能假定未见内容；报告是 JSON 证据，不应送入密码分析工具作为解密载荷。完整摘要取自原公开响应的 `reportSha256`。区分首次工具实际交付与之后上下文压缩：后来只剩摘要不代表第一次读取截断。任务允许时保存简短进度及证据引用，避免重复读取已核验的全部页面；确需恢复丢失细节时重读对应范围。

解释末控制时从 `control.condition` 追踪到最终节点，包括 `BOOL_NEGATE`：例如 JA 可能使用 `NOT(CF OR ZF)`，中间 OR 节点不能当作 taken 条件。记录实际条件规则及两侧目标，不根据助记符或中间节点猜测最终分支。

公开 project 会检查真实指令字节绑定的 flags 行为。遇到 `Undefined/unmodeled architectural flag`，记录具体指令和标志位：它可能是 CPU 架构未定义，也可能是固定解码器遗漏或错误公式；不能将已有但错误的公式描述成缺失。不能沿用旧 flags、注入观察值、删指令或换路径把拒绝改成原请求成功。完整报告的 `flagPolicies` 是有限分类依据，不是架构证明；后继确实覆盖相关 flags 的独立路径可作为另一个明确标注的案例验证。MUL/IMUL 的 ZF 等未定义项、ADD/CMP 的 AF 遗漏，以及多位/变量移位和旋转边界尤其需要保留。移位结论必须保留具体编码、位宽和计数范围，不能把显式 SHR 计数一的限制推广到所有移位，或把16位变量 SHL 的限制推广到其他形式。

寄存器结果也可能在架构上未定义。遇到 `Architecturally undefined 16-bit BSWAP` 时保留原指令与失败：即使 raw p-code 展示确定的 EAX 字节交换，也不能宣称恢复了架构结果，不能代入某次观察值或删去该指令重试。此入口在切片前整条拒绝该形式；正常32/64位及66+有效REX.W仍可分析，重复、错序及额外前缀保守拒绝。不要把“本入口未支持”泛化成“CPU非法”，也不要将这项特定检查称为完整未定义GPR模型。

能够建模末尾条件分支时，显式保存守卫和两侧后继，未分析的后继正文继续未知。本地handler17的研究已在固定p-code／普通数据内存模型中证明守卫及taken路径与下一派发器的组合，并找到“沿用写前字节码／表值”的反例；false正文、原生VM可达性、全GPR／flags与代码／数据一致性仍未证明。历史3次taken观察不能删去false后继；该研究仍不是通用公开handler工具。

## 先声明投影，再切片

投影列出保留的寄存器、flags、内存和控制输出。用向后数据依赖保留全部内存写入与控制依赖；寄存器重叠按字节/位宽处理，32 位写入清高位必须进入语义。p-code 的 unique 临时空间按机器指令隔离。未建模副作用须拒绝或保留未知；不能以“输出没用到”隐藏其影响。

初始寄存器和内存保持自由。普通内存模型须说明地址位宽、字节序、写入顺序和别名；不假定虚拟栈、字节码、上下文区域互不重叠。缺失观测不能补零。对有限个读取使用一致性约束时保留全部“同地址则同字节”条件；查询最终内存可使用任意自由探测地址。OS、MMIO、访问故障与并发没有模型时留在未证明范围。

BSR/BSF 等单条机器指令可能解码为内部 p-code 循环。一般需要证明全部内部路径终止且退出覆盖全部初始输入。当前公开例外限于16/32/64位寄存器源的两种独立结构：BSR完整10/11条固定SLEIGH操作和三边，BSF完整11/12条和三边。BSF从零递增并在移位后取最低位，不套用BSR或带F3前缀的TZCNT；两者各有有限终止论证，不实现通用有界探索或通用循环证明。然后在同次planner中从所选GPR、全部STORE地址/值、末控制和每个中途side exit重新计算活依赖，目的寄存器写入范围及六个flags必须全部已死；32位写入包含完整64位清高位，活ZF也拒绝。`internalElisions`绑定原始p-code摘要、字节、地址、完整写入范围及出口活字节集合，kind区分BSR/BSF，不接受用户提供的证书授权。原始解码保留，省略前的操作仍计预算。活输出、内存源、未知结构/前缀及副作用继续拒绝；此例外不证明未定义输出的架构语义，也不是独立SMT等价证明。

摘要保存：绑定的代码和解码摘要、入口/出口、初始自由状态、寄存器更新、内存读写、分支守卫、未建模效应、投影和证明范围。静态候选、具体观察、符号证明分别记录。

## 证明与反例

验证实际 p-code 投影与候选转移的差异是否 UNSAT；所有原约束和完整 DAG 定义均保留。超时/预算/未知不算通过。可先使用既有等价 AST 优化减少表达式，再在同一求解预算下重验，保留原失败记录。

对同入口的多次录制核对实际寄存器、加载值和存储操作数；记录没有写后字节，就不能称已独立观察到最终内存。有限观察支持模型定位，不替代全输入证明。使用错误偏移、有符号扩展、遗漏 EAX 清高位等有意义的负例检查证明器是否能找到反例，并验证内存模型允许区域重叠。

本地自产 VMP 3.11 Ultra 的两条直线路径已能证明相同的局部投影：读取原虚拟栈顶 8 字节，读取原 VIP 处无符号字节作为上下文偏移，写入上下文，VSP 加 8、VIP 加 1。它只覆盖声明的状态与普通内存模型；scratch 寄存器及 flags 未包含。该研究结果不提供通用公开 handler 恢复入口，不代表 VMP 3.8 样本或业务已恢复。

## 组合前的必要证据

后继派发器及 handler 可能读取被省略的 scratch 寄存器、flags 或环境状态。必须证明这些分量在读取前已被覆盖，或把它们加入状态；仅证明两个局部投影相同不允许互相替换。

从栈读取 VIP 再进入派发器的 handler 本身可能无条件；同一 VIP 在记录中有多个后继，不能直接称它是条件跳转，应追踪上游写入栈顶值的选择条件。两个上下文操作可有相同 VIP/VSP/内存效果但改写不同 scratch 寄存器，分别保留完整状态与所声明的家族等价范围。组合验证使用写后内存，包含 PUSH/RET 留下的存储；不能因 RSP 恢复就删除该写入。

栈区域不变量应显式包含所需对齐、非回绕条件和深度/剩余步数前提，并验证每个可达 handler 保持它。某个转移在假设带有限 fuel 的区域中闭合，不证明实际程序具有该深度上限；人为选取的地址带也不是观察到的系统栈分配边界。局部闭合不能恢复先前已失效的表/字节码常量。

保持代码、表、字节码和上下文的写入来源及失效关系。未知地址写入可能别名到这些区域时，不能沿用文件常量。条件 handler 需要守卫、两侧状态转移及覆盖；rolling key 与 VIP/VSP 迁移必须作为数据流处理。没有全量组合证据时，保存局部摘要与下一处具体缺口，继续目标。

## VM 录制观测、角色、取流与阶段恢复（`ig5_recovery` & `ig5_ir` 进阶）

- **持续 VM 逆向规划与 `case_ref`**：按完整函数合同、运行采集、VM 模型、ISA、字节码程序和业务/覆盖义务规划（见 `../../../docs/VM_RECOVERY_FRAMEWORK.md`）。有封存 case 时单独调用 `ig5_recovery recovery={case_ref:{path,sha256}}`（只读规划入口，不混传其他参数；读取完整 `reportPath`/`reportSha256` 中的 `caseSnapshot`、引用核验和依赖；`executionAuthority=not-inspected`）。
- **录制观测与存储事件（`observations` / `record_events` / `phase_model`）**：在原审批 `record_trace` 上显式加 `record_events=true` 可记录解码器 store 位置前后字节（共享 1MiB/512步/40秒预算，见 `../../../docs/NATIVE_STORE_EVENTS.md`）。随后单独调用 `ig5_recovery recovery={observations:{recordings:[{id,sha256}],target_sha256,offset:0,limit:32}}`（见 `../../../docs/VM_OBSERVATIONS.md`）。需研究代码变化时间关系时显式启用 `phase_model:true`（见 `../../../docs/VM_PHASE_MODEL.md`）；已有 context 时显式传 `phase_context_ref:{id,sha256}` 并给齐完整有序原录制清单，不把 `observationEpoch` 当全局 epoch，禁止跨观察点拼接。
- **寻址角色采样（`roles`）**：调用 `ig5_recovery recovery={roles:{recordings:[{id,sha256}],target_sha256}}` 自动提出寻址/窄加载/间接控制候选（最多128位置、每处首4尾4），不由运行时 PC 猜首选文件地址（见 `../../../docs/VM_ADDRESS_ROLES.md`）。
- **取流连接与语义核验（`flow`）**：调用 `ig5_recovery recovery={flow:{roles_ref:{id,sha256},target}}`（`target` 为同 SHA 原 PE，走 Java 完整状态与首指令投影，见 `../../../docs/VM_FETCH_FLOW.md`）。可显式加 `semantic_check:true` 获取独立回放见证（`assessed-v1`，仅对所选普通 IR 路径成立）。
- **重复路径核验与分页（`recurrences`）**：调用 `ig5_recovery recovery={recurrences:{flow_ref:{id,sha256}}}`；首尾采样重复同类主体时可显式设置 `sample_strategy:"distinct-source-targets",pair_offset:0`，按八组合分页读取 `nextPairOffset` 并交 `handlers`，勿预填地址或 opcode 标签。
- **分发主体静态投影（`handlers`）**：调用 `ig5_recovery recovery={handlers:{recurrences_ref:{id,sha256},target}}` 自动选择观测到的分发主体做 Java 静态投影，核对全部 16 末态 GPR、全部有序 STORE、相对控制两后继与 `partial` 原因（见 `../../../docs/VM_FETCH_FLOW.md#recorded-handler-bodies`）。
- **候选路径发现与 Java 解码后备（`discover` / `projection_decoder`）**：无逐条地址清单时先用 `ig5_ir level=discover`（可选 `follow_direct_calls=true` 进入规范 `E8` callee，RET 始终停，规范零位移见 `../../../docs/CALL_REL0.md` 与 `../../../docs/PATH_DISCOVERY.md`），再把 `candidatePath` 交显式 `projection_decoder="java"` 的 `project`（见 `../../../docs/JAVA_PROJECTION.md`）。若带 `analysisFailure` 报告路径和 SHA，先核对失败阶段回执（`failed-unverified` 不算通过）。
- **保存标志映像与过渡链合成（`opaque-status` / `transition-chain`）**：当 VM handler 通过 `PUSHFQ` 保存状态到虚拟栈时，单段 `project` 可选 `projection_mode="opaque-status"`（核对 `knownFlags`、`knownMask`/`unknownMask`、`freshInputBits`/`effectiveUnknownBits`；`handler250` 研究 67 个初始字节中仅 1 个新增、4 个表字节复用，见 `../../../docs/OPAQUE_STATUS_PROJECTION.md`）。多段 `compose` 遇到 flat 深度限制可选 `representation="transition-chain"`（见 `../../../docs/TRANSITION_CHAIN.md`），保留跨段标志映像时配 `template_mode="opaque-status"`（读取 `layers[].flagImages` 实际 STORE 根与 18 个 `state_binding.source` 等式；固定 3.11 的 `136/78` 接点归纳见 `../../../docs/CONTEXT_WRITE_JOIN.md` 与 `../../../docs/OPAQUE_STATUS_COMPOSITION.md`）。

参考架构研究见 [研究与引擎选择](strategy.md)；完整输出、函数返回及业务覆盖的验收区别见 [证据与停止判断](evidence.md)。
