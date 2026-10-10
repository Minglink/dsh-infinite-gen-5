# 调查任务与单函数证据包

这条工作流在 Core8 中建立可恢复的调查进展，再围绕少量候选函数收集系统证据。它使用已有静态数据库，不执行样本，不修改 IDB；新增参数不增加公开工具数量。需要独立高级工具时仍显式切换 Full38，写入、仿真和调试保持原有授权与审批。

## 1. 绑定已打开目标

先用 `ig5_open` 打开目标，再用 `ig5_status` 核对 target、engine、provider、artifactId、attachmentId、dbRevision 与分析状态。默认 `engine=reverse`、`reverseProvider=bundled` 使用随包服务，实际 `provider=ghidra`；显式 Ghidra 是另一数据库车道。不同 engine 或不同版本目标分别建立任务，不能复用另一数据库的证据。

以下 JSON 是分别传给对应工具的参数。示例路径、地址、任务 ID、快照 ID 都须替换为真实目标或前一步返回值；`expected_task_revision` 必须使用刚读取的 `taskRevision`，不能固定使用示例值。

调用 `ig5_profile` 建立任务：

```json
{
  "target": "C:\\samples\\app.exe",
  "engine": "reverse",
  "workspace": {
    "action": "create",
    "goal": "解释输入长度检查与拒绝路径",
    "hypothesis": "长度在复制前被约束",
    "next_step": "查看候选函数与调用者"
  }
}
```

create 必须提供 goal。任务文字是调用者陈述，保存 hypothesis 或 conclusion 不会将其升级为系统验证结论。status 只接受 `active`、`paused`、`completed`，表达调用者工作进度；`completed` 不代表全程序分析完整、协议恢复完成或补丁已验证。任务仅保存分析元数据与系统报告引用，不修改 IDB，不授予执行权限。

## 2. 收集少量函数证据

从 `ig5_funcs`、字符串引用或已有定位结果选取函数地址，调用 `ig5_decompile`：

```json
{
  "target": "C:\\samples\\app.exe",
  "engine": "reverse",
  "ea": "0x140001070",
  "style": "dossier",
  "dossier_max_bytes": 16000,
  "dossier_max_rows": 32,
  "task_id": "<create/get 返回的 taskId>"
}
```

`ea` 使用十六进制静态地址；也可按工具 schema 提供精确函数 name。不能拿运行时 ASLR 地址或文件偏移直接代入。task_id 可省略：省略时仍获得只读 dossier，但不绑定持久任务系统证据。

dossier 聚合反编译、CFG、调用者、被调函数与栈帧。每个章节保留 `ok`、`truncated`、`unsupported`、`error` 状态，所有章节共享证据包 provenance；检查实际来源、会话身份、修订以及 analysis 中的 partial/analysisComplete。某章节成功不能抵消另一章节失败，也不能将全程序的部分分析说成完整分析。截断时只针对影响结论的内容用独立工具补查。

`dossier_max_bytes` 为 4,000–64,000，默认 16,000，限制 dossier 正文 JSON 的 UTF-8 字节；`dossier_max_rows` 为 1–128，默认 32，是章节内每个数组的项数上限，并非伪代码字符串的行数上限。绑定任务后附加的少量 investigation 元数据可能使最终响应略大于正文预算。这些预算控制响应体，不是全部后端计算、反编译耗时或内存的总上限；不要用极小输出预算批量请求所有函数。

只读聚合与缓存限定在同一会话和数据库修订。变更、复开或切换数据库后重新获取结果。记录响应 `investigation` 中的 taskId、taskRevision、snapshotId、reportId、reportSha256 与 duplicate；系统捕获的报告 hash/引用证明所保存的是哪份快照，不能证明调用者假设正确，也不能证明报告未截断。文件落盘与任务引用不是跨文件原子提交；`investigation.ok=false` 或 `taskLinked=false` 时保留实际失败证据，不声称快照已绑定成功，不盲目重试。

## 3. 恢复任务与读取已绑定报告

调用 `ig5_profile` 读取任务：

```json
{
  "target": "C:\\samples\\app.exe",
  "engine": "reverse",
  "workspace": { "action": "get", "id": "<返回的 taskId>" }
}
```

同一目标的任务列表使用 `workspace:{"action":"list"}`，返回任务摘要及证据数量。先从列表选择 taskId，再用 `workspace:{"action":"get","id":"<taskId>"}` 查看完整 systemEvidence：每项保留 snapshot_id、report_id、report_sha256、context、stale 与 staleReasons。重开会话或 dbRevision 变化后旧系统快照是历史依据，需要重新取证；stale 表示上下文已旧，不表示原分析必然错误。任务能恢复进展，不会自动恢复调试控制权、运行时内存、授权或批准。

读取任务引用的独立 dossier 报告仍通过 `ig5_profile`：

```json
{
  "target": "C:\\samples\\app.exe",
  "engine": "reverse",
  "workspace": {
    "action": "evidence",
    "id": "<返回的 taskId>",
    "snapshot_id": "<该任务 systemEvidence 中的 snapshot_id>"
  }
}
```

该入口只读取指定任务真实引用的报告，不允许提交任意 report_id 伪造系统来源。返回 `workspace` 内的 taskId、taskRevision、snapshot 与 report；report 是当时按指定预算捕获的 dossier，不是未截断的全函数或完整全程序分析。旧报告的 stale 状态与来源需继续保留。

## 4. 保存下一步与结论

调用 `ig5_profile` 更新任务：

```json
{
  "target": "C:\\samples\\app.exe",
  "engine": "reverse",
  "workspace": {
    "action": "update",
    "id": "<返回的 taskId>",
    "expected_task_revision": 0,
    "hypothesis": "复制长度来自调用者参数，尚未确认别名",
    "next_step": "核查调用者的长度来源",
    "conclusion": "当前证据不足以判断所有输入路径",
    "status": "active"
  }
}
```

get/update 必须提供 id；update 必须提供与最新 taskRevision 相等的 expected_task_revision。新任务初始 taskRevision 为 0，但系统快照绑定也可能推进任务修订，因此 dossier 后应使用最新返回值或重新 get，不能照抄示例中的 0。CAS 冲突时重新读取、审阅并合并进展，不盲目重试覆盖。任务修订和数据库 dbRevision 是不同计数，不能互换。

## 5. 解密、协议与验证边界

七个原生技能均优先建立/恢复已有静态目标任务，再围绕候选函数读取 dossier。纯离线 `ig5_crypto` / `ig5_protocol` 不必打开静态数据库，其独立 result_id、输入/输出 ref、捕获方向和验证状态继续保留。任务文本只记敏感材料引用及来源，不复制密钥原值；引用本身不代表已认证或已还原协议。

识别线索、调用者假设和系统观测分别陈述。capa/FLOSS 尚未集成；当前 dossier 不新增自动算法识别、完整污点分析、通用去混淆或未知协议状态机恢复。需要写回名称、注释、类型或补丁，仍使用原有审批工具，并绑定当前数据库修订；调查任务与缓存不能绕过审批。
