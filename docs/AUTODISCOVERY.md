# 自动密钥恢复与未知协议推断

IG5 1.0.0 在原有 38 个工具内扩展 `ig5_crypto action=recover` 和 `ig5_protocol action=infer`。不新增一组重复工具，Core 8、Full 38 与七技能保持。处理用户提供或明确选择的离线字节，不启动样本、不修改数据库、不访问网络。

## 密钥恢复

`recovery.method` 为 `auto`、`xor-single`、`xor-repeat` 或 `aes-candidates`。单字节 XOR 可以枚举 256 个密钥；重复 XOR 使用有界密钥长度候选、文本统计以及可选已知明文约束。统计高分只是候选，短明文约束只解释这些字节，不能替代独立验证。缺少约束的任意二进制明文无法唯一确定重复 XOR 密钥；未知字节保持 unknown mask，禁止把占位字节当成恢复结果执行。

AES 检索 `key_candidates` 或 `key_material` 中的有界候选，支持从 ASCII hex/token 和对齐原始窗口提取。算法、IV、tag、AAD、padding 来自显式证据；不猜整个 AES 密钥空间，也不执行样本以提取秘密。`recovery.key_source` 可用现有四种 input 形式读取文件、ref、内联材料或静态范围，宿主核验来源与修订并保存来源说明。GCM 足够强的认证或完整独立 expected 比对可支持 verified；短 tag、padding 成功、可读性及 magic 命中保留 candidate。唯一性仅限实际检索过的假设，达到预算必须报告截断。

```json
{
  "action": "recover",
  "input": {"encoding": "hex", "data": "2b262f2f2c"},
  "recovery": {"method": "xor-single", "max_candidates": 5},
  "expected": {"encoding": "hex", "data": "68656c6c6f"}
}
```

示例用给定 plaintext 与 ciphertext 的周期关系恢复 XOR key `43`；expected 若同时参与恢复，不属于独立 holdout。实战应另取数据复核同一 key。无 expected 可以获得统计候选，但不能把可读文字当作确定恢复。评分包含 Latin/英文与有效 UTF-8 的 CJK 启发式，也检查有限 gzip/zlib、PNG、PE、ELF、ZIP、JPEG、PDF、SQLite 格式头；这些都是候选证据，不证明完整格式或正确密钥。中文评分可支持有足够字符与多样字节的单字节 XOR 候选；无 crib 的重复 XOR 列评分仍偏向 Latin，不保证任意中文编码、混合文本或未知二进制。任意二进制需已知明文/独立输出等额外约束。训练 crib 通过 `known_plaintext:[{offset,encoding,data}]` 提供，offset 相对本次选取的 ciphertext range。

恢复的候选包含 `keyComplete`、known/unknown mask、证据、分数和验证状态。默认恢复报告只显示 key 的 hash/ref/长度，不自动展开预览。绑定 producer 的敏感 ref 作为普通数据输入会被拒绝，只允许受控 `recovery.key_source` 或完整密钥的 `recipe.key_ref:{ref,result_id}` 消费。后者选择 `keyMaterial.dataRef.ref` 并配对 recovery result_id，核验完整 mask、target、engine、artifact/attachment 与修订。普通输入/输出 ref 和 partial key 不能冒充恢复密钥。

这不是本地秘密访问权限隔离：没有 producer 的 unbound ref 保留显式原始读取兼容，无法识别该引用的用途；用户仍可以直接读取本地文件。用户提供的 key/IV/tag/AAD 不写入恢复报告，敏感 artifact 属于用户数据，不分发。若 XOR expected 同时参与推导，报告标 usedForRecovery/non-independent；短数据不足两个 key 周期时不自动输出为已验证结果。AES 非认证明文的空/短 expected 不当作强密钥验证。

默认/硬上限：密钥长度最多 32、返回候选最多 8、尝试最多 4096、候选 key 输入最多 256、key material 最多 64 KiB；评分/变换 work bytes 包括参数准备与每次 AAD/IV/tag/密钥处理，不能用长认证附加数据绕过预算。候选 payload artifact 合计最多 8 MiB，敏感 key artifact 另限 256 bytes。worker 仍受内存、队列、15 秒超时与取消限制。not-found 表示这次有界检索未找到可发布结果，不证明样本不存在密钥。

## 未知协议推断

`inference.format` 为 `auto`、`stream`、`messages` 或 `capture`。自动候选包括有限搜索的整数长度前缀位置/宽度/端序、canonical unsigned LEB128 varint 长度前缀、有限宽度 TLV、固定长度及 LF/CRLF 分隔；从多条报文提出稳定 magic、长度关系、变化区域等字段假设。TLV 仅支持明确 Type/Length/Value 布局候选，不当作 BER/DER、嵌套 TLV 或通用协议识别。varint 前缀有有限字节长度及溢出/非 canonical 检查，动态前缀宽度后的 payload 不假造固定字段偏移。名称保持中性，不凭数值编造登录/密钥/消息语义。

stream 的 `boundary` 默认 unknown，只有独立证据支持消息起点时才指定 message-start。messages 的 `samples` 是已知完整报文，不能把 TCP packet 当成完整应用帧；capture 按 flow/方向独立推断，跳过缺口、重传冲突及未确定起点。`holdout_samples` 与训练样本分开，检查候选在另一批报文上是否成立，拒绝将自身拟合当成验证。

```json
{
  "action": "infer",
  "input": {"encoding": "hex", "data": "0003616263000464656667000568696a6b6c"},
  "inference": {
    "format": "stream", "boundary": "message-start", "min_frames": 3,
    "holdout_samples": [{"encoding": "hex", "data": "00026d6e"}],
    "max_candidates": 8
  }
}
```

候选的 `framing` / `schema` 可传给 `ig5_protocol action=decode`。stream 候选提供 `decodeInput.startOffset` 和 `decodeInput.byteLength`，分别映射到 decode 的顶层 `offset` 和 `length`，选中同一输入 ref 的准确范围；宿主先完整有界读取再切片，保存 sourceBytes/sourceSha256/range，不能借小 length 偷渡巨大文件。存在等价长度规则时保留歧义；新报文可能推翻某候选。固定长度切分不能由单消息确定，只有两种消息长度时还需稳定前缀或独立 holdout 支持；未知 stream 需至少三种已观察帧长。起点、尾部、unsupported、遗漏及预算均保留。推断不等于完整语义或状态机恢复。

输入仍最多 8 MiB；训练与 holdout 合计最多 64 条/1 MiB，推断最多扫描 256 KiB、返回最多 8 候选，并有全局枚举/工作上限。长捕获可能仅部分推断，不能把局部支持外推到所有方向或连接。

## 使用与验收

需要 Full 时先 `ig5_profile toolset=full`。支持 scoped API 的宿主只扩展当前 agent，其他会话保持原工具面；旧宿主返回 `toolsetScope=plugin-instance` 并明确全局影响。切换不持久化，也不授予运行或写权限。工作台 recover/infer 入口只插入可编辑草稿，由用户发送；读取既有结果使用 result_id/select，不触发后台重复检索。恢复后的 key ref、输出 ref 与 producer report ID 可组成“静态取证→密钥恢复→解密→推断→独立解码验证”闭环。`ig5_profile history` 的 archive/restore 保留报告 ID 与敏感/普通 blob 引用，不删除密钥产物或清空磁盘。

纯模块回归：`npm run test:crypto-recovery` 和 `npm run test:protocol-inference`。真实引擎闭环：`npm run test:discovery-runtime`，使用生成 PE，核对样本 hash、映射字节和数据库修订不变；不执行该 PE。回归成功说明所列夹具与路径成立，不承诺所有加密或未知协议均可恢复。手机原生离线引擎仍未移植。
