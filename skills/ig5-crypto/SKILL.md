---
name: ig5-crypto
description: "使用 IG5 定位加密数据、自动恢复 XOR 或检索 AES 候选密钥，再通过认证/独立明文验证与来源引用完成配置提取。"
---

先明确待分析的密文、配置或编码缓冲区。需要高级工具时调用 `ig5_profile toolset=full`；这只切换插件实例的工具面，不授权样本执行。记录样本 artifactId、静态 engine 与 dbRevision，以及字节的文件偏移或 VA；不能把运行时地址当作静态 VA。使用 `ig5_scan` 的标准结果、字符串、导入、xref、调用关系和反编译定位处理路径。常量、API、熵或块对齐只支持候选假设，不能据此确认算法或成功解密。

`ig5_crypto` 是离线数据工具，不需要打开静态数据库。`input` 必须选择一种来源：`{encoding:"hex"|"base64",data:"..."}`、`{path:"完整本地文件路径"}`、`{ref:"sha256:...",result_id:"产生该 ref 的报告 UUID"}`，或 `{source:{target,engine,ea,size,expected_revision}}`。引用输入使用明确 producer ID 保留来源；省略 `input.result_id` 会标记 unbound，不能从相同字节 hash 推断样本或引擎归属。文件和静态读取受字节预算约束；静态来源优先携带本次修订。先用 `action=inspect` 获取范围、SHA-256、编码/压缩头、熵及有限预览，不自动执行疑似处理函数，也不把头部匹配当作完整压缩载荷有效。

从函数参数、调用上下文、只读字节或已授权的暂停事件恢复 key、IV、计数器初值、tag、AAD 与 padding。记下来源地址和实际观察，不猜默认参数。需要执行函数时，仅在用户已授权该目标执行后，通过审批调用 `ig5_emulate` 或 `ig5_dbg`。受限 CPU 仿真支持实际 provider 提供的 x86/x64 或 Ghidra ARM64/AAPCS64，没有 OS/import/TLS；异常、指令上限和超时不能当成明文。调试捕获保留 runId、stopSeq、模块映射与缓冲区范围，不能重用旧暂停上下文。

密钥未知时先调用 `ig5_crypto action=recover`。`recovery.method=auto|xor-single|xor-repeat|aes-candidates`；用已知明文约束、有限候选或 `key_source` 的文件/ref/静态范围提高成功率。XOR 统计分数只是候选；partial key 的 unknown mask 不得当作完整字节执行。AES 需给准确 IV/tag/AAD/padding，用候选材料检索并验证，不尝试随机 AES 全空间。独立完整 expected 或足够强的 GCM tag 可支持 verified；训练 crib、padding、可读性不能替代独立验证。记录所有 budgets/truncated/歧义。

选完整恢复候选的 `keyMaterial.dataRef.ref`，配对 recovery `result_id`，作为 transform 的 `recipe.key_ref:{ref,result_id}`；宿主核验完整性、来源与修订，密钥无须在模型上下文展开。也可显式提供 `recipe.key`。`recipe.kind` 可选 `xor`、`aes-cbc`、`aes-ctr`、`aes-gcm`、`gzip` 或 `zlib`；IV/tag/AAD 来自准确证据。XOR 循环起点用 `recipe.key_offset`，AES 明确 padding，CTR/GCM 使用 none。GCM 认证失败不返回明文。输入/输出最多 1 MiB，预览最多 4096 字节；敏感 key blob 是用户数据，不分发，不自动预览。

多阶段变换使用前一步响应的 `output.ref` 和同一响应的顶层 `result_id`；下一步把两者放进 `input`，例如：

```json
{"action":"transform","input":{"ref":"<前一步 output.ref>","result_id":"<前一步顶层 result_id>"},"recipe":{"kind":"gzip"}}
```

将占位符替换为实际返回值。`input.result_id` 是下一次调用选择 producer 的参数；`action=result` 的顶层 `result_id` 则是要读取的历史报告。不要将“前一步捕获自哪里”与“本步骤生成的报告 UUID”混为一谈。若使用响应中对应 `output.result_id`，也须确认它与所选 ref 同属同一报告。

有确定的已知明文时，使用 `expected={encoding,data}`，检查响应的 `value.verification.status`、长度、SHA-256 与首个差异偏移；也可单独调用 `action=verify`。无 expected 时保留 not-requested，不能写成已验证。至少用独立测试向量或多条配置样本复核同一参数/处理路径；GCM 的 `value.authentication.status=passed` 只验证这次给定参数的认证关系，不证明样本采用了该算法。

完成后记录 `result_id`、输入/输出 blob ref、字节范围、来源与验证状态。用 `action=result result_id=... select=...` 读取此前报告的相关部分，避免重新发送完整数据。保存的结果不包含 key、IV、tag 或 AAD 值；可复现分析还需要用户保管参数及其证据，不能声称仅凭报告就能恢复秘密。工作台只读显示结果，composer 只插入可编辑草稿，不自动发送；若要回写名称、注释或类型，仍通过对应审批工具。结论分别陈述已经认证/比对的结果、候选算法和未恢复参数。
