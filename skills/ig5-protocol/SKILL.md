---
name: ig5-protocol
description: "使用 IG5 对离线捕获或未知报文进行有界重组、自动分帧/字段候选推断、独立报文验证与显式解码，保留来源和歧义。"
---

先确认输入是原始报文、文件格式、PCAP 或 PCAPNG，以及需要回答的协议问题。需要高级工具时调用 `ig5_profile toolset=full`；这不授权样本或网络执行。`ig5_protocol` 处理离线字节，提供未知 framing/字段候选推断，不抓实时网络、不主动发包。记录 capture 来源、样本身份、方向、时间与截断；字段假设和观察事实分开陈述。

`input` 选择一种来源：`{encoding:"hex"|"base64",data:"..."}`、`{path:"完整本地文件路径"}`、`{ref:"sha256:...",result_id:"产生该 ref 的报告 UUID"}`，或静态字节 `{source:{target,engine,ea,size,expected_revision}}`。引用来源优先提供明确 producer ID；省略 `input.result_id` 标记 unbound，不能从共享 hash 猜测样本归属。先用 `action=inspect` 查看有限字节/字符串预览、长度、熵与长度前缀候选。对 PCAP/PCAPNG 调用 `action=capture`，按需要设置 `max_packets`、`max_frames`、`max_reassembly_bytes` 与预览预算。检查实际支持的 link/IP 层、capture 截断、TCP 缺口、重传/重叠冲突和序号回绕，并分别核对响应 `value` 内的 parseComplete/reassemblyComplete/decodingComplete；不能把有缺口的片段拼成“完整流”，不能把一个方向流当作完整会话，也不能把时间顺序当作 TCP 字节顺序。UDP 保留单个报文边界，TCP 保留方向和连续 span。即使省略 packet 预览，也应读取 unsupportedSummary 的原因计数。

沿字符串、导入、调用和反编译定位收发、解压、解密与解析函数，再用字节、CFG、结构体与实际端序读取核验字段。`ig5_slice` 只是标识符焦点行，不是完备污点证明。需要动态缓冲区时，只有目标执行已获授权后才通过审批调用 `ig5_dbg` 或 `ig5_emulate`，记录真实暂停/返回身份；不可用只读工作台请求启动调试或绕开审批。若报文是加密/压缩数据，先按 `ig5-crypto` 的显式参数与验证流程处理；协议模块不会自动破解加密。

未知边界/字段时用 `action=infer`，`inference.format=auto|stream|messages|capture`。默认 stream boundary=unknown，只有证据支持时才给 message-start；samples 必须是已知完整应用消息，不能直接把 TCP packets 当成消息。用不同报文作 holdout_samples，检查候选在独立数据是否成立。capture 模式按 flow/方向分组，不能将缺口、冲突或未确定起点强行参与训练。保留等价候选、分数、覆盖、尾部与截断，单报文不足以确认协议。

候选的 framing/schema 直接交给 `action=decode`；支持 fixed、length-prefix 和 delimiter。长度规则保留位置/大小/端序/headerLength/长度是否含头；换行 delimiter 保留准确字节与是否包含分隔符。验证最短/零/极端/缺尾报文和 holdout；字段保持中性，u64/i64 不转换成失真 Number。可读结果不证明完整语义，未知状态机保持未确定。

引用所选 chunk/datagram 时，将其 `dataRef.ref` 与产生该捕获的顶层 `result_id` 配对，作为下一步的 `input.ref` 和 `input.result_id`。解密或解压结果转入协议车道时，同样配对前一步的 `output.ref` 与顶层 `result_id`，例如：

```json
{"action":"decode","input":{"ref":"<前一步 output.ref 或所选 dataRef.ref>","result_id":"<产生所选 ref 的顶层 result_id>"},"framing":{"type":"fixed","length":4},"schema":{"fields":[{"name":"value","offset":0,"type":"u32","endian":"big"}]}}
```

此例只有显式 4 字节整数假设，需按真实边界与字段证据替换配置及占位符。若使用嵌套 `dataRef.result_id`，先确认它绑定所选 ref。`action=result` 的顶层 `result_id` 读取历史报告，不是 `input.result_id` 的替代写法。

至少对多条独立报文检查方向、帧边界、长度、字段值和剩余字节，并包含截断或错误长度样本。将解码结果与真实解析函数的分支、返回值或已授权暂停观察对账；同一报文成功解码只说明显式 schema 可读，不证明完整协议已恢复。协议状态机需由多阶段会话和函数状态迁移支持，当前工具不自动推导状态机。报告所有 unsupported、incomplete、conflict、truncated 或 budget 标记。

保留 `result_id`、输入 ref、流/报文 buffer ref、capture indices/spans、明确的 framing/schema 和复核结果。用 `action=result result_id=... select=...` 选择报告的相关部分，避免将大报文反复塞入上下文；select 是路径选择，不能假定它提供分页游标。模型响应截断不等于磁盘报告丢失。工作台只读显示证据，composer 草稿需由用户发送；名称、注释、结构体或补丁回写继续经过宿主审批。最终交付可重复使用的显式解码配置和产物引用，同时列明未知字段、未验证方向及状态迁移。
