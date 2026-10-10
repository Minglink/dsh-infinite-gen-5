# Ghidra Python 脚本车道与常用 API 兼容子集

`ig5_run_idapython` 可在默认随包 Reverse 内核或显式 Ghidra 会话执行审批后的 Python，无需商业引擎。先通过 `ig5_open` 以 `engine=reverse`（内置模式）或 `engine=ghidra` 打开目标，再对该目标调用脚本工具；脚本中的原生对象使用真实 Ghidra API，返回的 `source` 保留实际实现来源。保留该工具名是为了已有工作流兼容，**不表示完整 IDAPython 实现**。显式配置外部商业 Reverse 时，其原生脚本 API 不属于本文的随包兼容子集。

实现见 [script_api.py](../adapters/ghidra/script_api.py)，事务入口见 [Ghidra worker](../adapters/ghidra/worker.py)，纯回归见 [test_ghidra_script_api.py](../scripts/test_ghidra_script_api.py)。工具仍经宿主写操作审批门；本文示例中的名称、注释、补丁同样需要审批。

## 执行环境

脚本具备以下原生对象与函数：

| 名称 | 实际含义 |
| --- | --- |
| `currentProgram` | 当前 Ghidra `Program` 对象 |
| `monitor` | 本次 worker 请求的 Ghidra `TaskMonitor` |
| `flat_api` | 绑定当前 Program 和 monitor 的真实 `FlatProgramAPI` |
| `toAddr` | `flat_api.toAddr`，把原生地址文本等转换为 Ghidra Address |

下文七个兼容模块可以直接使用，也可以通过普通 `import`、`from ... import ...` 导入。它们使用脚本局部 import hook，不替换进程的 `sys.modules`。标准 Python 模块及原生 Ghidra Java 包仍使用各自真实 API。

这是审批后的 Python 执行入口，**不是安全沙箱**。脚本可使用标准 Python 和原生 Ghidra 对象；直接原生调用、文件、网络、进程或线程副作用不受兼容 API 的读写计数管理，也不能由数据库 Undo 撤销。脚本返回 `target_executed=null`，表示车道没有观测脚本自行发起的 OS 执行，不能把它解释为“确认未执行样本”。

## 实际提供的七个模块

只承诺下表成员。未列出的 IDA 模块或成员会明确报 `UnsupportedCompatibilityError`，不会猜测替代 API，也不会自动执行外部 IDAPython 插件。

| 模块 | 成员 |
| --- | --- |
| `ida_bytes` | `get_bytes(ea, size, flags=0)`、`get_byte(ea)`、`get_word(ea)`、`get_dword(ea)`、`get_qword(ea)`、`patch_bytes(ea, payload)`、`patch_byte(ea, value)`、`get_cmt(ea, repeatable=False)`、`set_cmt(ea, text, repeatable=False)` |
| `ida_name` | `get_name(ea, flags=0)`、`set_name(ea, name, flags=0)`、`get_name_ea(from_ea, name)`、`SN_CHECK`、`SN_NOWARN` |
| `ida_funcs` | `get_func(ea)`、`get_func_name(ea)`、`get_func_qty()`、`FUNC_LIB` |
| `idautils` | `Functions(start=0, end=None)`、`Names()`、`Chunks(ea)`、`FuncItems(ea)`、`CodeRefsTo(ea, flow=False)`、`CodeRefsFrom(ea, flow=False)`、`DataRefsTo(ea)`、`DataRefsFrom(ea)` |
| `idc` | `ida_bytes` 和 `ida_name` 表中的全部成员，另有 `get_func_name(ea)`、`get_func_attr(ea, attribute)`、`FUNCATTR_START`、`FUNCATTR_END`、`FUNCATTR_FLAGS`、`BADADDR` |
| `ida_ida` | `inf_is_64bit()`、`inf_is_32bit_exactly()`、`inf_is_be()`、`inf_get_min_ea()`、`inf_get_max_ea()` |
| `ida_idaapi` | `BADADDR` |

地址可传 Python 整数或十六进制文本，按当前 32/64 位程序范围校验；布尔值不作为地址接受。整数读取遵守程序字节序。`get_bytes` 要求整个区间已加载、已初始化且可读；未映射或短读会报错，不能依赖返回零字节。名称和注释写入同样要求地址已加载。

`get_name` 和 `get_bytes` 的 `flags` 当前只接受 `0`。`set_name` 接受 `SN_CHECK=0` 与 `SN_NOWARN=0x100`；Ghidra 的名称校验仍生效，其它 IDA 名称标志不支持。名称最多 1,024 UTF-8 字节，注释最多 16,384 UTF-8 字节；空名称拒绝，空注释删除该位置对应注释。`repeatable` 与代码引用的 `flow` 只接受布尔值或整数 `0/1`。

`get_name_ea` 找不到名称时返回 `BADADDR`；同名对应多个不同地址时明确拒绝歧义。`from_ea` 为兼容参数并校验范围，不用它猜测命名空间。`Names` 和引用枚举只返回程序默认地址空间，引用目标地址去重。`CodeRefsTo/From(flow=False)` 排除普通 fallthrough；`flow=True` 包含它。引用来自已有 Ghidra 分析记录，不保证补齐所有间接调用。

`get_func` 找不到函数时返回 `None`，否则返回只读视图：`start_ea`、`end_ea`、`flags`、`ghidra_external`、`ghidra_thunk`、`library_classification`。`end_ea` 是函数体最大地址加一，不能把 `[start_ea,end_ea)` 视为非连续函数的完整范围；用 `Chunks` 获取真实函数体区间，末端均为排他地址。`FuncItems` 返回函数体内已定义 code unit 的起始地址，不把未定义字节假造为指令。

这里的 `FUNC_LIB` 位是 **Ghidra external/thunk 的明确投影**，不是原生 IDA flags，也不是标准库等价识别。需要实际后端分类时查看 `ghidra_external`、`ghidra_thunk` 和 `library_classification`。`idc.get_func_attr` 仅支持本模块提供的 `FUNCATTR_START/END/FLAGS` 常量；不要套用其它 SDK 的硬编码属性编号。

## 读取与函数调查

以下代码作为工具的 `code` 内容发送，目标必须已经打开：

```python
import ida_bytes
import ida_name
import ida_funcs
import idautils

ea = next(idautils.Functions(), None)
if ea is None:
    raise RuntimeError("当前分析没有函数")

function = ida_funcs.get_func(ea)
print(hex(ea), ida_name.get_name(ea))
print("首字节:", ida_bytes.get_bytes(ea, 1).hex())
print("函数范围:", [(hex(a), hex(b)) for a, b in idautils.Chunks(ea)])
print("定义项:", [hex(item) for item in idautils.FuncItems(ea)])
print("代码引用:", [hex(item) for item in idautils.CodeRefsTo(ea)])
print(function.library_classification)
```

每个枚举都消耗共享扫描预算。大型函数或名称库可触发明确预算错误；不会把静默截断的列表当作完整分析结果。

## 名称、注释与补丁

名称和注释示例：

```python
import ida_name
import idautils
import idc

ea = next(idautils.Functions(), None)
if ea is None:
    raise RuntimeError("当前分析没有函数")

ida_name.set_name(ea, "ig5_reviewed_entry", ida_name.SN_CHECK)
idc.set_cmt(ea, "已人工核对：此处为分析入口", False)
print(ida_name.get_name(ea), idc.get_cmt(ea, False))
```

补丁应先用只读工具核对原字节与静态地址。下例的地址、预期值和替换值必须换成已审查的实际补丁；例中相同替换值仅用于展示校验流程：

```python
import ida_bytes

ea = 0x1000                  # 换成当前样本已加载的静态地址
expected = b"\x90\x90"      # 换成已经核对的原字节
replacement = b"\x90\x90"   # 换成批准的补丁字节

before = ida_bytes.get_bytes(ea, len(expected))
if before != expected:
    raise ValueError("原字节不匹配，拒绝补丁")
ida_bytes.patch_bytes(ea, replacement)
print(ida_bytes.get_bytes(ea, len(replacement)).hex())
```

`patch_bytes` 每次接受 1–4,096 字节的 bytes/bytearray/memoryview，校验已加载区间并验证实际写回；通过 worker 的内部补丁原语处理相交 code unit，不调用会另行提交事务的公开补丁工具。

## 原生 Ghidra 对象

需要兼容子集以外的开源能力时，显式使用原生 Ghidra API，并保留实际后端语义：

```python
import idautils
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

ea = next(idautils.Functions(), None)
if ea is None:
    raise RuntimeError("当前分析没有函数")
address = toAddr(format(ea, "x"))

print(currentProgram.getLanguageID())
function = flat_api.getFunctionContaining(address)
print(function.getName() if function is not None else "无函数")
symbol = currentProgram.getSymbolTable().getPrimarySymbol(address)
if symbol is not None:
    symbol.setName("ig5_native_reviewed_entry", SourceType.USER_DEFINED)
currentProgram.getListing().setComment(address, CodeUnit.EOL_COMMENT, "原生 API 审查注释")
```

脚本车道自身不打开嵌套事务，不调用 Program save。原生对象仍暴露各自完整接口；不要在脚本中自行提交事务、保存数据库或启动后台写线程，否则会破坏外层事务和 session Undo 的工作流约定。直接原生调用不计入 `compatibilityWrites`；该字段只统计兼容封装成功执行的写调用。

## 预算、结果与撤销

公共工具当前只注册 `target` 和 `code` 参数。以下是脚本适配层的内建默认值与实现硬上限，不能把内部测试接口的预算参数当成公共工具参数：

| 预算 | 默认 | 实现上限 |
| --- | ---: | ---: |
| Python 源码 UTF-8 | 64 KiB | 64 KiB |
| stdout + stderr UTF-8 | 256 KiB | 1 MiB |
| 兼容 API 调用 | 10,000 | 100,000 |
| 兼容 API 读取累计 | 16 MiB | 64 MiB |
| 兼容 API 补丁累计 | 64 KiB | 1 MiB |
| 枚举扫描项 | 65,536 | 200,000 |
| 当前脚本的 line/call 事件 | 1,000,000 | 5,000,000 |
| 协作式执行时间 | 30 秒 | 120 秒 |

枚举扫描项包括被筛掉或去重的项；读取计数包括补丁前后验证及名称/注释写入的加载检查。Python 捕获输出共享预算，在 UTF-8 字符边界保留前缀；Java/native 直接写文件描述符的日志不属于此捕获预算。行数与时间限制为协作式检查，不能抢占阻塞的 Java/native 调用，标准 Python 模块内执行也不是完整逐指令限制；宿主 RPC 超时仍可能结束该请求所属 worker。

成功结果包含 `stdout`、`stderr`、兼容旧调用的 `output=stdout`、`compatibility`、`source`、`budget` 和 `compatibilityWrites`。外层 worker 增补 `committed/saved/revision/journalId/undoMode/persistence` 等真实持久化信息。

脚本未捕获的异常、语法错误、SystemExit 或预算耗尽会抛出 `ScriptExecutionError`，保留捕获输出与异常类型，并让外层 Ghidra 事务回滚。兼容 API 预算即使被脚本的 `except` 捕获，也在结束时拒绝成功提交。正常失败后的 `transactionRolledBack` 由完成事务异常处理的 worker 设置；外部文件、网络或进程副作用仍不可回滚。

脚本正常提交采用 **session-only 原生 Undo**，不立即保存数据库；可以使用 `ig5_undo` 撤销当前可用操作。正常关闭或后续保存可使原生 Undo 失效，以工具实际 `saved/persistence/undoMode` 为准。宿主硬超时、强终止或 worker 崩溃不保证执行 `finally` 或完成事务回滚；需要检查会话恢复、未保存修改与数据库状态，不能自动重放已执行过的脚本。
