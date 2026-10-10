"""Approved Python scripts over Ghidra with a limited, explicit IDAPython API.

The caller MUST run ``run_script`` inside one ``worker.commit`` transaction and
let exceptions propagate out of that transaction. This module never commits,
saves, opens another transaction, or calls the public mutation methods.

Scripts are authorized Python execution, not a security sandbox. Code/output,
compatibility API work, and cooperative Python execution are bounded. Blocking
Java/native calls are not preemptible here; the host worker timeout remains the
last resort. Direct FlatProgramAPI/currentProgram calls belong to the same outer
Ghidra transaction but bypass the compatibility API's accounting.
"""

import builtins
from dataclasses import dataclass
import io
import sys
import time
import types


class UnsupportedCompatibilityError(ImportError):
    pass


class ScriptBudgetError(RuntimeError):
    pass


class ScriptExecutionError(ValueError):
    def __init__(self, message, details):
        super().__init__(message)
        self.details = details


def _integer(value, name, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
        raise ValueError(name + " must be a bounded integer")
    return value


def _boolean_flag(value, name):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    raise ValueError(name + " must be a boolean or 0/1")


class _Budget:
    def __init__(self, params):
        self.limits = {
            "apiCalls": _integer(params.get("max_api_calls", 10000), "max_api_calls", 1, 100000),
            "readBytes": _integer(params.get("max_read_bytes", 16 * 1024 * 1024), "max_read_bytes", 1, 64 * 1024 * 1024),
            "writeBytes": _integer(params.get("max_write_bytes", 65536), "max_write_bytes", 1, 1024 * 1024),
            "enumerated": _integer(params.get("max_enumerated", 65536), "max_enumerated", 1, 200000),
            "pythonLines": _integer(params.get("max_python_lines", 1000000), "max_python_lines", 1, 5000000),
            "outputBytes": _integer(params.get("max_output_bytes", 256 * 1024), "max_output_bytes", 1, 1024 * 1024),
            "seconds": _integer(params.get("timeout", 30), "timeout", 1, 120),
        }
        self.used = {key: 0 for key in self.limits if key != "seconds"}
        self.started = time.monotonic()
        self.exhausted = None

    def check_time(self):
        if time.monotonic() - self.started > self.limits["seconds"]:
            self.exhausted = "seconds"
            raise ScriptBudgetError("script cooperative time budget exhausted")

    def consume(self, key, amount=1):
        self.check_time()
        if self.exhausted is not None:
            raise ScriptBudgetError("script " + self.exhausted + " budget already exhausted")
        if self.used[key] + amount > self.limits[key]:
            self.exhausted = key
            raise ScriptBudgetError("script " + key + " budget exhausted")
        self.used[key] += amount

    def report(self):
        return {"limits": dict(self.limits), "used": dict(self.used), "exhausted": self.exhausted,
                "elapsedSeconds": max(0.0, time.monotonic() - self.started), "cooperative": True,
                "javaNativeCallsPreemptible": False}


class _Capture(io.TextIOBase):
    def __init__(self, budget):
        self.budget = budget
        self.parts = []

    @property
    def encoding(self):
        return "utf-8"

    def writable(self):
        return True

    def write(self, text):
        if not isinstance(text, str):
            raise TypeError("captured output requires text")
        payload = text.encode("utf-8", "replace")
        remaining = self.budget.limits["outputBytes"] - self.budget.used["outputBytes"]
        if len(payload) > remaining:
            self.parts.append(payload[:remaining].decode("utf-8", "ignore"))
            self.budget.used["outputBytes"] += remaining
            self.budget.exhausted = "outputBytes"
            raise ScriptBudgetError("script outputBytes budget exhausted")
        self.budget.consume("outputBytes", len(payload))
        self.parts.append(payload.decode("utf-8"))
        return len(text)

    def flush(self):
        pass

    def getvalue(self):
        return "".join(self.parts)


class _CompatModule(types.ModuleType):
    def __init__(self, name, values):
        super().__init__(name)
        self.__dict__.update(values)
        self.__all__ = sorted(values)

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        raise UnsupportedCompatibilityError("IDAPython compatibility subset does not support " + self.__name__ + "." + name)


@dataclass(frozen=True)
class _FunctionView:
    start_ea: int
    end_ea: int
    flags: int
    ghidra_external: bool
    ghidra_thunk: bool
    library_classification: str = "Ghidra external or thunk; not standard-library equivalence"


def _each(iterator):
    if hasattr(iterator, "hasNext"):
        while iterator.hasNext():
            yield iterator.next()
    else:
        yield from iterator


class _API:
    def __init__(self, worker, budget, bindings, monitor):
        self.worker, self.program, self.budget = worker, worker.program, budget
        self.flat = bindings["FlatProgramAPI"](self.program, monitor)
        self.source = bindings["SourceType"].USER_DEFINED
        self.comment_kind = bindings["CodeUnit"]
        self.bits = int(self.program.getLanguage().getDefaultSpace().getSize())
        if self.bits not in (32, 64):
            raise ValueError("IDAPython compatibility addresses require a 32-bit or 64-bit program")
        self.badaddr = (1 << self.bits) - 1
        self.order = "big" if bool(self.program.getLanguage().isBigEndian()) else "little"
        self.writes = 0

    def tick(self):
        self.budget.consume("apiCalls")

    def number(self, value):
        if isinstance(value, str):
            try:
                value = int(value, 16 if value.lower().startswith("0x") else 10)
            except ValueError:
                raise ValueError("script address must be an integer or hexadecimal string") from None
        return _integer(value, "script address", 0, self.badaddr)

    def address(self, ea):
        return self.worker.address({"ea": hex(self.number(ea))})

    def address_number(self, address):
        return int(address.getOffset()) & self.badaddr

    def get_bytes(self, ea, size, flags=0):
        self.tick()
        _integer(flags, "get_bytes flags", 0, 0)
        size = _integer(size, "get_bytes size", 1, 16 * 1024 * 1024)
        self.budget.consume("readBytes", size)
        return self.worker.read_bytes(self.address(ea), size)

    def read_integer(self, ea, size):
        return int.from_bytes(self.get_bytes(ea, size), self.order)

    def patch_bytes(self, ea, payload):
        self.tick()
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise ValueError("patch_bytes requires 1..4096 bytes")
        # len(memoryview) counts first-dimension elements, not raw bytes. Check
        # nbytes before flattening/copying typed or strided views; bytes and
        # bytearray use their byte length directly to avoid oversized copies.
        size = payload.nbytes if isinstance(payload, memoryview) else len(payload)
        if not 1 <= size <= 4096:
            raise ValueError("patch_bytes requires 1..4096 bytes")
        payload = bytes(payload)
        if not 1 <= len(payload) <= 4096:
            raise ValueError("patch_bytes requires 1..4096 bytes")
        self.budget.consume("writeBytes", len(payload))
        address = self.address(ea)
        self.budget.consume("readBytes", len(payload) * 2)
        self.worker.read_bytes(address, len(payload))  # require a loaded initialized range
        units = self.worker.patch_units(address, len(payload))
        self.worker.write_patch(address, payload, units)
        if self.worker.read_bytes(address, len(payload)) != payload:
            raise RuntimeError("script patch verification failed")
        self.writes += 1
        return True

    def patch_byte(self, ea, value):
        return self.patch_bytes(ea, bytes([_integer(value, "byte value", 0, 255)]))

    def get_name(self, ea, flags=0):
        self.tick()
        _integer(flags, "get_name flags", 0, 0)
        symbol = self.program.getSymbolTable().getPrimarySymbol(self.address(ea))
        return str(symbol.getName()) if symbol is not None else ""

    def set_name(self, ea, name, flags=0):
        self.tick()
        _integer(flags, "set_name flags", 0, 0x100)
        if flags not in (0, 0x100):
            raise UnsupportedCompatibilityError("set_name supports SN_CHECK and SN_NOWARN only")
        if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 1024:
            raise ValueError("set_name requires a nonempty name of at most 1024 UTF-8 bytes")
        address = self.address(ea)
        self.budget.consume("readBytes")
        self.worker.read_bytes(address, 1)
        symbol = self.program.getSymbolTable().getPrimarySymbol(address)
        if symbol is not None:
            symbol.setName(name, self.source)
        else:
            self.program.getSymbolTable().createLabel(address, name, self.source)
        self.writes += 1
        return True

    def get_name_ea(self, from_ea, name):
        self.tick()
        self.number(from_ea)
        if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 1024:
            raise ValueError("symbol name must be bounded nonempty text")
        matches = set()
        for symbol in _each(self.program.getSymbolTable().getSymbols(name)):
            self.budget.consume("enumerated")
            if symbol.getAddress().getAddressSpace() == self.program.getAddressFactory().getDefaultAddressSpace():
                matches.add(self.address_number(symbol.getAddress()))
                if len(matches) > 1:
                    raise ValueError("script symbol lookup is ambiguous")
        return next(iter(matches)) if matches else self.badaddr

    def function(self, ea):
        return self.program.getFunctionManager().getFunctionContaining(self.address(ea))

    def function_view(self, function):
        if function is None:
            return None
        return _FunctionView(self.address_number(function.getEntryPoint()), self.address_number(function.getBody().getMaxAddress()) + 1,
                             4 if bool(function.isExternal() or function.isThunk()) else 0,
                             bool(function.isExternal()), bool(function.isThunk()))

    def get_func(self, ea):
        self.tick()
        return self.function_view(self.function(ea))

    def get_func_name(self, ea):
        self.tick()
        function = self.function(ea)
        return str(function.getName()) if function is not None else ""

    def get_func_attr(self, ea, attribute):
        view = self.get_func(ea)
        if view is None:
            return self.badaddr
        if attribute == 0:
            return view.start_ea
        if attribute == 4:
            return view.end_ea
        if attribute == 8:
            return view.flags
        raise UnsupportedCompatibilityError("IDAPython compatibility subset does not support this function attribute")

    def functions(self, start=0, end=None):
        self.tick()
        start, end = self.number(start), self.badaddr if end is None else self.number(end)
        if end < start:
            raise ValueError("function enumeration end must not precede start")
        for function in _each(self.program.getFunctionManager().getFunctions(True)):
            self.budget.consume("enumerated")
            ea = self.address_number(function.getEntryPoint())
            if start <= ea < end:
                yield ea

    def names(self):
        self.tick()
        for symbol in _each(self.program.getSymbolTable().getAllSymbols(True)):
            self.budget.consume("enumerated")
            address = symbol.getAddress()
            if address.getAddressSpace() == self.program.getAddressFactory().getDefaultAddressSpace():
                yield self.address_number(address), str(symbol.getName())

    def chunks(self, ea):
        self.tick()
        function = self.function(ea)
        if function is None:
            return
        for region in _each(function.getBody().getAddressRanges(True)):
            self.budget.consume("enumerated")
            yield self.address_number(region.getMinAddress()), self.address_number(region.getMaxAddress()) + 1

    def func_items(self, ea):
        self.tick()
        function = self.function(ea)
        if function is None:
            return
        for unit in _each(self.program.getListing().getCodeUnits(function.getBody(), True)):
            self.budget.consume("enumerated")
            if not hasattr(unit, "isDefined") or unit.isDefined():
                yield self.address_number(unit.getMinAddress())

    def refs(self, ea, direction, kind, flow=False):
        self.tick()
        flow = _boolean_flag(flow, "flow")
        address = self.address(ea)
        manager = self.program.getReferenceManager()
        references = manager.getReferencesTo(address) if direction == "to" else manager.getReferencesFrom(address)
        seen = set()
        for reference in _each(references):
            self.budget.consume("enumerated")
            ref_type = reference.getReferenceType()
            if kind == "code":
                if not ref_type.isFlow() or (not flow and ref_type.isFallthrough()):
                    continue
            elif not ref_type.isData():
                continue
            other = reference.getFromAddress() if direction == "to" else reference.getToAddress()
            if other.getAddressSpace() != self.program.getAddressFactory().getDefaultAddressSpace():
                continue
            result = self.address_number(other)
            if result not in seen:
                seen.add(result)
                yield result

    def set_cmt(self, ea, text, repeatable=False):
        self.tick()
        if not isinstance(text, str) or len(text.encode("utf-8")) > 16384:
            raise ValueError("comment must be at most 16384 UTF-8 bytes")
        repeatable = _boolean_flag(repeatable, "repeatable")
        address = self.address(ea)
        self.budget.consume("readBytes")
        self.worker.read_bytes(address, 1)
        kind = self.comment_kind.REPEATABLE_COMMENT if repeatable else self.comment_kind.EOL_COMMENT
        self.program.getListing().setComment(address, kind, text or None)
        self.writes += 1
        return True

    def get_cmt(self, ea, repeatable=False):
        self.tick()
        repeatable = _boolean_flag(repeatable, "repeatable")
        kind = self.comment_kind.REPEATABLE_COMMENT if repeatable else self.comment_kind.EOL_COMMENT
        text = self.program.getListing().getComment(kind, self.address(ea))
        return str(text) if text is not None else None

    def bounds(self):
        self.tick()
        starts, ends = [], []
        space = self.program.getAddressFactory().getDefaultAddressSpace()
        for block in self.program.getMemory().getBlocks():
            self.budget.consume("enumerated")
            if block.getStart().getAddressSpace() == space:
                starts.append(self.address_number(block.getStart()))
                ends.append(self.address_number(block.getEnd()) + 1)
        if not starts:
            return self.badaddr, self.badaddr
        return min(starts), max(ends)

    def modules(self):
        byte_api = {"get_bytes": self.get_bytes, "get_byte": lambda ea: self.read_integer(ea, 1),
                    "get_word": lambda ea: self.read_integer(ea, 2), "get_dword": lambda ea: self.read_integer(ea, 4),
                    "get_qword": lambda ea: self.read_integer(ea, 8), "patch_bytes": self.patch_bytes,
                    "patch_byte": self.patch_byte, "get_cmt": self.get_cmt, "set_cmt": self.set_cmt}
        name_api = {"get_name": self.get_name, "set_name": self.set_name, "get_name_ea": self.get_name_ea,
                    "SN_CHECK": 0, "SN_NOWARN": 0x100}
        function_api = {"get_func": self.get_func, "get_func_name": self.get_func_name,
                        "get_func_qty": lambda: sum(1 for _ in self.functions()), "FUNC_LIB": 4}
        return {name: _CompatModule(name, values) for name, values in {
            "ida_bytes": byte_api, "ida_name": name_api, "ida_funcs": function_api,
            "idautils": {"Functions": self.functions, "Names": self.names, "Chunks": self.chunks,
                         "FuncItems": self.func_items,
                         "CodeRefsTo": lambda ea, flow=False: self.refs(ea, "to", "code", flow),
                         "CodeRefsFrom": lambda ea, flow=False: self.refs(ea, "from", "code", flow),
                         "DataRefsTo": lambda ea: self.refs(ea, "to", "data"),
                         "DataRefsFrom": lambda ea: self.refs(ea, "from", "data")},
            "idc": {**byte_api, **name_api, "get_func_name": self.get_func_name, "get_func_attr": self.get_func_attr,
                    "FUNCATTR_START": 0, "FUNCATTR_END": 4, "FUNCATTR_FLAGS": 8, "BADADDR": self.badaddr},
            "ida_ida": {"inf_is_64bit": lambda: self.bits == 64, "inf_is_32bit_exactly": lambda: self.bits == 32,
                        "inf_is_be": lambda: self.order == "big", "inf_get_min_ea": lambda: self.bounds()[0],
                        "inf_get_max_ea": lambda: self.bounds()[1]},
            "ida_idaapi": {"BADADDR": self.badaddr},
        }.items()}


def _native_bindings():
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SourceType
    return {"FlatProgramAPI": FlatProgramAPI, "CodeUnit": CodeUnit, "SourceType": SourceType}


def run_script(worker, params, *, bindings=None):
    """Run an approved script; propagate failures so the outer commit rolls back.

    ``bindings`` is an explicit test seam; production uses real Ghidra classes.
    Seven compatibility modules are supplied by a local import hook, without
    replacing process ``sys.modules`` entries. Standard Python and native
    Ghidra imports remain available and retain their actual APIs/provenance.
    """
    if not isinstance(params, dict):
        raise ValueError("script params must be an object")
    code = params.get("code")
    if not isinstance(code, str) or not code.strip() or len(code.encode("utf-8")) > 65536:
        raise ValueError("script code must contain 1..65536 UTF-8 bytes")
    worker.require()
    budget = _Budget(params)
    monitor = worker.monitor(params)
    api = _API(worker, budget, _native_bindings() if bindings is None else bindings, monitor)
    modules = api.modules()
    stdout, stderr = _Capture(budget), _Capture(budget)
    previous_stdout, previous_stderr, previous_trace = sys.stdout, sys.stderr, sys.gettrace()
    original_import = builtins.__import__

    def script_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in modules:
            return modules[name]
        if level == 0 and (name.startswith("ida_") or name.split(".")[0] in ("idc", "idautils", "idaapi")):
            raise UnsupportedCompatibilityError("IDAPython compatibility subset does not support module " + name)
        return original_import(name, globals, locals, fromlist, level)

    def trace(frame, event, arg):
        if frame.f_code.co_filename == "<ig5-approved-script>" and event in ("line", "call"):
            budget.consume("pythonLines")
        return trace

    namespace = {"__name__": "ig5_approved_script", "__builtins__": {**vars(builtins), "__import__": script_import},
                 "currentProgram": worker.program, "monitor": monitor, "flat_api": api.flat,
                 "toAddr": api.flat.toAddr, **modules}
    compatibility = {"mode": "explicit-common-subset", "fullIDAPythonCompatibility": False,
                     "modules": {name: module.__all__ for name, module in modules.items()},
                     "functionEnd": "maximum body address plus one; noncontiguous tails are not represented",
                     "functionFlags": "FUNC_LIB bit is an explicit Ghidra external/thunk projection, not native IDA flags or standard-library equivalence; views expose ghidra_external/ghidra_thunk",
                     "nameFlags": "SN_CHECK/SN_NOWARN accepted; Ghidra name validation remains active; other IDA flags are unsupported",
                     "unsupported": ["unsupported IDA modules and members fail explicitly", "commercial microcode APIs",
                                     "debugger APIs", "automatic IDAPython plug-in execution"]}
    provenance = {"engine": "Ghidra", "implementation": "ig5-script-api", "bindings": "Ghidra FlatProgramAPI/currentProgram",
                  "commercialEngineUsed": False, "transactionOwner": "worker.commit", "securitySandbox": False,
                  "directNativeCallsAccounted": False, "targetExecutionControlledByScript": True}
    failure = None
    try:
        compiled = compile(code, "<ig5-approved-script>", "exec")
        sys.stdout, sys.stderr = stdout, stderr
        sys.settrace(trace)
        exec(compiled, namespace)
        budget.check_time()
        if budget.exhausted is not None:
            raise ScriptBudgetError("script " + budget.exhausted + " budget exhausted")
    except BaseException as error:
        failure = error
    finally:
        sys.settrace(previous_trace)
        sys.stdout, sys.stderr = previous_stdout, previous_stderr
    result = {"ok": failure is None, "stdout": stdout.getvalue(), "stderr": stderr.getvalue(),
              "output": stdout.getvalue(), "compatibility": compatibility, "source": provenance,
              "budget": budget.report(), "compatibilityWrites": api.writes,
              "target_executed": None, "limitations": ["Approved Python execution is not a security sandbox; arbitrary script-side OS execution is not observed",
                 "Java/native calls cannot be cooperatively interrupted", "Compatibility API work is bounded; direct native APIs bypass its accounting",
                 "No automatic full IDAPython compatibility; unsupported modules/members fail", "No save/commit is performed inside this script lane"]}
    if failure is not None:
        message = (type(failure).__name__ + ": " + str(failure)[:2048]).encode("utf-8", "replace").decode("utf-8")
        result["exceptionType"] = type(failure).__name__
        result["error"] = message
        raise ScriptExecutionError(message, result) from failure
    return result
