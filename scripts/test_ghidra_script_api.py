"""Pure fixtures for approved Python/Ghidra compatibility and rollback contract.

No JVM, DLL, commercial engine or target is loaded by this test file. Native
FlatProgramAPI and real outer-transaction rollback require separate worker proof.
"""

import copy
from array import array
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters" / "ghidra"))
from script_api import run_script, ScriptExecutionError


class Address:
    def __init__(self, offset, space="ram"):
        self.offset, self.space = offset, space
    def getOffset(self): return self.offset
    def getAddressSpace(self): return self.space


class Symbol:
    def __init__(self, address, name): self.address, self.name = address, name
    def getAddress(self): return self.address
    def getName(self): return self.name
    def setName(self, name, source): self.name = name


class Symbols:
    def __init__(self): self.rows = {0x1000: Symbol(Address(0x1000), "fixture_function")}
    def getPrimarySymbol(self, address): return self.rows.get(address.offset)
    def createLabel(self, address, name, source):
        self.rows[address.offset] = Symbol(address, name)
        return self.rows[address.offset]
    def getSymbols(self, name): return [item for item in self.rows.values() if item.name == name]
    def getAllSymbols(self, forward): return list(self.rows.values())


class Function:
    def __init__(self, program, start, end, library=False): self.program, self.start, self.end, self.library = program, start, end, library
    def getEntryPoint(self): return Address(self.start)
    def getBody(self):
        spans = [(self.start, self.start + 4), (self.start + 8, self.end)] if self.start == 0x1000 else [(self.start, self.end)]
        return SimpleNamespace(start=self.start, getMaxAddress=lambda: Address(self.end - 1),
            getAddressRanges=lambda forward: [SimpleNamespace(getMinAddress=lambda a=a: Address(a),
                getMaxAddress=lambda b=b: Address(b - 1)) for a, b in spans])
    def getName(self):
        symbol = self.program.symbols.rows.get(self.start)
        return symbol.name if symbol else "function_%x" % self.start
    def isExternal(self): return self.library
    def isThunk(self): return False


class Functions:
    def __init__(self, program): self.rows = [Function(program, 0x1000, 0x1010), Function(program, 0x1020, 0x1030, True)]
    def getFunctionContaining(self, address): return next((f for f in self.rows if f.start <= address.offset < f.end), None)
    def getFunctions(self, forward): return list(self.rows)


class Listing:
    def __init__(self): self.comments = {}
    def setComment(self, address, kind, text): self.comments[address.offset, kind] = text
    def getComment(self, kind, address): return self.comments.get((address.offset, kind))
    def getCodeUnits(self, body, forward):
        if body.start != 0x1000: return [SimpleNamespace(getMinAddress=lambda: Address(body.start))]
        return [SimpleNamespace(getMinAddress=lambda: Address(0x1000)),
                SimpleNamespace(getMinAddress=lambda: Address(0x1002), isDefined=lambda: True),
                SimpleNamespace(getMinAddress=lambda: Address(0x1003), isDefined=lambda: False),
                SimpleNamespace(getMinAddress=lambda: Address(0x1008))]


class Reference:
    def __init__(self, source, target, kind, space="ram"):
        self.source, self.target, self.kind, self.space = source, target, kind, space
    def getFromAddress(self): return Address(self.source)
    def getToAddress(self): return Address(self.target, self.space)
    def getReferenceType(self):
        return SimpleNamespace(isFlow=lambda: self.kind in ("call", "fallthrough"),
            isFallthrough=lambda: self.kind == "fallthrough", isData=lambda: self.kind == "data")


class References:
    def __init__(self):
        self.rows = [Reference(0x1000, 0x1020, "call"), Reference(0x1000, 0x1001, "fallthrough"),
                     Reference(0x1000, 0x1004, "data"), Reference(0x1000, 0x1004, "data"),
                     Reference(0x1000, 0x3000, "data", "external"), Reference(0x1008, 0x1020, "call"),
                     Reference(0x1009, 0x1004, "data")]
    def getReferencesFrom(self, address): return [ref for ref in self.rows if ref.source == address.offset]
    def getReferencesTo(self, address): return [ref for ref in self.rows if ref.target == address.offset and ref.space == address.space]


class Program:
    def __init__(self, bits=64, big=False):
        self.bits, self.big = bits, big
        self.symbols, self.listing = Symbols(), Listing()
        self.functions = Functions(self)
        self.references = References()
    def getLanguage(self):
        return SimpleNamespace(getDefaultSpace=lambda: SimpleNamespace(getSize=lambda: self.bits), isBigEndian=lambda: self.big)
    def getAddressFactory(self): return SimpleNamespace(getDefaultAddressSpace=lambda: "ram")
    def getSymbolTable(self): return self.symbols
    def getFunctionManager(self): return self.functions
    def getListing(self): return self.listing
    def getReferenceManager(self): return self.references
    def getMemory(self):
        return SimpleNamespace(getBlocks=lambda: [SimpleNamespace(getStart=lambda: Address(0x1000), getEnd=lambda: Address(0x103f))])


class FlatAPI:
    def __init__(self, program, monitor): self.program, self.monitor = program, monitor
    def toAddr(self, value): return Address(int(value, 16) if isinstance(value, str) else value)


BINDINGS = {"FlatProgramAPI": FlatAPI, "SourceType": SimpleNamespace(USER_DEFINED="user"),
            "CodeUnit": SimpleNamespace(EOL_COMMENT=0, REPEATABLE_COMMENT=1)}


class WorkerFixture:
    def __init__(self, bits=64, big=False):
        self.program = Program(bits, big)
        self.memory = bytearray(range(64))
        self.mon = object()
        self.reads, self.patches = [], []
        self.transactions, self.commits, self.rollbacks = 0, 0, 0
    def require(self):
        if self.program is None: raise ValueError("no fixture program")
    def monitor(self, params): return self.mon
    def address(self, params): return Address(int(params["ea"], 16))
    def read_bytes(self, address, size):
        start = address.offset - 0x1000
        if start < 0 or start + size > len(self.memory): raise ValueError("unmapped fixture read")
        self.reads.append((address.offset, size))
        return bytes(self.memory[start:start + size])
    def patch_units(self, address, size): return [{"start": address.offset, "size": size}]
    def write_patch(self, address, payload, units):
        start = address.offset - 0x1000
        self.memory[start:start + len(payload)] = payload
        self.patches.append((address.offset, bytes(payload), copy.deepcopy(units)))
    def outer_transaction(self, code, **params):
        self.transactions += 1
        before = bytes(self.memory), copy.deepcopy(self.program.symbols.rows), copy.deepcopy(self.program.listing.comments)
        try:
            result = run_script(self, {"code": code, **params}, bindings=BINDINGS)
        except BaseException:
            self.memory[:], self.program.symbols.rows, self.program.listing.comments = before
            self.rollbacks += 1
            raise
        self.commits += 1
        return result


class ScriptAPIFixtures(unittest.TestCase):
    def setUp(self): self.worker = WorkerFixture()
    def run_code(self, code, **params): return run_script(self.worker, {"code": code, **params}, bindings=BINDINGS)

    def test_common_reads_names_functions_and_bits(self):
        code = """import ida_bytes, ida_name, ida_funcs, idautils, idc, ida_ida, ida_idaapi
print(ida_bytes.get_bytes(0x1000, 4).hex())
print(ida_name.get_name(0x1000), ida_funcs.get_func_name(0x1001))
f = ida_funcs.get_func(0x1001)
print(hex(f.start_ea), hex(f.end_ea), f.flags)
print(list(idautils.Functions()), list(idautils.Names()))
print(ida_ida.inf_is_64bit(), ida_ida.inf_is_be(), hex(ida_idaapi.BADADDR))
print(idc.get_func_attr(0x1001, idc.FUNCATTR_START))
"""
        result = self.run_code(code)
        self.assertTrue(result["ok"])
        self.assertIn("00010203", result["stdout"])
        self.assertIn("fixture_function fixture_function", result["stdout"])
        self.assertIn("0x1000 0x1010 0", result["stdout"])
        self.assertIn("[4096, 4128]", result["stdout"])
        self.assertIn("True False 0xffffffffffffffff", result["stdout"])
        self.assertEqual(result["output"], result["stdout"])
        self.assertFalse(result["compatibility"]["fullIDAPythonCompatibility"])

    def test_native_bindings_namespace_points_to_same_program_and_monitor(self):
        result = self.run_code("print(currentProgram is flat_api.program, monitor is flat_api.monitor, toAddr(0x1000).getOffset())")
        self.assertEqual(result["stdout"], "True True 4096\n")
        self.assertEqual(result["source"]["transactionOwner"], "worker.commit")
        self.assertFalse(result["source"]["securitySandbox"])
        self.assertIsNone(result["target_executed"])

    def test_from_import_and_import_star(self):
        result = self.run_code("from ida_bytes import get_word\nfrom ida_idaapi import *\nprint(get_word(0x1000), hex(BADADDR))")
        self.assertEqual(result["stdout"], "256 0xffffffffffffffff\n")

    def test_standard_python_import_remains_available(self):
        self.assertEqual(self.run_code("import json\nprint(json.dumps({'x': 3}, sort_keys=True))")["stdout"], '{"x": 3}\n')

    def test_compat_import_does_not_replace_sys_modules(self):
        sentinel = object()
        with patch.dict(sys.modules, {"ida_bytes": sentinel}):
            self.assertEqual(self.run_code("import ida_bytes\nprint(ida_bytes.get_byte(0x1001))")["stdout"], "1\n")
            self.assertIs(sys.modules["ida_bytes"], sentinel)

    def test_scripted_mutations_share_one_outer_transaction(self):
        result = self.worker.outer_transaction("import ida_name, ida_bytes, idc\nida_name.set_name(0x1000, 'script_changed', ida_name.SN_NOWARN)\nida_bytes.patch_bytes(0x1004, b'\\x41\\x42')\nidc.set_cmt(0x1000, 'script comment')\nprint(ida_name.get_name(0x1000))")
        self.assertEqual(result["stdout"], "script_changed\n")
        self.assertEqual(result["compatibilityWrites"], 3)
        self.assertEqual(self.worker.memory[4:6], b"AB")
        self.assertEqual(self.worker.program.listing.comments[0x1000, 0], "script comment")
        self.assertEqual((self.worker.transactions, self.worker.commits, self.worker.rollbacks), (1, 1, 0))
        self.assertEqual(len(self.worker.patches), 1)

    def test_script_exception_propagates_and_outer_fixture_rolls_back(self):
        before = bytes(self.worker.memory)
        with self.assertRaises(ScriptExecutionError) as caught:
            self.worker.outer_transaction("ida_name.set_name(0x1000, 'temporary')\nida_bytes.patch_byte(0x1004, 0x90)\nidc.set_cmt(0x1000, 'temporary')\nprint('before failure')\nraise RuntimeError('rollback fixture')")
        self.assertEqual(bytes(self.worker.memory), before)
        self.assertEqual(self.worker.program.symbols.rows[0x1000].name, "fixture_function")
        self.assertEqual(self.worker.program.listing.comments, {})
        self.assertEqual((self.worker.transactions, self.worker.commits, self.worker.rollbacks), (1, 0, 1))
        self.assertEqual(caught.exception.details["stdout"], "before failure\n")
        self.assertEqual(caught.exception.details["exceptionType"], "RuntimeError")

    def test_stdout_stderr_and_trace_are_restored_after_success_failure(self):
        before = sys.stdout, sys.stderr, sys.gettrace()
        self.run_code("import sys\nprint('out')\nprint('err', file=sys.stderr)")
        self.assertEqual((sys.stdout, sys.stderr, sys.gettrace()), before)
        with self.assertRaises(ScriptExecutionError): self.run_code("raise RuntimeError('fixture')")
        self.assertEqual((sys.stdout, sys.stderr, sys.gettrace()), before)

    def test_stdout_stderr_share_output_budget(self):
        before = sys.stdout, sys.stderr
        with self.assertRaises(ScriptExecutionError) as caught:
            self.run_code("import sys\nsys.stdout.write('abc')\nsys.stderr.write('def')", max_output_bytes=5)
        details = caught.exception.details
        self.assertEqual(details["stdout"], "abc")
        self.assertEqual(details["stderr"], "de")
        self.assertEqual(details["budget"]["used"]["outputBytes"], 5)
        self.assertEqual(details["budget"]["exhausted"], "outputBytes")
        self.assertEqual((sys.stdout, sys.stderr), before)

    def test_utf8_capture_never_returns_broken_codepoint(self):
        with self.assertRaises(ScriptExecutionError) as caught:
            self.run_code("print('中文')", max_output_bytes=5)
        output = caught.exception.details["stdout"]
        self.assertEqual(output, "中")
        self.assertLessEqual(len(output.encode("utf-8")), 5)

    def test_surrogate_output_and_exception_are_utf8_safe(self):
        self.assertEqual(self.run_code("print(chr(0xd800))")["stdout"], "?\n")
        with self.assertRaises(ScriptExecutionError) as caught:
            self.run_code("raise RuntimeError(chr(0xd800))")
        self.assertEqual(str(caught.exception), "RuntimeError: ?")
        caught.exception.details["error"].encode("utf-8", "strict")

    def test_unsupported_module_and_member_fail_explicitly(self):
        for code, text in (("import ida_hexrays", "module ida_hexrays"),
                           ("import ida_bytes\nida_bytes.del_items(0x1000)", "ida_bytes.del_items"),
                           ("import idaapi", "module idaapi"), ("import ida_bytes.unknown", "module ida_bytes.unknown")):
            with self.subTest(code=code), self.assertRaises(ScriptExecutionError) as caught:
                self.run_code(code)
            self.assertEqual(caught.exception.details["exceptionType"], "UnsupportedCompatibilityError")
            self.assertIn(text, str(caught.exception))

    def test_unsupported_name_flags_fail(self):
        with self.assertRaises(ScriptExecutionError) as caught:
            self.run_code("ida_name.set_name(0x1000, 'unsupported', 1)")
        self.assertIn("SN_CHECK", str(caught.exception))

    def test_get_name_ea_missing_and_ambiguous(self):
        result = self.run_code("print(ida_name.get_name_ea(ida_idaapi.BADADDR, 'fixture_function'))\nprint(ida_name.get_name_ea(ida_idaapi.BADADDR, 'missing') == ida_idaapi.BADADDR)")
        self.assertEqual(result["stdout"], "4096\nTrue\n")
        self.worker.program.symbols.rows[0x1004] = Symbol(Address(0x1004), "same")
        self.worker.program.symbols.rows[0x1008] = Symbol(Address(0x1008), "same")
        with self.assertRaises(ScriptExecutionError) as caught:
            self.run_code("ida_name.get_name_ea(ida_idaapi.BADADDR, 'same')")
        self.assertIn("ambiguous", str(caught.exception))

    def test_function_filters_missing_and_library_flag(self):
        result = self.run_code("print(list(idautils.Functions(0x1010, 0x1030)))\nprint(ida_funcs.get_func(0x1001).flags, ida_funcs.get_func(0x1021).flags)\nprint(ida_funcs.get_func(0x103f), ida_funcs.get_func_name(0x103f))")
        self.assertIn("[4128]\n0 4\nNone", result["stdout"])
        self.assertIn("external/thunk projection", result["compatibility"]["functionFlags"])

    def test_noncontiguous_chunks_and_defined_function_items(self):
        result = self.run_code("print(list(idautils.Chunks(0x1001)))\nprint(list(idautils.FuncItems(0x1001)))\nprint(list(idautils.Chunks(0x103f)), list(idautils.FuncItems(0x103f)))")
        self.assertEqual(result["stdout"], "[(4096, 4100), (4104, 4112)]\n[4096, 4098, 4104]\n[] []\n")

    def test_code_refs_respect_flow_flag_and_data_refs_deduplicate(self):
        result = self.run_code("print(list(idautils.CodeRefsFrom(0x1000, 0)))\nprint(list(idautils.CodeRefsFrom(0x1000, 1)))\nprint(list(idautils.CodeRefsTo(0x1020)))\nprint(list(idautils.DataRefsFrom(0x1000)))\nprint(list(idautils.DataRefsTo(0x1004)))")
        self.assertEqual(result["stdout"], "[4128]\n[4128, 4097]\n[4096, 4104]\n[4100]\n[4096, 4105]\n")

    def test_chunks_items_and_references_share_enumeration_budget(self):
        for code in ("list(idautils.Chunks(0x1000))", "list(idautils.FuncItems(0x1000))",
                     "list(idautils.DataRefsFrom(0x1000))"):
            with self.subTest(code=code), self.assertRaises(ScriptExecutionError) as caught:
                self.run_code(code, max_enumerated=1)
            self.assertEqual(caught.exception.details["budget"]["exhausted"], "enumerated")

    def test_reference_flow_flags_require_bool_or_integer(self):
        with self.assertRaises(ScriptExecutionError): self.run_code("list(idautils.CodeRefsFrom(0x1000, 0.0))")

    def test_comments_get_clear_and_repeatable(self):
        result = self.run_code("idc.set_cmt(0x1000, 'eol')\nidc.set_cmt(0x1000, 'repeat', True)\nprint(idc.get_cmt(0x1000), idc.get_cmt(0x1000, 1))\nidc.set_cmt(0x1000, '')\nprint(idc.get_cmt(0x1000))")
        self.assertEqual(result["stdout"], "eol repeat\nNone\n")

    def test_integer_reads_follow_program_byteorder_and_bitness(self):
        self.worker = WorkerFixture(bits=32, big=True)
        result = self.run_code("print(ida_bytes.get_word(0x1000), ida_ida.inf_is_32bit_exactly(), ida_ida.inf_is_be(), hex(ida_idaapi.BADADDR))")
        self.assertEqual(result["stdout"], "1 True True 0xffffffff\n")

    def test_image_bounds_and_names_ignore_nondefault_space(self):
        self.worker.program.symbols.rows[0x3000] = Symbol(Address(0x3000, "external"), "external_name")
        result = self.run_code("print(hex(ida_ida.inf_get_min_ea()), hex(ida_ida.inf_get_max_ea()))\nprint(list(idautils.Names()))")
        self.assertIn("0x1000 0x1040", result["stdout"])
        self.assertNotIn("external_name", result["stdout"])

    def test_read_and_api_call_budgets_stop_before_extra_work(self):
        for params, code, budget in (({"max_read_bytes": 1}, "ida_bytes.get_dword(0x1000)", "readBytes"),
                                     ({"max_api_calls": 1}, "ida_name.get_name(0x1000)\nida_name.get_name(0x1000)", "apiCalls")):
            with self.subTest(params=params), self.assertRaises(ScriptExecutionError) as caught:
                self.run_code(code, **params)
            self.assertEqual(caught.exception.details["budget"]["exhausted"], budget)
        self.assertEqual(self.worker.reads, [])

    def test_write_budget_and_loaded_range_guard(self):
        before = bytes(self.worker.memory)
        with self.assertRaises(ScriptExecutionError) as caught:
            self.run_code("ida_bytes.patch_bytes(0x1000, b'AB')", max_write_bytes=1)
        self.assertEqual(caught.exception.details["budget"]["exhausted"], "writeBytes")
        with self.assertRaises(ScriptExecutionError): self.run_code("ida_bytes.patch_byte(0x2000, 1)")
        self.assertEqual(bytes(self.worker.memory), before)

    def test_oversized_typed_views_rejected_by_byte_count_before_copy_or_write(self):
        for expression in ("memoryview(array('I', range(1025)))", "memoryview(array('I', range(2050)))[::2]"):
            with self.subTest(expression=expression):
                before = bytes(self.worker.memory)
                with self.assertRaises(ScriptExecutionError) as caught:
                    self.run_code("from array import array\nview = " + expression + "\nassert len(view) < 4096 and view.nbytes > 4096\nida_bytes.patch_bytes(0x1000, view)")
                self.assertIn("1..4096 bytes", str(caught.exception))
                self.assertEqual(bytes(self.worker.memory), before)
                self.assertEqual(self.worker.patches, [])
                self.assertEqual(self.worker.reads, [])
                self.assertEqual(caught.exception.details["compatibilityWrites"], 0)
                self.assertEqual(caught.exception.details["budget"]["used"]["writeBytes"], 0)

    def test_exact_4096_byte_typed_view_is_accepted_and_accounted(self):
        self.worker.memory = bytearray(8192)
        expected = bytes(memoryview(array('I', [0x11223344] * 1024)))
        self.assertEqual(len(expected), 4096)
        result = self.run_code("from array import array\nview = memoryview(array('I', [0x11223344] * 1024))\nida_bytes.patch_bytes(0x1000, view)")
        self.assertEqual(self.worker.memory[:4096], expected)
        self.assertEqual(result["compatibilityWrites"], 1)
        self.assertEqual(result["budget"]["used"]["writeBytes"], 4096)
        self.assertEqual(result["budget"]["used"]["readBytes"], 8192)

    def test_bounded_strided_typed_and_multidimensional_views_preserve_raw_bytes(self):
        cases = (("memoryview(array('I', [1, 2, 3, 4]))[::2]", bytes(memoryview(array('I', [1, 2, 3, 4]))[::2])),
                 ("memoryview(b'ABCDEFGH')[::2]", b'ACEG'),
                 ("memoryview(bytearray(range(16))).cast('B', shape=[4, 4])", bytes(range(16))))
        for expression, expected in cases:
            with self.subTest(expression=expression):
                self.worker = WorkerFixture()
                result = self.run_code("from array import array\nview = " + expression + "\nida_bytes.patch_bytes(0x1004, view)")
                self.assertEqual(self.worker.memory[4:4 + len(expected)], expected)
                self.assertEqual(result["compatibilityWrites"], 1)
                self.assertEqual(result["budget"]["used"]["writeBytes"], len(expected))

    def test_byte_payload_limits_reject_empty_and_oversized_without_memory_work(self):
        for expression in ("b''", "b'A' * 4097", "bytearray(4097)", "memoryview(b'')"):
            with self.subTest(expression=expression), self.assertRaises(ScriptExecutionError) as caught:
                self.run_code("ida_bytes.patch_bytes(0x1000, " + expression + ")")
            self.assertEqual(caught.exception.details["compatibilityWrites"], 0)
            self.assertEqual(caught.exception.details["budget"]["used"]["writeBytes"], 0)
        self.assertEqual(self.worker.reads, [])
        self.assertEqual(self.worker.patches, [])

    def test_enumeration_budget_fails_instead_of_silent_truncation(self):
        with self.assertRaises(ScriptExecutionError) as caught:
            self.run_code("print(list(idautils.Functions()))", max_enumerated=1)
        self.assertEqual(caught.exception.details["budget"]["exhausted"], "enumerated")

    def test_caught_budget_failure_still_rejects_outer_transaction(self):
        with self.assertRaises(ScriptExecutionError) as caught:
            self.worker.outer_transaction("ida_name.set_name(0x1000, 'temporary')\ntry:\n    ida_bytes.get_bytes(0x1000, 2)\nexcept Exception:\n    pass", max_read_bytes=1)
        self.assertEqual(caught.exception.details["budget"]["exhausted"], "readBytes")
        self.assertEqual(self.worker.program.symbols.rows[0x1000].name, "fixture_function")
        self.assertEqual(self.worker.rollbacks, 1)

    def test_python_line_budget_stops_simple_infinite_loop_and_restores_trace(self):
        previous = sys.gettrace()
        with self.assertRaises(ScriptExecutionError) as caught:
            self.run_code("while True:\n    pass", max_python_lines=20)
        self.assertEqual(caught.exception.details["budget"]["exhausted"], "pythonLines")
        self.assertEqual(sys.gettrace(), previous)

    def test_syntax_errors_and_systemexit_are_transaction_failures(self):
        for code, kind in (("if", "SyntaxError"), ("raise SystemExit(2)", "SystemExit")):
            with self.subTest(code=code), self.assertRaises(ScriptExecutionError) as caught:
                self.run_code(code)
            self.assertEqual(caught.exception.details["exceptionType"], kind)

    def test_code_and_budget_validation(self):
        for code in (None, "", "   ", "a" * 65537, "中" * 30000):
            with self.subTest(code_type=type(code).__name__), self.assertRaises(ValueError): self.run_code(code)
        for params in ({"max_output_bytes": 0}, {"max_api_calls": True}, {"timeout": 121}, {"max_python_lines": -1}):
            with self.subTest(params=params), self.assertRaises(ValueError): self.run_code("pass", **params)

    def test_address_payload_and_comment_validation(self):
        for code in ("ida_bytes.get_byte(True)", "ida_bytes.get_byte(-1)", "ida_bytes.get_byte(1 << 64)",
                     "ida_bytes.patch_bytes(0x1000, 'text')", "ida_bytes.patch_bytes(0x1000, b'A' * 4097)",
                     "idc.set_cmt(0x1000, 'x', 2)", "ida_name.set_name(0x1000, '')"):
            with self.subTest(code=code), self.assertRaises(ScriptExecutionError): self.run_code(code)

    def test_missing_program_rejected_without_capture(self):
        self.worker.program = None
        previous = sys.stdout, sys.stderr
        with self.assertRaises(ValueError): self.run_code("pass")
        self.assertEqual((sys.stdout, sys.stderr), previous)


if __name__ == "__main__":
    unittest.main(verbosity=2)
