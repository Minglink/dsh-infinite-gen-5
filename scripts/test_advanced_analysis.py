"""Contract and parser regression tests; all engine modules are synthetic."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


source = Path(__file__).resolve().parents[1] / "worker" / "advanced_analysis.py"
spec = importlib.util.spec_from_file_location("ig5_advanced_test", source)
advanced = importlib.util.module_from_spec(spec)
spec.loader.exec_module(advanced)
BADADDR = (1 << 64) - 1


def module(name, **values):
    result = types.ModuleType(name)
    result.__dict__.update(values)
    return result


class SI:
    def __init__(self):
        self.flags = 0
        self.ncases = 2
        self.jumps = 0x104000
        self.values = BADADDR
        self.defjump = BADADDR
        self.startea = 0x200000
        self.elbase = 0
        self.lowcase = 0
        self.width = 8
        self.shift = 0

    def get_jtable_element_size(self):
        return self.width

    def set_jtable_element_size(self, width):
        self.width = width

    def get_jtable_size(self):
        return self.ncases

    def get_shift(self):
        return self.shift

    def set_shift(self, shift):
        self.shift = shift

    def get_lowcase(self):
        return self.lowcase

    def has_default(self):
        return self.defjump != BADADDR

    def has_elbase(self):
        return bool(self.flags & 2)

    def set_elbase(self, base):
        self.elbase = base
        self.flags |= 2

    def is_sparse(self):
        return False

    def is_indirect(self):
        return False

    def is_custom(self):
        return bool(self.flags & 128)


class Operand:
    def __init__(self, kind=0, text="", number=0, size=4):
        self.t, self.text, self.number, self.size = kind, text, number, size
        self.effects = False

    def empty(self):
        return self.t == 0

    def dstr(self):
        return self.text

    def equal_mops(self, other, flags):
        return self.t == other.t and self.text == other.text and self.size == other.size

    def has_side_effects(self, include_memory):
        return self.effects

    def make_number(self, value, width):
        self.t, self.text, self.number, self.size = 2, f"#{value}", value, width

    def assign(self, other):
        self.t, self.text, self.number, self.size = other.t, other.text, other.number, other.size

    def erase(self):
        self.t, self.text, self.size = 0, "", -1


class Instruction:
    def __init__(self, opcode, text, left=None, right=None, ea=0x200000):
        self.opcode, self.text, self.ea = opcode, text, ea
        self.l, self.r, self.d = left or Operand(), right or Operand(), Operand()
        self.next = None
        self.effects = self.floating = self.barrier = self.persistent = False

    def dstr(self):
        if self.opcode == 12:
            return f"mov {self.l.dstr()}, {self.d.dstr()}"
        return self.text

    def is_fpinsn(self):
        return self.floating

    def is_mbarrier(self):
        return self.barrier

    def is_persistent(self):
        return self.persistent

    def has_side_effects(self, include_memory):
        return self.effects


class Block:
    def __init__(self, serial, instructions, preds=(), succs=()):
        self.serial, self.start, self.end, self.type = serial, 0x200000, 0x200020, 2
        self.predecessors, self.successors = preds, succs
        for before, after in zip(instructions, instructions[1:]):
            before.next = after
        self.head = instructions[0] if instructions else None
        self.dirty_calls = 0

    def mark_lists_dirty(self):
        self.dirty_calls += 1

    def npred(self):
        return len(self.predecessors)

    def nsucc(self):
        return len(self.successors)

    def pred(self, index):
        return self.predecessors[index]

    def succ(self, index):
        return self.successors[index]


class MBA:
    def __init__(self, blocks):
        self.blocks, self.qty, self.maturity = blocks, len(blocks), 7
        self.graph_calls, self.optimization_calls = 0, 0
        self.verify_calls = 0
        self.hx = None
        self.raise_optimization = False
        for block in blocks:
            block.mba = self

    def get_mblock(self, index):
        return self.blocks[index]

    def build_graph(self):
        self.graph_calls += 1
        return 0

    def optimize_local(self, flags):
        self.optimization_calls += 1
        if self.raise_optimization:
            raise RuntimeError("fake native optimization failure")
        if self.hx is not None and self.hx.active_filter is not None:
            for block in self.blocks:
                instruction = block.head
                while instruction is not None:
                    self.hx.active_filter.func(block, instruction, flags)
                    instruction = instruction.next
        self.blocks[0].head.text = "mov #0, r0"
        return 1

    def verify(self, always):
        self.verify_calls += 1


class AdvancedAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.bits = 64
        self.memory = bytearray(0x10000)
        self.symbols = {}
        self.named_items = []
        self.code_flags = {}
        self.writes = []
        self.reads = []
        self.frame_present = True
        self.frame_members = [self.member("local", 0, 32), self.member("ret", 192, 64, ret=True),
                              self.member("arg", 256, 64)]
        self.data_segment = types.SimpleNamespace(start_ea=0x100000, end_ea=0x110000, perm=4)
        self.code_segment = types.SimpleNamespace(start_ea=0x200000, end_ea=0x201000, perm=5)
        self.function = types.SimpleNamespace(start_ea=0x200000, end_ea=0x200100)
        self.switch_info = {0x200010: SI()}
        self.switch_targets = [0x200030, 0x200040]
        self.case_failure = False
        self.init_available = True
        self.generation_failure = False
        self.requests = []
        self.mba = MBA([Block(0, [Instruction(10, "jz r0, r0", Operand(1, "r0"), Operand(1, "r0"))], succs=(1,)),
                        Block(1, [Instruction(11, "mov #1, r0")], preds=(0,))])

        def frame_type():
            return types.SimpleNamespace(get_udt_details=lambda udt: (udt.extend(self.frame_members) or True),
                                         get_size=lambda: 48)

        def frame_part(span, pfn, part):
            span.start_ea, span.end_ea = ((0, 16), (16, 24), (24, 32), (32, 48))[part]

        def getseg(ea):
            for segment in (self.data_segment, self.code_segment):
                if segment.start_ea <= ea < segment.end_ea:
                    return segment
            return None

        def getbytes(ea, size):
            self.reads.append((ea, size))
            if 0x100000 <= ea and ea + size <= 0x110000:
                return bytes(self.memory[ea - 0x100000:ea - 0x100000 + size])
            if 0x200000 <= ea and ea + size <= 0x201000:
                return b"\x90" * size
            return None

        def calculate(ea, si):
            if self.case_failure:
                return None
            return types.SimpleNamespace(cases=[[i + int(si.lowcase)] for i in range(len(self.switch_targets))],
                                         targets=list(self.switch_targets))

        def generate(ranges, failure, retlist, flags, maturity):
            self.requests.append((ranges, retlist, flags, maturity))
            self.mba.maturity = maturity
            return None if self.generation_failure else self.mba

        self.hx = module("ida_hexrays", init_hexrays_plugin=lambda: self.init_available,
                         hexrays_failure_t=lambda: types.SimpleNamespace(code=-8, errea=0x200000),
                         mba_ranges_t=lambda pfn: pfn, gen_microcode=generate, MERR_OK=0,
                         mop_n=2, mop_r=1, mop_S=3, m_jz=10, m_mov=12, m_sub=13, m_xor=14,
                         mop_t=Operand, active_filter=None, remove_filter_ok=True,
                         is_mcode_jcond=lambda op: op == 10)
        self.mba.hx = self.hx
        hx = self.hx

        class FakeOptinsn:
            def install(self):
                hx.active_filter = self

            def remove(self):
                if not hx.remove_filter_ok:
                    return False
                hx.active_filter = None
                return True

        self.hx.optinsn_t = FakeOptinsn
        advanced._retained_optimizer_filters.clear()
        self.addCleanup(advanced._retained_optimizer_filters.clear)
        for value, name in enumerate(("GENERATED", "PREOPTIMIZED", "LOCOPT", "CALLS", "GLBOPT1", "GLBOPT2", "GLBOPT3", "LVARS"), 1):
            setattr(self.hx, "MMAT_" + name, value)
        self.modules = {
            "ida_idaapi": module("ida_idaapi", BADADDR=BADADDR),
            "ida_idp": module("ida_idp", is_indirect_jump_insn=lambda insn: True),
            "ida_ida": module("ida_ida", inf_is_64bit=lambda: self.bits == 64, inf_is_be=lambda: False),
            "ida_name": module("ida_name", get_name=lambda ea: self.symbols.get(ea, ""), MNG_LONG_FORM=0,
                               demangle_name=lambda name, flags: None,
                               get_name_ea=lambda bad, name: next((ea for ea, value in self.symbols.items() if value == name), BADADDR)),
            "ida_funcs": module("ida_funcs", get_func=lambda ea: self.function if 0x200000 <= ea < 0x200100 else None,
                                get_func_name=lambda ea: "test_func" if 0x200000 <= ea < 0x201000 else ""),
            "ida_range": module("ida_range", range_t=lambda: types.SimpleNamespace(start_ea=0, end_ea=0)),
            "ida_frame": module("ida_frame", FPC_LVARS=0, FPC_SAVREGS=1, FPC_RETADDR=2, FPC_ARGS=3,
                                get_frame_part=frame_part, get_func_frame=lambda tif, pfn: self.frame_present,
                                get_frame_size=lambda pfn: 48, get_frame_retsize=lambda pfn: 8,
                                soff_to_fpoff=lambda pfn, offset: offset - 16),
            "ida_typeinf": module("ida_typeinf", tinfo_t=frame_type, udt_type_data_t=list),
            "ida_nalt": module("ida_nalt", get_switch_info=lambda ea: self.switch_info.get(ea), switch_info_t=SI,
                               set_switch_info=lambda ea, si: self.writes.append(("metadata", ea)),
                               SWI_USER=1, SWI_ELBASE=2, SWI_SIGNED=4, SWI_SUBTRACT=8),
            "ida_xref": module("ida_xref", calc_switch_cases=calculate,
                               create_switch_table=lambda ea, si: (self.writes.append(("table", ea)) or True),
                               create_switch_xrefs=lambda ea, si: (self.writes.append(("xrefs", ea)) or True)),
            "ida_ua": module("ida_ua", create_insn=lambda ea: (self.writes.append(("insn", ea)) or 1),
                             insn_t=lambda: types.SimpleNamespace(), decode_insn=lambda insn, ea: 2),
            "ida_bytes": module("ida_bytes", get_bytes=getbytes,
                                get_full_flags=lambda ea: self.code_flags.get(ea, 1 if ea == 0x200010 else 0),
                                is_code=lambda flags: flags == 1, is_unknown=lambda flags: flags == 0),
            "ida_segment": module("ida_segment", SEGPERM_EXEC=1, getseg=getseg,
                                  get_first_seg=lambda: self.data_segment,
                                  get_next_seg=lambda ea: self.code_segment if ea == 0x100000 else None),
            "idautils": module("idautils", FuncItems=lambda start: [0x200000, 0x200010, 0x200020],
                               Names=lambda: iter(self.named_items)),
            "ida_hexrays": self.hx,
        }
        self.patcher = patch.dict(sys.modules, self.modules)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    @staticmethod
    def member(name, offset, size, ret=False, saved=False):
        return types.SimpleNamespace(name=name, offset=offset, size=size, type="int",
                                     is_retaddr=lambda: ret, is_savregs=lambda: saved, is_gap=lambda: False)

    def put(self, ea, value, width=4, signed=False):
        self.memory[ea - 0x100000:ea - 0x100000 + width] = int(value).to_bytes(width, "little", signed=signed)

    def string(self, ea, value):
        data = value.encode("ascii") + b"\0"
        self.memory[ea - 0x100000:ea - 0x100000 + len(data)] = data

    def msvc_fixture(self, bits=64):
        self.bits = bits
        ptr = bits // 8
        col, td, chd, array, bcd = 0x101000, 0x102000, 0x103000, 0x104000, 0x105000
        table = 0x106000 + ptr
        resolve = (lambda address: address - 0x100000) if bits == 64 else (lambda address: address)
        self.put(table - ptr, col, ptr)
        self.put(col, 1 if bits == 64 else 0)
        self.put(col + 12, resolve(td))
        self.put(col + 16, resolve(chd))
        if bits == 64:
            self.put(col + 20, resolve(col))
        self.string(td + ptr * 2, ".?AVDerived@@")
        self.put(chd + 8, 2)
        self.put(chd + 12, resolve(array))
        self.put(array, resolve(bcd))
        self.put(array + 4, resolve(bcd + 32))
        self.put(bcd, resolve(td))
        self.put(bcd + 4, 1)
        self.put(bcd + 12, -1, signed=True)
        self.put(bcd + 32, resolve(td + 128))
        self.string(td + 128 + ptr * 2, ".?AVBase@@")
        self.put(bcd + 32 + 12, -1, signed=True)
        self.put(table, 0x200030, ptr)
        self.put(table + ptr, 0x200040, ptr)
        return table

    def itanium_fixture(self, variant="si"):
        table, info, base, runtime, names = 0x106000, 0x102000, 0x102100, 0x107000, 0x108000
        self.symbols[table] = "_ZTV7Derived"
        self.put(table, 0, 8)
        self.put(table + 8, info, 8)
        self.put(table + 16, 0x200030, 8)
        self.put(table + 24, 0x200040, 8)
        self.put(info, runtime + 16, 8)
        self.put(info + 8, names, 8)
        self.string(names, "7Derived")
        self.symbols[runtime] = "_ZTVN10__cxxabiv1" + ("20__si_class_type_infoE" if variant == "si" else "21__vmi_class_type_infoE")
        self.put(base, runtime + 0x100 + 16, 8)
        self.put(base + 8, names + 32, 8)
        self.string(names + 32, "4Base")
        self.symbols[runtime + 0x100] = "_ZTVN10__cxxabiv117__class_type_infoE"
        if variant == "si":
            self.put(info + 16, base, 8)
        else:
            self.put(info + 16, 0)
            self.put(info + 20, 1)
            self.put(info + 24, base, 8)
            self.put(info + 32, (16 << 8) | 2, 8)
        return table, info

    def test_frame_does_not_require_decompiler_and_classifies_offsets(self):
        with patch.dict(sys.modules, {"ida_hexrays": None}):
            result = advanced.m_stack({"ea": "200000"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["total_members"], 3)
        self.assertEqual([member["kind"] for member in result["members"]], ["locals", "retaddr", "args"])
        self.assertEqual(result["members"][0]["fp_offset"], -16)
        self.assertEqual(result["parts"]["savedregs"]["size"], 8)

    def test_no_frame_is_reported_without_synthesis(self):
        self.frame_present = False
        result = advanced.m_stack({"ea": "200000"})
        self.assertFalse(result["has_frame"])
        self.assertEqual(result["members"], [])

    def test_frame_truncation_and_invalid_function(self):
        self.assertTrue(advanced.m_stack({"ea": "200000", "limit": 1})["truncated"])
        with self.assertRaises(ValueError):
            advanced.m_stack({"ea": "999"})

    def test_switch_function_enumeration_and_exact_address(self):
        result = advanced.m_switches({"ea": "200000"})
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["switches"][0]["cases"][1], {"values": [1], "target": "0x200040"})
        self.assertEqual(advanced.m_switches({"ea": "200000", "exact": True})["total"], 0)

    def test_switch_unavailable_cases_are_explicit(self):
        self.case_failure = True
        result = advanced.m_switches({"ea": "200010"})
        self.assertIn("error", result["switches"][0])
        self.assertEqual(result["switches"][0]["cases"], [])

    def test_switch_repair_preview_is_read_only(self):
        result = advanced.m_switch_repair({"ea": "200010", "action": "define", "table": "104000",
                                           "ncases": 2, "element_size": 8})
        self.assertFalse(result["applied"])
        self.assertEqual(result["targets"], ["0x200030", "0x200040"])
        self.assertEqual(self.writes, [])

    def test_switch_repair_apply_and_instruction_creation(self):
        result = advanced.m_switch_repair({"ea": "200010", "apply": True, "create_instructions": True})
        self.assertTrue(result["ok"])
        self.assertEqual(self.writes, [("table", 0x200010), ("xrefs", 0x200010),
                                      ("insn", 0x200030), ("insn", 0x200040)])

    def test_switch_repair_rejects_bad_layout_before_any_write(self):
        cases = [{"element_size": 3}, {"ncases": 0}, {"relative": True}, {"shift": 4}]
        for values in cases:
            with self.subTest(values=values):
                params = {"ea": "200010", "action": "define", "apply": True, "table": "104000",
                          "ncases": 2, "element_size": 8, **values}
                with self.assertRaises(ValueError):
                    advanced.m_switch_repair(params)
                self.assertEqual(self.writes, [])

    def test_switch_repair_rejects_data_targets_and_nonexec_targets(self):
        self.code_flags[0x200030] = 2
        with self.assertRaises(ValueError):
            advanced.m_switch_repair({"ea": "200010", "apply": True, "create_instructions": True})
        self.switch_targets = [0x104000]
        with self.assertRaises(ValueError):
            advanced.m_switch_repair({"ea": "200010", "apply": True})
        self.assertEqual(self.writes, [])

    def test_switch_repair_rejects_non_jump_instruction(self):
        self.modules["ida_idp"].is_indirect_jump_insn = lambda insn: False
        with self.assertRaises(ValueError):
            advanced.m_switch_repair({"ea": "200010", "apply": True})
        self.assertEqual(self.writes, [])

    def test_microcode_topology_and_structural_candidates(self):
        result = advanced.m_microcode({"ea": "200000"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["edges"], [{"from": 0, "to": 1}])
        self.assertEqual(result["opaque_predicate_candidates"][0]["kind"], "self-comparison")
        self.assertEqual(result["maturity"], "glbopt3")
        self.assertEqual(self.requests[0][1:], (None, 0, 7))

    def test_microcode_generation_failure_is_structured(self):
        self.generation_failure = True
        result = advanced.m_microcode({"ea": "200000"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["failure_code"], -8)
        self.init_available = False
        self.assertFalse(advanced.m_microcode({"ea": "200000"})["ok"])

    def test_microcode_builds_early_graph_only_once(self):
        advanced.m_microcode({"ea": "200000", "maturity": "generated"})
        self.assertEqual(self.mba.graph_calls, 1)

    def test_microcode_limits_and_pointer_cycles_are_bounded(self):
        result = advanced.m_microcode({"ea": "200000", "max_instructions": 1})
        self.assertEqual(result["returned_instructions"], 1)
        self.assertTrue(result["truncated"])
        self.mba.blocks[0].head.next = self.mba.blocks[0].head
        result = advanced.m_microcode({"ea": "200000"})
        self.assertIn("traversal_error", result["blocks"][0])

    def test_microcode_temporary_optimization_has_before_after_evidence(self):
        result = advanced.m_microcode({"ea": "200000", "maturity": "generated", "action": "optimize"})
        self.assertEqual(result["optimization"]["changes"], 1)
        self.assertNotEqual(result["optimization"]["before"], result["optimization"]["after"])
        self.assertFalse(result["optimization"]["idb_modified"])
        self.assertEqual(self.mba.graph_calls, 0)
        with self.assertRaises(ValueError):
            advanced.m_microcode({"ea": "200000", "action": "optimize"})

    def rule_instruction(self, opcode):
        instruction = Instruction(opcode, "self operation r0, r0", Operand(1, "r0"), Operand(1, "r0"))
        instruction.d = Operand(1, "r1")
        self.mba = MBA([Block(0, [instruction])])
        self.mba.hx = self.hx
        return instruction

    def test_optinsn_rules_rewrite_plain_same_width_integer_operands(self):
        for opcode, rule in ((self.hx.m_xor, "xor-self"), (self.hx.m_sub, "sub-self")):
            with self.subTest(rule=rule):
                instruction = self.rule_instruction(opcode)
                result = advanced.m_microcode({"ea": "200000", "action": "optimize", "maturity": "generated", "rules": [rule]})
                optimization = result["optimization"]
                self.assertTrue(optimization["filter_installed"])
                self.assertTrue(optimization["filter_removed"])
                self.assertGreater(optimization["callback_invocations"], 0)
                self.assertIsNone(self.hx.active_filter)
                self.assertEqual(optimization["rule_hits"][0]["rule"], rule)
                self.assertEqual(instruction.opcode, self.hx.m_mov)
                self.assertEqual(instruction.l.number, 0)
                self.assertTrue(instruction.r.empty())
                self.assertEqual(instruction.d.text, "r1")
                self.assertEqual(self.mba.blocks[0].dirty_calls, 1)
                self.assertEqual(self.mba.verify_calls, 1)
                self.assertNotEqual(optimization["before"], optimization["after"])
                self.assertFalse(optimization["idb_modified"])

    def test_optinsn_rule_refuses_memory_side_effects_and_width_mismatch(self):
        for alteration in ("memory", "call", "width", "destination", "floating", "barrier", "persistent", "unequal"):
            with self.subTest(alteration=alteration):
                instruction = self.rule_instruction(self.hx.m_xor)
                if alteration == "memory":
                    instruction.l.t = instruction.r.t = 4
                elif alteration == "call":
                    instruction.l.effects = True
                elif alteration == "width":
                    instruction.r.size = 8
                elif alteration == "destination":
                    instruction.d.t = 4
                elif alteration == "unequal":
                    instruction.r.text = "r2"
                else:
                    setattr(instruction, alteration, True)
                result = advanced.m_microcode({"ea": "200000", "action": "optimize", "maturity": "generated", "rules": ["xor-self"]})
                self.assertEqual(result["optimization"]["rule_hits"], [])
                self.assertEqual(instruction.opcode, self.hx.m_xor)
                self.assertEqual(self.mba.blocks[0].dirty_calls, 0)

    def test_optinsn_filter_is_removed_when_native_optimization_raises(self):
        self.rule_instruction(self.hx.m_sub)
        self.mba.raise_optimization = True
        result = advanced.m_microcode({"ea": "200000", "action": "optimize", "maturity": "generated", "rules": ["sub-self"]})
        self.assertFalse(result["ok"])
        self.assertTrue(result["optimization"]["filter_removed"])
        self.assertIsNone(self.hx.active_filter)

    def test_optinsn_callback_failure_is_captured_and_filter_removed(self):
        instruction = self.rule_instruction(self.hx.m_sub)

        def reject_dirty_mark():
            raise RuntimeError("fake block failure")

        self.mba.blocks[0].mark_lists_dirty = reject_dirty_mark
        result = advanced.m_microcode({"ea": "200000", "action": "optimize", "maturity": "generated", "rules": ["sub-self"]})
        self.assertFalse(result["ok"])
        self.assertEqual(result["optimization"]["callback_errors"], ["RuntimeError"])
        self.assertTrue(result["optimization"]["filter_removed"])
        self.assertEqual(instruction.opcode, self.hx.m_sub)

    def test_optinsn_rule_supports_equal_integer_constants(self):
        instruction = self.rule_instruction(self.hx.m_xor)
        instruction.l = Operand(2, "#7", 7)
        instruction.r = Operand(2, "#7", 7)
        result = advanced.m_microcode({"ea": "200000", "action": "optimize", "maturity": "generated", "rules": ["xor-self", "xor-self"]})
        self.assertEqual(result["optimization"]["custom_rules"], ["xor-self"])
        self.assertEqual(len(result["optimization"]["rule_hits"]), 1)
        self.assertEqual(instruction.l.number, 0)

    def test_optinsn_remove_failure_retains_callback_and_blocks_more_work(self):
        self.rule_instruction(self.hx.m_sub)
        self.hx.remove_filter_ok = False
        result = advanced.m_microcode({"ea": "200000", "action": "optimize", "maturity": "generated", "rules": ["sub-self"]})
        self.assertFalse(result["ok"])
        self.assertFalse(result["optimization"]["filter_removed"])
        self.assertEqual(len(advanced._retained_optimizer_filters), 1)
        self.assertFalse(advanced.m_microcode({"ea": "200000"})["ok"])

    def test_optinsn_rules_validate_before_native_calls(self):
        for rules in ("xor-self", ["unknown"], [True]):
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                advanced.m_microcode({"ea": "200000", "action": "optimize", "maturity": "generated", "rules": rules})
        self.assertEqual(self.requests, [])

    def test_optinsn_filter_rejects_foreign_mba_or_missing_block(self):
        instruction = self.rule_instruction(self.hx.m_xor)
        optimizer = advanced._make_rule_filter(self.hx, self.mba, ["xor-self"], 8)
        foreign = Block(0, [instruction])
        foreign.mba = MBA([])
        self.assertEqual(optimizer.func(None, instruction, 0), 0)
        self.assertEqual(optimizer.func(foreign, instruction, 0), 0)
        self.assertEqual(instruction.opcode, self.hx.m_xor)

    def test_msvc_64_and_32_recover_class_hierarchy_and_slots(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                self.memory[:] = b"\0" * len(self.memory)
                table = self.msvc_fixture(bits)
                result = advanced.m_vtables({"ea": hex(table), "abi": "msvc", "offset": bits // 8})
                self.assertTrue(result["ok"])
                row = result["tables"][0]
                self.assertEqual(row["pointer_size"], bits // 8)
                self.assertEqual(row["rtti"]["type"]["raw_name"], ".?AVDerived@@")
                self.assertEqual(row["rtti"]["bases"][1]["type"]["raw_name"], ".?AVBase@@")
                self.assertEqual(row["rtti"]["inheritance_edges"][0]["base_index"], 1)
                self.assertEqual(row["selected_slot"]["target"], "0x200040")
                self.assertIn("void (*slot_001)(void)", row["struct_decl"])

    def test_msvc_invalid_locator_and_incomplete_base_are_not_invented(self):
        table = self.msvc_fixture()
        self.put(0x104004, 0x700000)
        result = advanced.m_vtables({"ea": hex(table), "abi": "msvc"})
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["tables"][0]["rtti"]["bases"]), 1)
        self.assertEqual(len(result["tables"][0]["rtti"]["parse_errors"]), 1)
        self.put(0x101000, 99)
        result = advanced.m_vtables({"ea": hex(table), "abi": "msvc"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["tables"], [])

    def test_itanium_si_and_vmi_inheritance_evidence(self):
        for variant in ("si", "vmi"):
            with self.subTest(variant=variant):
                table, info = self.itanium_fixture(variant)
                result = advanced.m_vtables({"ea": hex(table), "abi": "itanium"})
                self.assertTrue(result["ok"])
                rtti = result["tables"][0]["rtti"]
                self.assertEqual(rtti["type"]["kind"], variant + "-class")
                self.assertEqual(rtti["bases"][0]["type"]["raw_name"], "4Base")
                self.assertEqual(rtti["bases"][0]["offset"], 0 if variant == "si" else 16)

    def test_itanium_unknown_variant_does_not_guess_bases(self):
        table, info = self.itanium_fixture()
        self.symbols.pop(0x107000)
        result = advanced.m_vtables({"ea": hex(table), "abi": "itanium"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["tables"][0]["rtti"]["type"]["kind"], "unknown")
        self.assertEqual(result["tables"][0]["rtti"]["bases"], [])

    def test_vtable_discovery_and_limits(self):
        table = self.msvc_fixture()
        self.named_items = [(table, "??_7Derived@@6B@")]
        result = advanced.m_vtables({"limit": 1, "max_slots": 1})
        self.assertEqual(result["total"], 1)
        self.assertTrue(result["truncated"])
        self.assertTrue(result["tables"][0]["truncated"])
        self.named_items = []
        result = advanced.m_vtables({"max_scan_bytes": 32})
        self.assertEqual(result["scanned_bytes"], 32)
        self.assertTrue(result["truncated"])

    def test_vtable_offset_requires_alignment_and_explicit_table(self):
        table = self.msvc_fixture()
        for params in ({"offset": 0}, {"ea": hex(table), "offset": 1}):
            with self.assertRaises(ValueError):
                advanced.m_vtables(params)

    def test_invalid_numeric_parameters_do_not_silently_coerce(self):
        for value in (True, 0, -1, 1.5, "invalid"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                advanced.m_stack({"ea": "200000", "limit": value})


if __name__ == "__main__":
    unittest.main(verbosity=2)
