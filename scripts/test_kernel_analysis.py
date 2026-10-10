"""IG5 CFG/local-IR pure algorithms with bounded memory and decoder fixtures.

These tests do not instantiate SleighDecoder, load a DLL/JVM, or execute target
code. They establish algorithm contracts independently of native decoder proof.
"""

import copy
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "worker"))
from kernel_analysis import analyze, bounded, build_cfg, optimize_ir


def value(space, offset, size=4):
    return {"space": space, "offset": hex(offset), "size": size}


def operation(opcode, *inputs, output=None, **metadata):
    return {"opcode": opcode, "inputs": list(inputs), "output": output, **metadata}


def row(ea, *ops, size=1):
    return {"ea": hex(ea), "size": size, "mnemonic": "fixture", "pcode": list(ops)}


def return_op():
    return operation("RETURN", value("register", 0))


class MemoryFixture:
    def __init__(self, entrypoint=0x1000, permissions=5):
        self.entrypoint = entrypoint
        self.architecture, self.bits, self.byteorder = "x86", 64, "little"
        self.code = bytes(range(256))
        self.regions = [SimpleNamespace(start=0x1000, size=len(self.code), permissions=permissions)]
        self.sha256 = hashlib.sha256(self.code).hexdigest()
        self.reads = []

    def read(self, ea, size):
        self.reads.append((ea, size))
        if not (0x1000 <= ea and ea + size <= 0x1100):
            raise ValueError("fixture read outside mapped code")
        return self.code[ea - 0x1000:ea - 0x1000 + size]

    def describe(self):
        return {"architecture": self.architecture, "bits": self.bits, "byteorder": self.byteorder}


class DecoderFixture:
    def __init__(self, instructions, *, truncated=False, error=None):
        self.result = {"instructions": instructions, "truncated": truncated, "error": error,
                       "consumedBytes": sum(item["size"] for item in instructions)}
        self.calls = []

    def decode(self, image, code, address, maximum):
        self.calls.append({"image": image, "code": bytes(code), "address": address, "maximum": maximum})
        return copy.deepcopy(self.result)


class LocalIRFixtures(unittest.TestCase):
    def fold(self, opcode, left, right, width):
        instructions = [row(0x1000, operation(opcode, value("const", left, width), value("const", right, width),
                                             output=value("unique", 0x200, width), fixtureTag="retained"))]
        result, changes = optimize_ir(instructions)
        return instructions, result[0]["pcode"][0], changes

    def test_add_wraps_to_output_width(self):
        for width in (1, 2, 4, 8, 16):
            with self.subTest(width=width):
                maximum = (1 << (8 * width)) - 1
                original, result, changes = self.fold("INT_ADD", maximum, 1, width)
                self.assertEqual(result["opcode"], "COPY")
                self.assertEqual(result["inputs"], [value("const", 0, width)])
                self.assertEqual(changes[0]["rule"], "constant-fold")
                self.assertEqual(original[0]["pcode"][0]["opcode"], "INT_ADD")

    def test_unsigned_subtraction_and_multiplication_wrap(self):
        for opcode, left, right, expected in (("INT_SUB", 0, 1, 0xff), ("INT_MULT", 0x80, 4, 0)):
            with self.subTest(opcode=opcode):
                _, result, changes = self.fold(opcode, left, right, 1)
                self.assertEqual(result["inputs"][0]["offset"], hex(expected))
                self.assertEqual(len(changes), 1)

    def test_bitwise_operations_preserve_exact_values(self):
        for opcode, expected in (("INT_AND", 0x20), ("INT_OR", 0xaf), ("INT_XOR", 0x8f)):
            with self.subTest(opcode=opcode):
                _, result, _ = self.fold(opcode, 0xa5, 0x2a, 1)
                self.assertEqual(result["inputs"][0]["offset"], hex(expected))

    def test_high_width_constant_does_not_pass_through_float(self):
        _, result, _ = self.fold("INT_ADD", 0x1000000000000001, 1, 8)
        self.assertEqual(result["inputs"][0]["offset"], "0x1000000000000002")

    def test_xor_self_and_sub_self_register_unique_only(self):
        for opcode, rule in (("INT_XOR", "xor-self"), ("INT_SUB", "sub-self")):
            for space in ("register", "unique"):
                with self.subTest(opcode=opcode, space=space):
                    source = value(space, 0x20, 8)
                    instructions = [row(0x1000, operation(opcode, source, copy.deepcopy(source), output=value("unique", 0x30, 8)))]
                    result, changes = optimize_ir(instructions)
                    self.assertEqual(result[0]["pcode"][0]["inputs"], [value("const", 0, 8)])
                    self.assertEqual(changes[0]["rule"], rule)

    def test_nonconstant_and_distinct_variable_inputs_stay_unchanged(self):
        for inputs in ((value("register", 1), value("register", 2)),
                       (value("register", 1), value("const", 0)),
                       (value("unique", 1, 2), value("unique", 1, 4))):
            with self.subTest(inputs=inputs):
                instructions = [row(0x1000, operation("INT_XOR", *inputs, output=value("unique", 0x40)))]
                result, changes = optimize_ir(instructions)
                self.assertEqual(result, instructions)
                self.assertEqual(changes, [])

    def test_memory_self_is_not_assumed_stable(self):
        memory = value("ram", 0x2000)
        instructions = [row(0x1000, operation("INT_XOR", memory, copy.deepcopy(memory), output=value("register", 1)))]
        self.assertEqual(optimize_ir(instructions), (instructions, []))

    def test_unsupported_opcode_no_output_and_invalid_width_do_not_fold(self):
        for opcode, output, inputs in (("INT_EQUAL", value("unique", 1, 1), [value("const", 1), value("const", 1)]),
                                      ("INT_ADD", None, [value("const", 1), value("const", 2)]),
                                      ("INT_ADD", value("unique", 1, 0), [value("const", 1), value("const", 2)]),
                                      ("INT_ADD", value("unique", 1, 17), [value("const", 1), value("const", 2)]),
                                      ("INT_ADD", value("unique", 1), [value("const", 1)])):
            with self.subTest(opcode=opcode, output=output, inputs=inputs):
                instructions = [row(0x1000, operation(opcode, *inputs, output=output))]
                self.assertEqual(optimize_ir(instructions), (instructions, []))

    def test_changes_have_independent_before_after_and_preserved_destination(self):
        original, optimized, changes = self.fold("INT_ADD", 1, 2, 4)
        change = changes[0]
        self.assertEqual(change["ea"], "0x1000")
        self.assertEqual(change["index"], 0)
        self.assertEqual(change["before"], original[0]["pcode"][0])
        self.assertEqual(change["after"], optimized)
        self.assertEqual(optimized["output"], value("unique", 0x200, 4))
        self.assertEqual(optimized["fixtureTag"], "retained")
        optimized["inputs"][0]["offset"] = "0x1234"
        self.assertEqual(change["after"]["inputs"][0]["offset"], "0x3")
        self.assertEqual(change["before"]["opcode"], "INT_ADD")


class GraphFixtures(unittest.TestCase):
    def test_fallthrough_and_return_boundaries(self):
        graph = build_cfg([row(0x1000, size=2), row(0x1002, return_op(), size=3), row(0x1005)], 0x1000)
        self.assertEqual(graph["reachable"], {0x1000, 0x1002})
        self.assertEqual(graph["edges"], [{"from": 0, "to": 1, "kind": "fallthrough"}])
        self.assertEqual(graph["blocks"][1]["end"], "0x1005")
        self.assertEqual(graph["unresolved"], [])

    def test_conditional_machine_branch_has_two_paths(self):
        instructions = [row(0x1000, operation("CBRANCH", value("ram", 0x1003), value("register", 1))),
                        row(0x1001, return_op()), row(0x1003, return_op())]
        graph = build_cfg(instructions, 0x1000)
        self.assertEqual(graph["reachable"], {0x1000, 0x1001, 0x1003})
        self.assertEqual({edge["kind"] for edge in graph["edges"]}, {"branch", "fallthrough"})
        self.assertEqual(graph["blocks"][0]["succs"], [1, 2])
        self.assertEqual(graph["blocks"][1]["preds"], [0])
        self.assertEqual(graph["blocks"][2]["preds"], [0])

    def test_unconditional_machine_branch_does_not_fall_through(self):
        instructions = [row(0x1000, operation("BRANCH", value("ram", 0x1002))), row(0x1001), row(0x1002, return_op())]
        graph = build_cfg(instructions, 0x1000)
        self.assertEqual(graph["reachable"], {0x1000, 0x1002})
        self.assertEqual(graph["edges"][0]["kind"], "branch")

    def test_multiple_external_pcode_exits_are_preserved_with_uncertainty(self):
        instructions = [row(0x1000, operation("CBRANCH", value("ram", 0x1002), value("register", 1)),
                             operation("BRANCH", value("ram", 0x1003))),
                        row(0x1001, return_op()), row(0x1002, return_op()), row(0x1003, return_op())]
        graph = build_cfg(instructions, 0x1000)
        self.assertTrue({0x1002, 0x1003}.issubset(graph["reachable"]))
        by_id = {block["id"]: block["start"] for block in graph["blocks"]}
        branch_targets = {by_id[edge["to"]] for edge in graph["edges"]
                          if by_id[edge["from"]] == "0x1000" and edge["kind"] == "branch"}
        self.assertEqual(branch_targets, {"0x1002", "0x1003"})
        self.assertTrue(graph["unresolved"])
        self.assertTrue(any(item["source"] == "0x1000" for item in graph["unresolved"]))

    def test_const_space_internal_jump_never_becomes_machine_edge(self):
        for opcode in ("BRANCH", "CBRANCH"):
            with self.subTest(opcode=opcode):
                graph = build_cfg([row(0x1000, operation(opcode, value("const", 0x9999))), row(0x1001, return_op())], 0x1000)
                self.assertEqual(graph["reachable"], {0x1000, 0x1001})
                self.assertEqual(graph["unresolved"], [])
                self.assertEqual(graph["edges"], [{"from": 0, "to": 1, "kind": "fallthrough"}])

    def test_internal_jump_with_return_retains_possible_fallthrough_and_uncertainty(self):
        graph = build_cfg([row(0x1000, operation("CBRANCH", value("const", 2)), return_op()), row(0x1001)], 0x1000)
        self.assertEqual(graph["reachable"], {0x1000, 0x1001})
        self.assertEqual(graph["edges"], [{"from": 0, "to": 1, "kind": "fallthrough"}])
        self.assertTrue(any(item["source"] == "0x1000" for item in graph["unresolved"]))

    def test_direct_call_is_reported_without_stealing_fallthrough(self):
        target = 0x2000000000000011
        graph = build_cfg([row(0x1000, operation("CALL", value("ram", target, 8))), row(0x1001, return_op())], 0x1000)
        self.assertEqual(graph["calls"], [{"ea": "0x1000", "target": hex(target), "indirect": False}])
        self.assertEqual(graph["reachable"], {0x1000, 0x1001})
        self.assertEqual(graph["edges"][0]["kind"], "fallthrough")

    def test_indirect_call_register_target_stays_unresolved(self):
        graph = build_cfg([row(0x1000, operation("CALLIND", value("register", 0x40, 8))), row(0x1001, return_op())], 0x1000)
        self.assertEqual(len(graph["calls"]), 1)
        self.assertIsNone(graph["calls"][0]["target"])
        self.assertTrue(graph["calls"][0]["indirect"])
        self.assertEqual(graph["reachable"], {0x1000, 0x1001})

    def test_indirect_call_ram_operand_is_not_a_resolved_destination(self):
        graph = build_cfg([row(0x1000, operation("CALLIND", value("ram", 0x3000, 8))), row(0x1001, return_op())], 0x1000)
        self.assertIsNone(graph["calls"][0]["target"])
        self.assertTrue(graph["calls"][0]["indirect"])

    def test_indirect_machine_branch_stops_and_records_uncertainty(self):
        for space in ("register", "ram"):
            with self.subTest(space=space):
                graph = build_cfg([row(0x1000, operation("BRANCHIND", value(space, 0x1001))), row(0x1001, return_op())], 0x1000)
                self.assertEqual(graph["reachable"], {0x1000})
                self.assertEqual(graph["edges"], [])
                self.assertEqual(graph["unresolved"], [{"source": "0x1000", "target": None, "reason": "indirect branch"}])

    def test_nonboundary_target_is_reported_and_not_decoded_as_instruction(self):
        graph = build_cfg([row(0x1000, operation("BRANCH", value("ram", 0x1001)), size=2), row(0x1002, return_op())], 0x1000)
        self.assertEqual(graph["reachable"], {0x1000})
        self.assertEqual(graph["unresolved"][0]["target"], "0x1001")

    def test_machine_self_loop_is_finite(self):
        graph = build_cfg([row(0x1000, operation("BRANCH", value("ram", 0x1000)))], 0x1000)
        self.assertEqual(graph["reachable"], {0x1000})
        self.assertEqual(graph["edges"], [{"from": 0, "to": 0, "kind": "branch"}])
        self.assertEqual(graph["blocks"][0]["preds"], [0])

    def test_missing_entry_produces_unresolved_graph(self):
        graph = build_cfg([row(0x1000, return_op())], 0x2000)
        self.assertEqual(graph["blocks"], [])
        self.assertEqual(graph["reachable"], set())
        self.assertEqual(graph["unresolved"][0]["target"], "0x2000")

    def test_cfg_truncation_reports_and_has_no_dangling_edge_ids(self):
        graph = build_cfg([row(0x1000), row(0x1001), row(0x1002, return_op())], 0x1000, max_blocks=2)
        self.assertTrue(graph["truncated"])
        self.assertEqual(len(graph["blocks"]), 2)
        ids = {block["id"] for block in graph["blocks"]}
        self.assertTrue(all(edge["from"] in ids and edge["to"] in ids for edge in graph["edges"]))
        self.assertTrue(all(succ in ids for block in graph["blocks"] for succ in block["succs"]))

    def test_cfg_truncation_keeps_entry_when_branch_target_has_lower_address(self):
        graph = build_cfg([row(0x2000, operation("BRANCH", value("ram", 0x1000))), row(0x1000, return_op())], 0x2000, max_blocks=1)
        self.assertTrue(graph["truncated"])
        self.assertEqual([block["start"] for block in graph["blocks"]], ["0x2000"])


class AnalysisFixtures(unittest.TestCase):
    def test_analyze_stays_stateless_and_does_not_execute(self):
        image = MemoryFixture()
        decoder = DecoderFixture([row(0x1000, return_op())])
        result = analyze(image, decoder, {})
        self.assertTrue(result["ok"])
        self.assertEqual(result["implementation"], "ig5-kernel")
        self.assertFalse(result["idb_modified"])
        self.assertFalse(result["target_executed"])
        self.assertFalse(result["source"]["jvmStarted"])
        self.assertFalse(result["source"]["commercialEngineUsed"])
        self.assertEqual(result["source"]["artifactSHA256"], image.sha256)
        self.assertEqual(image.reads, [(0x1000, 256)])
        self.assertEqual(len(decoder.calls), 1)

    def test_explicit_entry_code_and_limits_are_forwarded_exactly(self):
        image = MemoryFixture()
        decoder = DecoderFixture([row(0x10fc, return_op())])
        result = analyze(image, decoder, {"ea": "0x10fc", "max_code_bytes": 100, "max_instructions": 7, "max_blocks": 2})
        self.assertEqual(result["ea"], "0x10fc")
        self.assertEqual(image.reads, [(0x10fc, 4)])
        self.assertEqual(decoder.calls[0]["code"], bytes((252, 253, 254, 255)))
        self.assertEqual(decoder.calls[0]["maximum"], 7)
        self.assertEqual(decoder.calls[0]["address"], 0x10fc)

    def test_max_code_byte_budget_caps_actual_read(self):
        image = MemoryFixture()
        decoder = DecoderFixture([row(0x1000, return_op())])
        analyze(image, decoder, {"max_code_bytes": 3})
        self.assertEqual(image.reads, [(0x1000, 3)])
        self.assertEqual(len(decoder.calls[0]["code"]), 3)

    def test_nonexecutable_and_unmapped_entries_rejected_before_decode(self):
        for image, params in ((MemoryFixture(permissions=1), {}), (MemoryFixture(), {"ea": "0x2000"}),
                              (MemoryFixture(), {"ea": "-0x1"})):
            with self.subTest(params=params, permissions=image.regions[0].permissions):
                decoder = DecoderFixture([row(0x1000, return_op())])
                with self.assertRaises(ValueError):
                    analyze(image, decoder, params)
                self.assertEqual(image.reads, [])
                self.assertEqual(decoder.calls, [])

    def test_missing_entrypoint_and_nonhex_entry_types_rejected(self):
        for image, params in ((MemoryFixture(entrypoint=None), {}), (MemoryFixture(), {"ea": 0x1000}),
                              (MemoryFixture(), {"ea": True}), (MemoryFixture(), {"ea": "invalid"})):
            with self.subTest(params=params):
                with self.assertRaises(ValueError):
                    analyze(image, DecoderFixture([row(0x1000, return_op())]), params)

    def test_input_work_budgets_reject_bool_noninteger_zero_and_overflow(self):
        for name, maximum in (("max_instructions", 1024), ("max_code_bytes", 65536), ("max_blocks", 1024)):
            for bad in (False, True, 0, -1, 1.0, "1", maximum + 1):
                with self.subTest(name=name, bad=bad):
                    image, decoder = MemoryFixture(), DecoderFixture([row(0x1000, return_op())])
                    with self.assertRaises(ValueError):
                        analyze(image, decoder, {name: bad})
                    self.assertEqual(image.reads, [])
                    self.assertEqual(decoder.calls, [])

    def test_optimize_requires_boolean(self):
        for bad in (None, 0, 1, "false", [], {}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                analyze(MemoryFixture(), DecoderFixture([row(0x1000, return_op())]), {"optimize": bad})

    def test_reachable_filter_discards_linear_dead_bytes(self):
        decoder = DecoderFixture([row(0x1000, operation("BRANCH", value("ram", 0x1002))), row(0x1001), row(0x1002, return_op())])
        result = analyze(MemoryFixture(), decoder, {})
        self.assertEqual([item["ea"] for item in result["instructions"]], ["0x1000", "0x1002"])

    def test_optimization_preserves_cfg_and_original_decoder_fixture(self):
        add = operation("INT_ADD", value("const", 255, 1), value("const", 1, 1), output=value("register", 1, 1))
        decoder = DecoderFixture([row(0x1000, add), row(0x1001, return_op())])
        original = copy.deepcopy(decoder.result)
        baseline = analyze(MemoryFixture(), decoder, {})
        optimized = analyze(MemoryFixture(), decoder, {"optimize": True})
        self.assertEqual(optimized["cfg"], baseline["cfg"])
        self.assertEqual(decoder.result, original)
        self.assertEqual(optimized["instructions"][0]["pcode"][0]["opcode"], "COPY")
        self.assertEqual(len(optimized["optimizations"]), 1)
        self.assertEqual(baseline["optimizations"], [])

    def test_empty_decode_rejected(self):
        with self.assertRaises(ValueError):
            analyze(MemoryFixture(), DecoderFixture([]), {})

    def test_decode_error_propagates_partial_status(self):
        result = analyze(MemoryFixture(), DecoderFixture([row(0x1000, return_op())], error="fixture bounded decode stop"), {})
        self.assertTrue(result["partial"])
        self.assertEqual(result["decode"]["error"], "fixture bounded decode stop")

    def test_decode_truncation_cannot_claim_complete_analysis(self):
        result = analyze(MemoryFixture(), DecoderFixture([row(0x1000, return_op())], truncated=True), {})
        self.assertTrue(result["partial"])
        self.assertTrue(result["decode"]["truncated"])

    def test_cfg_unresolved_and_truncated_each_propagate_partial_status(self):
        unresolved = analyze(MemoryFixture(), DecoderFixture([row(0x1000, operation("BRANCHIND", value("register", 1)))]), {})
        self.assertTrue(unresolved["partial"])
        truncated = analyze(MemoryFixture(), DecoderFixture([row(0x1000), row(0x1001, return_op())]), {"max_blocks": 1})
        self.assertTrue(truncated["partial"])
        self.assertTrue(truncated["cfg"]["truncated"])

    def test_multiple_external_pcode_exits_cannot_claim_solved_machine_flow(self):
        rows = [row(0x1000, operation("CBRANCH", value("ram", 0x1002), value("register", 1)),
                    operation("BRANCH", value("ram", 0x1003))),
                row(0x1001, return_op()), row(0x1002, return_op()), row(0x1003, return_op())]
        result = analyze(MemoryFixture(), DecoderFixture(rows), {})
        self.assertTrue(result["partial"])
        self.assertTrue(result["cfg"]["unresolved"])
        self.assertTrue({"0x1002", "0x1003"}.issubset({item["ea"] for item in result["instructions"]}))

    def test_bounded_defaults_and_edge_values(self):
        self.assertEqual(bounded(None, "fixture", 5, 7), 5)
        self.assertEqual(bounded(1, "fixture", 5, 7), 1)
        self.assertEqual(bounded(7, "fixture", 5, 7), 7)

    def test_local_pcode_branch_can_bypass_return_and_retain_machine_fallthrough(self):
        rows = [row(0x1000, operation("CBRANCH", value("const", 2), value("register", 1)),
                    return_op(), operation("COPY", value("register", 2), output=value("unique", 0))),
                row(0x1001, return_op())]
        result = analyze(MemoryFixture(), DecoderFixture(rows), {})
        self.assertTrue(result["partial"])
        self.assertTrue(result["cfg"]["unresolved"])
        self.assertEqual([item["ea"] for item in result["instructions"]], ["0x1000", "0x1001"])
        self.assertEqual(result["cfg"]["edges"][0]["kind"], "fallthrough")


if __name__ == "__main__":
    unittest.main(verbosity=2)
