"""Pure-byte RTTI fixtures: no JVM, debugger, or commercial runtime required."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "worker"))
from kernel_rtti import analyze_vtables


class ByteProvider:
    def __init__(self, pointer_size=8, byteorder="little", imagebase=0x140000000):
        self.pointer_size, self.byteorder, self.imagebase = pointer_size, byteorder, imagebase
        self.data = bytearray(0x8000)
        self.ranges = [{"start": imagebase + 0x1000, "end": imagebase + 0x4000, "executable": False},
                       {"start": imagebase + 0x6000, "end": imagebase + 0x7000, "executable": True}]
        self.names = {}
        self.read_count = 0
        self.bytes_read = 0

    def read(self, ea, size):
        self.read_count += 1
        self.bytes_read += size
        return bytes(self.data[ea - self.imagebase:ea - self.imagebase + size])

    def is_executable(self, ea):
        return self.imagebase + 0x6000 <= ea < self.imagebase + 0x7000

    def symbol(self, ea):
        return self.names.get(ea, "")

    def symbols(self):
        return self.names.items()

    def resolve_symbol(self, name):
        return next((ea for ea, value in self.names.items() if value == name), None)

    def write_uint(self, offset, value, size=4, signed=False):
        self.data[offset:offset + size] = value.to_bytes(size, self.byteorder, signed=signed)

    def ptr(self, offset, target_offset):
        self.write_uint(offset, self.imagebase + target_offset if target_offset else 0, self.pointer_size)

    def string(self, offset, value):
        data = value.encode("ascii") + b"\0"
        self.data[offset:offset + len(data)] = data


def msvc(pointer_size=8, base_count=2, imagebase=None):
    provider = ByteProvider(pointer_size, imagebase=imagebase if imagebase is not None else
                            (0x140000000 if pointer_size == 8 else 0x400000))
    p = pointer_size
    point = provider.imagebase + 0x1800 + p
    provider.ptr(0x1800, 0x1100)
    provider.write_uint(0x1100, 1 if p == 8 else 0)
    provider.write_uint(0x1104, 16)
    provider.write_uint(0x1108, 0)
    resolve = lambda offset: offset if p == 8 else provider.imagebase + offset
    provider.write_uint(0x110c, resolve(0x1200))
    provider.write_uint(0x1110, resolve(0x1300))
    if p == 8:
        provider.write_uint(0x1114, 0x1100)
    provider.string(0x1200 + 2 * p, ".?AVDerived@@")
    provider.string(0x1280 + 2 * p, ".?AVBase@@")
    provider.string(0x12c0 + 2 * p, ".?AVRoot@@")
    provider.write_uint(0x1300, 0)
    provider.write_uint(0x1304, 1)
    provider.write_uint(0x1308, base_count)
    provider.write_uint(0x130c, resolve(0x1400))
    for index in range(base_count):
        descriptor = 0x1500 + index * 0x40
        td = (0x1200, 0x1280, 0x12c0)[index]
        provider.write_uint(0x1400 + index * 4, resolve(descriptor))
        provider.write_uint(descriptor, resolve(td))
        provider.write_uint(descriptor + 4, base_count - index - 1)
        provider.write_uint(descriptor + 8, index * 16, signed=True)
        provider.write_uint(descriptor + 12, -1, signed=True)
        provider.write_uint(descriptor + 16, 0, signed=True)
        provider.write_uint(descriptor + 20, 0)
    provider.ptr(0x1800 + p, 0x6010)
    provider.ptr(0x1800 + 2 * p, 0x6030)
    provider.ptr(0x1800 + 3 * p, 0)
    provider.names[point] = "??_7Derived@@6B@"
    provider.names[provider.imagebase + 0x6010] = "Derived::first"
    provider.names[provider.imagebase + 0x6030] = "Derived::second"
    return provider, point


def itanium(kind="class", pointer_size=8, byteorder="little"):
    base = 0x140000000 if pointer_size == 8 else 0x400000
    provider = ByteProvider(pointer_size, byteorder, base)
    p = pointer_size
    runtime = {"class": 0x2000, "si-class": 0x2100, "vmi-class": 0x2200}
    variants = {"class": "__class_type_info", "si-class": "__si_class_type_info", "vmi-class": "__vmi_class_type_info"}
    for label, offset in runtime.items():
        provider.names[base + offset + 2 * p] = "_ZTV" + variants[label]
    provider.ptr(0x2500, runtime[kind] + 2 * p)
    provider.ptr(0x2500 + p, 0x2700)
    provider.string(0x2700, "3Foo")
    for offset, name, name_offset in ((0x2540, "3Bar", 0x2740), (0x2580, "3Baz", 0x2780)):
        provider.ptr(offset, 0x2000 + 2 * p)
        provider.ptr(offset + p, name_offset)
        provider.string(name_offset, name)
    if kind == "si-class":
        provider.ptr(0x2500 + 2 * p, 0x2540)
    elif kind == "vmi-class":
        provider.write_uint(0x2500 + 2 * p, 0)
        provider.write_uint(0x2500 + 2 * p + 4, 2)
        start = 0x2500 + 2 * p + 8
        provider.ptr(start, 0x2540)
        provider.write_uint(start + p, (16 << 8) | 2, p, signed=True)
        provider.ptr(start + 2 * p, 0x2580)
        provider.write_uint(start + 3 * p, (-24 << 8) | 3, p, signed=True)
    provider.write_uint(0x2800, -16, p, signed=True)
    provider.ptr(0x2800 + p, 0x2500)
    provider.ptr(0x2800 + 2 * p, 0x6010)
    provider.ptr(0x2800 + 3 * p, 0x6030)
    provider.ptr(0x2800 + 4 * p, 0)
    provider.names[base + 0x2800] = "_ZTV3Foo"
    provider.names[base + 0x2500] = "_ZTI3Foo"
    provider.names[base + 0x6010] = "Foo::first"
    return provider, base + 0x2800 + 2 * p


class RTTIFixtures(unittest.TestCase):
    def test_msvc_x64_two_slots_and_base(self):
        provider, point = msvc()
        result = analyze_vtables(provider, {"ea": hex(point), "offset": 8})
        self.assertTrue(result["ok"])
        self.assertEqual(result["implementation"], "ig5-kernel")
        table = result["requested"]
        self.assertEqual(table["slot_count"], 2)
        self.assertEqual(table["selected_slot"]["target"], hex(provider.imagebase + 0x6030))
        self.assertEqual(table["rtti"]["type"]["name"], "Derived")
        self.assertEqual(table["rtti"]["bases"][1]["type"]["name"], "Base")
        self.assertEqual(table["rtti"]["bases"][1]["pdisp"], -1)
        self.assertEqual(table["rtti"]["inheritance_edges"][0]["base_index"], 1)
        self.assertIn("placeholder", table["signature_note"])

    def test_msvc_x86_absolute_pointers(self):
        provider, point = msvc(4)
        table = analyze_vtables(provider, {"ea": point, "abi": "msvc"})["requested"]
        self.assertTrue(table["ok"])
        self.assertEqual(table["pointer_size"], 4)
        self.assertIsNone(table["rtti"]["complete_object_locator"]["image_base"])
        self.assertEqual(table["slots"][1]["offset"], 4)

    def test_high_precision_addresses_remain_hex_strings(self):
        provider, point = msvc(imagebase=0x0020000000000000)
        table = analyze_vtables(provider, {"ea": hex(point)})["requested"]
        self.assertEqual(table["ea"], hex(point))
        self.assertEqual(table["slots"][0]["target"], hex(provider.imagebase + 0x6010))

    def test_msvc_three_level_preorder_edges(self):
        provider, point = msvc(base_count=3)
        edges = analyze_vtables(provider, {"ea": point})["requested"]["rtti"]["inheritance_edges"]
        self.assertEqual([(e["derived_index"], e["base_index"]) for e in edges], [(0, 1), (1, 2)])

    def test_msvc_base_limit_reports_partial_layout(self):
        provider, point = msvc()
        result = analyze_vtables(provider, {"ea": point, "max_bases": 1})
        self.assertTrue(result["ok"])
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["requested"]["rtti"]["bases"]), 1)

    def test_msvc_imagebase_mismatch_rejected(self):
        provider, point = msvc()
        provider.write_uint(0x1114, 0x1104)
        self.assertFalse(analyze_vtables(provider, {"ea": point, "abi": "msvc"})["ok"])

    def test_msvc_hierarchy_root_mismatch_rejected(self):
        provider, point = msvc()
        provider.write_uint(0x1500, 0x1280)
        result = analyze_vtables(provider, {"ea": point, "abi": "msvc"})
        self.assertFalse(result["ok"])
        self.assertIn("root", result["requested"]["errors"][0]["error"])

    def test_msvc_subtree_out_of_array_rejected(self):
        provider, point = msvc()
        provider.write_uint(0x1544, 1)
        self.assertFalse(analyze_vtables(provider, {"ea": point, "abi": "msvc"})["ok"])

    def test_msvc_null_rva_rejected(self):
        provider, point = msvc()
        provider.write_uint(0x110c, 0)
        self.assertFalse(analyze_vtables(provider, {"ea": point, "abi": "msvc"})["ok"])

    def test_msvc_bad_signature_and_unmapped_col_rejected(self):
        provider, point = msvc()
        provider.write_uint(0x1100, 0)
        self.assertFalse(analyze_vtables(provider, {"ea": point, "abi": "msvc"})["ok"])
        provider.ptr(0x1800, 0x5000)
        self.assertFalse(analyze_vtables(provider, {"ea": point, "abi": "msvc"})["ok"])

    def test_itanium_class_and_symbol_header_adjustment(self):
        provider, point = itanium()
        result = analyze_vtables(provider, {"name": "_ZTV3Foo", "offset": 0})
        self.assertTrue(result["ok"])
        self.assertEqual(result["requested"]["ea"], hex(point))
        self.assertEqual(result["requested"]["rtti"]["type"]["kind"], "class")
        self.assertEqual(result["requested"]["rtti"]["offset_to_top"], -16)
        self.assertEqual(result["requested"]["selected_slot"]["index"], 0)

    def test_itanium_si_base(self):
        provider, point = itanium("si-class")
        info = analyze_vtables(provider, {"ea": point, "abi": "itanium"})["requested"]["rtti"]["type"]
        self.assertEqual(info["kind"], "si-class")
        self.assertEqual(info["bases"][0]["type"]["name"], "Bar")
        self.assertTrue(info["bases"][0]["public"])
        self.assertFalse(info["bases"][0]["virtual"])

    def test_itanium_named_vbase_prefix_validates_actual_address_point(self):
        provider, point = itanium("vmi-class")
        provider.names.pop(provider.imagebase + 0x2800)
        provider.names[provider.imagebase + 0x27e8] = "_ZTV3Foo"
        provider.write_uint(0x27e8, -24, 8, signed=True)
        provider.write_uint(0x27f0, -32, 8, signed=True)
        provider.write_uint(0x27f8, -40, 8, signed=True)
        result = analyze_vtables(provider, {"name": "_ZTV3Foo", "abi": "itanium", "offset": 8})
        self.assertTrue(result["ok"])
        self.assertEqual(result["requested"]["ea"], hex(point))
        self.assertEqual(result["requested"]["header_prefix_words"], 3)
        self.assertEqual(result["requested"]["selected_slot"]["index"], 1)

    def test_itanium_named_prefix_bound_requires_explicit_address_point(self):
        provider, point = itanium("vmi-class")
        provider.names.pop(provider.imagebase + 0x2800)
        provider.names[provider.imagebase + 0x2600] = "_ZTV3Foo"
        result = analyze_vtables(provider, {"name": "_ZTV3Foo", "abi": "itanium"})
        self.assertFalse(result["ok"])
        self.assertTrue(analyze_vtables(provider, {"ea": point, "abi": "itanium"})["ok"])

    def test_itanium_vmi_signed_virtual_offset(self):
        provider, point = itanium("vmi-class")
        bases = analyze_vtables(provider, {"ea": point})["requested"]["rtti"]["bases"]
        self.assertEqual(bases[0]["offset"], 16)
        self.assertEqual(bases[1]["offset"], -24)
        self.assertTrue(bases[1]["virtual"])
        self.assertEqual(bases[1]["offset_basis"], "vtable vbase-offset entry")

    def test_itanium_x86_and_big_endian(self):
        for p, order in ((4, "little"), (8, "big"), (4, "big")):
            with self.subTest(pointer_size=p, byteorder=order):
                provider, point = itanium("vmi-class", p, order)
                result = analyze_vtables(provider, {"ea": point, "abi": "itanium"})
                self.assertTrue(result["ok"])
                self.assertEqual(result["requested"]["rtti"]["bases"][1]["offset"], -24)

    def test_itanium_self_cycle_rejected(self):
        provider, point = itanium("si-class")
        provider.ptr(0x2510, 0x2500)
        result = analyze_vtables(provider, {"ea": point, "abi": "itanium"})
        self.assertFalse(result["ok"])
        self.assertIn("cycle", result["requested"]["errors"][0]["error"])

    def test_itanium_longer_cycle_rejected(self):
        provider, point = itanium("si-class")
        provider.ptr(0x2540, 0x2110)
        provider.ptr(0x2550, 0x2500)
        self.assertFalse(analyze_vtables(provider, {"ea": point, "abi": "itanium"})["ok"])

    def test_itanium_shared_base_dag_not_rejected_as_cycle(self):
        provider, point = itanium("vmi-class")
        provider.ptr(0x2538, 0x2540)
        result = analyze_vtables(provider, {"ea": point, "abi": "itanium"})
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["requested"]["rtti"]["bases"]), 2)

    def test_itanium_recursion_depth_bound(self):
        provider, point = itanium("si-class")
        provider.ptr(0x2540, 0x2110)
        provider.ptr(0x2550, 0x2580)
        result = analyze_vtables(provider, {"ea": point, "abi": "itanium"}, limits={"depth": 1})
        self.assertFalse(result["ok"])
        self.assertIn("depth", result["requested"]["errors"][0]["error"])

    def test_itanium_count_and_reserved_flags_rejected(self):
        provider, point = itanium("vmi-class")
        provider.write_uint(0x2514, 4097)
        self.assertFalse(analyze_vtables(provider, {"ea": point, "abi": "itanium"})["ok"])
        provider.write_uint(0x2514, 2)
        provider.write_uint(0x2520, (16 << 8) | 4, 8)
        self.assertFalse(analyze_vtables(provider, {"ea": point, "abi": "itanium"})["ok"])

    def test_itanium_unknown_runtime_does_not_infer_inheritance(self):
        provider, point = itanium("si-class")
        provider.names = {provider.imagebase + 0x2500: "_ZTI3Foo"}
        info = analyze_vtables(provider, {"ea": point, "abi": "itanium"})["requested"]["rtti"]["type"]
        self.assertEqual(info["kind"], "unknown")
        self.assertEqual(info["bases"], [])

    def test_itanium_unknown_runtime_without_symbol_evidence_rejected(self):
        provider, point = itanium()
        provider.names.clear()
        self.assertFalse(analyze_vtables(provider, {"ea": point, "abi": "itanium"})["ok"])

    def test_bad_name_and_name_bound_rejected(self):
        provider, point = msvc()
        provider.data[0x1210] = 0x80
        self.assertFalse(analyze_vtables(provider, {"ea": point, "abi": "msvc"})["ok"])
        provider, point = msvc()
        result = analyze_vtables(provider, {"ea": point, "abi": "msvc"}, limits={"name_bytes": 4})
        self.assertFalse(result["ok"])
        self.assertIn("terminated", result["requested"]["errors"][0]["error"])

    def test_short_provider_read_rejected(self):
        provider, point = msvc()
        provider.read = lambda ea, size: b"\0" * (size - 1)
        self.assertFalse(analyze_vtables(provider, {"ea": point})["ok"])

    def test_valid_rtti_without_executable_slots_rejected(self):
        provider, point = msvc()
        provider.is_executable = lambda ea: False
        result = analyze_vtables(provider, {"ea": point, "abi": "msvc"})
        self.assertFalse(result["ok"])
        self.assertIsNotNone(result["requested"]["rtti"])
        self.assertEqual(result["requested"]["slots"], [])

    def test_explicit_missing_slot_is_not_guessed(self):
        provider, point = msvc()
        result = analyze_vtables(provider, {"ea": point, "offset": 24})
        self.assertTrue(result["ok"])
        self.assertIsNone(result["requested"]["selected_slot"])
        self.assertIn("selection_error", result["requested"])

    def test_offset_requires_explicit_aligned_table(self):
        provider, point = msvc()
        for params in ({"offset": 8}, {"ea": point, "offset": 3}, {"ea": point, "offset": -8}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                analyze_vtables(provider, params)

    def test_slot_limit_is_reported(self):
        provider, point = msvc()
        result = analyze_vtables(provider, {"ea": point, "max_slots": 1})
        self.assertTrue(result["truncated"])
        self.assertEqual(result["requested"]["slot_count"], 1)

    def test_scan_discovers_stripped_msvc_and_deduplicates_named_table(self):
        provider, point = msvc()
        named = analyze_vtables(provider, {"abi": "msvc"})
        self.assertEqual(named["total"], 1)
        provider.names.pop(point)
        stripped = analyze_vtables(provider, {"abi": "msvc"})
        self.assertEqual(stripped["total"], 1)
        self.assertEqual(stripped["tables"][0]["ea"], hex(point))

    def test_scan_byte_budget_and_result_limit(self):
        provider, point = msvc()
        provider.names.clear()
        result = analyze_vtables(provider, {"max_scan_bytes": 0x100})
        self.assertTrue(result["truncated"])
        self.assertEqual(result["scanned_bytes"], 0x100)
        self.assertEqual(result["total"], 0)
        provider, point = msvc()
        result = analyze_vtables(provider, {"limit": 1})
        self.assertTrue(result["truncated"])
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["scanned_bytes"], 0)

    def test_scan_candidate_budget_keeps_only_completed_evidence(self):
        provider, point = msvc()
        result = analyze_vtables(provider, {"abi": "msvc"}, limits={"candidates": 1})
        self.assertTrue(result["truncated"])
        self.assertEqual(result["budget"]["exhausted"], "candidates")
        self.assertEqual(result["budget"]["used"]["candidates"], 1)
        self.assertEqual(result["total"], 1)

    def test_shared_read_call_byte_and_type_node_budgets(self):
        for bound, value in (("read_bytes", 8), ("read_calls", 1), ("type_nodes", 1)):
            with self.subTest(bound=bound):
                provider, point = msvc()
                result = analyze_vtables(provider, {"ea": point, "abi": "msvc"}, limits={bound: value})
                self.assertFalse(result["ok"])
                self.assertTrue(result["truncated"])
                self.assertEqual(result["budget"]["exhausted"], bound)
                self.assertLessEqual(result["budget"]["used"][bound], value)
                self.assertEqual(result["tables"], [])

    def test_mapping_rejects_cross_range_read_and_overlap(self):
        provider, point = msvc()
        provider.ranges[0]["end"] = provider.imagebase + 0x1108
        self.assertFalse(analyze_vtables(provider, {"ea": point})["ok"])
        provider, point = msvc()
        provider.ranges.append({"start": provider.imagebase + 0x2000, "end": provider.imagebase + 0x3000})
        with self.assertRaises(ValueError):
            analyze_vtables(provider, {"ea": point})

    def test_parameter_and_provider_validation(self):
        provider, point = msvc()
        invalid = ({"abi": "guess"}, {"ea": True}, {"ea": point, "name": "x"},
                   {"max_slots": 4097}, {"max_bases": 0}, {"max_scan_bytes": 64 * 1024 * 1024 + 1},
                   {"ea": 1 << 64}, {"name": "missing"})
        for params in invalid:
            with self.subTest(params=params), self.assertRaises(ValueError):
                analyze_vtables(provider, params)
        for limits in ({"unknown": 1}, {"depth": 33}, {"read_calls": False}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                analyze_vtables(provider, {"ea": point}, limits=limits)
        provider.pointer_size = 5
        with self.assertRaises(ValueError):
            analyze_vtables(provider, {"ea": point})

    def test_provider_read_failures_are_sanitized(self):
        provider, point = msvc()
        def fail(ea, size):
            raise OSError("private-provider-path")
        provider.read = fail
        result = analyze_vtables(provider, {"ea": point})
        self.assertFalse(result["ok"])
        self.assertNotIn("private-provider-path", str(result))


if __name__ == "__main__":
    unittest.main(verbosity=2)
