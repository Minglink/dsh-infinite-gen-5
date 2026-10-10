"""Pure native-provider contract tests; synthetic mapping APIs, no engine startup."""
import ast
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'worker'))


def load_method(path, name):
    tree = ast.parse(path.read_text(encoding='utf-8-sig'))
    found = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)
    namespace = {'sys': sys, 'ADAPTER_ROOT': ROOT / 'adapters' / 'ghidra',
                 '_worker_module_dir': str(ROOT / 'worker'),
                 '_open': True, '_resolve_ea': lambda params: int(params['ea'], 0),
                 'addrstr': lambda address: hex(address.value)}
    exec(compile(ast.Module(body=[found], type_ignores=[]), str(path), 'exec'), namespace)
    return namespace[name]


reverse = load_method(ROOT / 'worker' / 'ig5_worker.py', 'm_fileoffset')
ghidra = load_method(ROOT / 'adapters' / 'ghidra' / 'worker.py', 'm_fileoffset')


class Address:
    def __init__(self, value, bits=64):
        self.value, self.bits = value, bits

    def add(self, value):
        return Address(self.value + value, self.bits)

    def getOffset(self):
        return self.value

    def getAddressSpace(self):
        return SimpleNamespace(getSize=lambda: self.bits)


class FileMapping(unittest.TestCase):
    def call(self, engine, mapping, params, bits=64):
        reads = []
        def offset(value):
            reads.append(value)
            return mapping.get(value, -1)
        if engine == 'reverse':
            with patch.dict(sys.modules, {'ida_loader': SimpleNamespace(get_fileregion_offset=offset)}):
                result = reverse(params)
        else:
            memory = SimpleNamespace(getAddressSourceInfo=lambda address: SimpleNamespace(getFileOffset=lambda: offset(address.value)))
            owner = SimpleNamespace(program=SimpleNamespace(getMemory=lambda: memory),
                                    address=lambda values: Address(int(values['ea'], 0), bits))
            result = ghidra(owner, params)
        return result, reads

    def test_all_bytes_must_have_consecutive_file_offsets(self):
        for engine in ('reverse', 'ghidra'):
            with self.subTest(engine=engine):
                result, reads = self.call(engine, {0x1000 + i: 0x400 + i for i in range(4)}, {'ea': '0x1000', 'size': 4})
                self.assertEqual(result, {'ea': '0x1000', 'fileOffset': 0x400, 'size': 4, 'contiguous': True})
                self.assertEqual(reads, [0x1000, 0x1001, 0x1002, 0x1003])

    def test_hole_discontinuity_and_bss_do_not_claim_a_file_offset(self):
        for engine in ('reverse', 'ghidra'):
            for mapping in ({0x1000: 0x400}, {0x1000: 0x400, 0x1001: 0x800}, {}):
                with self.subTest(engine=engine, mapping=mapping):
                    result, reads = self.call(engine, mapping, {'ea': '0x1000', 'size': 2})
                    self.assertFalse(result['contiguous'])
                    self.assertEqual(result['fileOffset'], -1)

    def test_ea_only_defaults_to_one_byte_and_preserves_existing_offset(self):
        for engine in ('reverse', 'ghidra'):
            result, reads = self.call(engine, {0x1000: 42}, {'ea': '0x1000'})
            self.assertTrue(result['contiguous'])
            self.assertEqual(result['fileOffset'], 42)
            self.assertEqual(result['size'], 1)
            self.assertEqual(reads, [0x1000])

    def test_invalid_size_is_rejected_before_mapping_queries(self):
        for engine in ('reverse', 'ghidra'):
            for size in (0, -1, 4097, True, None, 1.5, 'bad'):
                with self.subTest(engine=engine, size=size):
                    with self.assertRaises(ValueError):
                        self.call(engine, {}, {'ea': '0x1000', 'size': size})

    def test_maximum_range_is_bounded_and_hex_size_is_supported(self):
        for engine in ('reverse', 'ghidra'):
            result, reads = self.call(engine, {0x1000 + i: i for i in range(4096)}, {'ea': '0x1000', 'size': '0x1000'})
            self.assertTrue(result['contiguous'])
            self.assertEqual(len(reads), 4096)

    def test_address_space_overflow_does_not_wrap_into_valid_mapping(self):
        result, reads = self.call('ghidra', {0xffffffff: 42, 0x100000000: 43}, {'ea': '0xffffffff', 'size': 2}, bits=32)
        self.assertFalse(result['contiguous'])
        self.assertEqual(result['fileOffset'], -1)
        result, reads = self.call('reverse', {(1 << 64) - 1: 42}, {'ea': hex((1 << 64) - 1), 'size': 2})
        self.assertFalse(result['contiguous'])
        self.assertEqual(reads, [])


if __name__ == '__main__':
    unittest.main()
