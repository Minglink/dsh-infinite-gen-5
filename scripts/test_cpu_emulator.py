"""Real bundled Unicorn execution; no commercial engine or debuggee process."""
import os
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))
from memory_image import MemoryImage, MemoryRegion, MEMORY_BUDGET
from cpu_emulator import emulate_image


def image(code, arch='x86', bits=64, base=0x100000):
    return MemoryImage(arch, bits, base,
                       [MemoryRegion(base, len(code), lambda offset, length: code[offset:offset + length])],
                       source='standalone-fixture')


class CpuExecution(unittest.TestCase):
    def test_win64_register_arguments(self):
        result = emulate_image(image(bytes.fromhex('4889c84801d0c3')), {'args': ['0x11', '0x2a']})
        self.assertTrue(result['ok'])
        self.assertEqual(result['return_value'], '0x3b')
        self.assertEqual(result['sourceEngine'], 'standalone-fixture')

    def test_sysv_register_arguments(self):
        result = emulate_image(image(bytes.fromhex('4889f84801f0c3')), {'abi': 'sysv64', 'args': ['17', '42']})
        self.assertEqual(result['return_value'], '0x3b')
        self.assertTrue(result['ok'])

    def test_cdecl_stack_arguments(self):
        result = emulate_image(image(bytes.fromhex('8b44240403442408c3'), bits=32), {'args': ['17', '42']})
        self.assertEqual(result['return_value'], '0x3b')
        self.assertTrue(result['ok'])

    def test_arm64_aapcs_register_arguments(self):
        result = emulate_image(image(bytes.fromhex('0000018bc0035fd6'), arch='arm64'), {'args': ['17', '42']})
        self.assertEqual(result['arch'], 'arm64')
        self.assertEqual(result['abi'], 'aapcs64')
        self.assertTrue(result['ok'])
        self.assertEqual(result['return_value'], '0x3b')

    def test_memory_result_and_original_unchanged(self):
        original = bytes.fromhex('4889c8488902c3')
        result = emulate_image(image(original), {'args': ['0x2a', '0x200000'],
            'memory': [{'ea': '0x200000', 'hex': '0000000000000000'}],
            'capture': [{'ea': '0x200000', 'size': 8}]})
        self.assertTrue(result['ok'])
        self.assertEqual(result['memory'][0]['hex'], '2a00000000000000')
        self.assertEqual(original.hex(), '4889c8488902c3')

    def test_fault_and_instruction_limit(self):
        fault = emulate_image(image(bytes.fromhex('488b042500002000c3')), {})
        self.assertFalse(fault['ok'])
        self.assertEqual(fault['reason'], 'unmapped-memory')
        self.assertEqual(fault['fault']['ea'], '0x200000')
        limited = emulate_image(image(bytes.fromhex('ebfe')), {'max_instructions': 12})
        self.assertEqual(limited['reason'], 'instruction-limit')
        self.assertEqual(limited['instructions'], 12)

    def test_overflow_overlap_and_budget_rejected_before_read(self):
        def fail(*args):
            self.fail('invalid image must not read engine memory')
        with self.assertRaisesRegex(ValueError, 'outside'):
            MemoryImage('x86', 64, (1 << 64) - 1, [MemoryRegion((1 << 64) - 1, 2, fail)])
        with self.assertRaisesRegex(ValueError, 'overlap'):
            MemoryImage('x86', 64, 1, [MemoryRegion(1, 8, fail), MemoryRegion(4, 8, fail)])
        with self.assertRaisesRegex(ValueError, 'budget'):
            MemoryImage('x86', 64, 1, [MemoryRegion(1, MEMORY_BUDGET + 1, fail)])

    def test_halt_is_not_reported_as_timeout(self):
        result = emulate_image(image(b'\xf4'), {'timeout_ms': 1000})
        self.assertFalse(result['ok'])
        self.assertEqual(result['instructions'], 1)
        self.assertEqual(result['reason'], 'halt')

    def test_real_timeout_uses_native_stop_query(self):
        result = emulate_image(image(b'\xeb\xfe'), {'timeout_ms': 10, 'max_instructions': 1000000})
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], 'timeout')
        self.assertLess(result['instructions'], 1000000)

    def test_oversized_payload_rejected_before_hex_decode(self):
        class Decoder:
            @staticmethod
            def fromhex(value):
                raise AssertionError('must reject oversized text before allocating decoded memory')
        with patch('cpu_emulator.bytes', Decoder, create=True):
            with self.assertRaisesRegex(ValueError, 'encoded memory'):
                emulate_image(image(b'\xc3'), {'memory': [{'ea': '0x200000', 'hex': 'aa' * 65537}]})

    def test_os_instructions_do_not_report_successful_function_return(self):
        for code, arch, bits in [(b'\x0f\x05\xc3', 'x86', 64), (b'\x0f\x34\xc3', 'x86', 32), (b'\xcd\x80\xc3', 'x86', 32), (bytes.fromhex('010000d4c0035fd6'), 'arm64', 64)]:
            result = emulate_image(image(code, arch=arch, bits=bits), {})
            self.assertFalse(result['ok'])
            self.assertEqual(result['reason'], 'unsupported-system')
            self.assertIsNotNone(result['systemInstruction'])

    def test_stack_collision_includes_supplied_buffers(self):
        with self.assertRaisesRegex(ValueError, 'collides'):
            emulate_image(image(b'\xc3'), {'memory': [{'ea': '0x700000000000', 'hex': '01'}]})

    def test_input_errors_do_not_read_memory(self):
        sample = MemoryImage('x86', 64, 0x1000, [MemoryRegion(0x1000, 1, lambda *args: self.fail('read before validation'))])
        for params in ({'registers': {'rax': '-1'}}, {'args': [True]},
                       {'capture': [{'ea': '0x1000', 'size': 65537}]}, {'abi': 'aapcs64'}):
            with self.assertRaises(ValueError):
                emulate_image(sample, params)

    def test_missing_bytes_are_explicit_and_partial_reads_rejected(self):
        sample = MemoryImage('x86', 64, 0x1000, [MemoryRegion(0x1000, 1, lambda *args: None)])
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            list(sample.chunks())
        zero = MemoryImage('x86', 64, 0x1000, [MemoryRegion(0x1000, 1, lambda *args: None, zero_fill=True)])
        self.assertEqual(list(zero.chunks()), [(0x1000, None, 1)])
        short = MemoryImage('x86', 64, 0x1000, [MemoryRegion(0x1000, 2, lambda *args: b'\xc3')])
        with self.assertRaisesRegex(ValueError, 'partial'):
            list(short.chunks())


if __name__ == '__main__':
    unittest.main()
