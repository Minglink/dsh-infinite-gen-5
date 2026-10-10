"""Real bundled Unicorn execution; no commercial engine or debuggee process."""
import os
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))
from memory_image import MemoryImage, MemoryRegion, MEMORY_BUDGET, PAGE_SIZE, PERM_READ, PERM_WRITE, PERM_EXEC
from cpu_emulator import emulate_image


def image(code, arch='x86', bits=64, base=0x100000, permissions=PERM_READ | PERM_EXEC):
    return MemoryImage(arch, bits, base,
                       [MemoryRegion(base, len(code), lambda offset, length: code[offset:offset + length], permissions=permissions)],
                       source='standalone-fixture')


def region(base, data, permissions):
    return MemoryRegion(base, len(data), lambda offset, length: data[offset:offset + length], permissions=permissions)


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

    def test_permission_masks_match_native_unicorn_and_validate_before_read(self):
        from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
        self.assertEqual((PERM_READ, PERM_WRITE, PERM_EXEC), (UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC))
        for permission in (True, -1, 8, '5', 1.5):
            with self.assertRaisesRegex(ValueError, 'permissions'):
                MemoryRegion(0x1000, 1, lambda *args: self.fail('invalid permissions must not read'), permissions=permission)

    def test_rx_function_return_uses_rw_stack_and_non_executable_sentinel(self):
        # PUSH/POP/RET exercise real stack accesses and the sentinel end check.
        result = emulate_image(image(bytes.fromhex('50b82a0000005850b82a00000059c3')), {})
        self.assertTrue(result['ok'])
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['return_value'], '0x2a')
        self.assertEqual(result['protectionMode'], 'engine-page-permissions')
        self.assertEqual(result['unknownPermissionRegions'], 0)

    def test_synthetic_stack_is_non_executable(self):
        result = emulate_image(image(bytes.fromhex('ffe4')), {})  # JMP RSP.
        self.assertEqual(result['reason'], 'memory-protection')
        self.assertEqual(result['fault']['accessType'], 'execute')
        self.assertEqual(result['fault']['permissions'], PERM_READ | PERM_WRITE)

    def test_total_page_budget_includes_synthetic_stack_before_snapshot_read(self):
        sample = MemoryImage('x86', 64, 0x1000,
            [MemoryRegion(0x1000, MEMORY_BUDGET, lambda *args: self.fail('budget must fail before snapshot read'), permissions=5)])
        with self.assertRaisesRegex(ValueError, 'budget'):
            emulate_image(sample, {})

    def test_rw_data_allows_real_cpu_read_and_write(self):
        code = bytes.fromhex('c6015a0fb601c3')
        sample = MemoryImage('x86', 64, 0x1000, [region(0x1000, code, 5), region(0x3000, b'\x11', 3)])
        result = emulate_image(sample, {'args': ['0x3000'], 'capture': [{'ea': '0x3000', 'size': 1}]})
        self.assertTrue(result['ok'])
        self.assertEqual(result['return_value'], '0x5a')
        self.assertEqual(result['memory'][0]['hex'], '5a')

    def test_read_only_page_rejects_write_and_reports_native_fault(self):
        sample = MemoryImage('x86', 64, 0x1000, [region(0x1000, bytes.fromhex('c6015ac3'), 5), region(0x3000, b'\x11', 1)])
        result = emulate_image(sample, {'args': ['0x3000'], 'capture': [{'ea': '0x3000', 'size': 1}]})
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], 'memory-protection')
        self.assertEqual(result['fault']['kind'], 'protection')
        self.assertEqual(result['fault']['accessType'], 'write')
        self.assertEqual(result['fault']['permissions'], 1)
        self.assertEqual(result['memory'][0]['hex'], '11')

    def test_nx_page_rejects_execute(self):
        sample = MemoryImage('x86', 64, 0x1000, [region(0x1000, bytes.fromhex('ffe1'), 5), region(0x3000, b'\xc3', 3)])
        result = emulate_image(sample, {'args': ['0x3000']})
        self.assertEqual(result['reason'], 'memory-protection')
        self.assertEqual(result['fault']['accessType'], 'execute')
        self.assertEqual(result['fault']['ea'], '0x3000')
        self.assertEqual(result['fault']['permissions'], 3)

    def test_no_access_page_rejects_read_write_and_execute(self):
        for code, access in [('0fb601c3', 'read'), ('c6015ac3', 'write'), ('ffe1', 'execute')]:
            sample = MemoryImage('x86', 64, 0x1000, [region(0x1000, bytes.fromhex(code), 5), region(0x3000, b'\xc3', 0)])
            result = emulate_image(sample, {'args': ['0x3000']})
            self.assertFalse(result['ok'])
            self.assertEqual(result['reason'], 'memory-protection')
            self.assertEqual(result['fault']['accessType'], access)
            self.assertEqual(result['fault']['permissions'], 0)

    def test_supplied_buffers_do_not_upgrade_engine_or_existing_page_permissions(self):
        # Both an existing byte and unused bytes on its RX page remain RX.
        for address in (0x1000, 0x1100):
            sample = image(bytes.fromhex('c6015ac3'), base=0x1000)
            result = emulate_image(sample, {'args': [address],
                'memory': [{'ea': hex(address), 'hex': 'c6' if address == 0x1000 else '11'}]})
            self.assertEqual(result['reason'], 'memory-protection')
            self.assertEqual(result['fault']['accessType'], 'write')
            self.assertEqual(result['fault']['permissions'], 5)

    def test_supplied_new_pages_are_rw_and_nx(self):
        result = emulate_image(image(bytes.fromhex('ffe1')), {'args': ['0x3000'], 'memory': [{'ea': '0x3000', 'hex': 'c3'}]})
        self.assertEqual(result['reason'], 'memory-protection')
        self.assertEqual(result['fault']['accessType'], 'execute')
        self.assertEqual(result['fault']['permissions'], 3)

    def test_byte_disjoint_regions_use_bounded_page_union(self):
        # RX code and writable data share one 4-KiB page; its page union is RWX.
        sample = MemoryImage('x86', 64, 0x1000, [region(0x1000, bytes.fromhex('c6015ac3'), 5), region(0x1100, b'\x11', 3)])
        self.assertEqual(dict(sample.page_permissions), {0x1000: 7})
        result = emulate_image(sample, {'args': ['0x1100'], 'capture': [{'ea': '0x1100', 'size': 1}]})
        self.assertTrue(result['ok'])
        self.assertEqual(result['memory'][0]['hex'], '5a')
        self.assertEqual(result['pagePermissionMerges'], 1)
        self.assertEqual(result['pageSize'], PAGE_SIZE)
        self.assertTrue(any('permission union' in item for item in result['limitations']))
        with self.assertRaises(TypeError):
            sample.page_permissions[0x1000] = 0

    def test_unknown_permissions_are_explicit_rwx_compatibility(self):
        result = emulate_image(image(b'\xc3', permissions=None), {})
        self.assertTrue(result['ok'])
        self.assertEqual(result['protectionMode'], 'engine-page-permissions-with-unknown-rwx')
        self.assertEqual(result['unknownPermissionRegions'], 1)
        self.assertEqual(result['unknownPermissionPages'], 1)
        self.assertTrue(any('Unknown engine permissions' in item for item in result['limitations']))
        sample = MemoryImage('x86', 64, 0x1000, [region(0x1000, bytes.fromhex('c6015ac3'), 5), region(0x1100, b'\x11', None)])
        self.assertEqual(sample.page_permissions[0x1000], 7)
        result = emulate_image(sample, {'args': ['0x1100']})
        self.assertTrue(result['ok'])
        self.assertEqual(result['unknownPermissionPages'], 1)

    def test_arm64_nx_and_read_only_protection_are_real_native_faults(self):
        # BR X0 and STRB W1,[X0]; RET.
        for code, permission, access in [('00001fd6', 3, 'execute'), ('01000039c0035fd6', 1, 'write')]:
            sample = MemoryImage('arm64', 64, 0x1000, [region(0x1000, bytes.fromhex(code), 5), region(0x3000, bytes.fromhex('c0035fd6'), permission)])
            result = emulate_image(sample, {'args': ['0x3000', '0x5a']})
            self.assertEqual(result['reason'], 'memory-protection')
            self.assertEqual(result['fault']['accessType'], access)

    def test_reverse_provider_maps_native_masks_and_zero_means_unknown(self):
        # Synthetic engine APIs exercise the actual provider; CPU execution is
        # real Unicorn. Native provider acceptance is a separate generated PE.
        import execution_analysis
        code = bytes.fromhex('c6015ac3')
        for native_permission, expected in ((4, 1), (6, 3), (0, None)):
            segments = [SimpleNamespace(start_ea=0x1000, end_ea=0x1004, perm=5),
                        SimpleNamespace(start_ea=0x3000, end_ea=0x3001, perm=native_permission)]
            def read(address, size):
                data = code[address - 0x1000:address - 0x1000 + size] if address < 0x3000 else b'\x11'
                return data
            modules = {'ida_bytes': SimpleNamespace(get_bytes=read),
                       'ida_segment': SimpleNamespace(get_segm_qty=lambda: 2, getnseg=lambda index: segments[index],
                           get_segm_name=lambda segment: 'fixture', SEGPERM_READ=4, SEGPERM_WRITE=2, SEGPERM_EXEC=1),
                       'ida_ida': SimpleNamespace(inf_get_procname=lambda: 'metapc', inf_is_64bit=lambda: True)}
            with patch.dict(sys.modules, modules), patch.object(execution_analysis, '_function', return_value=SimpleNamespace(start_ea=0x1000)):
                result = execution_analysis.m_emulate({'ea': '0x1000', 'args': ['0x3000']})
            if expected == 1:
                self.assertEqual(result['reason'], 'memory-protection')
                self.assertEqual(result['fault']['permissions'], 1)
            else:
                self.assertTrue(result['ok'])
            self.assertEqual(result['unknownPermissionRegions'], int(expected is None))


if __name__ == '__main__':
    unittest.main()
