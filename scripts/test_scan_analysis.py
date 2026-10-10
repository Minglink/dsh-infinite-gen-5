"""Shared scan vectors and optional real-engine fixture acceptance.

Run with --runtime both on the validated Windows maintenance machine. Generated
PE bytes are analyzed only, never executed, and the original sample is unused.
"""
from pathlib import Path
import argparse
import hashlib
import json
import math
import os
import queue
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'worker'))
from scan_analysis import AES_SBOX, AES_INV_SBOX, MD5_K, SHA256_K, SHA512_K, CRC32_K, scan_image, words, CHUNK_SIZE


def segment(data, base=0x1000, name='.data'):
    return {'name': name, 'start': base, 'size': len(data), 'read': lambda offset, size: data[offset:offset + size]}


def cube_root(number):
    low, high = 0, 1 << ((number.bit_length() + 2) // 3)
    while low < high:
        middle = (low + high + 1) // 2
        if middle ** 3 <= number:
            low = middle
        else:
            high = middle - 1
    return low


def reference_sha(width):
    return tuple(cube_root(prime << (width * 3)) - (cube_root(prime) << width)
                 for prime in (2, 3, 5, 7, 11, 13, 17, 19))


def gf_multiply(left, right):
    value = 0
    for _ in range(8):
        if right & 1:
            value ^= left
        left = (left << 1) ^ (0x11b if left & 0x80 else 0)
        right >>= 1
    return value


def reference_aes():
    values = []
    for value in range(256):
        inverse = 0 if value == 0 else next(candidate for candidate in range(1, 256) if gf_multiply(value, candidate) == 1)
        mapped = inverse ^ 0x63
        for shift in range(1, 5):
            mapped ^= ((inverse << shift) | (inverse >> (8 - shift))) & 0xff
        values.append(mapped)
    return bytes(values)


class ScanTests(unittest.TestCase):
    def scan(self, data, **kwargs):
        return scan_image([segment(data)], source_engine='test', **kwargs)

    def test_constants_independently_derived(self):
        self.assertEqual(AES_SBOX, reference_aes())
        self.assertEqual(SHA256_K, reference_sha(32))
        self.assertEqual(SHA512_K, reference_sha(64))
        self.assertEqual(MD5_K, tuple(int(abs(math.sin(index)) * (1 << 32)) for index in range(1, 9)))
        for index, expected in enumerate(CRC32_K):
            value = index
            for _ in range(8):
                value = (value >> 1) ^ (0xedb88320 if value & 1 else 0)
            self.assertEqual(value, expected)

    def test_sha_width_and_both_byte_orders(self):
        for name, constants, width in [('SHA-256', SHA256_K, 4), ('SHA-512', SHA512_K, 8)]:
            for order in ('little', 'big'):
                output = self.scan(words(constants, width, order))
                hit = output['crypto_markers'][0]
                self.assertIn(name, hit['name'])
                self.assertEqual(hit['evidence']['verifiedBytes'], width * 8)
                self.assertEqual(hit['evidence']['byteOrder'], order)
                self.assertEqual(hit['kind'], 'hash')
        self.assertEqual(self.scan(bytes.fromhex('428a2f98d728ae22'))['crypto_markers'], [])

    def test_md5_and_crc_both_byte_orders(self):
        md5 = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
        for order in ('little', 'big'):
            hits = self.scan(words(md5, 4, order) + b'gap' + words(CRC32_K, 4, order))['crypto_markers']
            self.assertEqual([row['kind'] for row in hits], ['hash', 'checksum'])
            self.assertEqual([row['evidence']['byteOrder'] for row in hits], [order, order])
            self.assertEqual(hits[0]['confidence'], 'medium')
            self.assertIn('SHA-1', hits[0]['evidence']['candidateAlgorithms'])
        self.assertEqual(self.scan(bytes.fromhex('0123456789abcdef0000000096300777'))['crypto_markers'], [])

    def test_aes_full_and_partial_evidence(self):
        hits = self.scan(AES_SBOX + b'gap' + AES_INV_SBOX)['crypto_markers']
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(row['confidence'] == 'high' and row['evidence']['verifiedBytes'] == 256 for row in hits))
        self.assertTrue(all(row['kind'] == 'cipher' for row in hits))
        partial = self.scan(AES_SBOX[:32])['crypto_markers'][0]
        self.assertEqual(partial['confidence'], 'medium')
        self.assertEqual(partial['evidence']['verifiedBytes'], 32)
        self.assertEqual(self.scan(AES_SBOX[:8])['crypto_markers'], [])

    def test_multiple_matches_and_bound(self):
        data = (words(SHA256_K, 4, 'little') + b'!') * 10
        result = self.scan(data, params={'max_matches': 3})
        self.assertEqual(len(result['crypto_markers']), 3)
        self.assertTrue(result['truncation']['matches'])
        self.assertEqual(result['crypto_markers'][1]['ea'], hex(0x1000 + 33))

    def test_contiguous_chunk_boundary_and_full_upgrade(self):
        offset = CHUNK_SIZE - 50
        result = self.scan(b'\xff' * offset + AES_SBOX + b'\xff' * 400)
        hit = result['crypto_markers'][0]
        self.assertEqual(len(result['crypto_markers']), 1)
        self.assertEqual(hit['ea'], hex(0x1000 + offset))
        self.assertEqual(hit['evidence']['verifiedBytes'], 256)

    def test_no_synthetic_pattern_across_unreadable_gap(self):
        pattern = words(SHA256_K, 4, 'big')
        calls = []
        def reader(offset, size):
            calls.append((offset, size))
            return pattern[:16] if offset == 0 else pattern[16:]
        result = scan_image([{'name': 'holes', 'start': 0, 'size': CHUNK_SIZE + 16, 'read': reader}], source_engine='test')
        self.assertEqual(result['crypto_markers'], [])
        self.assertTrue(result['truncated'])
        self.assertEqual(result['entropies'][0]['readFailures'], 1)
        self.assertEqual(result['entropies'][0]['failedRanges'][0]['reason'], 'short-read')

    def test_sparse_sampling_and_global_budget(self):
        data = bytearray(1000)
        data[-32:] = words(SHA256_K, 4, 'little')
        result = scan_image([segment(data), segment(bytes(100), base=0x5000)], source_engine='test',
                            params={'max_bytes': 120, 'max_segment_bytes': 120})
        self.assertEqual(result['crypto_markers'][0]['ea'], hex(0x1000 + 968))
        self.assertEqual(result['coverage']['bytesAttempted'], 120)
        self.assertEqual(result['entropies'][1]['sampledBytes'], 0)
        self.assertTrue(result['truncated'])

    def test_unreadable_and_provider_error_explicit(self):
        def broken(offset, size):
            raise ValueError('private provider path must not leak')
        result = scan_image([{'name': 'bss', 'start': 0, 'size': 12, 'readable': False, 'skipReason': 'uninitialized memory'},
                             {'name': 'error', 'start': 32, 'size': 12, 'read': broken}], source_engine='test')
        self.assertIsNone(result['entropies'][0]['entropy'])
        self.assertEqual(result['entropies'][0]['skipReason'], 'uninitialized memory')
        self.assertEqual(result['entropies'][1]['readFailures'], 1)
        self.assertNotIn('private', json.dumps(result))

    def test_entropy_is_only_a_clue(self):
        high = self.scan(bytes(range(256)) * 4)['entropies'][0]
        low = self.scan(bytes(1024))['entropies'][0]
        short = self.scan(bytes(range(255)))['entropies'][0]
        self.assertEqual(high['entropy'], 8.0)
        self.assertTrue(high['flag'])
        self.assertFalse(low['flag'])
        self.assertFalse(short['flag'])
        self.assertIn('only', high['interpretation'])

    def test_constant_entropy_has_positive_zero_json(self):
        for byte, size in ((0, 1), (0, 1024), (0xff, 1024)):
            with self.subTest(byte=byte, size=size):
                output = self.scan(bytes([byte]) * size)
                entropy = output['entropies'][0]['entropy']
                self.assertEqual(entropy, 0.0)
                self.assertEqual(math.copysign(1.0, entropy), 1.0)
                # JSON round trips preserve the sign, so equality with 0 alone
                # would miss the strict host validator's negative-zero failure.
                restored = json.loads(json.dumps(output))['entropies'][0]['entropy']
                self.assertEqual(math.copysign(1.0, restored), 1.0)
        # No observed bytes remains unknown rather than fabricated zero entropy.
        empty = self.scan(b'')['entropies'][0]
        self.assertEqual(empty['sampledBytes'], 0)
        self.assertIsNone(empty['entropy'])

    def test_contract_imports_and_legacy_aliases(self):
        imports = [{'module': 'bcrypt.dll', 'api': '__imp_BCryptDecrypt@24', 'ea': '0x1234', 'addressSpace': 'memory'},
                   {'module': 'libssl', 'api': 'SSL_read'}, {'module': 'winsock', 'api': 'recv'},
                   {'module': 'fixture', 'api': 'my_send_helper'}]
        result = self.scan(AES_SBOX, imports=imports, strings=['AES-256 encrypt', 'https://example.invalid', 'plain'])
        self.assertEqual(result['schemaVersion'], 2)
        self.assertIs(result['crypto'], result['crypto_markers'])
        self.assertIs(result['entropy'], result['entropies'])
        self.assertIs(result['suspiciousApis'], result['suspicious_apis'])
        self.assertEqual([row['category'] for row in result['suspicious_apis']], ['crypto', 'network', 'network'])
        self.assertEqual(result['suspicious_apis'][0]['ea'], '0x1234')
        self.assertEqual(result['stringFamilies']['total'], 3)
        self.assertEqual(result['stringFamilies']['network'], 1)
        self.assertFalse(result['idb_modified'])

    def test_metadata_and_string_budgets(self):
        result = scan_image([segment(b'!'), segment(b'?')],
                            [{'api': 'recv'}] * 3, ['aes'] * 3, source_engine='test',
                            params={'max_segments': 1, 'max_imports': 2, 'max_strings': 2, 'max_api_matches': 1})
        self.assertEqual(result['coverage']['segments'], 1)
        self.assertEqual(result['importSummary']['functions'], 2)
        self.assertEqual(result['stringFamilies']['total'], 2)
        self.assertEqual(len(result['suspicious_apis']), 1)
        for key in ('segments', 'imports', 'strings', 'api_matches'):
            self.assertTrue(result['truncation'][key])

    def test_budget_argument_validation(self):
        for value in (0, -1, True, '10', 1.5, 64 * 1024 * 1024 + 1):
            with self.assertRaises(ValueError):
                self.scan(b'!', params={'max_bytes': value})

    def test_string_materialization_and_read_evidence(self):
        result = self.scan(b'!', strings=[{'text': 'aes key', 'truncated': True}, {'text': '', 'readError': True}, 'network' * 10],
                           params={'max_string_chars': 8})
        self.assertTrue(result['truncation']['string_reads'])
        self.assertTrue(result['truncation']['string_chars'])
        self.assertEqual(result['coverage']['stringReadFailures'], 1)
        self.assertEqual(result['coverage']['stringsShortened'], 2)
        self.assertEqual(result['stringFamilies']['total'], 3)

    def test_address_precision_and_numeric_rejection(self):
        address = 0x8000000000012345
        hit = scan_image([segment(AES_SBOX, base=address)], source_engine='test')['crypto_markers'][0]
        self.assertEqual(hit['ea'], hex(address))
        for start, size in [(True, 1), (1.5, 1), (1, True), (1, 1.5), (-1, 1)]:
            with self.assertRaises(ValueError):
                scan_image([{'start': start, 'size': size, 'read': lambda offset, length: b'!'}], source_engine='test')

    def test_non_default_address_space_is_not_a_flat_va(self):
        overlay = segment(AES_SBOX)
        overlay.update(addressSpace='overlay', sourceAddress='overlay:00001000')
        result = scan_image([overlay], source_engine='test')
        self.assertEqual(result['crypto_markers'], [])
        self.assertEqual(result['coverage']['bytesAttempted'], 0)
        self.assertIsNone(result['entropies'][0]['ea'])
        self.assertEqual(result['entropies'][0]['sourceAddress'], 'overlay:00001000')

    def test_adjacent_samples_preserve_continuity(self):
        # A one-byte unsampled gap precedes adjacent middle/suffix windows.
        data = b'!' * 32 + words(SHA256_K, 4, 'little') + b'!' * 32
        result = self.scan(data, params={'max_bytes': len(data) - 1})
        self.assertEqual(result['crypto_markers'][0]['ea'], '0x1020')


def pe_fixture():
    image = bytearray(0x1400)
    def u16(offset, value): struct.pack_into('<H', image, offset, value)
    def u32(offset, value): struct.pack_into('<I', image, offset, value)
    def u64(offset, value): struct.pack_into('<Q', image, offset, value)
    def raw(rva): return rva - 0x1000 + 0x200 if rva < 0x2000 else rva - 0x2000 + 0x400
    def text(offset, value): image[offset:offset + len(value)] = value
    text(0, b'MZ'); u32(0x3c, 0x80); text(0x80, b'PE\0\0')
    u16(0x84, 0x8664); u16(0x86, 2); u16(0x94, 0xf0); u16(0x96, 0x22)
    optional = 0x98
    u16(optional, 0x20b); u32(optional + 4, 0x200); u32(optional + 8, 0x1000)
    u32(optional + 16, 0x1000); u32(optional + 20, 0x1000); u64(optional + 24, 0x140000000)
    u32(optional + 32, 0x1000); u32(optional + 36, 0x200)
    u16(optional + 40, 6); u16(optional + 48, 6)
    u32(optional + 56, 0x3000); u32(optional + 60, 0x200); u16(optional + 68, 3)
    u64(optional + 72, 0x100000); u64(optional + 80, 0x1000); u64(optional + 88, 0x100000); u64(optional + 96, 0x1000)
    u32(optional + 108, 16); u32(optional + 120, 0x2000); u32(optional + 124, 60)
    for index, name, rva, offset, size, perm in [(0, b'.text', 0x1000, 0x200, 0x200, 0x60000020),
                                                (1, b'.rdata', 0x2000, 0x400, 0x1000, 0x40000040)]:
        section = optional + 0xf0 + 40 * index
        text(section, name); u32(section + 8, size); u32(section + 12, rva)
        u32(section + 16, size); u32(section + 20, offset); u32(section + 36, perm)
    image[0x200:0x400] = b'\xcc' * 0x200
    text(0x200, b'\xff\x15' + struct.pack('<i', 0x2120 - 0x1006) + b'\xff\x15' + struct.pack('<i', 0x2160 - 0x100c) + b'\xc3')
    for index, module, name, oft, iat, module_rva, name_rva in [
            (0, b'WS2_32.dll\0', b'recv\0', 0x2100, 0x2120, 0x2080, 0x2180),
            (1, b'bcrypt.dll\0', b'BCryptDecrypt\0', 0x2140, 0x2160, 0x20a0, 0x21a0)]:
        descriptor = raw(0x2000) + index * 20
        u32(descriptor, oft); u32(descriptor + 12, module_rva); u32(descriptor + 16, iat)
        text(raw(module_rva), module); text(raw(name_rva), b'\0\0' + name)
        u64(raw(oft), name_rva); u64(raw(iat), name_rva)
    for rva, data in [(0x2400, AES_SBOX), (0x2500, words(SHA256_K, 4, 'little')),
                      (0x2540, words(SHA512_K, 8, 'big')), (0x2600, words(CRC32_K, 4, 'little')),
                      (0x2640, b'https://example.invalid/api\0AES-256 encrypt config\0')]:
        text(raw(rva), data)
    return bytes(image)


def runtime_test(engine):
    scratch = Path(tempfile.mkdtemp(prefix='ig5-scan-'))
    target = scratch / '扫描只读夹具.exe'
    image = pe_fixture(); target.write_bytes(image)
    env = os.environ.copy()
    if engine == 'ghidra':
        runtime_root = ROOT / 'runtimes' / 'ghidra'
        runtime = json.loads((runtime_root / 'runtime.json').read_text(encoding='utf-8-sig'))
        command = [str(runtime_root / runtime['pythonExe']), '-I', '-B', str(ROOT / 'adapters/ghidra/worker.py')]
        env.update(IG5_GHIDRA_HOME=str(runtime_root / runtime['ghidraHome']), IG5_JAVA_HOME=str(runtime_root / runtime['javaHome']),
                   IG5_GHIDRA_PROJECT_ROOT=str(scratch / 'projects'))
    else:
        engine_root = Path(os.environ.get('IG5_IDA_DIR', r'C:\Users\Administrator\Desktop\IDA Professional 9.2'))
        command = [str(engine_root / 'python311/python.exe'), '-B', str(ROOT / 'worker/ig5_worker.py'), '--ida-dir', str(engine_root)]
    messages = queue.Queue()
    with (scratch / 'stderr.log').open('w', encoding='utf-8') as log:
        process = subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                                   encoding='utf-8', creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        def read():
            for line in process.stdout:
                messages.put(line)
            messages.put(None)
        reader = threading.Thread(target=read, daemon=True); reader.start()
        counter = 0
        def receive(predicate, ready=False):
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                line = messages.get(timeout=max(0.1, deadline - time.monotonic()))
                if line is None:
                    raise AssertionError('owned worker exited; see ' + str(scratch / 'stderr.log'))
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    if ready or engine == 'reverse':
                        continue
                    raise AssertionError('non-JSON stdout: ' + line)
                if predicate(message):
                    if message.get('error'):
                        raise AssertionError(message['error'])
                    return message
            raise AssertionError('RPC timeout')
        def rpc(method, params=None):
            nonlocal counter
            counter += 1
            process.stdin.write(json.dumps({'id': counter, 'method': method, 'params': params or {}}, ensure_ascii=False) + '\n')
            process.stdin.flush()
            return receive(lambda message: message.get('id') == counter and ('result' in message or 'error' in message))['result']
        try:
            greeting = receive(lambda message: message.get('ig5') == 'ready', ready=True)
            assert 'scan' in greeting['capabilities']
            opened = rpc('open', {'path': str(target), 'auto': True, 'fresh': True})
            before = rpc('stats')
            output = rpc('scan')
            assert output['schemaVersion'] == 2 and output['sourceEngine'] == engine
            assert output['idb_modified'] is False
            expected = [('AES S-box', '0x140002400'), ('SHA-256 round constants', '0x140002500'),
                        ('SHA-512 round constants', '0x140002540'), ('CRC32 reflected table', '0x140002600')]
            for name, ea in expected:
                assert any(row['name'] == name and row['ea'] == ea for row in output['crypto_markers']), (name, output)
            apis = {row['api'].lower(): row for row in output['suspicious_apis']}
            assert apis['recv']['category'] == 'network'
            assert apis['bcryptdecrypt']['category'] == 'crypto'
            assert all(apis[name]['ea'].startswith('0x14000') for name in ('recv', 'bcryptdecrypt'))
            assert output['stringFamilies']['network'] >= 1 and output['stringFamilies']['crypto'] >= 1
            limited = rpc('scan', {'max_bytes': 200, 'max_segment_bytes': 100, 'max_matches': 1})
            assert limited['coverage']['bytesAttempted'] <= 200 and limited['truncated']
            after = rpc('stats')
            if engine == 'ghidra':
                assert after['revision'] == before['revision']
                assert after['modificationNumber'] == before['modificationNumber']
            rpc('close')
            assert hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(image).digest()
            report = {'ok': True, 'engine': engine, 'fixtureSHA256': hashlib.sha256(image).hexdigest(),
                      'capabilities': greeting['capabilities'], 'open': opened, 'scan': output, 'boundedScan': limited,
                      'sourceUnchanged': True, 'targetExecuted': False}
            (scratch / 'acceptance.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
            print(json.dumps({'ok': True, 'engine': engine, 'markers': len(output['crypto_markers']),
                              'apis': list(apis), 'artifacts': str(scratch)}, ensure_ascii=False))
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=10)
            reader.join(timeout=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', choices=('reverse', 'ghidra', 'both'))
    args = parser.parse_args()
    results = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ScanTests))
    if not results.wasSuccessful():
        sys.exit(1)
    if args.runtime:
        for engine in ('reverse', 'ghidra') if args.runtime == 'both' else (args.runtime,):
            runtime_test(engine)
