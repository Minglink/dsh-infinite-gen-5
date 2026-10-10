"""Bounded, engine-independent static indicators; findings are evidence, not keys.

Providers expose segments with a ``read(offset, size)`` callable. Missing ranges
are never filled with synthetic zeroes, and sampling coverage is always returned.
No target execution, database writes, packet capture or network access occurs.
"""
from __future__ import annotations

from collections import Counter
from itertools import islice
import math
import re


AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
AES_INV_SBOX = bytes(AES_SBOX.index(index) for index in range(256))
MD5_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
MD5_K = (0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
         0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501)
SHA256_K = (0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
            0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5)
SHA512_K = (0x428A2F98D728AE22, 0x7137449123EF65CD,
            0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
            0x3956C25BF348B538, 0x59F111F1B605D019,
            0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118)
CRC32_K = (0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
           0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3)


def words(values, width, order):
    return b''.join(value.to_bytes(width, order) for value in values)


def marker_patterns():
    rows = []
    for name, data in (('AES S-box', AES_SBOX), ('AES inverse S-box', AES_INV_SBOX)):
        for pattern in (data, data[:32]):
            rows.append({'name': name, 'pattern': pattern, 'kind': 'constant-table',
                         'byteOrder': 'bytes', 'confidence': 'high' if len(pattern) == 256 else 'medium',
                         'tableBytes': 256})
    for name, values, width, kind in (
            ('Shared MD5/SHA-1 initial words', MD5_IV, 4, 'initial-state'),
            ('MD5 round constants', MD5_K, 4, 'constant-table'),
            ('SHA-256 round constants', SHA256_K, 4, 'constant-table'),
            ('SHA-512 round constants', SHA512_K, 8, 'constant-table'),
            ('CRC32 reflected table', CRC32_K, 4, 'constant-table')):
        for order in ('little', 'big'):
            rows.append({'name': name, 'pattern': words(values, width, order),
                         'kind': kind, 'byteOrder': order, 'confidence': 'medium' if kind == 'initial-state' else 'high',
                         'tableBytes': len(values) * width})
    return tuple(rows)


PATTERNS = marker_patterns()
CHUNK_SIZE = 65536
OVERLAP = max(len(row['pattern']) for row in PATTERNS) - 1
LIMITS = {'max_bytes': (8 * 1024 * 1024, 64 * 1024 * 1024),
          'max_segment_bytes': (1024 * 1024, 16 * 1024 * 1024),
          'max_matches': (256, 4096), 'max_segments': (256, 4096),
          'max_imports': (20000, 100000), 'max_strings': (20000, 100000),
          'max_api_matches': (128, 4096), 'max_string_chars': (4096, 16384)}


def scan_limits(params=None):
    result = {}
    for key, (default, maximum) in LIMITS.items():
        value = (params or {}).get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise ValueError('%s must be an integer in 1..%d' % (key, maximum))
        result[key] = value
    return result


def sampled_ranges(size, budget):
    """Prefix/middle/suffix sampling, with no invented continuity across gaps."""
    if not budget or size <= 0:
        return []
    if size <= budget:
        return [(0, size)]
    if budget < 3:
        return [(0, budget)]
    first = budget // 3
    middle = budget // 3
    last = budget - first - middle
    ranges = [(0, first), ((size - middle) // 2, middle), (size - last, last)]
    merged = []
    for start, length in ranges:
        if merged and start == merged[-1][0] + merged[-1][1]:
            merged[-1] = (merged[-1][0], merged[-1][1] + length)
        else:
            merged.append((start, length))
    return merged


API_GROUPS = {
    'crypto': ('cryptencrypt', 'cryptdecrypt', 'cryptacquirecontext', 'cryptgenkey',
               'cryptderivekey', 'cryptimportkey', 'crypthashdata', 'cryptprotectdata',
               'cryptunprotectdata', 'bcryptencrypt', 'bcryptdecrypt', 'bcryptgeneratesymmetrickey',
               'bcryptderivekey', 'bcryptimportkey', 'bcryptcreatehash', 'bcrypthashdata',
               'bcryptgenrandom', 'ncryptdecrypt', 'ncryptencrypt', 'evp_encryptinit_ex',
               'evp_encryptupdate', 'evp_decryptinit_ex', 'evp_decryptupdate', 'aes_encrypt',
               'aes_decrypt', 'rc4', 'pk11_decrypt', 'pk11_encrypt'),
    'network': ('send', 'sendto', 'recv', 'recvfrom', 'wsasend', 'wsasendto', 'wsarecv',
                'wsarecvfrom', 'socket', 'connect', 'accept', 'bind', 'listen', 'getaddrinfo',
                'ssl_read', 'ssl_write', 'ssl_read_ex', 'ssl_write_ex', 'gnutls_record_recv',
                'gnutls_record_send', 'winhttpreaddata', 'winhttpwritedata', 'winhttpsendrequest',
                'winhttpconnect', 'internetreadfile', 'internetwritefile', 'internetopenurl',
                'httpsendrequest', 'urldownloadtofile'),
    'memory-execution': ('virtualalloc', 'virtualprotect', 'writeprocessmemory',
                         'createremotethread', 'ntallocatevirtualmemory', 'ntwritevirtualmemory',
                         'ntprotectvirtualmemory', 'mmap', 'mprotect'),
    'execution': ('winexec', 'shellexecute', 'createprocess', 'system', 'execve', 'popen'),
    'registry': ('regsetvalue', 'regsetvalueex'),
    'dynamic-loading': ('loadlibrary', 'loadlibraryex', 'getprocaddress', 'dlopen', 'dlsym'),
    'debug-detection': ('isdebuggerpresent', 'checkremotedebuggerpresent', 'ptrace'),
    'hooks': ('setwindowshookex',),
}
API_CATEGORIES = {name: category for category, names in API_GROUPS.items() for name in names}
STRING_GROUPS = {'crypto': ('aes', 'md5', 'sha1', 'sha-1', 'sha256', 'sha-256', 'sha512', 'sha-512', 'rsa', 'base64', 'rc4', 'decrypt', 'encrypt'),
                 'network': ('http', 'tcp', 'socket', 'dns', 'hostname', 'websocket', 'content-length'),
                 'exec': ('cmd.exe', 'powershell', 'schtasks', 'regsvr32', '/bin/sh'),
                 'registry': ('software\\', 'hkey_', 'currentversion')}


def api_category(name):
    cleaned = str(name).lower().split('@@')[0].split('@')[0]
    cleaned = re.sub(r'^(?:__imp_|imp_|_)+', '', cleaned)
    if cleaned in API_CATEGORIES:
        return API_CATEGORIES[cleaned]
    if cleaned.endswith(('a', 'w')):
        return API_CATEGORIES.get(cleaned[:-1])
    return None


def _address(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError('segment start must be an integer address')
    return int(value, 0) if isinstance(value, str) else int(value)


def scan_image(segments, imports=(), strings=(), *, source_engine, params=None):
    """Return a shared schema plus legacy aliases, with explicit bounded coverage."""
    limits = scan_limits(params)
    markers, entropy_rows = {}, []
    bytes_attempted = bytes_read = import_count = string_count = 0
    module_counts = Counter()
    api_rows = []
    flags = {'segments': False, 'bytes': False, 'matches': False,
             'imports': False, 'api_matches': False, 'strings': False, 'string_chars': False, 'string_reads': False}
    for index, segment in enumerate(islice(segments, limits['max_segments'] + 1)):
        if index == limits['max_segments']:
            flags['segments'] = True
            break
        name, start, size = str(segment.get('name', '')), _address(segment['start']), segment['size']
        if isinstance(size, bool) or not isinstance(size, int):
            raise ValueError('segment size must be an integer')
        if start < 0 or size < 0:
            raise ValueError('segment addresses and sizes must be nonnegative')
        address_space = str(segment.get('addressSpace', 'memory'))
        available = min(limits['max_segment_bytes'], limits['max_bytes'] - bytes_attempted)
        ranges = sampled_ranges(size, max(0, available)) if segment.get('readable', True) and address_space == 'memory' else []
        counts, failures, coverage, failed_ranges = Counter(), 0, [], []
        for offset, length in ranges:
            tail, cursor = b'', offset
            end = offset + length
            while cursor < end:
                requested = min(CHUNK_SIZE, end - cursor)
                bytes_attempted += requested
                reason = 'short-read'
                try:
                    data = segment['read'](cursor, requested)
                    if data is None:
                        data = b''
                        reason = 'unreadable'
                    if not isinstance(data, (bytes, bytearray, memoryview)):
                        raise TypeError('reader must return bytes')
                    data = bytes(data)
                    if len(data) > requested:
                        raise ValueError('reader returned more bytes than requested')
                except Exception:
                    data = b''
                    reason = 'reader-error'
                if len(data) != requested:
                    failures += 1
                    if len(failed_ranges) < 16:
                        failed_ranges.append({'ea': hex(start + cursor + len(data)), 'size': requested - len(data), 'reason': reason})
                if data:
                    counts.update(data)
                    bytes_read += len(data)
                    coverage.append({'start': hex(start + cursor), 'size': len(data)})
                    buffer = tail + data
                    base = start + cursor - len(tail)
                    for marker in PATTERNS:
                        position = buffer.find(marker['pattern'])
                        while position >= 0:
                            ea = base + position
                            key = (marker['name'], ea)
                            previous = markers.get(key)
                            if previous is None and len(markers) >= limits['max_matches']:
                                flags['matches'] = True
                                break
                            elif previous is None or previous['evidence']['verifiedBytes'] < len(marker['pattern']):
                                markers[key] = {'name': marker['name'], 'marker': marker['name'], 'ea': hex(ea),
                                                'kind': 'cipher' if marker['name'].startswith('AES') else 'checksum' if marker['name'].startswith('CRC') else 'hash',
                                                'constantRole': marker['kind'], 'confidence': marker['confidence'],
                                                'evidence': {'byteOrder': marker['byteOrder'], 'verifiedBytes': len(marker['pattern']),
                                                             'segment': name, 'claim': 'constant bytes match; algorithm use and keys are unproven'}}
                                if marker['kind'] == 'initial-state':
                                    markers[key]['evidence']['candidateAlgorithms'] = ['MD5', 'SHA-1', 'RIPEMD-160']
                            position = buffer.find(marker['pattern'], position + 1)
                    tail = buffer[-OVERLAP:] if len(data) == requested else b''
                else:
                    tail = b''
                cursor += requested
        sampled = sum(counts.values())
        entropy = -sum((count / sampled) * math.log2(count / sampled) for count in counts.values()) if sampled else None
        truncated = sampled < size
        flags['bytes'] |= truncated
        entropy_rows.append({'name': name, 'segment': name, 'ea': hex(start) if address_space == 'memory' else None,
                             'addressSpace': address_space, 'sourceAddress': segment.get('sourceAddress', hex(start)), 'size': size,
                             'sampledBytes': sampled, 'entropy': round(entropy, 4) if entropy is not None else None,
                             'flag': bool(sampled >= 256 and entropy is not None and entropy > 7.2),
                             'interpretation': 'high entropy is only a compression/encryption/random-data clue',
                             'coverage': coverage, 'truncated': truncated, 'readFailures': failures,
                             'failedRanges': failed_ranges, 'failedRangesTruncated': failures > len(failed_ranges),
                             'skipReason': segment.get('skipReason') if not ranges else None})
    for row in islice(imports, limits['max_imports'] + 1):
        if import_count == limits['max_imports']:
            flags['imports'] = True
            break
        import_count += 1
        module, api = str(row.get('module', ''))[:512], str(row.get('api', row.get('name', '')))[:512]
        module_counts[module] += 1
        category = api_category(api)
        if category:
            if len(api_rows) >= limits['max_api_matches']:
                flags['api_matches'] = True
                continue
            hit = {'module': module, 'api': api, 'category': category,
                   'interpretation': 'import presence is a lead; behavior is unproven'}
            for key in ('ea', 'addressSpace', 'addressRole', 'thunkEas', 'externalAddress', 'referenceEas', 'referencesTruncated'):
                if key in row:
                    hit[key] = row[key]
            api_rows.append(hit)
    families = {key: 0 for key in STRING_GROUPS}
    string_failures = string_truncations = 0
    for row in islice(strings, limits['max_strings'] + 1):
        if string_count == limits['max_strings']:
            flags['strings'] = True
            break
        string_count += 1
        text = str(row.get('text', '') if isinstance(row, dict) else row)
        shortened = len(text) > limits['max_string_chars'] or bool(isinstance(row, dict) and row.get('truncated'))
        unreadable = bool(isinstance(row, dict) and row.get('readError'))
        flags['string_chars'] |= shortened
        flags['string_reads'] |= unreadable
        string_truncations += int(shortened)
        string_failures += int(unreadable)
        text = text[:limits['max_string_chars']].lower()
        for family, words_in_family in STRING_GROUPS.items():
            if any(word in text for word in words_in_family):
                families[family] += 1
    families['total'] = string_count
    marker_rows = sorted(markers.values(), key=lambda row: (_address(row['ea']), row['name']))
    summary = {'modules': len(module_counts), 'functions': import_count,
               'byModule': dict(module_counts.most_common(12)), 'truncated': flags['imports']}
    return {'schemaVersion': 2, 'sourceEngine': source_engine, 'idb_modified': False,
            'crypto_markers': marker_rows, 'entropies': entropy_rows, 'suspicious_apis': api_rows,
            'stringFamilies': families, 'importSummary': summary,
            'coverage': {'bytesAttempted': bytes_attempted, 'bytesRead': bytes_read,
                         'segments': len(entropy_rows), 'imports': import_count, 'strings': string_count,
                         'stringReadFailures': string_failures, 'stringsShortened': string_truncations,
                         'sampling': 'bounded prefix/middle/suffix; unobserved bytes are not classified'},
            'limits': limits, 'truncated': any(flags.values()), 'truncation': flags,
            'crypto': marker_rows, 'entropy': entropy_rows, 'suspiciousApis': api_rows}
