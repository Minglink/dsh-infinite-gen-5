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
import struct

import feature_rules
import rule_match
from behavior_inventory import behavior_inventory
from behavior_rules import API_CATEGORIES, API_GROUPS, api_category, canonical, is_api_name_string  # noqa: F401  (re-exported for providers)


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
          'max_api_matches': (128, 4096), 'max_string_chars': (4096, 16384),
          'max_rule_matches': (256, 4096)}


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


STRING_GROUPS = {'crypto': ('aes', 'md5', 'sha1', 'sha-1', 'sha256', 'sha-256', 'sha512', 'sha-512', 'rsa', 'base64', 'rc4', 'decrypt', 'encrypt'),
                 'network': ('http', 'tcp', 'socket', 'dns', 'hostname', 'websocket', 'content-length'),
                 'exec': ('cmd.exe', 'powershell', 'schtasks', 'regsvr32', '/bin/sh'),
                 'registry': ('software\\', 'hkey_', 'currentversion'),
                 'persistence': ('currentversion\\run', 'schtasks', '/etc/cron', 'crontab', 'systemd', 'rc.local', '.bashrc', 'launchagents', 'startup\\'),
                 'anti-analysis': ('vmware', 'virtualbox', 'vboxservice', 'qemu', 'sbiedll', 'wireshark', 'procmon', 'x64dbg', 'ollydbg', 'sandbox')}


def _address(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError('segment start must be an integer address')
    return int(value, 0) if isinstance(value, str) else int(value)


def rule_source(params):
    """Return (source, origin, version) for the built-in or caller-supplied rule table."""
    params = params or {}
    if params.get('rules') is None:
        return feature_rules.RULES_SOURCE, 'builtin', feature_rules.RULES_VERSION
    source = params['rules']
    if not isinstance(source, str):
        raise ValueError('rules must be a string containing rule source text')
    if len(source.encode('utf-8')) > rule_match.MAX_SOURCE_BYTES:
        raise ValueError('rules is longer than %d bytes' % rule_match.MAX_SOURCE_BYTES)
    return source, 'custom', rule_match.SUBSET_VERSION


def parse_clr_metadata_bytes(meta: bytes) -> dict | None:
    """Bounded pure-Python ECMA-335 CLR BSJB metadata parser (#Strings, #US UTF-16 user literals, TypeDef & MethodDef RVAs)."""
    if not meta or len(meta) < 20 or meta[:4] != b'BSJB':
        return None
    major, minor, _, vlen = struct.unpack_from('<HHII', meta, 4)
    aligned_vlen = (vlen + 3) & ~3
    if vlen == 0 or aligned_vlen > 256 or 16 + aligned_vlen + 4 > len(meta):
        return None
    runtime_version = meta[16:16 + aligned_vlen].split(b'\0', 1)[0].decode('latin1', errors='replace')
    _, stream_count = struct.unpack_from('<HH', meta, 16 + aligned_vlen)
    pos, streams = 20 + aligned_vlen, {}
    for _ in range(min(stream_count, 32)):
        if pos + 8 > len(meta):
            break
        s_off, s_size = struct.unpack_from('<II', meta, pos)
        pos += 8
        end = meta.find(b'\0', pos, min(len(meta), pos + 32))
        if end < 0:
            break
        s_name = meta[pos:end].decode('latin1', errors='replace')
        pos += ((end - pos + 1) + 3) & ~3
        if s_off <= len(meta):
            chunk = meta[s_off:min(len(meta), s_off + s_size)]
            prev_chunk = streams.get(s_name)
            if prev_chunk is None or (len(prev_chunk) == 0 and len(chunk) > 0) or (s_name in ('#~', '#-') and len(prev_chunk) < 24 <= len(chunk)):
                streams[s_name] = chunk
    if not ({'#~', '#-', '#Strings', '#US', '#GUID', '#Blob'} & streams.keys()):
        return None
    s_str, s_us = streams.get('#Strings', b''), streams.get('#US', b'')
    read_str = lambda idx: s_str[idx:s_str.find(b'\0', idx, min(len(s_str), idx + 256)) if s_str.find(b'\0', idx, min(len(s_str), idx + 256)) >= 0 else min(len(s_str), idx + 256)].decode('utf-8', errors='replace') if 0 <= idx < len(s_str) else ''
    identifiers = []
    for raw_id in s_str.split(b'\0'):
        if 2 <= len(raw_id) <= 128:
            val = raw_id.decode('utf-8', errors='replace')
            if val not in identifiers:
                identifiers.append(val)
            if len(identifiers) >= 96:
                break
    user_strings, us_map, u = [], {}, 1
    while u < len(s_us) and len(user_strings) < 128:
        u_off, b0 = u, s_us[u]
        if (b0 & 0x80) == 0:
            blen, hdr = b0, 1
        elif (b0 & 0xc0) == 0x80 and u + 1 < len(s_us):
            blen, hdr = ((b0 & 0x3f) << 8) | s_us[u + 1], 2
        elif (b0 & 0xe0) == 0xc0 and u + 3 < len(s_us):
            blen, hdr = ((b0 & 0x1f) << 24) | (s_us[u + 1] << 16) | (s_us[u + 2] << 8) | s_us[u + 3], 4
        else:
            break
        u += hdr
        if blen == 0:
            continue
        if u + blen > len(s_us):
            break
        u16 = s_us[u:u + ((blen - 1) & ~1)]
        u += blen
        if u16:
            lit = u16.decode('utf-16le', errors='replace')
            us_map[u_off] = lit[:256]
            if lit and lit not in user_strings:
                user_strings.append(lit[:256])
    types, methods = [], []
    s_tbl = streams.get('#~') if len(streams.get('#~', b'')) >= 24 else streams.get('#-', b'')
    if len(s_tbl) >= 24:
        heap_sizes = s_tbl[6]
        valid_mask = struct.unpack_from('<Q', s_tbl, 8)[0]
        rows, tp = [0] * 64, 24
        for tid in range(64):
            if (valid_mask >> tid) & 1 and tp + 4 <= len(s_tbl):
                rows[tid] = struct.unpack_from('<I', s_tbl, tp)[0]
                tp += 4
        if (heap_sizes & 0x40) and tp + 4 <= len(s_tbl):
            tp += 4
        str_w, guid_w, blob_w = (4 if heap_sizes & 1 else 2), (4 if heap_sizes & 2 else 2), (4 if heap_sizes & 4 else 2)
        res_w = 4 if max(rows[0x00], rows[0x1a], rows[0x23], rows[0x01]) >= (1 << 14) else 2
        tdor_w = 4 if max(rows[0x02], rows[0x01], rows[0x1b]) >= (1 << 14) else 2
        fld_w, mth_w, prm_w = (4 if rows[0x04] >= 65536 else 2), (4 if rows[0x06] >= 65536 else 2), (4 if rows[0x08] >= 65536 else 2)
        r_idx = lambda off, w: struct.unpack_from('<I' if w == 4 else '<H', s_tbl, off)[0]
        tp += rows[0x00] * (2 + str_w + 3 * guid_w) + rows[0x01] * (res_w + 2 * str_w)
        td_w, raw_types = 4 + 2 * str_w + tdor_w + fld_w + mth_w, []
        for i in range(rows[0x02]):
            if tp + td_w > len(s_tbl):
                break
            t_name, t_ns = read_str(r_idx(tp + 4, str_w)), read_str(r_idx(tp + 4 + str_w, str_w))
            m_start = r_idx(tp + 4 + 2 * str_w + tdor_w + fld_w, mth_w)
            full_name = f'{t_ns}.{t_name}' if t_ns else t_name
            raw_types.append((full_name, m_start, f'0x{0x02000001 + i:08x}'))
            tp += td_w
        types = [{'token': tok, 'fullName': fn, 'methodStartRid': ms} for fn, ms, tok in raw_types[:128]]
        tp += rows[0x03] * fld_w + rows[0x04] * (2 + str_w + blob_w)
        method_ptr_map = None
        if rows[0x05] > 0 and tp + rows[0x05] * mth_w <= len(s_tbl):
            method_ptr_map = {r_idx(tp + idx_p * mth_w, mth_w): idx_p + 1 for idx_p in range(min(rows[0x05], 4096))}
        tp += rows[0x05] * mth_w
        md_w = 8 + str_w + blob_w + prm_w
        for i in range(min(rows[0x06], 256)):
            if tp + md_w > len(s_tbl):
                break
            m_rva, m_impl, m_flags = struct.unpack_from('<IHH', s_tbl, tp)
            m_name = read_str(r_idx(tp + 8, str_w))
            rid = method_ptr_map.get(i + 1, i + 1) if method_ptr_map else (i + 1)
            owner = None
            for idx_t, (fn, ms, _) in enumerate(raw_types):
                next_ms = raw_types[idx_t + 1][1] if idx_t + 1 < len(raw_types) else max(rows[0x06], rows[0x05]) + 1
                if ms <= rid < next_ms:
                    owner = fn
                    break
            methods.append({'token': f'0x{0x06000001 + i:08x}', 'type': owner, 'name': m_name, 'rva': hex(m_rva) if m_rva else None, 'implFlags': m_impl, 'flags': m_flags})
            tp += md_w
    return {'signature': 'BSJB', 'metadataVersion': f'{major}.{minor}', 'runtimeVersion': runtime_version,
            'streams': sorted(streams.keys()), 'userStrings': user_strings, '_usMap': us_map, 'identifiers': identifiers,
            'typeCount': len(types), 'types': types, 'methodCount': len(methods), 'methods': methods}


_CIL_SIMPLE = {0x58: 'add', 0x59: 'sub', 0x5a: 'mul', 0x5b: 'div', 0x5c: 'div.un', 0x5d: 'rem', 0x5e: 'rem.un',
               0x5f: 'and', 0x60: 'or', 0x61: 'xor', 0x62: 'shl', 0x63: 'shr', 0x64: 'shr.un', 0x65: 'neg', 0x66: 'not', 0xd2: 'conv.u1', 0x2a: 'ret'}


def decode_cil_method(mb: bytes, clr_meta: dict) -> tuple[str | None, int | None, list[str]]:
    if not mb:
        return None, None, []
    tag = mb[0] & 3
    if tag == 2:
        fmt, csize, body = 'tiny', mb[0] >> 2, mb[1:1 + (mb[0] >> 2)]
    elif tag == 3 and len(mb) >= 12:
        fmt, csize = 'fat', struct.unpack_from('<I', mb, 4)[0]
        body = mb[12:12 + min(csize, 512)]
    else:
        return None, None, []
    us_map = clr_meta.get('_usMap') or {}
    m_map = {int(m['token'], 16): f"{m.get('type') or ''}.{m['name']}".strip('.') for m in clr_meta.get('methods', ()) if m.get('token')}
    ops, pc = [], 0
    while pc < len(body) and len(ops) < 48:
        op = body[pc]
        pc += 1
        if op == 0xfe and pc < len(body):
            op2 = body[pc]; pc += 1
            pc += 4 if op2 in (0x06, 0x07) else (2 if 0x09 <= op2 <= 0x0e else 0)
        elif 0x16 <= op <= 0x1e:
            ops.append(f'ldc.i4 {op - 0x16}')
        elif op == 0x15:
            ops.append('ldc.i4 -1')
        elif op == 0x1f and pc < len(body):
            v = struct.unpack_from('<b', body, pc)[0]; pc += 1
            ops.append(f'ldc.i4.s {v} ({hex(v & 0xff)})')
        elif op == 0x20 and pc + 4 <= len(body):
            v = struct.unpack_from('<i', body, pc)[0]; pc += 4
            ops.append(f'ldc.i4 {v} ({hex(v & 0xffffffff)})')
        elif op == 0x21 and pc + 8 <= len(body):
            v = struct.unpack_from('<q', body, pc)[0]; pc += 8
            ops.append(f'ldc.i8 {hex(v)}')
        elif op in (0x22, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0xdd) and pc + 4 <= len(body):
            pc += 4
        elif op == 0x23 and pc + 8 <= len(body):
            pc += 8
        elif (0x0e <= op <= 0x13 or 0x2b <= op <= 0x37 or op == 0xde) and pc < len(body):
            pc += 1
        elif op == 0x45 and pc + 4 <= len(body):
            n_sw = struct.unpack_from('<I', body, pc)[0]
            pc += 4 + 4 * min(n_sw, 128)
        elif op == 0x72 and pc + 4 <= len(body):
            tok = struct.unpack_from('<I', body, pc)[0]; pc += 4
            s = us_map.get(tok & 0xffffff)
            ops.append(f'ldstr {s!r}' if s is not None else f'ldstr 0x{tok:08x}')
        elif op in (0x28, 0x6f, 0x73) and pc + 4 <= len(body):
            tok = struct.unpack_from('<I', body, pc)[0]; pc += 4
            mn = 'call' if op == 0x28 else ('callvirt' if op == 0x6f else 'newobj')
            ops.append(f'{mn} {m_map.get(tok, f"0x{tok:08x}")}')
        elif op in (0x27, 0x70, 0x71, 0x74, 0x75, 0x79, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x8c, 0x8d, 0xa3, 0xa4, 0xa5, 0xc2, 0xc6, 0xd0) and pc + 4 <= len(body):
            pc += 4
        elif op in _CIL_SIMPLE:
            ops.append(_CIL_SIMPLE[op])
    return fmt, csize, ops


def scan_image(segments, imports=(), strings=(), *, source_engine, params=None):
    """Return a shared schema plus legacy aliases, with explicit bounded coverage."""
    limits = scan_limits(params)
    source, origin, version = rule_source(params)
    ruleset = rule_match.compile_rules(source, origin=origin, version=version,
                                       max_locations=limits['max_rule_matches'])
    markers, entropy_rows = {}, []
    clr_metadata = None
    bytes_attempted = bytes_read = import_count = string_count = 0
    module_counts = Counter()
    api_rows, behavior_rows, imported_keys = [], [], set()
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
            tail, rule_tail, cursor = b'', b'', offset
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
                    if clr_metadata is None:
                        bsjb_pos, bsjb_tries = buffer.find(b'BSJB'), 0
                        while bsjb_pos >= 0 and clr_metadata is None and bsjb_tries < 16:
                            bsjb_tries += 1
                            seg_off = (cursor - len(tail)) + bsjb_pos
                            try:
                                clr_blob = segment['read'](seg_off, min(524288, max(0, size - seg_off))) or b''
                                clr_metadata = parse_clr_metadata_bytes(bytes(clr_blob))
                                if clr_metadata is not None:
                                    clr_metadata['metadataEa'] = hex(start + seg_off)
                                    img_base = start & ~0xffff
                                    for m in clr_metadata.get('methods', ()):
                                        if m.get('rva'):
                                            rva_i = int(m['rva'], 16)
                                            m['ea'] = hex(img_base + rva_i)
                                            m_off = (img_base + rva_i) - start
                                            if 0 <= m_off < size:
                                                mb = bytes(segment['read'](m_off, min(524, size - m_off)) or b'')
                                                fmt, csize, ops = decode_cil_method(mb, clr_metadata)
                                                if fmt:
                                                    m['ilFormat'], m['ilCodeSize'], m['ilOps'] = fmt, csize, ops
                                    clr_metadata.pop('_usMap', None)
                            except Exception:
                                clr_metadata = None
                            bsjb_pos = buffer.find(b'BSJB', bsjb_pos + 1)
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
                    rule_buffer = rule_tail + data
                    ruleset.feed(rule_buffer, start + cursor - len(rule_tail), name, len(rule_tail))
                    tail = buffer[-OVERLAP:] if len(data) == requested else b''
                    rule_tail = rule_buffer[-ruleset.overlap:] if ruleset.overlap and len(data) == requested else b''
                else:
                    tail, rule_tail = b'', b''
                cursor += requested
        sampled = sum(counts.values())
        entropy = -sum((count / sampled) * math.log2(count / sampled) for count in counts.values()) if sampled else None
        # A constant sample has zero information, but the leading minus above
        # yields IEEE -0.0. Host tool JSON accepts positive zero only.
        if entropy == 0:
            entropy = 0.0
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
            imported_keys.add(canonical(api))
            if len(api_rows) >= limits['max_api_matches']:
                flags['api_matches'] = True
                continue
            hit = {'module': module, 'api': api, 'category': category,
                   'interpretation': 'import presence is a lead; behavior is unproven'}
            for key in ('ea', 'addressSpace', 'addressRole', 'thunkEas', 'externalAddress', 'referenceEas', 'referencesTruncated'):
                if key in row:
                    hit[key] = row[key]
            api_rows.append(hit)
            # Per-function attribution feeds the behavior inventory only; the visible rows stay compact.
            behavior_rows.append({**hit, 'referenceFunctions': row.get('referenceFunctions')})
    families = {key: 0 for key in STRING_GROUPS}
    dynamic_api_rows = []
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
        if isinstance(row, dict) and row.get('apiNameCandidate') and is_api_name_string(text) and len(dynamic_api_rows) < limits['max_api_matches']:
            # A name string that no instruction references, for an API that is imported normally, is the import
            # table's own name entry (every PE/ELF has them), not a lead for run-time resolution.
            used_by_code = any(isinstance(ref, dict) and ref.get('function') for ref in row.get('referenceFunctions') or ())
            if used_by_code or canonical(text) not in imported_keys:
                dynamic_api_rows.append({'api': text, 'stringEa': row.get('ea'), 'referenceFunctions': row.get('referenceFunctions'),
                                         'confidence': 'medium' if any(c.isupper() for c in text) else 'low'})
        text = text[:limits['max_string_chars']].lower()
        for family, words_in_family in STRING_GROUPS.items():
            if any(word in text for word in words_in_family):
                families[family] += 1
    families['total'] = string_count
    marker_rows = sorted(markers.values(), key=lambda row: (_address(row['ea']), row['name']))
    summary = {'modules': len(module_counts), 'functions': import_count,
               'byModule': dict(module_counts.most_common(12)), 'truncated': flags['imports']}
    rule_report = ruleset.result(bytes_read)
    flags['rule_matches'] = rule_report['coverage']['truncated']
    out = {'schemaVersion': 2, 'sourceEngine': source_engine, 'idb_modified': False,
           'crypto_markers': marker_rows, 'entropies': entropy_rows, 'suspicious_apis': api_rows,
           'stringFamilies': families, 'importSummary': summary,
           'behaviors': behavior_inventory(behavior_rows, dynamic_api_rows),
           'ruleMatches': rule_report,
           'coverage': {'bytesAttempted': bytes_attempted, 'bytesRead': bytes_read,
                        'segments': len(entropy_rows), 'imports': import_count, 'strings': string_count,
                        'stringReadFailures': string_failures, 'stringsShortened': string_truncations,
                        'sampling': 'bounded prefix/middle/suffix; unobserved bytes are not classified'},
           'limits': limits, 'truncated': any(flags.values()), 'truncation': flags,
           'crypto': marker_rows, 'entropy': entropy_rows, 'suspiciousApis': api_rows}
    if clr_metadata is not None:
        out['clrMetadata'] = clr_metadata
    return out
