"""Packer / protector detection for PE and ELF files, from the file itself (no engine, nothing executed).

Names and strings are attacker-controlled, so the verdict leans on structure: where the entry point lands, which
sections have no file content, how random the executable bytes are, how little the import table holds. Every
indicator carries its evidence. The result says whether the image still looks packed; it never claims to have unpacked
anything (``unpack.status`` is ``not-unpacked`` or ``not-applicable``).

``analyze_packing(path)`` is the entry point; it returns a dict even for files it cannot parse (``format: unknown``).
"""
import math
import os
import re
import struct
from collections import Counter

import packer_rules as rules

SCHEMA = 'ig5.packing.v1'
DEFAULT_LIMITS = {'max_bytes': 8 * 1024 * 1024, 'sample_chunk': 64 * 1024, 'sample_chunks': 4, 'max_sections': 96, 'max_imports': 8192, 'max_descriptors': 512, 'marker_bytes': rules.MARKER_SCAN_BYTES}
SCN_EXEC, SCN_READ, SCN_WRITE, SCN_UNINIT, SCN_CODE = 0x20000000, 0x40000000, 0x80000000, 0x80, 0x20


class _Source:
    """Read-only random access to bytes or a file, counting what was actually read."""

    def __init__(self, data=None, path=None):
        self.path, self.data, self.handle, self.bytes_read = path, data, None, 0
        if path is not None:
            self.handle = open(path, 'rb')
            self.size = os.fstat(self.handle.fileno()).st_size
        else:
            self.size = len(data)

    def read(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b''
        length = min(length, self.size - offset)
        if self.handle is None:
            chunk = self.data[offset:offset + length]
        else:
            self.handle.seek(offset)
            chunk = self.handle.read(length)
        self.bytes_read += len(chunk)
        return chunk

    def close(self):
        if self.handle is not None:
            self.handle.close()


def entropy(data):
    if not data:
        return 0.0
    total = len(data)
    return -sum(count / total * math.log2(count / total) for count in Counter(data).values())


def _sample_entropy(src, offset, length, limits, budget):
    """Entropy over up to a few evenly spaced chunks of a range; ``budget`` is a one-element list of bytes still allowed."""
    if length <= 0 or offset >= src.size:
        return None, 0
    length = min(length, src.size - offset)
    chunk, count = limits['sample_chunk'], limits['sample_chunks']
    starts = [offset] if length <= chunk * count else [offset + (length - chunk) * i // (count - 1) for i in range(count)]
    data = b''
    for start in starts:
        if budget[0] <= 0:
            break
        part = src.read(start, min(chunk, offset + length - start, budget[0]))
        budget[0] -= len(part)
        data += part
    return (entropy(data) if data else None), len(data)


def _u(fmt, buffer, at):
    return struct.unpack_from(fmt, buffer, at)[0]


def _flags(characteristics):
    return ''.join(c for c, bit in (('r', SCN_READ), ('w', SCN_WRITE), ('x', SCN_EXEC)) if characteristics & bit)


def _printable_name(raw):
    name = raw.split(b'\0', 1)[0]
    return name.decode('latin1'), name


# ---- PE ------------------------------------------------------------------------------------------------------------

def _rva_to_offset(rva, sections, headers_size):
    if rva < headers_size:
        return rva
    for s in sections:
        extent = max(s['virtualSize'], s['rawSize'])
        if s['virtualAddress'] <= rva < s['virtualAddress'] + extent:
            delta = rva - s['virtualAddress']
            return s['rawPointer'] + delta if delta < s['rawSize'] else None
    return None


def _cstring(src, offset, limit=96):
    data = src.read(offset, limit)
    end = data.find(b'\0')
    return data[:end if end >= 0 else len(data)].decode('latin1')


def _read_imports(src, directory, sections, headers_size, plus, limits):
    rva, size = directory
    result = {'dlls': [], 'functions': 0, 'sample': [], 'names': set(), 'truncated': False}
    if not rva:
        return result
    base = _rva_to_offset(rva, sections, headers_size)
    if base is None:
        result['unreadable'] = True
        return result
    width = 8 if plus else 4
    for index in range(limits['max_descriptors']):
        raw = src.read(base + index * 20, 20)
        if len(raw) < 20:
            break
        original, _, _, name_rva, first = struct.unpack('<IIIII', raw)
        if not (original or first or name_rva):
            break
        dll_off = _rva_to_offset(name_rva, sections, headers_size)
        dll = _cstring(src, dll_off, 64).lower() if dll_off is not None else '?'
        result['dlls'].append(dll)
        thunk_off = _rva_to_offset(original or first, sections, headers_size)
        if thunk_off is None:
            continue
        for slot in range(4096):
            entry = src.read(thunk_off + slot * width, width)
            if len(entry) < width:
                break
            value = int.from_bytes(entry, 'little')
            if value == 0:
                break
            result['functions'] += 1
            if value >> (width * 8 - 1) == 0 and len(result['names']) < limits['max_imports']:       # imported by name
                name_off = _rva_to_offset(value & 0x7fffffff, sections, headers_size)
                if name_off is not None:
                    api = _cstring(src, name_off + 2, 64)
                    result['names'].add(api.lower())
                    if len(result['sample']) < 48:
                        result['sample'].append(api)
            if result['functions'] >= limits['max_imports']:
                result['truncated'] = True
                break
        if result['truncated']:
            break
    return result


def _parse_pe(src, limits):
    head = src.read(0, 0x40)
    if len(head) < 0x40 or head[:2] != b'MZ':
        return None
    lfanew = _u('<I', head, 0x3c)
    nt = src.read(lfanew, 24)
    if len(nt) < 24 or nt[:4] != b'PE\0\0':
        return None
    machine, section_count, _, _, _, optional_size, characteristics = struct.unpack_from('<HHIIIHH', nt, 4)
    optional = src.read(lfanew + 24, min(optional_size, 0x400))
    if len(optional) < 96:
        return {'error': 'truncated-optional-header'}
    magic = _u('<H', optional, 0)
    if magic not in (0x10b, 0x20b):
        return {'error': f'unknown-optional-magic-{magic:#x}'}
    plus = magic == 0x20b
    image_base = _u('<Q', optional, 24) if plus else _u('<I', optional, 28)
    subsystem = _u('<H', optional, 68)
    entry_rva, section_align, file_align, image_size, headers_size = _u('<I', optional, 16), _u('<I', optional, 32), _u('<I', optional, 36), _u('<I', optional, 56), _u('<I', optional, 60)
    count_at, dirs_at = (108, 112) if plus else (92, 96)
    directory_count = min(_u('<I', optional, count_at), 16) if len(optional) >= count_at + 4 else 0
    directories = []
    for i in range(16):
        at = dirs_at + i * 8
        directories.append(struct.unpack_from('<II', optional, at) if i < directory_count and at + 8 <= len(optional) else (0, 0))
    table = src.read(lfanew + 24 + optional_size, min(section_count, limits['max_sections']) * 40)
    sections = []
    for i in range(len(table) // 40):
        raw_name, vsize, vaddr, rsize, rptr, _, _, _, _, ch = struct.unpack_from('<8sIIIIIIHHI', table, i * 40)
        name, name_bytes = _printable_name(raw_name)
        sections.append({'name': name, 'nameBytes': name_bytes, 'virtualAddress': vaddr, 'virtualSize': vsize, 'rawPointer': rptr, 'rawSize': rsize, 'characteristics': ch, 'index': i})
    return {'machine': machine, 'plus': plus, 'subsystem': subsystem, 'dll': bool(characteristics & 0x2000), 'imageBase': image_base, 'entryRva': entry_rva, 'sectionAlignment': section_align, 'fileAlignment': file_align,
            'imageSize': image_size, 'headersSize': headers_size, 'headers_size': headers_size, 'directories': directories, 'sections': sections, 'sectionCountDeclared': section_count}


def _extract_pe_clr_metadata(src, pe):
    clr_rva, clr_size = pe['directories'][14]
    if not clr_rva or clr_size < 24:
        return None
    clr_off = _rva_to_offset(clr_rva, pe['sections'], pe['headers_size'])
    if clr_off is None:
        return None
    clr_hdr = src.read(clr_off, 24)
    if len(clr_hdr) < 24:
        return None
    _, maj_rt, min_rt, meta_rva, meta_size, clr_flags, ep_token = struct.unpack_from('<IHHIIII', clr_hdr, 0)
    if not meta_rva or not meta_size:
        return None
    meta_off = _rva_to_offset(meta_rva, pe['sections'], pe['headers_size'])
    if meta_off is None:
        return None
    from scan_analysis import parse_clr_metadata_bytes, decode_cil_method
    meta_blob = src.read(meta_off, min(meta_size, 524288))
    parsed = parse_clr_metadata_bytes(meta_blob)
    if parsed is None:
        return None
    parsed['clrRuntimeHeader'] = {'rva': hex(clr_rva), 'majorRuntimeVersion': maj_rt, 'minorRuntimeVersion': min_rt,
                                  'metadataRva': hex(meta_rva), 'metadataSize': meta_size, 'flags': hex(clr_flags),
                                  'entryPointToken': f'0x{ep_token:08x}' if ep_token else None}
    for m in parsed.get('methods', ()):
        if m.get('rva'):
            rva_i = int(m['rva'], 16)
            m['ea'] = hex(pe['imageBase'] + rva_i)
            m_off = _rva_to_offset(rva_i, pe['sections'], pe['headers_size'])
            mb = src.read(m_off, 524) if m_off is not None else b''
            fmt, csize, ops = decode_cil_method(mb, parsed)
            if fmt:
                m['ilFormat'], m['ilCodeSize'], m['ilOps'] = fmt, csize, ops
    parsed.pop('_usMap', None)
    return parsed


def _tls_callbacks(src, pe, limits):
    rva, size = pe['directories'][9]
    off = _rva_to_offset(rva, pe['sections'], pe['headers_size']) if rva else None
    if off is None:
        return 0
    width = 8 if pe['plus'] else 4
    raw = src.read(off + (24 if pe['plus'] else 12), width)
    if len(raw) < width:
        return 0
    va = int.from_bytes(raw, 'little')
    callbacks_off = _rva_to_offset(va - pe['imageBase'], pe['sections'], pe['headers_size']) if va >= pe['imageBase'] else None
    if callbacks_off is None:
        return 0
    count = 0
    while count < 16 and int.from_bytes(src.read(callbacks_off + count * width, width).ljust(width, b'\0'), 'little') != 0:
        count += 1
    return count


def _analyze_pe(src, limits, pe):
    sections, budget = pe['sections'], [limits['max_bytes']]
    findings, identified, anomalies = [], [], []

    def add(indicator, detail=None):
        findings.append({'id': indicator, 'weight': rules.INDICATORS[indicator][0], 'detail': detail or rules.INDICATORS[indicator][1]})

    rows = []
    # Executable and entry sections first, so a small byte budget is spent where it matters.
    order = sorted(sections, key=lambda s: (not (s['characteristics'] & SCN_EXEC), s['virtualAddress']))
    measured = {}
    for s in order:
        if s['rawSize'] and s['rawPointer'] < src.size:
            value, used = _sample_entropy(src, s['rawPointer'], s['rawSize'], limits, budget)
            measured[s['index']] = (value, used)
    entry_section = next((s for s in sections if s['virtualAddress'] <= pe['entryRva'] < s['virtualAddress'] + max(s['virtualSize'], s['rawSize'], 1)), None)
    for s in sections:
        value, used = measured.get(s['index'], (None, 0))
        executable = bool(s['characteristics'] & (SCN_EXEC | SCN_CODE))
        shown = s['name'] if s['nameBytes'] and all(32 <= b < 127 for b in s['nameBytes']) else (s['name'].encode('unicode_escape').decode() or '<empty>')
        rows.append({'name': shown,
                     'virtualAddress': s['virtualAddress'], 'virtualSize': s['virtualSize'], 'rawPointer': s['rawPointer'], 'rawSize': s['rawSize'], 'flags': _flags(s['characteristics']),
                     'entropy': None if value is None else round(value, 3), 'sampledBytes': used, 'entry': s is entry_section, 'executable': executable})

    # ---- signatures: names (weak, spoofable) ----
    for s in sections:
        known = rules.SECTION_NAMES.get(s['name'].lower())
        if known and not any(i['name'] == known[0] and i['confidence'] == 'name-only' for i in identified):
            identified.append({'name': known[0], 'kind': known[1], 'confidence': 'name-only', 'basis': f'section {s["name"]!r}'})
    if identified:
        add('signature-name', 'Section names: ' + ', '.join(f"{i['name']} ({i['basis']})" for i in identified))

    # ---- structure ----
    managed = bool(pe['directories'][14][0])
    kernel = pe['subsystem'] == 1        # native subsystem: drivers and the kernel keep discardable INIT/PAGE sections and padding on purpose
    exec_sections = [s for s in sections if s['characteristics'] & SCN_EXEC]
    entry_name = entry_section['name'].lower() if entry_section else None
    if pe['entryRva'] and not pe['dll'] and entry_section is None and pe['entryRva'] >= pe['headersSize']:
        add('entry-outside-sections', f'entry RVA {pe["entryRva"]:#x}')
    if entry_section is not None:
        if entry_section['characteristics'] & SCN_WRITE:
            add('entry-in-writable', f'entry section {entry_section["name"]!r}')
        first_code = min((s for s in exec_sections if s['rawSize']), key=lambda s: s['virtualAddress'], default=None)
        if not kernel and first_code is not None and entry_section is not first_code and (entry_section['characteristics'] & SCN_EXEC):
            add('entry-not-first-code', f'{entry_section["name"]!r} follows {first_code["name"]!r}')
        if not kernel and entry_name not in rules.STANDARD_CODE_NAMES and entry_section['characteristics'] & SCN_EXEC:
            add('entry-nonstandard-section', f'entry section {entry_section["name"]!r}')
    big_empty = [s for s in sections if s['characteristics'] & (SCN_EXEC | SCN_WRITE) and s['rawSize'] == 0 and s['virtualSize'] >= rules.VIRTUAL_ONLY_BYTES and s['name'].lower() != '.bss' and s['name'].lower() not in rules.STANDARD_NAMES
                 and not (s['characteristics'] & SCN_UNINIT and not s['characteristics'] & SCN_EXEC)]
    if big_empty:
        add('virtual-only-exec', ', '.join(f'{s["name"]!r} ({s["virtualSize"]:#x} bytes)' for s in big_empty[:4]))
    emptied = [s for s in exec_sections if s['rawSize'] == 0 and s['virtualSize'] >= 0x100 and s['name'].lower() != '.textbss' and not re.fullmatch(r'pad\d', s['name'].lower()) and s not in big_empty]
    if emptied:
        add('emptied-code-section', ', '.join(f'{s["name"]!r} ({s["virtualSize"]:#x} bytes)' for s in emptied[:4]))
    rwx = [s for s in sections if s['characteristics'] & SCN_EXEC and s['characteristics'] & SCN_WRITE and s['characteristics'] & SCN_READ]
    if rwx:
        add('rwx-section', ', '.join(repr(s['name']) for s in rwx[:4]))
    worst = None
    for s in exec_sections:
        value, used = measured.get(s['index'], (None, 0))
        if value is not None and used >= rules.MIN_ENTROPY_BYTES and (worst is None or value > worst[0]):
            worst = (value, s)
    if worst and worst[0] >= rules.ENTROPY_ENCRYPTED:
        add('encrypted-exec', f'{worst[1]["name"]!r} entropy {worst[0]:.2f}')
    elif worst and worst[0] >= rules.ENTROPY_PACKED:
        add('high-entropy-exec', f'{worst[1]["name"]!r} entropy {worst[0]:.2f}')
    resource = next((s for s in sections if s['name'].lower() == '.rsrc'), None)
    if resource:
        value, used = measured.get(resource['index'], (None, 0))
        if value is not None and used >= rules.MIN_ENTROPY_BYTES and value >= rules.ENTROPY_ENCRYPTED and resource['rawSize'] >= 64 * 1024:
            add('high-entropy-resources', f'.rsrc entropy {value:.2f}, {resource["rawSize"]} bytes')
    odd = [s for s in sections if (not rules.IDENTIFIER_NAME.match(s['name']) or not s['name']) and not rules.DEBUG_NAME.match(s['name'])]
    foreign = [s for s in sections if s['name'].lower() not in rules.STANDARD_NAMES and not rules.DEBUG_NAME.match(s['name']) and s['name'].lower() not in rules.SECTION_NAMES]
    if kernel:
        pass
    elif len(odd) >= 2 or (len(odd) >= 1 and len(foreign) >= 3):
        add('random-section-names', ', '.join(repr(s['name']) for s in odd[:5]))
    elif foreign:
        findings.append({'id': 'nonstandard-section-names', 'weight': min(9, rules.INDICATORS['nonstandard-section-names'][0] * len(foreign)), 'detail': ', '.join(repr(s['name']) for s in foreign[:5])})

    # ---- imports, TLS, overlay ----
    imports = _read_imports(src, pe['directories'][1], sections, pe['headersSize'], pe['plus'], limits)
    only_runtime = bool(imports['dlls']) and set(imports['dlls']) <= rules.MANAGED_RUNTIME_DLLS
    if not managed and not only_runtime and not pe['dll'] and not kernel and pe['entryRva']:
        total = imports['functions']
        if total <= rules.FEW_IMPORTS and (sum(s['rawSize'] for s in sections) >= 8192 or total == 0):
            add('few-imports', f'{total} imported functions in {len(imports["dlls"])} libraries')
        if imports['names'] and total <= rules.LOADER_IMPORTS and 'getprocaddress' in imports['names'] and any(n.startswith('loadlibrary') for n in imports['names']) and len(imports['names'] - rules.LOADER_APIS) <= 6:
            add('loader-imports', 'LoadLibrary + GetProcAddress among ' + str(total))
    callbacks = _tls_callbacks(src, pe, limits)
    if callbacks:
        add('tls-callbacks', f'{callbacks} callback(s)')
    raw_end = max((s['rawPointer'] + s['rawSize'] for s in sections), default=0)
    overlay = None
    if src.size > raw_end > 0:
        value, used = _sample_entropy(src, raw_end, src.size - raw_end, limits, budget)
        overlay = {'offset': raw_end, 'size': src.size - raw_end, 'entropy': None if value is None else round(value, 3)}
        if value is not None and used >= rules.MIN_ENTROPY_BYTES and value >= rules.ENTROPY_ENCRYPTED and overlay['size'] >= src.size // 2:
            add('overlay-encrypted', f'{overlay["size"]} bytes, entropy {value:.2f}')
    # ---- header consistency ----
    for s in sections:
        if s['rawSize'] and s['rawPointer'] + s['rawSize'] > src.size:
            anomalies.append(f'section {s["name"]!r} raw data extends past the end of the file')
    ordered = sorted((s for s in sections if s['virtualSize'] or s['rawSize']), key=lambda s: s['virtualAddress'])
    for left, right in zip(ordered, ordered[1:]):
        if left['virtualAddress'] + max(left['virtualSize'], 1) > right['virtualAddress'] and left['virtualSize'] and right['virtualAddress'] >= left['virtualAddress']:
            anomalies.append(f'sections {left["name"]!r} and {right["name"]!r} overlap in memory')
            break
    if sections and pe['imageSize'] and max(s['virtualAddress'] + s['virtualSize'] for s in sections) > pe['imageSize']:
        anomalies.append('SizeOfImage is smaller than the last section end')
    if pe['sectionCountDeclared'] > len(sections):
        anomalies.append(f'{pe["sectionCountDeclared"]} sections declared, {len(sections)} readable')
    if anomalies:
        add('header-anomaly', '; '.join(anomalies[:3]))

    # ---- UPX-style layout, whatever the sections are called ----
    entry_value = measured.get(entry_section['index'], (None, 0))[0] if entry_section else None
    if emptied and (len(odd) >= 2 or (odd and len(foreign) >= 3)) and entry_value is not None and entry_value >= rules.ENTROPY_PACKED and not identified:
        identified.append({'name': 'Unidentified protector', 'kind': 'protector', 'confidence': 'structural', 'basis': 'emptied original sections + random section names + entry in a high-entropy section'})
        findings.append({'id': 'protector-layout', 'weight': 0, 'detail': rules.INDICATORS['protector-layout'][1]})
    if len(sections) >= 2:
        by_va = sorted(sections, key=lambda s: s['virtualAddress'])
        first, second = by_va[0], by_va[1]
        value = measured.get(second['index'], (None, 0))[0]
        if (first['rawSize'] == 0 and first['characteristics'] & SCN_EXEC and first['virtualSize'] >= rules.VIRTUAL_ONLY_BYTES and entry_section is second
                and value is not None and value >= rules.ENTROPY_PACKED and first['virtualSize'] >= second['rawSize']):
            add('upx-like-layout', f'{first["name"]!r} (empty, {first["virtualSize"]:#x} bytes) then {second["name"]!r} (entropy {value:.2f}, entry)')
            if not any(i['kind'] == 'compressor' and i['name'].startswith('UPX') for i in identified):
                identified.append({'name': 'UPX-style stub', 'kind': 'compressor', 'confidence': 'structural', 'basis': 'empty executable first section + compressed entry section'})
    return {'managed': managed, 'entry': entry_section, 'findings': findings, 'identified': identified, 'rows': rows, 'imports': imports, 'overlay': overlay, 'anomalies': anomalies, 'exec_entropy': worst,
            'measured': measured, 'exec_sections': exec_sections, 'sampled': limits['max_bytes'] - budget[0]}


# ---- ELF -----------------------------------------------------------------------------------------------------------

def _analyze_elf(src, limits):
    head = src.read(0, 64)
    if len(head) < 52 or head[:4] != b'\x7fELF' or head[4] not in (1, 2) or head[5] not in (1, 2):
        return None
    is64, endian = head[4] == 2, '<' if head[5] == 1 else '>'
    if is64 and len(head) < 64:
        return None
    if is64:
        e_type, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(endian + 'HHIQQQIHHHHHH', head, 16)
    else:
        e_type, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(endian + 'HHIIIIIHHHHHH', head, 16)
    budget = [limits['max_bytes']]
    findings, identified, rows = [], [], []

    def add(indicator, detail=None):
        findings.append({'id': indicator, 'weight': rules.INDICATORS[indicator][0], 'detail': detail or rules.INDICATORS[indicator][1]})

    loads, dynamic, interp = [], False, False
    for i in range(min(phnum, 128)):
        raw = src.read(phoff + i * phentsize, phentsize) if phentsize >= (56 if is64 else 32) else b''
        if len(raw) < (56 if is64 else 32):
            break
        if is64:
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(endian + 'IIQQQQQQ', raw, 0)
        else:
            p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack_from(endian + 'IIIIIIII', raw, 0)
        if p_type == 2:
            dynamic = True
        elif p_type == 3:
            interp = True
        elif p_type == 1:
            value, used = _sample_entropy(src, p_offset, p_filesz, limits, budget) if p_flags & 1 and p_filesz else (None, 0)
            loads.append({'offset': p_offset, 'vaddr': p_vaddr, 'fileSize': p_filesz, 'memSize': p_memsz, 'flags': ''.join(c for c, bit in (('r', 4), ('w', 2), ('x', 1)) if p_flags & bit),
                          'entropy': None if value is None else round(value, 3), 'sampledBytes': used, 'entry': p_vaddr <= entry < p_vaddr + max(p_memsz, 1)})
    if not shnum or not shoff:
        add('elf-no-sections')
    rwx = [l for l in loads if l['flags'] == 'rwx']
    if rwx:
        add('elf-rwx-segment', f'{len(rwx)} segment(s)')
    hot = max((l for l in loads if 'x' in l['flags'] and l['entropy'] is not None and l['sampledBytes'] >= rules.MIN_ENTROPY_BYTES), key=lambda l: l['entropy'], default=None)
    if hot and hot['entropy'] >= rules.ENTROPY_PACKED:
        add('elf-high-entropy-load', f'executable segment at {hot["vaddr"]:#x}, entropy {hot["entropy"]}')
    entry_load = next((l for l in loads if l['entry']), None)
    if entry_load and 'w' in entry_load['flags']:
        add('elf-entry-in-writable', f'segment at {entry_load["vaddr"]:#x}')
    first_exec = next((l for l in loads if 'x' in l['flags']), None)
    if entry_load and first_exec is not None and entry_load is not first_exec:
        add('elf-entry-not-first-code', f'entry segment {entry_load["vaddr"]:#x}, first executable segment {first_exec["vaddr"]:#x}')
    if loads and len(loads) <= 2 and not dynamic and not interp and e_type in (2, 3):
        add('elf-few-loads', f'{len(loads)} loadable segment(s)')
    return {'sampled': limits['max_bytes'] - budget[0], 'findings': findings, 'identified': identified, 'loads': loads, 'entry': entry, 'machine': machine, 'is64': is64, 'sections': (shnum, shoff), 'dynamic': dynamic, 'type': e_type}


# ---- driver --------------------------------------------------------------------------------------------------------

def _scan_markers(src, limits):
    """UPX-style byte markers anywhere in the file (bounded)."""
    found, longest = [], max(len(m[0]) for m in rules.MARKERS)
    carry, offset = b'', 0
    while offset < min(src.size, limits['marker_bytes']):
        chunk = carry + src.read(offset, 1 << 20)
        if not chunk:
            break
        for marker, name, kind in rules.MARKERS:
            at = chunk.find(marker)
            while at >= 0 and len(found) < 16:
                found.append({'name': name, 'kind': kind, 'confidence': 'marker', 'basis': f'bytes {marker[:24]!r}', 'offset': offset - len(carry) + at})
                at = chunk.find(marker, at + len(marker))
        carry = chunk[-(longest - 1):]
        offset += 1 << 20
    return found


def _verdict(findings, identified, entry_intact):
    score = min(100, sum(f['weight'] for f in findings))
    status = 'packed' if score >= rules.STATUS_PACKED else 'suspected' if score >= rules.STATUS_SUSPECTED else 'plain'
    if status == 'packed' and entry_intact and identified:
        status = 'protected'
    return score, status


def _next_steps(status, identified):
    if status == 'plain':
        return []
    steps = []
    if any(i['name'].startswith('UPX') for i in identified):
        steps.append('UPX files that were not modified can be restored with the official `upx -d` (not bundled); a modified stub has to be dumped instead.')
    steps.append('Run the sample only inside the guest-debug workflow (ig5_dbg), break where control leaves the stub for a low-entropy region, dump the image, then open the dump.')
    steps.append('Or emulate the stub with ig5_emulate until it jumps into memory it has just written, and read the original entry point from there.')
    if status == 'protected':
        steps.insert(0, 'The entry point is still in ordinary code: expect selected functions to be virtualized or encrypted rather than the whole image compressed.')
    return steps


def analyze_packing(path=None, *, data=None, limits=None):
    """Packing assessment of a file (``path``) or of bytes (``data``). Never raises for unparseable input."""
    limits = {**DEFAULT_LIMITS, **(limits or {})}
    src = _Source(data=data, path=path)
    try:
        report = {'schema': SCHEMA, 'format': 'unknown', 'size': src.size}
        pe = _parse_pe(src, limits)
        elf = None if pe is not None else _analyze_elf(src, limits)
        if pe is None and elf is None:
            return {**report, 'status': 'unknown', 'score': 0, 'identified': [], 'indicators': [], 'unpack': {'attempted': False, 'status': 'not-applicable', 'next': []},
                    'notes': ['Not a PE or ELF file; no packing assessment.']}
        if pe is not None and 'error' in pe:
            return {**report, 'format': 'pe', 'status': 'unknown', 'score': 0, 'identified': [], 'indicators': [], 'unpack': {'attempted': False, 'status': 'not-applicable', 'next': []}, 'notes': [f'PE header unreadable: {pe["error"]}']}
        markers = _scan_markers(src, limits)
        if pe is not None:
            # A UPX string inside .rdata is a scanner's signature list, not a packed file: the marker must sit in executable or entry-section data.
            spans = [(s['rawPointer'], s['rawPointer'] + s['rawSize']) for s in pe['sections'] if s['characteristics'] & SCN_EXEC]
            markers = [m for m in markers if any(a <= m['offset'] < b for a, b in spans)]
        else:
            markers = [m for m in markers if m['offset'] < 0x10000]
        seen_markers = set()
        markers = [m for m in markers if not (m['name'] in seen_markers or seen_markers.add(m['name']))]
        if pe is not None:
            detail = _analyze_pe(src, limits, pe)
            identified, findings = detail['identified'], detail['findings']
            for marker in markers:
                if not any(i['name'] == marker['name'] and i['confidence'] == 'marker' for i in identified):
                    identified.append(marker)
            if markers:
                findings.append({'id': 'signature-marker', 'weight': rules.INDICATORS['signature-marker'][0], 'detail': ', '.join(m['basis'] for m in markers)})
            entry = detail['entry']
            value = detail['measured'].get(entry['index'], (None, 0))[0] if entry else None
            first_code = min((s for s in detail['exec_sections'] if s['rawSize']), key=lambda s: s['virtualAddress'], default=None)
            entry_intact = bool(entry and entry is first_code and entry['name'].lower() in rules.STANDARD_CODE_NAMES and (value is None or value < rules.ENTROPY_PACKED))
            score, status = _verdict(findings, identified, entry_intact)
            imports = detail['imports']
            report.update(format='pe', bits=64 if pe['plus'] else 32, machine=f'{pe["machine"]:#06x}', managed=detail['managed'], dll=pe['dll'],
                          entry={'rva': pe['entryRva'], 'section': entry['name'] if entry else None, 'intact': entry_intact},
                          sections=detail['rows'], imports={'libraries': imports['dlls'][:32], 'functions': imports['functions'], 'sample': imports['sample'], 'truncated': imports['truncated']},
                          overlay=detail['overlay'], anomalies=detail['anomalies'])
            if detail['managed']:
                clr_info = _extract_pe_clr_metadata(src, pe)
                if clr_info is not None:
                    report['clrMetadata'] = clr_info
        else:
            identified, findings = elf['identified'], elf['findings']
            identified.extend(markers)
            if markers:
                findings.append({'id': 'signature-marker', 'weight': rules.INDICATORS['signature-marker'][0], 'detail': ', '.join(m['basis'] for m in markers)})
            score, status = _verdict(findings, identified, False)
            report.update(format='elf', bits=64 if elf['is64'] else 32, machine=f'{elf["machine"]:#06x}', segments=elf['loads'], entry={'address': elf['entry']}, hasSectionHeaders=bool(elf['sections'][0]), dynamic=elf['dynamic'])
        kind = next((i['kind'] for i in identified), None)
        report.update(status=status, score=score, kind=kind, identified=identified, indicators=sorted(findings, key=lambda f: -f['weight']),
                      unpack={'attempted': False, 'status': 'not-applicable' if status == 'plain' else 'not-unpacked', 'reason': 'This analysis detects packing; it does not unpack.', 'next': _next_steps(status, identified)},
                      coverage={'sampledBytes': (detail if pe is not None else elf)['sampled'], 'budget': limits['max_bytes'], 'markerScanBytes': min(src.size, limits['marker_bytes']), 'bytesRead': src.bytes_read},
                      notes=['Section names and strings are controlled by the packer author; the structural indicators decide the status.'])
        return report
    finally:
        src.close()
