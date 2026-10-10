"""Read-only disassembly/semantic snapshots and isolated CPU emulation."""
import collections
import hashlib
import json
import os
import sys
import time


def _number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def _function(params):
    import ida_funcs
    import ida_name
    import ida_idaapi
    ea = _number(params['ea']) if params.get('ea') else ida_name.get_name_ea(ida_idaapi.BADADDR, params.get('name', ''))
    fn = ida_funcs.get_func(ea)
    if not fn:
        raise ValueError('function not found; provide ea or name')
    return fn


def m_disasm(params):
    import ida_bytes
    import ida_lines
    import ida_idaapi
    ea = _number(params['ea'])
    limit = max(1, min(int(params.get('limit') or 80), 500))
    size = max(1, min(int(params.get('size') or 1024), 65536))
    rows, current = [], ea
    while current < ea + size and len(rows) < limit and ida_bytes.is_mapped(current):
        length = max(1, int(ida_bytes.get_item_size(current)))
        raw = ida_bytes.get_bytes(current, min(length, 32)) or b''
        text = ida_lines.tag_remove(ida_lines.generate_disasm_line(current, 0) or '')
        rows.append({'ea': hex(current), 'size': length, 'bytes': raw.hex(), 'text': text})
        next_ea = ida_bytes.next_head(current, ea + size)
        if next_ea == ida_idaapi.BADADDR or next_ea <= current:
            current += length
            break
        current = next_ea
    return {'ea': hex(ea), 'rows': rows, 'total': len(rows), 'nextEa': hex(current)}


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def m_semantics(params):
    import ida_funcs
    import ida_gdl
    import ida_bytes
    import ida_ua
    import ida_nalt
    import ida_name
    import ida_segment
    import idautils
    limit = max(1, min(int(params.get('limit') or 500), 2000))
    offset = max(0, int(params.get('offset') or 0))
    user_only = params.get('user_only', True)
    name_filter = str(params.get('filter') or '').lower()
    rows, total = [], 0
    for ea in idautils.Functions():
        fn = ida_funcs.get_func(ea)
        if not fn or (user_only and fn.flags & ida_funcs.FUNC_LIB):
            continue
        name = ida_funcs.get_func_name(ea)
        if name_filter and name_filter not in name.lower():
            continue
        total += 1
        if total <= offset or len(rows) >= limit:
            continue
        tokens, constants, strings, calls, blocks = [], set(), set(), [], []
        normalized, byte_parts = [], []
        flow = list(ida_gdl.FlowChart(fn))
        block_at = {block.start_ea: index for index, block in enumerate(flow)}
        def address_token(address):
            if address in block_at:
                return 'block:' + str(block_at[address])
            symbol = ida_name.get_name(address)
            if symbol and not symbol.startswith(('sub_', 'loc_', 'off_', 'unk_', 'byte_', 'word_', 'dword_', 'qword_')):
                return 'symbol:' + symbol
            if ida_bytes.is_mapped(address):
                # Preserve anonymous reference identity while tolerating image rebases.
                # Collapsing every unknown callee/data address to "mapped" hid retargeted calls.
                segment = ida_segment.getseg(address)
                if segment is not None:
                    return 'mapped:' + ida_segment.get_segm_name(segment) + '+' + hex(address - segment.start_ea)
                return 'mapped:' + hex(address)
            return hex(address)
        for block in flow:
            block_tokens = []
            block_values = []
            for address in idautils.Heads(block.start_ea, block.end_ea):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(address)):
                    continue
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, address) <= 0:
                    continue
                mnemonic = insn.get_canon_mnem().lower()
                operands = []
                for operand in insn.ops:
                    if operand.type == ida_ua.o_void:
                        break
                    token = str(operand.type) + '/' + str(operand.dtype)
                    if operand.type == ida_ua.o_reg:
                        token += ':' + str(operand.reg)
                    elif operand.type == ida_ua.o_imm:
                        value = int(operand.value)
                        # Loaded addresses are relocation-sensitive, not constants.
                        if not ida_bytes.is_mapped(value):
                            constants.add(hex(value))
                            token += ':' + hex(value)
                        else:
                            token += ':' + address_token(value)
                    elif operand.type in (ida_ua.o_phrase, ida_ua.o_displ):
                        token += ':phrase=' + str(operand.phrase)
                        token += ':spec=' + ','.join(str(getattr(operand, 'specflag' + str(index), 0)) for index in range(1, 5))
                        if operand.type == ida_ua.o_displ:
                            token += ':disp=' + address_token(int(operand.addr))
                    elif operand.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                        token += ':' + address_token(int(operand.addr))
                    operands.append(token)
                block_tokens.append(mnemonic)
                block_values.append(mnemonic + ' ' + ','.join(operands))
                tokens.append(mnemonic)
                normalized.append(block_values[-1])
                byte_parts.append((ida_bytes.get_bytes(address, insn.size) or b'').hex())
                if mnemonic.startswith('call') or mnemonic in ('bl', 'blr'):
                    targets = list(idautils.CodeRefsFrom(address, False))
                    calls.extend(ida_funcs.get_func_name(target) or 'indirect' for target in targets)
                    if not targets:
                        calls.append('indirect')
                for target in idautils.DataRefsFrom(address):
                    value = ida_bytes.get_strlit_contents(target, -1, ida_nalt.STRTYPE_C)
                    if value:
                        strings.add(hashlib.sha256(value).hexdigest())
            blocks.append({'id': block.id, 'start': hex(block.start_ea), 'end': hex(block.end_ea),
                           'insns': len(block_tokens), 'hash': _hash(block_values),
                           'shape': _hash(block_tokens), 'succs': [s.id for s in block.succs()],
                           'preds': [p.id for p in block.preds()]})
        labels = {b['id']: _hash([b['shape'], len(b['succs']), len(b['preds'])]) for b in blocks}
        for _ in range(3):
            labels = {b['id']: _hash([labels[b['id']], sorted(labels.get(s, '') for s in b['succs']),
                                     sorted(labels.get(p, '') for p in b['preds'])]) for b in blocks}
        rows.append({'ea': hex(ea), 'name': name, 'size': fn.end_ea - fn.start_ea,
                     'instructions': len(tokens), 'mnemonics': dict(collections.Counter(tokens)),
                     'constants': sorted(constants), 'strings': sorted(strings),
                     'calls': calls, 'call_degree': len(calls), 'blocks': blocks,
                     'topology': sorted(labels.values()), 'semantic_hash': _hash([normalized,
                         [(b['id'], sorted(b['succs'])) for b in blocks], sorted(strings),
                         sorted(call for call in calls if not call.startswith(('sub_', 'j_sub_')))]),
                     'bytes_hash': _hash(byte_parts)})
    return {'total': total, 'offset': offset, 'count': len(rows), 'truncated': total > offset + len(rows),
            'functions': rows, 'algorithm': 'normalized instructions + 3-round CFG neighborhood labels'}


def m_emulate(params):
    """Collect engine memory; execution belongs to the portable CPU core."""
    import ida_bytes
    import ida_segment
    import ida_ida
    from memory_image import MemoryImage, MemoryRegion, PERM_READ, PERM_WRITE, PERM_EXEC
    from cpu_emulator import emulate_image
    if ida_ida.inf_get_procname() != 'metapc':
        raise ValueError('Reverse memory provider currently supports x86/x64 targets only')
    fn = _function(params)
    regions = []
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        base, size = segment.start_ea, segment.end_ea - segment.start_ea
        if size <= 0:
            continue
        native_permissions = getattr(segment, 'perm', None)
        # Reverse defines perm=0 as "no information", not no-access.
        permissions = None if not native_permissions else (
            (PERM_READ if native_permissions & ida_segment.SEGPERM_READ else 0) |
            (PERM_WRITE if native_permissions & ida_segment.SEGPERM_WRITE else 0) |
            (PERM_EXEC if native_permissions & ida_segment.SEGPERM_EXEC else 0))
        # Preserve the previous provider's zero-filled uninitialized ranges, now reported explicitly.
        regions.append(MemoryRegion(base, size,
            lambda offset, length, base=base: ida_bytes.get_bytes(base + offset, length),
            name=ida_segment.get_segm_name(segment), zero_fill=True, permissions=permissions))
    image = MemoryImage('x86', 64 if ida_ida.inf_is_64bit() else 32, fn.start_ea, regions, source='reverse')
    return {**emulate_image(image, params), 'idb_modified': False}
