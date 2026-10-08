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
            return 'mapped' if ida_bytes.is_mapped(address) else hex(address)
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
    """Run copied memory in Unicorn; never executes native code or modifies the IDB."""
    import ida_bytes
    import ida_segment
    import ida_ida
    vendor = os.path.join(os.path.dirname(__file__), 'vendor')
    if vendor not in sys.path:
        sys.path.insert(0, vendor)
    from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
    import unicorn.x86_const as regs
    if ida_ida.inf_get_procname() != 'metapc':
        raise ValueError('isolated emulation currently supports x86/x64 targets only')
    fn = _function(params)
    bits = 64 if ida_ida.inf_is_64bit() else 32
    abi = str(params.get('abi') or ('win64' if bits == 64 else 'cdecl'))
    if abi not in (('win64', 'sysv64') if bits == 64 else ('cdecl', 'stdcall')):
        raise ValueError('unsupported ABI for target bitness')
    args = params.get('args') or []
    if not isinstance(args, list) or len(args) > 32:
        raise ValueError('args must be an array of at most 32 integers')
    args = [_number(value) for value in args]
    max_instructions = max(1, min(int(params.get('max_instructions') or 100000), 1000000))
    timeout_ms = max(1, min(int(params.get('timeout_ms') or 1000), 10000))
    mu = Uc(UC_ARCH_X86, UC_MODE_64 if bits == 64 else UC_MODE_32)
    pages = set()
    mapped_bytes = 0
    def map_range(address, size):
        nonlocal mapped_bytes
        if address < 0 or size <= 0 or address + size > (1 << bits):
            raise ValueError('memory range outside target address space')
        first, end = address & ~0xfff, (address + size + 0xfff) & ~0xfff
        for page in range(first, end, 4096):
            if page not in pages:
                mapped_bytes += 4096
                if mapped_bytes > 64 * 1024 * 1024:
                    raise ValueError('emulation memory budget exceeded (64 MiB)')
                mu.mem_map(page, 4096)
                pages.add(page)
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = segment.end_ea - segment.start_ea
        if size <= 0:
            continue
        map_range(segment.start_ea, size)
        for address in range(segment.start_ea, segment.end_ea, 0x10000):
            data = ida_bytes.get_bytes(address, min(0x10000, segment.end_ea - address))
            if data:
                mu.mem_write(address, data)
    stack_base, stack_size = (0x700000000000 if bits == 64 else 0x70000000), 0x100000
    sentinel = stack_base - 0x1000
    if any(page in pages for page in range(sentinel, stack_base + stack_size, 4096)):
        raise ValueError('synthetic stack collides with target memory')
    map_range(sentinel, stack_size + 0x1000)
    pointer_size = bits // 8
    sp = stack_base + stack_size - 0x2008 if bits == 64 else stack_base + stack_size - 0x1004
    mu.mem_write(sp, sentinel.to_bytes(pointer_size, 'little'))
    arg_registers = ('rcx', 'rdx', 'r8', 'r9') if abi == 'win64' else (('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9') if abi == 'sysv64' else ())
    for index, value in enumerate(args):
        if not 0 <= value < (1 << bits):
            raise ValueError('argument does not fit target register width')
        if index < len(arg_registers):
            mu.reg_write(getattr(regs, 'UC_X86_REG_' + arg_registers[index].upper()), value)
        else:
            slot = sp + pointer_size + (32 if abi == 'win64' else 0) + (index - len(arg_registers)) * pointer_size
            mu.mem_write(slot, value.to_bytes(pointer_size, 'little'))
    mu.reg_write(regs.UC_X86_REG_RSP if bits == 64 else regs.UC_X86_REG_ESP, sp)
    allowed_regs = ('rax rbx rcx rdx rsi rdi rbp r8 r9 r10 r11 r12 r13 r14 r15' if bits == 64 else 'eax ebx ecx edx esi edi ebp').split()
    for name, value in (params.get('registers') or {}).items():
        if name.lower() not in allowed_regs:
            raise ValueError('unsupported initial register: ' + name)
        mu.reg_write(getattr(regs, 'UC_X86_REG_' + name.upper()), _number(value))
    memory = params.get('memory') or []
    if not isinstance(memory, list) or len(memory) > 32:
        raise ValueError('memory must contain at most 32 buffers')
    for item in memory:
        address, data = _number(item['ea']), bytes.fromhex(item.get('hex', ''))
        if not data or len(data) > 65536:
            raise ValueError('memory payload must contain 1..65536 bytes')
        map_range(address, len(data))
        mu.mem_write(address, data)
    state = {'instructions': 0, 'reason': None, 'fault': None}
    def trace(uc, address, size, _):
        state['instructions'] += 1
    def invalid(uc, access, address, size, value, _):
        state['reason'] = 'unmapped-memory'
        state['fault'] = {'access': access, 'ea': hex(address), 'size': size}
        return False
    mu.hook_add(UC_HOOK_CODE, trace)
    mu.hook_add(UC_HOOK_MEM_INVALID, invalid)
    started = time.monotonic()
    error = None
    try:
        mu.emu_start(fn.start_ea, sentinel, timeout=timeout_ms * 1000, count=max_instructions)
    except UcError as exc:
        error = str(exc)
    ip = mu.reg_read(regs.UC_X86_REG_RIP if bits == 64 else regs.UC_X86_REG_EIP)
    returned = ip == sentinel
    reason = 'returned' if returned else (state['reason'] or ('instruction-limit' if state['instructions'] >= max_instructions else ('emulator-error' if error else 'timeout')))
    capture_requests = params.get('capture') or []
    if not isinstance(capture_requests, list) or len(capture_requests) > 32:
        raise ValueError('capture must contain at most 32 memory ranges')
    captures = []
    for item in capture_requests:
        address, size = _number(item['ea']), max(1, min(int(item.get('size') or 64), 65536))
        try:
            captures.append({'ea': hex(address), 'size': size, 'hex': bytes(mu.mem_read(address, size)).hex()})
        except UcError as exc:
            captures.append({'ea': hex(address), 'error': str(exc)})
    return {'ok': returned, 'engine': 'Unicorn', 'isolated': True, 'ea': hex(fn.start_ea), 'bits': bits,
            'abi': abi, 'reason': reason, 'return_value': hex(mu.reg_read(regs.UC_X86_REG_RAX if bits == 64 else regs.UC_X86_REG_EAX)),
            'ip': hex(ip), 'instructions': state['instructions'], 'elapsedMs': int((time.monotonic() - started) * 1000),
            'registers': {name: hex(mu.reg_read(getattr(regs, 'UC_X86_REG_' + name.upper()))) for name in allowed_regs},
            'memory': captures, 'fault': state['fault'], 'error': error,
            'limitations': ['CPU and copied memory only; no OS APIs, TLS setup, or imported function emulation']}
