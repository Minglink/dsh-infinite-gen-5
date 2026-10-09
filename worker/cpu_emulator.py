"""Portable CPU-only execution over MemoryImage; no native process, imports, TLS or OS."""
import os
import sys
import time
from memory_image import MemoryImage, MEMORY_BUDGET, PAGE_SIZE, integer, page_range


def emulate_image(image, params):
    if not isinstance(image, MemoryImage):
        raise ValueError('a validated MemoryImage is required')
    bits, arch = image.bits, image.arch
    default_abi = 'aapcs64' if arch == 'arm64' else ('win64' if bits == 64 else 'cdecl')
    abi = str(params.get('abi') or default_abi)
    supported = ('aapcs64',) if arch == 'arm64' else (('win64', 'sysv64') if bits == 64 else ('cdecl', 'stdcall'))
    if abi not in supported:
        raise ValueError('unsupported ABI for target architecture and bitness')
    args = params.get('args') or []
    if not isinstance(args, list) or len(args) > 32:
        raise ValueError('args must be an array of at most 32 integers')
    args = [integer(value, 'argument') for value in args]
    allowed_regs = ([f'x{i}' for i in range(30)] if arch == 'arm64' else
                    ('rax rbx rcx rdx rsi rdi rbp r8 r9 r10 r11 r12 r13 r14 r15' if bits == 64 else 'eax ebx ecx edx esi edi ebp').split())
    initial = params.get('registers') or {}
    if not isinstance(initial, dict):
        raise ValueError('registers must be an object')
    initial = {str(name).lower(): integer(value, 'register') for name, value in initial.items()}
    if any(name not in allowed_regs for name in initial):
        raise ValueError('unsupported initial register')
    if any(not 0 <= value < (1 << bits) for value in args + list(initial.values())):
        raise ValueError('argument or register does not fit target width')
    max_instructions = max(1, min(integer(params.get('max_instructions') or 100000), 1000000))
    timeout_ms = max(1, min(integer(params.get('timeout_ms') or 1000), 10000))
    memory, captures = params.get('memory') or [], params.get('capture') or []
    if not isinstance(memory, list) or len(memory) > 32:
        raise ValueError('memory must contain at most 32 buffers')
    if not isinstance(captures, list) or len(captures) > 32:
        raise ValueError('capture must contain at most 32 memory ranges')
    buffers, requests, pages = [], [], set(image.pages)
    for item in memory:
        if not isinstance(item, dict):
            raise ValueError('invalid memory buffer')
        address = integer(item['ea'])
        payload = item.get('hex', '')
        if not isinstance(payload, str) or len(payload) > 3 * 65536 or len(''.join(payload.split())) > 2 * 65536:
            raise ValueError('encoded memory payload exceeds 65536-byte limit')
        data = bytes.fromhex(payload)
        if not 1 <= len(data) <= 65536:
            raise ValueError('memory payload must contain 1..65536 bytes')
        pages.update(page_range(address, len(data), bits))
        buffers.append((address, data))
    for item in captures:
        if not isinstance(item, dict):
            raise ValueError('invalid memory capture')
        address, size = integer(item['ea']), integer(item.get('size') or 64)
        if not 1 <= size <= 65536:
            raise ValueError('capture size must be 1..65536 bytes')
        page_range(address, size, bits)
        requests.append((address, size))
    stack_base, stack_size = (0x700000000000 if bits == 64 else 0x70000000), 0x100000
    sentinel = stack_base - PAGE_SIZE
    stack_pages = set(page_range(sentinel, stack_size + PAGE_SIZE, bits))
    if pages & stack_pages:
        raise ValueError('synthetic stack collides with target memory')
    pages.update(stack_pages)
    if len(pages) * PAGE_SIZE > MEMORY_BUDGET:
        raise ValueError('emulation memory budget exceeded (64 MiB)')
    vendor = os.path.join(os.path.dirname(__file__), 'vendor')
    if vendor not in sys.path:
        sys.path.insert(0, vendor)
    from unicorn import Uc, UcError, UC_ARCH_X86, UC_ARCH_ARM64, UC_MODE_32, UC_MODE_64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_QUERY_TIMEOUT, UC_HOOK_INSN, UC_HOOK_INTR
    if arch == 'arm64':
        import unicorn.arm64_const as regs
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        register = lambda name: getattr(regs, 'UC_ARM64_REG_' + name.upper())
        sp_reg, ip_reg, result_reg = regs.UC_ARM64_REG_SP, regs.UC_ARM64_REG_PC, regs.UC_ARM64_REG_X0
        arg_registers = tuple(f'x{i}' for i in range(8))
        sp = stack_base + stack_size - 0x2000
        mu.reg_write(regs.UC_ARM64_REG_LR, sentinel)
    else:
        import unicorn.x86_const as regs
        mu = Uc(UC_ARCH_X86, UC_MODE_64 if bits == 64 else UC_MODE_32)
        register = lambda name: getattr(regs, 'UC_X86_REG_' + name.upper())
        sp_reg = regs.UC_X86_REG_RSP if bits == 64 else regs.UC_X86_REG_ESP
        ip_reg = regs.UC_X86_REG_RIP if bits == 64 else regs.UC_X86_REG_EIP
        result_reg = regs.UC_X86_REG_RAX if bits == 64 else regs.UC_X86_REG_EAX
        arg_registers = ('rcx', 'rdx', 'r8', 'r9') if abi == 'win64' else (('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9') if abi == 'sysv64' else ())
        sp = stack_base + stack_size - (0x2008 if bits == 64 else 0x1004)
    for page in sorted(pages):
        mu.mem_map(page, PAGE_SIZE)
    zero_filled = 0
    for address, data, missing in image.chunks():
        if data is not None:
            mu.mem_write(address, data)
        zero_filled += missing
    if arch == 'x86':
        mu.mem_write(sp, sentinel.to_bytes(bits // 8, 'little'))
    for index, value in enumerate(args):
        if index < len(arg_registers):
            mu.reg_write(register(arg_registers[index]), value)
        else:
            slot = sp + (0 if arch == 'arm64' else bits // 8) + (32 if abi == 'win64' else 0) + (index - len(arg_registers)) * (bits // 8)
            mu.mem_write(slot, value.to_bytes(bits // 8, 'little'))
    mu.reg_write(sp_reg, sp)
    for name, value in initial.items():
        mu.reg_write(register(name), value)
    for address, data in buffers:
        mu.mem_write(address, data)
    state = {'instructions': 0, 'fault': None, 'last_address': None, 'last_size': 0, 'system': None}
    def trace(uc, address, size, _):
        state['instructions'] += 1
        state['last_address'], state['last_size'] = address, size
    def invalid(uc, access, address, size, value, _):
        state['fault'] = {'access': access, 'ea': hex(address), 'size': size}
        return False
    mu.hook_add(UC_HOOK_CODE, trace)
    mu.hook_add(UC_HOOK_MEM_INVALID, invalid)
    def stop_system(uc, instruction):
        state['system'] = {'instruction': instruction, 'ea': hex(uc.reg_read(ip_reg))}
        uc.emu_stop()
    def interrupt(uc, number, _):
        stop_system(uc, 'interrupt-' + str(number))
    mu.hook_add(UC_HOOK_INTR, interrupt)
    if arch == 'x86':
        for instruction, name in ((regs.UC_X86_INS_SYSCALL, 'syscall'), (regs.UC_X86_INS_SYSENTER, 'sysenter')):
            mu.hook_add(UC_HOOK_INSN, lambda uc, label: stop_system(uc, label), name, 1, 0, instruction)
    started, error = time.monotonic(), None
    try:
        mu.emu_start(image.entry, sentinel, timeout=timeout_ms * 1000, count=max_instructions)
    except UcError as exc:
        error = str(exc)
    ip = mu.reg_read(ip_reg)
    returned = ip == sentinel
    timed_out = bool(mu.query(UC_QUERY_TIMEOUT))
    halted = arch == 'x86' and state['last_size'] == 1 and state['last_address'] is not None and bytes(mu.mem_read(state['last_address'], 1)) == b'\xf4'
    reason = 'unsupported-system' if state['system'] else ('returned' if returned else ('unmapped-memory' if state['fault'] else ('emulator-error' if error else ('timeout' if timed_out else ('halt' if halted else ('instruction-limit' if state['instructions'] >= max_instructions else 'cpu-stopped'))))))
    result_memory = []
    for address, size in requests:
        try:
            result_memory.append({'ea': hex(address), 'size': size, 'hex': bytes(mu.mem_read(address, size)).hex()})
        except UcError as exc:
            result_memory.append({'ea': hex(address), 'error': str(exc)})
    return {'ok': returned and not state['system'], 'engine': 'Unicorn', 'isolated': True, 'sourceEngine': image.source,
            'ea': hex(image.entry), 'bits': bits, 'arch': arch, 'abi': abi, 'reason': reason,
            'return_value': hex(mu.reg_read(result_reg)), 'ip': hex(ip), 'instructions': state['instructions'],
            'elapsedMs': int((time.monotonic() - started) * 1000),
            'registers': {name: hex(mu.reg_read(register(name))) for name in allowed_regs},
            'memory': result_memory, 'fault': state['fault'], 'systemInstruction': state['system'], 'error': error, 'zeroFilledBytes': zero_filled,
            'limitations': ['CPU and copied memory only; no OS APIs, TLS setup, or imported function emulation']}
