"""Controlled native C ABI assertions; each case runs in its own timed child.

No JVM, commercial engine, target process, or existing native suite is started.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, 'reconfigure'): stream.reconfigure(encoding='utf-8', errors='strict')

ROOT = Path(__file__).resolve().parents[3]
BASE = 0x140001000
ABI_CASES = {
    'x86-windows-constant': ('x86:LE:32:default:windows', 'b82a000000c3'),
    'x86-windows-argument': ('x86:LE:32:default:windows', '8b44240483c001c3'),
    'x86-gcc-constant': ('x86:LE:32:default:gcc', 'b82a000000c3'),
    'x86-gcc-argument': ('x86:LE:32:default:gcc', '8b44240483c001c3'),
    'x64-gcc-constant': ('x86:LE:64:default:gcc', 'b82a000000c3'),
    'x64-gcc-argument': ('x86:LE:64:default:gcc', '8d4701c3'),
    'arm64-windows-constant': ('AARCH64:LE:64:v8A:windows', '40058052c0035fd6'),
    'arm64-windows-argument': ('AARCH64:LE:64:v8A:windows', '00040011c0035fd6'),
    'arm64-default-constant': ('AARCH64:LE:64:v8A:default', '40058052c0035fd6'),
    'arm64-default-argument': ('AARCH64:LE:64:v8A:default', '00040011c0035fd6'),
}
CASES = ('constant', 'argument', 'branch', 'readonly-global', 'image-gap', 'instruction-limit',
         'function-end-branch', 'overlap', 'zero-tail-refused', 'not-executable', 'output-too-small', 'missing-spec') + tuple(ABI_CASES)


class Region(ctypes.Structure):
    _fields_ = [('start', ctypes.c_uint64), ('size', ctypes.c_uint64), ('data', ctypes.POINTER(ctypes.c_uint8)),
                ('data_length', ctypes.c_size_t), ('flags', ctypes.c_uint32)]


def modules():
    if os.name != 'nt': return []
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    psapi.EnumProcessModules.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    psapi.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
    handles = (ctypes.c_void_p * 1024)()
    size = ctypes.c_ulong()
    process = kernel.GetCurrentProcess()
    if not psapi.EnumProcessModules(process, handles, ctypes.sizeof(handles), ctypes.byref(size)):
        raise OSError('module inventory failed')
    if size.value > ctypes.sizeof(handles): raise ValueError('module inventory budget exceeded')
    result = []
    for handle in list(handles)[:size.value // ctypes.sizeof(ctypes.c_void_p)]:
        name = ctypes.create_unicode_buffer(32768)
        if not psapi.GetModuleFileNameExW(process, handle, name, len(name)):
            raise OSError('module filename lookup failed')
        result.append(Path(name.value).name.lower())
    return sorted(result)


def case(name, dll, specs):
    library = ctypes.CDLL(str(dll), winmode=0x900) if os.name == 'nt' else ctypes.CDLL(str(dll))
    entry = library.ig5_decompiler_function
    entry.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(Region), ctypes.c_size_t,
                      ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32,
                      ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    entry.restype = ctypes.c_int
    code = bytes.fromhex('b82a000000c3')
    target = 'x86:LE:64:default:windows'
    base = BASE
    if name in ABI_CASES:
        target, machine_code = ABI_CASES[name]
        code = bytes.fromhex(machine_code)
        if name.startswith('x86-'): base = 0x401000
    if name == 'argument': code = bytes.fromhex('8d4101c3')
    if name == 'branch': code = bytes.fromhex('85c97506b801000000c3b802000000c3')
    if name == 'readonly-global': code = bytes.fromhex('8b05fa0f0000c3')  # RIP+0xffa -> BASE+0x1000
    if name == 'image-gap': code = bytes.fromhex('e920000000')
    if name == 'instruction-limit': code = b'\x90' * 16 + b'\xc3'
    if name == 'function-end-branch': code = bytes.fromhex('eb02')
    buffer = (ctypes.c_uint8 * len(code)).from_buffer_copy(code)
    data_before = bytes(buffer)
    region = Region(base, 64, buffer, len(code), 1 | 2 | 4)
    regions = [region]
    keep = [buffer]
    function_size = len(code)
    maximum = 100
    capacity = 8 * 1024 * 1024
    spec_argument = specs
    if name == 'readonly-global':
        global_data = (ctypes.c_uint8 * 16).from_buffer_copy((42).to_bytes(4, 'little') + bytes(12))
        regions.append(Region(base + 0x1000, 16, global_data, len(global_data), 1))
        keep.append(global_data)
    if name == 'image-gap': function_size = 128; region.size = 16
    if name == 'instruction-limit': maximum = 2
    if name == 'function-end-branch': function_size = 4
    if name == 'overlap': regions.append(Region(base + 1, 2, buffer, 2, 3))
    if name == 'zero-tail-refused': region.flags = 3
    if name == 'not-executable': region.flags = 1 | 4
    if name == 'output-too-small': capacity = 8
    if name == 'missing-spec': spec_argument = 'missing-owned-specs'
    array = (Region * len(regions))(*regions)
    output = ctypes.create_string_buffer(capacity)
    required = ctypes.c_size_t()
    status = entry(spec_argument.encode('utf-8'), target.encode('ascii'), array, len(regions),
                   base, base, base + function_size, maximum, output, capacity, ctypes.byref(required))
    assert bytes(buffer) == data_before, 'original function buffer was modified'
    inventory = modules()
    assert not any(value in inventory for value in ('jvm.dll', 'idalib.dll', 'ida64.dll', 'ida.dll'))
    assert not any(value.startswith('_jpype') for value in inventory)
    if name == 'output-too-small':
        assert status == 1 and required.value > capacity and output.value == b''
        value = {'ok': False, 'bufferTooSmall': True, 'required': required.value}
    else:
        value = json.loads(output.value.decode('utf-8'))
        assert required.value == len(output.value) + 1
        if name in ('constant', 'argument', 'branch', 'readonly-global') or name in ABI_CASES:
            assert status == 0 and value['ok'] and value['complete'], value
            assert value['jvmStarted'] is False and value['commercialEngineUsed'] is False
            assert 'return' in value['code'] and 'ig5_function' in value['code'], value
            if name in ('constant', 'readonly-global') or name.endswith('-constant'):
                assert '0x2a' in value['code'] or '42' in value['code'], value
            if name == 'argument' or name.endswith('-argument'):
                assert '+ 1' in value['code'] and 'param_1' in value['code'], value
            if name == 'branch': assert value['blocks'] >= 3, value
        elif name in ('overlap', 'zero-tail-refused', 'not-executable'):
            assert status == 2 and value['ok'] is False and value['stage'] == 'validate', value
        elif name == 'instruction-limit':
            assert status == 4 and value['budgetExceeded'] and value['stage'] == 'follow-flow', value
        else:
            assert status == 3 and value['ok'] is False and value['complete'] is False, value
    return {'case': name, 'targetID': target, 'hostArchitecture': 'win32-x64',
            'passed': True, 'status': status, 'response': value,
            'originalBytesUnchanged': True, 'nativeJavaModulesLoaded': False, 'commercialModulesLoaded': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dll', default=str(ROOT / 'adapters/kernel/native/ig5_decompiler.dll'))
    parser.add_argument('--specs', default='runtimes/ghidra/ghidra_12.1.4_PUBLIC/Ghidra/Processors/x86/data/languages')
    parser.add_argument('--aarch64-specs', default='runtimes/ghidra/ghidra_12.1.4_PUBLIC/Ghidra/Processors/AARCH64/data/languages')
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--report')
    args = parser.parse_args()
    dll = Path(args.dll).resolve()
    if args.case:
        selected_specs = args.aarch64_specs if args.case.startswith('arm64-') else args.specs
        print(json.dumps(case(args.case, dll, selected_specs), ensure_ascii=False))
        return
    environment = {key: value for key, value in os.environ.items() if not key.startswith(('IG5_', 'IDA', 'PYTHON', 'JAVA', 'GHIDRA'))}
    environment['PATH'] = str(Path(environment.get('SystemRoot', 'C:/Windows')) / 'System32')
    results = []
    for name in CASES:
        child = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--dll', str(dll),
                                '--specs', args.specs, '--aarch64-specs', args.aarch64_specs, '--case', name], cwd=ROOT, env=environment,
                               capture_output=True, timeout=30)
        if child.returncode:
            raise RuntimeError('native case ' + name + ' failed: ' + child.stdout[-4000:].decode('utf-8', errors='replace') + child.stderr[-4000:].decode('utf-8', errors='replace'))
        results.append(json.loads(child.stdout.decode('utf-8')))
    report = {'ok': True, 'dllSHA256': hashlib.sha256(dll.read_bytes()).hexdigest(),
              'assertions': len(results), 'jvmStarted': False, 'commercialEngineUsed': False,
              'targetsExecuted': False, 'originalImageBytesUnchanged': True, 'cases': results,
              'testedTargetIDs': sorted({result['targetID'] for result in results if result['status'] == 0}),
              'scope': 'controlled Windows x64 native C decompiler C ABI for x86/x64/ARM64 targets; no mobile-host, host registry or release-package claim'}
    if args.report:
        with Path(args.report).open('x', encoding='utf-8') as stream: json.dump(report, stream, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__': main()
