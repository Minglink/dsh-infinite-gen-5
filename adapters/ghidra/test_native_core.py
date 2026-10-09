"""Real C ABI decoder tests over x64 and AArch64 processor specifications."""
import argparse
import ctypes as c
import json
from pathlib import Path
import subprocess
import tempfile


class Context(c.Structure):
    _fields_ = [('name', c.c_char_p), ('value', c.c_uint32)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--ghidra-home', type=Path, required=True)
    parser.add_argument('--compiler', type=Path)
    args = parser.parse_args()
    library = c.CDLL(str(args.library))
    decode = library.ig5_sleigh_decode
    decode.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t, c.c_uint64,
                       c.POINTER(Context), c.c_size_t, c.c_size_t, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
    decode.restype = c.c_int
    def invoke(sla, data, context=(), base=0x400000, maximum=1024):
        variables = (Context * len(context))(*[Context(name.encode('ascii'), value) for name, value in context])
        required = c.c_size_t()
        output = c.create_string_buffer(1024 * 1024)
        status = decode(sla, len(sla), data, len(data), base, variables, len(variables), maximum, output, len(output), c.byref(required))
        assert required.value <= len(output), required.value
        return status, json.loads(output.value)
    processors = args.ghidra_home / 'Ghidra/Processors'
    x86 = (processors / 'x86/data/languages/x86-64.sla').read_bytes()
    context = [('longMode', 1), ('addrsize', 2), ('opsize', 1)]
    status, x64 = invoke(x86, bytes.fromhex('488d0411c3'), context, base=0xFFFFFFFF00001000)
    assert status == 0 and x64['count'] == 2 and not x64['truncated'], x64
    assert x64['instructions'][0]['ea'] == '0xffffffff00001000'
    assert x64['instructions'][0]['mnemonic'] == 'LEA'
    assert x64['instructions'][1]['mnemonic'] == 'RET'
    assert any(op['opcode'] == 'INT_ADD' for op in x64['instructions'][0]['pcode'])
    status, limited = invoke(x86, bytes.fromhex('488d0411c3'), context, maximum=1)
    assert status == 0 and limited['truncated'] and limited['count'] == 1
    status, incomplete = invoke(x86, bytes.fromhex('488d04'), context)
    assert status == 3 and not incomplete['ok'] and incomplete['count'] == 0 and incomplete['truncated']
    arm = (processors / 'AARCH64/data/languages/AARCH64.sla').read_bytes()
    status, arm64 = invoke(arm, bytes.fromhex('0000018bc0035fd6'))
    assert status == 0 and arm64['count'] == 2 and not arm64['truncated'], arm64
    assert arm64['instructions'][0]['mnemonic'].lower() == 'add'
    assert any(op['opcode'] == 'INT_ADD' for op in arm64['instructions'][0]['pcode'])
    assert arm64['instructions'][1]['mnemonic'].lower() == 'ret'
    status, invalid = invoke(b'bad specification', b'\0\0\0\0')
    assert status == 3 and not invalid['ok']
    required = c.c_size_t()
    assert decode(x86, len(x86), bytes.fromhex('c3'), 1, 0x400000, None, 0, 1, None, 0, c.byref(required)) == 1
    assert required.value > 1
    assert decode(None, 0, None, 0, 0, None, 0, 0, None, 0, None) == 2
    if args.compiler:
        with tempfile.TemporaryDirectory(prefix='ig5-sleigh-compile-') as temporary:
            source = Path(temporary) / 'ig5-test.slaspec'
            compiled = source.with_suffix('.sla')
            source.write_text('''define endian=little;
define alignment=1;
define space ram type=ram_space size=8 default;
define space register type=register_space size=8;
define register offset=0 size=8 [ R0 R1 ];
define token opbyte(8) opcode=(0,7);
:ADD is opcode=1 { R0 = R0 + R1; }
:RET is opcode=2 { return [R0]; }
''', encoding='ascii')
            result = subprocess.run([str(args.compiler), str(source), str(compiled)], capture_output=True, timeout=30)
            assert result.returncode == 0, result.stderr.decode('utf-8', errors='replace')
            status, toy = invoke(compiled.read_bytes(), b'\x01\x02')
            assert status == 0 and toy['count'] == 2
            assert toy['instructions'][0]['pcode'][0]['opcode'] == 'INT_ADD'
            assert toy['instructions'][1]['pcode'][0]['opcode'] == 'RETURN'
    print(json.dumps({'ok': True, 'host': 'Windows x64', 'targetArchitectures': ['x64', 'AArch64'],
                      'tests': 9 if args.compiler else 8, 'compiledSleighSpec': bool(args.compiler),
                      'x64': x64, 'arm64': arm64, 'mobileRuntimeValidated': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
