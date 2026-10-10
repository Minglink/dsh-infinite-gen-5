"""IG5 owned image -> attributed native Ghidra decompiler, without Java.

Always called inside a disposable worker with a host-enforced deadline.
Function extents are caller bounded, not inferred from arbitrary linear bytes.
"""
from __future__ import annotations
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
from kernel_analysis import bounded


class Region(c.Structure):
    _fields_ = [('start', c.c_uint64), ('size', c.c_uint64), ('data', c.POINTER(c.c_uint8)),
                ('data_length', c.c_size_t), ('flags', c.c_uint32)]


def decompile(image, params, ghidra_home):
    if os.name != 'nt' or c.sizeof(c.c_void_p) != 8:
        raise ValueError('IG5 native C decompiler currently validates Windows x64 hosts only')
    if image.byteorder != 'little':
        raise ValueError('Native C decompilation currently supports little-endian targets only')
    if image.architecture == 'x86':
        processor = 'x86'
        target = f'x86:LE:{image.bits}:default:' + ('windows' if image.format == 'PE' else 'gcc')
    elif image.architecture == 'arm64' and image.bits == 64:
        processor = 'AARCH64'
        target = 'AARCH64:LE:64:v8A:' + ('windows' if image.format == 'PE' else 'default')
    else:
        raise ValueError('Native C decompilation supports x86/x64 and ARM64 targets')
    plugin = Path(__file__).resolve().parent.parent
    # Upstream spec streams use narrow filenames on Windows. A fixed child CWD
    # permits a Unicode plugin root while all spec filenames remain ASCII.
    if Path.cwd().resolve() != plugin.resolve():
        raise ValueError('Native C decompiler requires the owned worker plugin directory')
    home = Path(ghidra_home).resolve(strict=True)
    specs = (home / 'Ghidra' / 'Processors' / processor / 'data' / 'languages').resolve(strict=True)
    if not specs.is_relative_to(home): raise ValueError('Processor specs escaped the selected runtime')
    relative = os.path.relpath(specs, plugin)
    try: specification = relative.encode('ascii')
    except UnicodeEncodeError:
        raise ValueError('Native C specifications require an ASCII relative path; use the bundled runtime') from None
    raw_entry = params.get('ea')
    if raw_entry is None:
        if image.entrypoint is None: raise ValueError('Image has no entrypoint; provide an explicit ea')
        entry = image.entrypoint
    elif isinstance(raw_entry, str): entry = int(raw_entry, 16)
    else: raise ValueError('ea must be a hexadecimal string')
    code_region = next((r for r in image.regions if r.start <= entry < r.end), None)
    if code_region is None or not code_region.permissions & 4:
        raise ValueError('Kernel entry must be a mapped executable address')
    code_size = bounded(params.get('max_code_bytes'), 'max_code_bytes', 4096, 65536)
    maximum = bounded(params.get('max_instructions'), 'max_instructions', 1024, 1024)
    end = min(entry + code_size, code_region.end)
    if len(image.regions) > 512 or sum(r.size for r in image.regions) > 64 * 1024 * 1024:
        raise ValueError('Native C mapped image exceeds 512 regions or 64 MiB')
    keep, regions = [], []
    for region in image.regions:
        data = (c.c_uint8 * len(region.data)).from_buffer_copy(region.data)
        keep.append(data)
        flags = (0 if region.permissions & 2 else 1) | (2 if region.permissions & 4 else 0)
        if region.size > len(region.data): flags |= 4
        regions.append(Region(region.start, region.size, data, len(region.data), flags))
    mapped = (Region * len(regions))(*regions)
    native = plugin / 'adapters' / 'kernel' / 'native'
    proof_path = native / 'build-proof.json'
    if proof_path.stat().st_size > 1024 * 1024: raise ValueError('Native build proof exceeds its input budget')
    proof = json.loads(proof_path.read_text(encoding='utf-8-sig'))
    binary = native / 'ig5_decompiler.dll'
    expected = proof.get('artifact', {})
    if expected.get('path') != binary.name or expected.get('bytes') != binary.stat().st_size or not 0 < binary.stat().st_size <= 16 * 1024 * 1024:
        raise ValueError('Native C decompiler build proof does not match the artifact')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != expected.get('sha256'):
        raise ValueError('Native C decompiler SHA-256 does not match the build proof')
    library = c.CDLL(str(binary), winmode=0x900)
    function = library.ig5_decompiler_function
    function.argtypes = [c.c_char_p, c.c_char_p, c.POINTER(Region), c.c_size_t, c.c_uint64, c.c_uint64,
                         c.c_uint64, c.c_uint32, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
    function.restype = c.c_int
    output, required = c.create_string_buffer(8 * 1024 * 1024), c.c_size_t()
    status = function(specification, target.encode('ascii'), mapped, len(mapped), entry, entry, end,
                      maximum, output, len(output), c.byref(required))
    if status == 1 or required.value > len(output):
        raise ValueError('Native C decompiler exceeded its output buffer budget')
    if not output.value: raise ValueError('Native C decompiler returned no structured result')
    result = json.loads(output.value)
    result.update(implementation='ig5-kernel', kind='native-c', image=image.describe(),
                  language=target, compiler_selection='format-based default, not a compiler fingerprint',
                  target_executed=False, idb_modified=False, partial=not result.get('complete', False),
                  source={'artifactSHA256': image.sha256, 'loader': 'IG5 owned bounded PE/ELF loader',
                          'decompiler': 'Ghidra native decompiler', 'jvmStarted': False,
                          'commercialEngineUsed': False},
                  limits={'maxCodeBytes': code_size, 'maxInstructions': maximum,
                          'mappedBytes': 64 * 1024 * 1024, 'deadline': 'host isolated worker'},
                  limitations=['Function extent is bounded by ea/max_code_bytes, not auto-discovered',
                               'No imported prototypes, relocations, debug symbols or IDAPython compatibility',
                               'Indirect call/branch recovery remains dependent on native analysis',
                               'Windows x64 host validated; Android/iOS hosts are not validated'])
    if status != 0 and result.get('ok'):
        raise ValueError('Native C decompiler returned inconsistent status')
    return result
