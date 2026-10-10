"""IG5-owned graph/IR analysis, using the separately attributed SLEIGH decoder.

No commercial engine, JVM, database or target execution. Native decode is linear;
the graph retains only reachable instruction boundaries and reports unresolved
edges. It is deliberately not represented as a complete C decompiler.
"""
from __future__ import annotations
import collections
import copy
import ctypes as c
import json
import os
from pathlib import Path


def bounded(value, name, default, maximum):
    value = default if value is None else value
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(f'{name} must be an integer in 1..{maximum}')
    return value


class Context(c.Structure):
    _fields_ = [('name', c.c_char_p), ('value', c.c_uint32)]


class SleighDecoder:
    def __init__(self, runtime_root, ghidra_home, java_home):
        if os.name != 'nt' or c.sizeof(c.c_void_p) != 8:
            raise ValueError('IG5 native kernel currently validates Windows x64 hosts only')
        root = Path(runtime_root).resolve(strict=True)
        home = Path(ghidra_home).resolve(strict=True)
        library = (root / 'ig5_sleigh.dll').resolve(strict=True)
        if not library.is_relative_to(root) or not home.is_relative_to(root):
            raise ValueError('Kernel decoder/specifications must belong to the selected runtime')
        import sys
        adapter = Path(__file__).resolve().parent.parent / 'adapters' / 'ghidra'
        sys.path.insert(0, str(adapter))
        from native_bootstrap import bootstrap_windows_dlls
        self.crt = bootstrap_windows_dlls(java_home)
        self.library = c.CDLL(str(library))
        self.function = self.library.ig5_sleigh_decode
        self.function.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t, c.c_uint64,
                                  c.POINTER(Context), c.c_size_t, c.c_size_t, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
        self.function.restype = c.c_int
        self.home = home
        self.specs = {}

    def decode(self, image, code, address, maximum):
        if image.byteorder != 'little':
            raise ValueError('Native decoding currently supports little-endian targets only')
        if image.architecture == 'x86':
            name = 'x86-64.sla' if image.bits == 64 else 'x86.sla'
            relative = 'Ghidra/Processors/x86/data/languages/' + name
            contexts = [('longMode', 1), ('addrsize', 2), ('opsize', 1)] if image.bits == 64 else [('addrsize', 1), ('opsize', 1)]
        elif image.architecture == 'arm64' and image.bits == 64:
            relative = 'Ghidra/Processors/AARCH64/data/languages/AARCH64.sla'
            contexts = []
        else:
            raise ValueError('Native decoding supports x86/x64 and ARM64 targets')
        if relative not in self.specs:
            file = (self.home / relative).resolve(strict=True)
            if not file.is_relative_to(self.home) or not 0 < file.stat().st_size <= 64 * 1024 * 1024:
                raise ValueError('Invalid bounded processor specification')
            self.specs[relative] = file.read_bytes()
        spec = self.specs[relative]
        variables = (Context * len(contexts))(*[Context(name.encode('ascii'), value) for name, value in contexts])
        output = c.create_string_buffer(8 * 1024 * 1024)
        required = c.c_size_t()
        status = self.function(spec, len(spec), code, len(code), address, variables, len(variables), maximum,
                               output, len(output), c.byref(required))
        if status in (1, 2) or required.value > len(output):
            raise ValueError('Native decoder exceeded its output budget or rejected arguments')
        return json.loads(output.value)


def optimize_ir(instructions):
    """Width-aware local constant folding; never writes bytes or changes CFG."""
    result, changes = copy.deepcopy(instructions), []
    for instruction in result:
        for index, op in enumerate(instruction.get('pcode', [])):
            inputs, output = op.get('inputs', []), op.get('output')
            if len(inputs) != 2 or not output or not 1 <= output.get('size', 0) <= 16:
                continue
            opcode = op['opcode']
            value, rule = None, None
            if opcode in ('INT_XOR', 'INT_SUB') and inputs[0] == inputs[1] and inputs[0].get('space') in ('register', 'unique'):
                value, rule = 0, 'xor-self' if opcode == 'INT_XOR' else 'sub-self'
            elif all(item.get('space') == 'const' for item in inputs):
                left, right = (int(item['offset'], 16) for item in inputs)
                if opcode == 'INT_ADD': value = left + right
                elif opcode == 'INT_SUB': value = left - right
                elif opcode == 'INT_MULT': value = left * right
                elif opcode == 'INT_AND': value = left & right
                elif opcode == 'INT_OR': value = left | right
                elif opcode == 'INT_XOR': value = left ^ right
                if value is not None: rule = 'constant-fold'
            if value is not None:
                value &= (1 << (output['size'] * 8)) - 1
                changes.append({'ea': instruction['ea'], 'index': index, 'rule': rule, 'before': copy.deepcopy(op)})
                op.update(opcode='COPY', inputs=[{'space': 'const', 'offset': hex(value), 'size': output['size']}])
                changes[-1]['after'] = copy.deepcopy(op)
    return result, changes


def build_cfg(instructions, entry, max_blocks=256):
    by_ea = {int(row['ea'], 16): row for row in instructions}
    pending, reachable, edges, unresolved, calls = collections.deque([entry]), set(), [], [], []
    while pending:
        ea = pending.popleft()
        if ea in reachable: continue
        if ea not in by_ea:
            unresolved.append({'source': None, 'target': hex(ea), 'reason': 'outside decoded boundaries'})
            continue
        reachable.add(ea)
        row = by_ea[ea]
        successors = []
        terminators = []
        local_branch = False
        for op in row.get('pcode', []):
            if op['opcode'] in ('CALL', 'CALLIND'):
                operand = op['inputs'][0] if op['inputs'] else None
                calls.append({'ea': hex(ea), 'target': operand['offset'] if op['opcode'] == 'CALL' and operand and operand.get('space') == 'ram' else None,
                              'indirect': op['opcode'] == 'CALLIND'})
            if op['opcode'] in ('BRANCH', 'CBRANCH', 'BRANCHIND', 'RETURN'):
                operand = op['inputs'][0] if op['inputs'] else None
                # Constant-space destinations are p-code instruction indices,
                # not machine addresses and do not end the machine instruction.
                if op['opcode'] in ('BRANCH', 'CBRANCH') and operand and operand.get('space') == 'const':
                    local_branch = True
                    continue
                terminators.append(op)
        if terminators:
            if local_branch:
                unresolved.append({'source': hex(ea), 'target': None, 'reason': 'local p-code branch may bypass an external exit'})
                successors.append((ea + row['size'], 'fallthrough'))
            # Multiple external p-code exits can depend on internal p-code
            # branches. Preserve all possible exits and disclose that this
            # instruction-node graph has not solved their internal predicates.
            if len(terminators) > 1:
                unresolved.append({'source': hex(ea), 'target': None, 'reason': 'multiple p-code exits; internal instruction control flow unresolved'})
            for terminator in terminators:
                opcode = terminator['opcode']
                operand = terminator['inputs'][0] if terminator['inputs'] else None
                if opcode in ('BRANCH', 'CBRANCH'):
                    if operand and operand.get('space') == 'ram': successors.append((int(operand['offset'], 16), 'branch'))
                    else: unresolved.append({'source': hex(ea), 'target': None, 'reason': 'unknown p-code branch destination'})
                elif opcode == 'BRANCHIND': unresolved.append({'source': hex(ea), 'target': None, 'reason': 'indirect branch'})
            if terminators[-1]['opcode'] == 'CBRANCH': successors.append((ea + row['size'], 'fallthrough'))
        else: successors.append((ea + row['size'], 'fallthrough'))
        for target, kind in dict.fromkeys(successors):
            if target in by_ea:
                edges.append((ea, target, kind)); pending.append(target)
            else: unresolved.append({'source': hex(ea), 'target': hex(target), 'reason': 'outside decoded boundaries'})
    # Instruction nodes provide exact control flow; grouping is a separate step.
    kept = ([entry] + sorted(reachable - {entry}))[:max_blocks] if entry in reachable else []
    ids = {ea: index for index, ea in enumerate(kept)}
    blocks = [{'id': ids[ea], 'start': hex(ea), 'end': hex(ea + by_ea[ea]['size']), 'insns': 1,
               'succs': sorted({ids[b] for a, b, _ in edges if a == ea and b in ids}),
               'preds': sorted({ids[a] for a, b, _ in edges if b == ea and a in ids})} for ea in kept]
    return {'blocks': blocks, 'edges': [{'from': ids[a], 'to': ids[b], 'kind': k} for a, b, k in edges if a in ids and b in ids],
            'unresolved': unresolved, 'calls': calls, 'reachable': reachable, 'truncated': len(reachable) > max_blocks,
            'representation': 'instruction-node CFG; not grouped basic blocks'}


def analyze(image, decoder, params):
    maximum = bounded(params.get('max_instructions'), 'max_instructions', 256, 1024)
    count = bounded(params.get('max_code_bytes'), 'max_code_bytes', 4096, 65536)
    blocks = bounded(params.get('max_blocks'), 'max_blocks', 256, 1024)
    entry = params.get('ea')
    if entry is None:
        if image.entrypoint is None: raise ValueError('Image has no entrypoint; provide an explicit ea')
        ea = image.entrypoint
    elif isinstance(entry, str): ea = int(entry, 16)
    else: raise ValueError('ea must be a hexadecimal string')
    if not isinstance(params.get('optimize', False), bool): raise ValueError('optimize must be a boolean')
    region = next((r for r in image.regions if r.start <= ea < r.start + r.size), None)
    if region is None or not region.permissions & 4:
        raise ValueError('Kernel entry must be a mapped executable address')
    code = image.read(ea, min(count, region.start + region.size - ea))
    decoded = decoder.decode(image, code, ea, maximum)
    rows = decoded.get('instructions', [])
    if not rows: raise ValueError('Kernel could not decode the selected entry')
    graph = build_cfg(rows, ea, blocks)
    reachable = graph.pop('reachable')
    rows = [row for row in rows if int(row['ea'], 16) in reachable]
    optimized, changes = optimize_ir(rows) if params.get('optimize') else (rows, [])
    return {'ok': True, 'engine': 'IG5 Kernel', 'implementation': 'ig5-kernel', 'kind': 'ig5-native-raw-pcode',
            'ea': hex(ea), 'image': image.describe(), 'instructions': optimized, 'cfg': graph,
            'optimizations': changes, 'idb_modified': False, 'target_executed': False,
            'partial': bool(decoded.get('error') or decoded.get('truncated') or graph['unresolved'] or graph['truncated']),
            'decode': {'consumedBytes': decoded.get('consumedBytes'), 'truncated': decoded.get('truncated'), 'error': decoded.get('error')},
            'source': {'decoder': 'Ghidra SLEIGH C ABI', 'analysis': 'IG5-owned image/CFG/local IR rules',
                       'artifactSHA256': image.sha256, 'jvmStarted': False, 'commercialEngineUsed': False},
            'limitations': ['Bounded linear decode followed by reachable instruction graph', 'Indirect flows remain unresolved',
                            'No SSA or complete C decompiler; no IDAPython compatibility', 'No database writes or OS execution']}
