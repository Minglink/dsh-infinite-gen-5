"""Bounded native Ghidra intermediate analysis and temporary SSA rewrites.

The legacy IG5 maturity names select documented Ghidra native analysis styles.
They do not describe equivalent Hex-Rays maturity stages. All objects belong to
one private DecompInterface request; changes never update the Program database.
"""
from __future__ import annotations
import json

STAGES = {
    'generated': 'firstpass', 'preoptimized': 'normalize', 'locopt': 'normalize',
    'calls': 'normalize', 'glbopt1': 'decompile', 'glbopt2': 'decompile',
    'glbopt3': 'decompile', 'lvars': 'decompile',
}
RULES = ('xor-self', 'sub-self')


def _limit(params, key, default, maximum):
    value = params.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError('%s must be an integer in 1..%d' % (key, maximum))
    return value


def _request(params):
    maturity = str(params.get('maturity', 'glbopt3')).lower().removeprefix('mmat_')
    if maturity not in STAGES:
        raise ValueError('maturity must be one of ' + ', '.join(STAGES))
    action = params.get('action', 'inspect')
    if action not in ('inspect', 'optimize'):
        raise ValueError('microcode action must be inspect or optimize')
    rules = params.get('rules', [])
    if not isinstance(rules, list) or any(not isinstance(rule, str) or rule not in RULES for rule in rules):
        raise ValueError('rules must contain only xor-self or sub-self')
    rules = list(dict.fromkeys(rules))
    if rules and action != 'optimize':
        raise ValueError('custom rules require action optimize')
    blocks = _limit(params, 'max_blocks', 512, 4096)
    instructions = _limit(params, 'max_instructions', 10000, 100000)
    timeout = _limit(params, 'timeout', 30, 120)
    return maturity, action, rules, {
        'requestedBlocks': blocks, 'requestedInstructions': instructions,
        'maxBlocks': min(blocks, 512), 'maxInstructions': min(instructions, 4096),
        'maxVarnodes': 32768, 'maxEdges': 4096, 'maxTextChars': 262144,
        'maxRuleHits': 512, 'maxRuleTextChars': 65536,
        'timeout': timeout, 'nativeInstructionLimit': 100000,
        'nativePayloadMiB': 32,
    }


def _addr(address):
    space = address.getAddressSpace()
    if not space.isMemorySpace():
        return str(address)
    return '0x' + (str(address.toString(False)).lstrip('0') or '0')


def _node(node):
    if node is None:
        return None
    space, size = node.getAddress().getAddressSpace(), int(node.getSize())
    kind = ('constant' if node.isConstant() else 'register' if node.isRegister()
            else 'unique' if node.isUnique() else 'stack' if node.getAddress().isStackAddress() else 'memory')
    row = {'space': str(space.getName())[:128], 'offset': hex(int(node.getOffset()) & ((1 << 64) - 1)),
           'size': size, 'kind': kind}
    if node.isConstant():
        # Java Address.getOffset() is a signed 64-bit long. It never supplies
        # the high value bits of a wider constant; do not invent sign extension.
        value_bits = min(max(0, size * 8), 64)
        row['value'] = hex((int(node.getOffset()) & ((1 << 64) - 1)) & ((1 << value_bits) - 1))
        row['valueBits'] = value_bits
        row['offsetOnly'] = size > 8
        row['valueComplete'] = 0 < size <= 8
        if size > 8:
            row['valueSemantics'] = 'unsigned 64-bit address offset only; higher value bits are unspecified'
    if hasattr(node, 'getUniqueId'):
        row['id'] = int(node.getUniqueId())
    return row


def _operation(operation, index, budget):
    seq = operation.getSeqnum()
    count = int(operation.getNumInputs())
    output = operation.getOutput()
    output_allowed = output is not None and budget['varnodes'] > 0
    used = int(output_allowed)
    inputs = min(count, 64, max(0, budget['varnodes'] - used))
    used += inputs
    budget['varnodes'] -= used
    raw = str(operation)
    text = raw[:min(2048, budget['text'])]
    budget['text'] -= len(text)
    return {'index': index, 'ea': _addr(seq.getTarget()), 'opcode': int(operation.getOpcode()),
            'mnemonic': str(operation.getMnemonic()), 'text': text,
            'textTruncated': len(text) < len(raw),
            'sequence': {'time': int(seq.getTime()), 'order': int(seq.getOrder())},
            'inputs': [_node(operation.getInput(i)) for i in range(inputs)],
            'output': _node(output) if output_allowed else None,
            'totalInputs': count, 'inputsTruncated': inputs < count,
            'outputOmitted': output is not None and not output_allowed}


def _graph(high, limits, monitor):
    native = high.getBasicBlocks()
    total = len(native)
    retained = list(native)[:limits['maxBlocks']]
    retained_ids = {int(block.getIndex()) for block in retained}
    blocks, edges, rows, candidates = [], [], [], []
    budget = {'varnodes': limits['maxVarnodes'], 'text': limits['maxTextChars']}
    edge_budget = limits['maxEdges']
    instructions_incomplete = total > limits['maxBlocks']
    edges_incomplete = total > len(retained)
    def neighbors(count, getter):
        nonlocal edge_budget
        inspected = min(count, edge_budget)
        selected, omitted = [], []
        for index in range(inspected):
            identity = int(getter(index).getIndex())
            (selected if identity in retained_ids else omitted).append(identity)
        edge_budget -= inspected
        return selected, omitted, count - inspected
    for native_block in retained:
        monitor.checkCancelled()
        identity = int(native_block.getIndex())
        incoming, outgoing = int(native_block.getInSize()), int(native_block.getOutSize())
        preds, omitted_preds, uninspected_preds = neighbors(incoming, native_block.getIn)
        succs, omitted_succs, uninspected_succs = neighbors(outgoing, native_block.getOut)
        edges.extend({'from': identity, 'to': value} for value in succs)
        iterator = native_block.getIterator()
        instructions = []
        while iterator.hasNext() and len(rows) < limits['maxInstructions']:
            if len(rows) % 128 == 0:
                monitor.checkCancelled()
            operation = iterator.next()
            row = _operation(operation, len(instructions), budget)
            instructions.append(row)
            rows.append(row)
            if row['mnemonic'] == 'CBRANCH' and int(operation.getNumInputs()) == 2:
                condition = operation.getInput(1)
                if condition is not None and condition.isConstant() and len(candidates) < 128:
                    condition_size = int(condition.getSize())
                    value_bits = min(max(0, condition_size * 8), 64)
                    value = ((int(condition.getOffset()) & ((1 << 64) - 1)) & ((1 << value_bits) - 1))
                    complete_value = 0 < condition_size <= 8
                    candidates.append({'block': identity, 'instruction': row['index'], 'ea': row['ea'],
                                       'kind': 'constant-predicate', 'branchTaken': bool(value) if complete_value else None,
                                       'conditionValue': hex(value), 'conditionValueBits': value_bits,
                                       'conditionValueComplete': complete_value,
                                       'confidence': 'constant IR condition; original execution requires verification'})
        truncated = bool(iterator.hasNext())
        instructions_incomplete |= truncated
        block_edges_incomplete = bool(omitted_preds or omitted_succs or uninspected_preds or uninspected_succs)
        edges_incomplete |= block_edges_incomplete
        blocks.append({'id': identity, 'start': _addr(native_block.getStart()),
                       'end': _addr(native_block.getStop()), 'endInclusive': True,
                       'preds': preds, 'succs': succs, 'totalPreds': incoming,
                       'totalSuccs': outgoing, 'omittedPreds': omitted_preds, 'omittedSuccs': omitted_succs,
                       'uninspectedPreds': uninspected_preds, 'uninspectedSuccs': uninspected_succs,
                       'edgesTruncated': block_edges_incomplete,
                       'instructions': instructions, 'truncated': truncated})
    varnodes_incomplete = any(r['inputsTruncated'] or r['outputOmitted'] for r in rows)
    text_incomplete = any(r['textTruncated'] for r in rows)
    partial = bool(instructions_incomplete or edges_incomplete or varnodes_incomplete or text_incomplete)
    return {'blocks': blocks, 'edges': edges, 'total_blocks': total,
            'returned_instructions': len(rows), 'truncated': partial,
            'partial': partial, 'scopePartial': partial, 'scopeComplete': not partial,
            'scope': 'current function temporary intermediate representation',
            'instructionsTruncated': bool(instructions_incomplete), 'edgesTruncated': bool(edges_incomplete),
            'total_instructions': len(rows) if not instructions_incomplete else None,
            'opaque_predicate_candidates': candidates,
            'varnodesTruncated': varnodes_incomplete, 'textTruncated': text_incomplete}


def _snapshot(graph):
    rows = []
    remaining = 65536
    for block in graph['blocks']:
        for operation in block['instructions']:
            if len(rows) >= 2048:
                return rows
            text = operation['text'][:remaining]
            remaining -= len(text)
            rows.append({'ea': operation['ea'], 'opcode': operation['mnemonic'], 'text': text,
                         'sequence': operation['sequence'], 'textTruncated': len(text) < len(operation['text'])})
    return rows


def _rewrite(high, program, rules, limits, monitor, opcodes):
    """Update actual Java PcodeSyntaxTree def-use lists, never serialized copies."""
    iterator = high.getPcodeOps()
    hits, scanned, remaining_text = [], 0, limits['maxRuleTextChars']
    table = {opcodes.INT_XOR: 'xor-self', opcodes.INT_SUB: 'sub-self'}
    while iterator.hasNext() and scanned < limits['maxInstructions'] and len(hits) < limits['maxRuleHits']:
        if scanned % 128 == 0:
            monitor.checkCancelled()
        operation = iterator.next()
        scanned += 1
        # getPcodeOps() includes dead/unlinked operations as well as live SSA.
        if operation.getParent() is None:
            continue
        rule = table.get(int(operation.getOpcode()))
        if rule not in rules or int(operation.getNumInputs()) != 2:
            continue
        left, right, output = operation.getInput(0), operation.getInput(1), operation.getOutput()
        if left is None or right is None or output is None or not bool(left.equals(right)):
            continue
        size = int(output.getSize())
        if not 1 <= size <= 16 or int(left.getSize()) != size or int(right.getSize()) != size:
            continue
        raw_before = str(operation)
        before = raw_before[:min(1024, remaining_text)] or str(operation.getMnemonic())
        remaining_text = max(0, remaining_text - len(before))
        output_id = int(output.getUniqueId())
        constant = high.newVarnode(size, program.getAddressFactory().getConstantSpace().getAddress(0))
        high.unSetInput(operation, 1)
        operation.removeInput(1)
        high.setInput(operation, constant, 0)
        high.setOpcode(operation, opcodes.COPY)
        if operation.getOutput() is not output and not bool(operation.getOutput().equals(output)):
            raise RuntimeError('Temporary rewrite changed the output varnode')
        if int(operation.getNumInputs()) != 1 or int(operation.getOpcode()) != opcodes.COPY or not operation.getInput(0).isConstant() or int(operation.getInput(0).getOffset()) != 0:
            raise RuntimeError('Temporary rewrite verification failed')
        raw_after = str(operation)
        after = raw_after[:min(1024, remaining_text)] or str(operation.getMnemonic())
        remaining_text = max(0, remaining_text - len(after))
        hits.append({'rule': rule, 'ea': _addr(operation.getSeqnum().getTarget()),
                     'before': before, 'after': after,
                     'textTruncated': len(before) < len(raw_before) or len(after) < len(raw_after),
                     'outputId': output_id, 'outputSize': size, 'verified': True})
    return hits, scanned, bool(iterator.hasNext())


def _analysis(interface, worker, function, stage, limits, monitor):
    if not interface.setSimplificationStyle(stage):
        raise RuntimeError('Ghidra could not select native analysis stage ' + stage)
    result = interface.decompileFunction(function, limits['timeout'], monitor)
    if not result.decompileCompleted() or result.getHighFunction() is None:
        raise RuntimeError('Ghidra intermediate analysis failed: ' + str(result.getErrorMessage())[:2048])
    return result.getHighFunction()


def run_microcode(worker, params):
    maturity, action, rules, limits = _request(params)
    worker.require()
    function = worker.function(params)
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.program.model.pcode import PcodeOp
    stage = STAGES[maturity]
    program, before_modification = worker.program, int(worker.program.getModificationNumber())
    monitor = worker.monitor({'timeout': limits['timeout']})
    interface = DecompInterface()
    try:
        options = DecompileOptions()
        options.setMaxPayloadMBytes(limits['nativePayloadMiB'])
        options.setMaxInstructions(limits['nativeInstructionLimit'])
        options.setMaxJumpTableEntries(4096)
        if not interface.setOptions(options) or not interface.toggleSyntaxTree(True) or not interface.toggleCCode(False):
            raise RuntimeError('Ghidra intermediate analysis options could not be configured')
        if not interface.setSimplificationStyle(stage) or not interface.openProgram(program):
            raise RuntimeError('Private Ghidra decompiler unavailable: ' + str(interface.getLastMessage())[:2048])
        high = _analysis(interface, worker, function, stage, limits, monitor)
        graph = _graph(high, limits, monitor)
        optimization = None
        if action == 'optimize':
            before = _snapshot(graph)
            before_partial = (graph['truncated'] or graph['returned_instructions'] > len(before)
                              or any(row['textTruncated'] for row in before))
            hits, scanned, rewrite_truncated = [], 0, False
            native_stage_changed = False
            if rules:
                hits, scanned, rewrite_truncated = _rewrite(high, program, rules, limits, monitor, PcodeOp)
            else:
                optimized_stage = 'normalize' if stage == 'firstpass' else 'decompile'
                native_stage_changed = optimized_stage != stage
                high = _analysis(interface, worker, function, optimized_stage, limits, monitor)
                stage = optimized_stage
            graph = _graph(high, limits, monitor)
            after = _snapshot(graph)
            changes = sum(a != b for a, b in zip(before, after)) + abs(len(before) - len(after))
            optimization = {'ok': True, 'before': before, 'after': after,
                            'changes': len(hits) if rules else changes,
                            'changesScope': 'verified Java SSA rewrites' if rules else 'bounded observed operation-row differences',
                            'custom_rules': rules, 'rule_hits': hits, 'scannedOperations': scanned,
                            'truncated': bool(rewrite_truncated or before_partial or graph['truncated']
                                              or graph['returned_instructions'] > len(after)
                                              or any(row['textTruncated'] for row in after)
                                              or any(hit['textTruncated'] for hit in hits)),
                            'nativeOptimizationApplied': native_stage_changed,
                            'temporaryIRRewritten': bool(hits), 'idb_modified': False,
                            'filter_installed': False, 'filter_removed': None,
                            'ruleMechanism': 'temporary HighFunction SSA rewrite' if rules else 'native analysis style',
                            'cCodeRegeneratedFromRewrittenIR': False}
            if optimization['truncated']:
                graph.update(truncated=True, partial=True, scopePartial=True, scopeComplete=False)
        if int(program.getModificationNumber()) != before_modification:
            raise RuntimeError('Database changed during read-only intermediate analysis')
        result = {'ok': True, 'engine': 'Ghidra', 'representation': 'Ghidra p-code',
                  'hexRaysEquivalent': False, 'requested_maturity': maturity,
                  'maturity': stage, 'actualStage': stage, 'available_maturities': list(STAGES),
                  'maturityMapping': dict(STAGES), 'ea': _addr(function.getEntryPoint()),
                  'func': str(function.getName())[:4096], 'action': action, 'graph_built': True,
                  'idb_modified': False, 'revision': worker.revision, 'optimization': optimization,
                  'limits': limits, **graph,
                  'source': {'engine': 'Ghidra', 'representation': 'native HighFunction dataflow',
                             'language': str(program.getLanguageID()), 'artifactSHA256': worker.source_hash},
                  'limitations': ['Legacy maturity names select Ghidra analysis styles; they are not equivalent Hex-Rays stages.',
                                  'Custom rules modify only this temporary Java SSA graph; they do not feed the native optimizer or regenerate C code.',
                                  'No database bytes/types/symbols are modified. Predicate candidates require original execution verification.',
                                  'Output, text, varnodes and edges are bounded; missing operation totals remain null when truncated.']}
        if len(json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) > 12 * 1024 * 1024:
            raise RuntimeError('Ghidra intermediate response exceeds its 12 MiB budget')
        return result
    finally:
        interface.dispose()
