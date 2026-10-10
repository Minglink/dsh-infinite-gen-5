"""Explicit native intermediate-analysis acceptance against a generated PE.

Run with the bundled isolated Python. The caller supplies a test-only fixture
and output directory; no target execution or host GUI is started.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ghidra-home', required=True)
    parser.add_argument('--java-home', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / 'adapters/ghidra'))
    from worker import Worker
    import microcode_analysis as microcode
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = Path(args.fixture).resolve()
    original_sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
    worker = Worker(Path(args.ghidra_home).resolve(), Path(args.java_home).resolve(), output / 'projects')
    checks, evidence = [], []
    started = time.monotonic()

    def check(name, condition, detail=None):
        if not condition:
            raise AssertionError(name)
        checks.append(name)
        print('PASS ' + name, file=sys.stderr, flush=True)
        if detail is not None:
            evidence.append({'name': name, 'detail': detail})

    try:
        opened = worker.m_open({'path': str(fixture), 'fresh': True, 'analysis_timeout': 120})
        check('generated PE native import', opened['open'] and opened['n_funcs'] >= 16)
        params = {'ea': '0x140001000', 'max_blocks': 30, 'max_instructions': 200}
        code_before = worker.m_decompile(params)['code']
        shared_decompiler = worker.decompiler
        modification = int(worker.program.getModificationNumber())
        for maturity, stage in microcode.STAGES.items():
            result = microcode.run_microcode(worker, {**params, 'maturity': maturity})
            check('real native stage ' + maturity, result['ok'] and result['actualStage'] == stage and result['returned_instructions'] > 0 and result['total_blocks'] > 0 and result['hexRaysEquivalent'] is False,
                  {'stage': stage, 'blocks': result['total_blocks'], 'instructions': result['returned_instructions']})
        optimized = microcode.run_microcode(worker, {**params, 'maturity': 'generated', 'action': 'optimize'})
        optimization = optimized['optimization']
        check('native firstpass to normalize', optimized['actualStage'] == 'normalize' and optimization['nativeOptimizationApplied'] and bool(optimization['before']) and bool(optimization['after']), optimization)
        limited = microcode.run_microcode(worker, {**params, 'maturity': 'generated', 'max_instructions': 1})
        check('instruction truncation truthful', limited['truncated'] and limited['returned_instructions'] == 1 and limited['total_instructions'] is None)
        clipped = microcode.run_microcode(worker, {**params, 'ea': '0x140001140', 'maturity': 'generated', 'max_blocks': 1})
        ids = {block['id'] for block in clipped['blocks']}
        check('native clipped graph has no dangling edges', clipped['partial'] and clipped['edgesTruncated']
              and all(edge['from'] in ids and edge['to'] in ids for edge in clipped['edges'])
              and all(value in ids for block in clipped['blocks'] for value in block['preds'] + block['succs'])
              and any(block['omittedPreds'] or block['omittedSuccs'] for block in clipped['blocks']), clipped['blocks'])
        natural = []
        for ea, rule in [('0x140001320', 'xor-self'), ('0x140001340', 'sub-self')]:
            result = microcode.run_microcode(worker, {**params, 'ea': ea, 'maturity': 'generated', 'action': 'optimize', 'rules': [rule]})
            check('natural fixture probe ' + rule, result['ok'] and result['optimization']['custom_rules'] == [rule] and result['optimization']['idb_modified'] is False and result['optimization']['cCodeRegeneratedFromRewrittenIR'] is False)
            natural.append({'rule': rule, 'hits': result['optimization']['rule_hits']})
        evidence.append({'name': 'natural native hit counts', 'detail': natural})
        # Construct real temporary Java SSA operations only in a HighFunction
        # from actual native analysis. This proves mutation/def-use APIs even
        # when the native first pass has already folded a natural x^x sample.
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.pcode import PcodeOp, SequenceNumber
        from java.util import ArrayList
        for index, (opcode, rule) in enumerate([(PcodeOp.INT_XOR, 'xor-self'), (PcodeOp.INT_SUB, 'sub-self')]):
            interface = DecompInterface()
            try:
                interface.setSimplificationStyle('firstpass')
                check('private native interface ' + rule, interface.openProgram(worker.program))
                function = worker.function(params)
                response = interface.decompileFunction(function, 30, worker.monitor({'timeout': 30}))
                high = response.getHighFunction()
                check('native HighFunction ' + rule, response.decompileCompleted() and high is not None)
                block = high.getBasicBlocks().get(0)
                anchor = block.getIterator().next()
                unique = worker.program.getAddressFactory().getUniqueSpace()
                input_node = high.newVarnode(4, unique.getAddress(0x10000000 + index * 32))
                output_node = high.newVarnode(4, unique.getAddress(0x10000010 + index * 32))
                inputs = ArrayList()
                inputs.add(input_node); inputs.add(input_node)
                sequence = SequenceNumber(function.getEntryPoint(), 100000 + index)
                operation = high.newOp(sequence, opcode, inputs, output_node)
                high.insertBefore(operation, anchor)
                before = str(operation)
                hits, _, _ = microcode._rewrite(high, worker.program, [rule], microcode._request(params)[3], worker.monitor({'timeout': 30}), PcodeOp)
                selected = [hit for hit in hits if hit['outputId'] == int(output_node.getUniqueId())]
                check('real Java SSA rewrite ' + rule, len(selected) == 1 and operation.getOpcode() == PcodeOp.COPY and operation.getNumInputs() == 1 and operation.getInput(0).isConstant() and operation.getInput(0).getOffset() == 0 and operation.getOutput().equals(output_node) and operation.getOutput().getDef().equals(operation) and before != str(operation), selected)
                descendants = input_node.getDescendants()
                old_links = []
                while descendants.hasNext(): old_links.append(descendants.next())
                check('old def-use descendants removed ' + rule, not any(op.equals(operation) for op in old_links))
                check('constant def-use descendant preserved ' + rule, operation.getInput(0).getLoneDescend().equals(operation))
                if index == 0:
                    constant_space = worker.program.getAddressFactory().getConstantSpace()
                    wide_node = high.newVarnode(16, constant_space.getAddress(-1))
                    wide = microcode._node(wide_node)
                    check('real Java wide constant offset-only', wide['value'] == '0xffffffffffffffff'
                          and wide['valueBits'] == 64 and wide['offsetOnly'] and not wide['valueComplete'], wide)
                    for probe, (offset, expected) in enumerate([(256, False), (-256, False), (-1, True)]):
                        condition = high.newVarnode(1, constant_space.getAddress(offset))
                        branch_inputs = ArrayList()
                        branch_inputs.add(high.newVarnode(8, function.getEntryPoint()))
                        branch_inputs.add(condition)
                        branch = high.newOp(SequenceNumber(function.getEntryPoint(), 200000 + probe), PcodeOp.CBRANCH, branch_inputs, None)
                        high.insertBefore(branch, anchor)
                        graph = microcode._graph(high, microcode._request(params)[3], worker.monitor({'timeout': 30}))
                        candidates = graph['opaque_predicate_candidates']
                        check('real Java byte predicate ' + str(offset), candidates[-1]['branchTaken'] is expected
                              and candidates[-1]['conditionValueBits'] == 8 and candidates[-1]['conditionValueComplete'], candidates[-1])
            finally:
                interface.dispose()
        check('shared C decompiler remains unchanged', worker.decompiler is shared_decompiler and worker.m_decompile(params)['code'] == code_before)
        check('Program unchanged', int(worker.program.getModificationNumber()) == modification)
        check('fixture bytes unchanged', hashlib.sha256(fixture.read_bytes()).hexdigest() == original_sha)
        report = {'ok': True, 'native': True, 'engine': 'Ghidra', 'representation': 'Ghidra p-code', 'hexRaysEquivalent': False,
                  'targetExecuted': False, 'idbModified': False, 'checks': checks, 'count': len(checks),
                  'fixtureSHA256': original_sha, 'moduleSHA256': hashlib.sha256((root / 'adapters/ghidra/microcode_analysis.py').read_bytes()).hexdigest(),
                  'elapsedSeconds': round(time.monotonic() - started, 3), 'evidence': evidence}
        (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print('REPORT=' + str(output / 'report.json'), file=sys.stderr, flush=True)
    finally:
        worker.m_close({})


if __name__ == '__main__': main()
