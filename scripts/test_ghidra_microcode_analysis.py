"""Pure lifecycle, SSA identity, rewrite and output-budget boundary fixtures."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('microcode', ROOT / 'adapters/ghidra/microcode_analysis.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
OP = types.SimpleNamespace(COPY=1, INT_XOR=26, INT_SUB=20)


class Iterator:
    def __init__(self, rows): self.rows, self.index = rows, 0
    def hasNext(self): return self.index < len(self.rows)
    def next(self):
        result = self.rows[self.index]
        self.index += 1
        return result


class Space:
    def __init__(self, name='ram'): self.name = name
    def getName(self): return self.name
    def isMemorySpace(self): return self.name == 'ram'
    def getAddress(self, value): return Address(value, self)


class Address:
    def __init__(self, value, space=None): self.value, self.space = value, space or Space()
    def getAddressSpace(self): return self.space
    def toString(self, _): return format(self.value, 'x')
    def isStackAddress(self): return False
    def __str__(self): return self.toString(False)


class Node:
    def __init__(self, identity, size=4, offset=0, constant=False):
        self.identity, self.size, self.offset, self.constant = identity, size, offset, constant
    def getAddress(self): return Address(self.offset, Space('const' if self.constant else 'register'))
    def getOffset(self): return self.offset
    def getSize(self): return self.size
    def getUniqueId(self): return self.identity
    def isConstant(self): return self.constant
    def isRegister(self): return not self.constant
    def isUnique(self): return False
    def equals(self, other): return self.identity == other.identity


class Sequence:
    def __init__(self, index): self.index = index
    def getTarget(self): return Address(0x1000 + self.index)
    def getTime(self): return self.index
    def getOrder(self): return self.index


class Operation:
    def __init__(self, index, opcode, left, right, output):
        self.index, self.opcode, self.inputs, self.output = index, opcode, [left, right], output
    def getSeqnum(self): return Sequence(self.index)
    def getOpcode(self): return self.opcode
    def getMnemonic(self): return {1: 'COPY', 26: 'INT_XOR', 20: 'INT_SUB'}[self.opcode]
    def getNumInputs(self): return len(self.inputs)
    def getInput(self, i): return self.inputs[i]
    def getOutput(self): return self.output
    def getParent(self): return object()
    def removeInput(self, i): self.inputs.pop(i)
    def __str__(self): return self.getMnemonic() + ':' + ','.join(str(x.identity) for x in self.inputs if x is not None)


class Block:
    def __init__(self, index, operations, ins=(), outs=()):
        self.index, self.operations, self.ins, self.outs = index, operations, ins, outs
    def getIndex(self): return self.index
    def getStart(self): return Address(0x1000)
    def getStop(self): return Address(0x100f)
    def getInSize(self): return len(self.ins)
    def getOutSize(self): return len(self.outs)
    def getIn(self, index): return self.ins[index]
    def getOut(self, index): return self.outs[index]
    def getIterator(self): return Iterator(self.operations)


class High:
    def __init__(self, operations): self.operations, self.mutations = operations, []
    def getBasicBlocks(self): return [Block(0, self.operations)]
    def getPcodeOps(self): return Iterator(self.operations)
    def newVarnode(self, size, addr): return Node(999, size, addr.value, True)
    def unSetInput(self, operation, slot):
        self.mutations.append(('unset', slot))
        operation.inputs[slot] = None
    def setInput(self, operation, value, slot):
        self.mutations.append(('input', slot))
        operation.inputs[slot] = value
    def setOpcode(self, operation, opcode):
        self.mutations.append(('opcode', opcode))
        operation.opcode = opcode


class Program:
    def getAddressFactory(self): return self
    def getConstantSpace(self): return Space('const')
    def getModificationNumber(self): return 10
    def getLanguageID(self): return 'x86:LE:64:default'


class Monitor:
    def checkCancelled(self): pass


def operation(opcode=26, size=4):
    shared = Node(1, size)
    return Operation(0, opcode, shared, shared, Node(2, size))


class Tests(unittest.TestCase):
    def limits(self, **values): return m._request(values)[3]

    def test_input_budgets_reject_bool_invalid_rule_and_unknown_stage(self):
        for value in ({'max_blocks': True}, {'max_instructions': 0}, {'timeout': 121}, {'rules': ['unknown'], 'action': 'optimize'}, {'rules': ['xor-self']}, {'maturity': 'not-stage'}):
            with self.subTest(value=value), self.assertRaises(ValueError): m._request(value)
        result = m._request({'action': 'optimize', 'rules': ['xor-self', 'xor-self']})
        self.assertEqual(result[2], ['xor-self'])
        self.assertEqual(self.limits(max_instructions=100000)['maxInstructions'], 4096)

    def test_mapping_is_explicit_not_hexrays_stage_names(self):
        self.assertEqual(m._request({'maturity': 'MMAT_GENERATED'})[0], 'generated')
        self.assertEqual(m.STAGES['generated'], 'firstpass')
        self.assertEqual(m.STAGES['preoptimized'], 'normalize')
        self.assertEqual(m.STAGES['lvars'], 'decompile')

    def test_true_graph_rewrite_and_output_identity_preserved(self):
        for opcode, rule in ((26, 'xor-self'), (20, 'sub-self')):
            op = operation(opcode)
            high, original_output = High([op]), op.output
            hits, scanned, truncated = m._rewrite(high, Program(), [rule], self.limits(), Monitor(), OP)
            self.assertEqual((len(hits), scanned, truncated), (1, 1, False))
            self.assertIs(op.output, original_output)
            self.assertEqual(op.opcode, OP.COPY)
            self.assertEqual(len(op.inputs), 1)
            self.assertTrue(op.inputs[0].constant)
            self.assertEqual(op.inputs[0].offset, 0)
            self.assertEqual(high.mutations, [('unset', 1), ('input', 0), ('opcode', 1)])
            self.assertNotEqual(hits[0]['before'], hits[0]['after'])

    def test_same_storage_different_ssa_identity_not_rewritten(self):
        op = operation()
        op.inputs[1] = Node(3, 4, op.inputs[0].offset)
        high = High([op])
        hits, _, _ = m._rewrite(high, Program(), ['xor-self'], self.limits(), Monitor(), OP)
        self.assertEqual(hits, [])
        self.assertEqual(op.opcode, 26)
        self.assertEqual(high.mutations, [])

    def test_width_and_arity_mismatch_not_rewritten(self):
        for change in ('width', 'output', 'arity'):
            op = operation()
            if change == 'width': op.output.size = 8
            if change == 'output': op.output = None
            if change == 'arity': op.inputs.pop()
            hits, _, _ = m._rewrite(High([op]), Program(), ['xor-self'], self.limits(), Monitor(), OP)
            self.assertEqual(hits, [])

    def test_operation_and_rule_hit_budget_are_truthful(self):
        high = High([operation() for _ in range(3)])
        limits = self.limits(max_instructions=1)
        graph = m._graph(high, limits, Monitor())
        self.assertEqual(graph['returned_instructions'], 1)
        self.assertIsNone(graph['total_instructions'])
        self.assertTrue(graph['truncated'])
        hits, scanned, truncated = m._rewrite(high, Program(), ['xor-self'], limits, Monitor(), OP)
        self.assertEqual((len(hits), scanned, truncated), (1, 1, True))

    def test_operand_and_text_truncation_remain_partial_with_exact_op_count(self):
        for key in ('maxVarnodes', 'maxTextChars'):
            limits = self.limits()
            limits[key] = 0
            graph = m._graph(High([operation()]), limits, Monitor())
            self.assertTrue(graph['truncated'])
            self.assertTrue(graph['partial'])
            self.assertFalse(graph['scopeComplete'])
            self.assertFalse(graph['instructionsTruncated'])
            self.assertEqual(graph['total_instructions'], 1)

    def test_omitted_blocks_do_not_leak_dangling_edges(self):
        a, b = Block(0, [operation()]), Block(1, [])
        a.ins, a.outs = (b,), (b,)
        high = High([])
        high.getBasicBlocks = lambda: [a, b]
        graph = m._graph(high, self.limits(max_blocks=1), Monitor())
        self.assertEqual(graph['edges'], [])
        self.assertEqual(graph['blocks'][0]['preds'], [])
        self.assertEqual(graph['blocks'][0]['succs'], [])
        self.assertEqual(graph['blocks'][0]['omittedPreds'], [1])
        self.assertEqual(graph['blocks'][0]['omittedSuccs'], [1])
        self.assertEqual(graph['blocks'][0]['totalPreds'], 1)
        self.assertEqual(graph['blocks'][0]['totalSuccs'], 1)
        self.assertTrue(graph['blocks'][0]['edgesTruncated'])
        self.assertTrue(graph['edgesTruncated'])
        self.assertTrue(graph['partial'])

    def test_wide_constant_never_invents_high_bits(self):
        row = m._node(Node(99, size=16, offset=-1, constant=True))
        self.assertEqual(row['offset'], '0xffffffffffffffff')
        self.assertEqual(row['value'], '0xffffffffffffffff')
        self.assertEqual(row['valueBits'], 64)
        self.assertTrue(row['offsetOnly'])
        self.assertFalse(row['valueComplete'])
        self.assertEqual(m._node(Node(99, size=1, offset=-1, constant=True))['value'], '0xff')

    def test_constant_predicates_use_effective_width(self):
        for size, offset, taken in [(1, 256, False), (1, -256, False), (1, -1, True), (16, 0, None), (16, -1, None)]:
            op = operation()
            op.inputs[1] = Node(33, size=size, offset=offset, constant=True)
            op.getMnemonic = lambda: 'CBRANCH'
            graph = m._graph(High([op]), self.limits(), Monitor())
            candidate = graph['opaque_predicate_candidates'][0]
            self.assertIs(candidate['branchTaken'], taken)
            self.assertEqual(candidate['conditionValueBits'], min(size * 8, 64))
            self.assertEqual(candidate['conditionValueComplete'], size <= 8)

    def test_private_interface_disposed_on_success_and_exception(self):
        high = High([operation()])
        instances = []
        class Options:
            def setMaxPayloadMBytes(self, _): pass
            def setMaxInstructions(self, _): pass
            def setMaxJumpTableEntries(self, _): pass
        class Interface:
            fail = False
            def __init__(self): self.disposed = False; instances.append(self)
            def setOptions(self, _): return True
            def toggleSyntaxTree(self, _): return True
            def toggleCCode(self, _): return True
            def setSimplificationStyle(self, _): return True
            def openProgram(self, _): return True
            def decompileFunction(self, *_):
                if self.fail: raise RuntimeError('controlled failure')
                return types.SimpleNamespace(decompileCompleted=lambda: True, getHighFunction=lambda: high)
            def dispose(self): self.disposed = True
        decompiler = types.ModuleType('ghidra.app.decompiler')
        decompiler.DecompInterface, decompiler.DecompileOptions = Interface, Options
        pcode = types.ModuleType('ghidra.program.model.pcode'); pcode.PcodeOp = OP
        function = types.SimpleNamespace(getEntryPoint=lambda: Address(0x1000), getName=lambda: 'fixture')
        sentinel = object()
        worker = types.SimpleNamespace(require=lambda: None, function=lambda _: function, program=Program(),
                                       monitor=lambda _: Monitor(), revision=7, source_hash='a' * 64, decompiler=sentinel)
        with mock.patch.dict(sys.modules, {'ghidra.app.decompiler': decompiler, 'ghidra.program.model.pcode': pcode}):
            result = m.run_microcode(worker, {'maturity': 'generated', 'action': 'optimize', 'rules': ['xor-self']})
            self.assertEqual(result['optimization']['changes'], 1)
            self.assertFalse(result['hexRaysEquivalent'])
            self.assertEqual(result['actualStage'], 'firstpass')
            self.assertTrue(instances[-1].disposed)
            self.assertIs(worker.decompiler, sentinel)
            Interface.fail = True
            with self.assertRaises(RuntimeError): m.run_microcode(worker, {})
            self.assertTrue(instances[-1].disposed)
            self.assertIs(worker.decompiler, sentinel)


if __name__ == '__main__': unittest.main(verbosity=2)
