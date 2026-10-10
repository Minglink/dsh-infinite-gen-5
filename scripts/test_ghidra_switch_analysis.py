"""Switch boundary fixtures; --api-probe also inspects bundled Java signatures.

This does not start Ghidra or execute a sample.  Native recovery/persistence is a
separate explicit acceptance step, not inferred from these fixtures.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('ig5_ghidra_switch', ROOT / 'adapters/ghidra/switch_analysis.py')
switch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(switch)
API_PROBE = '--api-probe' in sys.argv
if API_PROBE:
    sys.argv.remove('--api-probe')


class Space:
    def __init__(self, bits=64, memory=True):
        self.bits, self.memory = bits, memory

    def getSize(self): return self.bits
    def isMemorySpace(self): return self.memory


class Address:
    def __init__(self, value, space): self.value, self.space = value, space
    def getAddressSpace(self): return self.space
    def getOffset(self): return self.value if self.value < 1 << 63 else self.value - (1 << 64)
    def toString(self, _): return format(self.value, '016x')
    def __eq__(self, other): return isinstance(other, Address) and self.value == other.value and self.space is other.space


class Flow:
    def __init__(self, jump=True, computed=True): self.jump, self.computed = jump, computed
    def isJump(self): return self.jump
    def isComputed(self): return self.computed


class Instruction:
    def __init__(self, worker, value): self.worker, self.value, self.references, self.flow = worker, value, [], Flow()
    def getFlowType(self): return self.flow
    def getReferencesFrom(self): return list(self.references)
    def addOperandReference(self, operand, target, kind, source):
        self.worker.events.append(('reference', target.value))
        self.references.append(types.SimpleNamespace(getToAddress=lambda: target, getReferenceType=lambda: kind))


class Table:
    def __init__(self, worker, targets=(0x2000, 0x2010, 0x2020), labels=(0, 1, 2), ea=0x1000, loads=()):
        self.worker, self.targets, self.labels, self.ea, self.loads = worker, targets, labels, ea, loads
    def getSwitchAddress(self): return self.worker.addr(self.ea)
    def getCases(self): return [self.worker.addr(value) for value in self.targets]
    def getLabelValues(self): return self.labels
    def getLoadTables(self): return self.loads


class FixtureWorker:
    def __init__(self, bits=64, big=False):
        self.space = Space(bits)
        self.events, self.commits, self.revision, self.big = [], [], 7, big
        self.table = b''.join(value.to_bytes(8, 'big' if big else 'little') for value in (0x2000, 0x2010, 0x2020))
        self.instructions = {value: Instruction(self, value) for value in (0x1000, 0x2000, 0x2010, 0x2020, 0x2030)}
        self.function_value = types.SimpleNamespace(getName=lambda: 'fixture', getEntryPoint=lambda: self.addr(0x1000))
        self.tables = [Table(self)]
        self.blocks = {value: (True, True) for value in self.instructions}
        factory = types.SimpleNamespace(getDefaultAddressSpace=lambda: self.space, getAddress=lambda value: self.addr(int(value, 16)))
        memory = types.SimpleNamespace(getBlock=lambda addr: types.SimpleNamespace(isExecute=lambda: self.blocks[addr.value][0], isInitialized=lambda: self.blocks[addr.value][1]) if addr.value in self.blocks else None)
        listing = types.SimpleNamespace(getInstructionAt=lambda addr: self.instructions.get(addr.value))
        def remove(reference):
            self.events.append(('remove-reference', reference.getToAddress().value))
            self.instructions[0x1000].references.remove(reference)
        refs = types.SimpleNamespace(delete=remove)
        self.program = types.SimpleNamespace(getAddressFactory=lambda: factory, getMemory=lambda: memory,
                                            getListing=lambda: listing, getReferenceManager=lambda: refs,
                                            getLanguage=lambda: types.SimpleNamespace(isBigEndian=lambda: self.big))
    def require(self): pass
    def addr(self, value): return Address(value, self.space)
    def address(self, params): return self.addr(int(str(params['ea']).removeprefix('0x'), 16))
    def function(self, params): return self.function_value
    def decompile(self, params):
        return self.function_value, types.SimpleNamespace(getHighFunction=lambda: types.SimpleNamespace(getJumpTables=lambda: self.tables))
    def read_bytes(self, address, count):
        self.events.append(('read', address.value, count))
        if address.value != 0x3000:
            raise ValueError('fixture unreadable table')
        return self.table[:count]
    def monitor(self, params): return 'fixture-monitor'
    def commit(self, method, params, body):
        self.commits.append((method, params))
        self.events.append(('commit', method))
        value = body()
        self.revision += 1
        return {**value, 'revision': self.revision, 'journalId': 'fixture-journal', 'saved': False, 'persistence': 'session-only'}


def fake_java(worker, fail_override=False):
    class ArrayList(list):
        def add(self, value): self.append(value)
    class JumpTable:
        def __init__(self, address, targets, override, display):
            worker.events.append(('construct-override', address.value, [a.value for a in targets], override, display))
        def writeOverride(self, function):
            worker.events.append(('write-override', function.getName()))
            if fail_override:
                raise ValueError('fixture override failed')
    class CreateFunctionCmd:
        @staticmethod
        def fixupFunctionBody(program, function, monitor):
            worker.events.append(('fixup', monitor))
            return True
    modules = {}
    values = {'java.util': {'ArrayList': ArrayList}, 'ghidra.program.model.pcode': {'JumpTable': JumpTable},
              'ghidra.program.model.symbol': {'RefType': types.SimpleNamespace(COMPUTED_JUMP=Flow()), 'SourceType': types.SimpleNamespace(USER_DEFINED='user')},
              'ghidra.app.cmd.function': {'CreateFunctionCmd': CreateFunctionCmd}}
    for name, attrs in values.items():
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        modules[name] = module
    return patch.dict(sys.modules, modules)


class SwitchTests(unittest.TestCase):
    def definition(self, **extra):
        return {'ea': '0x1000', 'action': 'define', 'table': '0x3000', 'ncases': 3, 'element_size': 8, **extra}

    def test_read_native_vectors_exact_and_limits(self):
        worker = FixtureWorker()
        worker.tables.append(Table(worker, ea=0x1010))
        value = switch.read_switches(worker, {'ea': '0x1000', 'exact': True, 'max_cases': 2})
        self.assertEqual(value['total'], 1)
        self.assertTrue(value['truncated'])
        record = value['switches'][0]
        self.assertEqual([row['values'] for row in record['cases']], [[0], [1]])
        self.assertTrue(record['defaultUnknown'])
        self.assertIsNone(record['default'])
        self.assertEqual(switch.read_switches(worker, {'ea': '0x1000', 'limit': 1})['total'], 2)

    def test_missing_label_does_not_shift_or_invent_default(self):
        worker = FixtureWorker()
        worker.tables = [Table(worker, labels=(11, 22))]
        record = switch.read_switches(worker, {'ea': '0x1000'})['switches'][0]
        self.assertFalse(record['labelsMapped'])
        self.assertEqual(record['labelValues'], [11, 22])
        self.assertTrue(all(row['values'] == [] for row in record['cases']))
        self.assertIsNone(record['default'])

    def test_case_budget_is_shared_across_all_tables(self):
        worker = FixtureWorker()
        worker.tables.append(Table(worker, ea=0x1010))
        value = switch.read_switches(worker, {'ea': '0x1000', 'max_cases': 4})
        self.assertEqual([len(record['cases']) for record in value['switches']], [3, 1])
        self.assertEqual(value['caseBudgetScope'], 'all returned switch tables combined')
        self.assertTrue(value['truncated'])

    def test_high_address_precision_and_signed_java_label_view(self):
        worker = FixtureWorker()
        worker.tables = [Table(worker, targets=(0xFFFFFFFFFFFF2010,), labels=(-1,))]
        record = switch.read_switches(worker, {'ea': '0x1000'})['switches'][0]
        self.assertEqual(record['cases'][0]['target'], '0xffffffffffff2010')
        self.assertEqual(record['cases'][0]['values'], [-1])
        self.assertEqual(record['labelSignedness'], 'unknown')

    def test_preview_has_no_mutation_or_java_import(self):
        worker = FixtureWorker()
        value = switch.repair_switch(worker, self.definition(default='0x2030', lowcase=4))
        self.assertFalse(value['applied'])
        self.assertEqual(value['targets'], ['0x2000', '0x2010', '0x2020', '0x2030'])
        self.assertEqual(value['switch']['cases'][0]['requestedValues'], [4])
        self.assertEqual(value['switch']['requestedDefault'], '0x2030')
        self.assertFalse(value['labelsPersisted'])
        self.assertFalse(value['defaultMetadataPersisted'])
        self.assertEqual(worker.commits, [])
        self.assertEqual(worker.revision, 7)
        self.assertEqual(worker.events, [('read', 0x3000, 24)])

    def test_apply_uses_commit_and_real_api_sequence(self):
        worker = FixtureWorker()
        with fake_java(worker):
            value = switch.repair_switch(worker, self.definition(apply=True))
        self.assertTrue(value['applied'])
        self.assertEqual(value['revision'], 8)
        self.assertEqual(value['journalId'], 'fixture-journal')
        self.assertFalse(value['saved'])
        sequence = [event[0] for event in worker.events]
        self.assertLess(sequence.index('commit'), sequence.index('write-override'))
        self.assertLess(sequence.index('write-override'), sequence.index('reference'))
        self.assertEqual(sequence[-1], 'fixup')

    def test_apply_failure_propagates_and_does_not_claim_success(self):
        worker = FixtureWorker()
        with fake_java(worker, True), self.assertRaisesRegex(ValueError, 'override failed'):
            switch.repair_switch(worker, self.definition(apply=True))
        self.assertEqual(worker.revision, 7)
        self.assertFalse(any(event[0] in ('reference', 'fixup') for event in worker.events))

    def test_remove_stale_computed_jump_preserve_nonjump(self):
        worker = FixtureWorker()
        branch = worker.instructions[0x1000]
        stale = types.SimpleNamespace(getToAddress=lambda: worker.addr(0x2030), getReferenceType=lambda: Flow())
        unrelated = types.SimpleNamespace(getToAddress=lambda: worker.addr(0x2030), getReferenceType=lambda: Flow(False, False))
        branch.references = [stale, unrelated]
        with fake_java(worker):
            value = switch.repair_switch(worker, self.definition(apply=True))
        self.assertEqual(value['removedStaleComputedJumpReferences'], ['0x2030'])
        self.assertIn(unrelated, branch.references)
        self.assertNotIn(stale, branch.references)

    def test_big_endian_table_and_duplicate_targets(self):
        worker = FixtureWorker(big=True)
        worker.table = b''.join(value.to_bytes(8, 'big') for value in (0x2000, 0x2000, 0x2010))
        value = switch.repair_switch(worker, self.definition())
        self.assertEqual(value['targets'], ['0x2000', '0x2010'])
        self.assertEqual(value['switch']['ncases'], 3)
        self.assertEqual(value['switch']['byteOrder'], 'big')

    def test_relative_signed_shift_and_subtract(self):
        worker = FixtureWorker()
        worker.table = (-8).to_bytes(4, 'little', signed=True) + (0).to_bytes(4, 'little') + (8).to_bytes(4, 'little')
        value = switch.repair_switch(worker, self.definition(element_size=4, relative=True, signed=True, elbase='0x2010', shift=1))
        self.assertEqual(value['targets'], ['0x2000', '0x2010', '0x2020'])
        value = switch.repair_switch(worker, self.definition(element_size=4, subtract=True, signed=True, elbase='0x2010', shift=1))
        self.assertEqual(value['targets'], ['0x2020', '0x2010', '0x2000'])

    def test_large_requested_labels_keep_json_precision(self):
        worker = FixtureWorker()
        value = switch.repair_switch(worker, self.definition(lowcase=(1 << 63) - 2))
        self.assertEqual(value['switch']['lowcase'], str((1 << 63) - 2))
        self.assertEqual(value['switch']['cases'][2]['requestedValues'], [str(1 << 63)])

    def test_invalid_parameters_are_pre_mutation(self):
        invalid = [{'ncases': 0}, {'ncases': 4097}, {'ncases': True}, {'ncases': 2.0}, {'element_size': 3},
                   {'shift': 4}, {'apply': 1}, {'signed': 'false'}, {'relative': True}, {'subtract': True},
                   {'create_instructions': True}, {'action': 'guess'}, {'max_cases': 0}]
        for extra in invalid[:-1]:
            worker = FixtureWorker()
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                switch.repair_switch(worker, self.definition(**extra))
            self.assertEqual(worker.commits, [])
        with self.assertRaises(ValueError): switch.read_switches(FixtureWorker(), {'ea': '0x1000', **invalid[-1]})

    def test_short_unreadable_or_noncode_targets_refused(self):
        for kind in ('short', 'unreadable', 'nonexecute', 'uninitialized', 'noncode', 'notcomputed'):
            worker = FixtureWorker()
            args = self.definition(apply=True)
            if kind == 'short': worker.table = worker.table[:-1]
            if kind == 'unreadable': args['table'] = '0x4000'
            if kind == 'nonexecute': worker.blocks[0x2000] = (False, True)
            if kind == 'uninitialized': worker.blocks[0x2000] = (True, False)
            if kind == 'noncode': del worker.instructions[0x2000]
            if kind == 'notcomputed': worker.instructions[0x1000].flow = Flow(True, False)
            with self.subTest(kind=kind), self.assertRaises(ValueError): switch.repair_switch(worker, args)
            self.assertEqual(worker.commits, [])

    def test_target_and_table_arithmetic_do_not_wrap(self):
        worker = FixtureWorker(bits=32)
        worker.table = (0xFFFFFFFF).to_bytes(4, 'little')
        with self.assertRaisesRegex(ValueError, 'overflows'):
            switch.repair_switch(worker, self.definition(ncases=1, element_size=4, shift=1))
        with self.assertRaisesRegex(ValueError, 'table overflows'):
            switch.repair_switch(worker, self.definition(table='0xfffffffc'))

    def test_rebuild_requires_one_bounded_actual_table(self):
        worker = FixtureWorker()
        value = switch.repair_switch(worker, {'ea': '0x1000'})
        self.assertEqual(value['targets'], ['0x2000', '0x2010', '0x2020'])
        for tables in ([], [Table(worker), Table(worker)], [Table(worker, targets=tuple(range(5000)), labels=tuple(range(5000)))]):
            worker.tables = tables
            with self.assertRaises(ValueError): switch.repair_switch(worker, {'ea': '0x1000'})

    def test_actual_upstream_api_shape_and_label_omission(self):
        base = ROOT / 'third_party/sources/ghidra-12.1.4/Ghidra'
        source = (base / 'Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/JumpTable.java').read_text(encoding='utf-8')
        for signature in ('Address[] getCases()', 'Integer[] getLabelValues()', 'LoadTable[] getLoadTables()',
                          'JumpTable(Address addr, ArrayList<Address> destlist, boolean override, int format)',
                          'void writeOverride(Function func)'):
            self.assertIn(signature, source)
        self.assertIn('lTable.add(label);', source)
        self.assertNotIn('lTable.add(null)', source)

    @unittest.skipUnless(API_PROBE, 'optional bundled javap probe; no Ghidra engine startup')
    def test_actual_bundled_java_class_signatures(self):
        root = ROOT / 'runtimes/ghidra'
        metadata = json.loads((root / 'runtime.json').read_text(encoding='utf-8-sig'))
        home = root / metadata['ghidraHome']
        javap = root / metadata['javaHome'] / 'bin/javap.exe'
        jars = [home / 'Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar', home / 'Ghidra/Features/Base/lib/Base.jar']
        probes = {
            'ghidra.program.model.pcode.JumpTable': ['getCases()', 'getLabelValues()', 'getLoadTables()', 'writeOverride(ghidra.program.model.listing.Function)', 'java.util.ArrayList<ghidra.program.model.address.Address>, boolean, int'],
            'ghidra.program.model.pcode.HighFunction': ['getJumpTables()'],
            'ghidra.app.cmd.function.CreateFunctionCmd': ['fixupFunctionBody(ghidra.program.model.listing.Program, ghidra.program.model.listing.Function, ghidra.util.task.TaskMonitor)'],
            'ghidra.program.model.symbol.ReferenceManager': ['delete(ghidra.program.model.symbol.Reference)'],
        }
        for name, signatures in probes.items():
            completed = subprocess.run([str(javap), '-classpath', ';'.join(str(jar) for jar in jars), name],
                                       capture_output=True, text=True, encoding='utf-8', timeout=30, check=True)
            for signature in signatures:
                with self.subTest(name=name, signature=signature): self.assertIn(signature, completed.stdout)


if __name__ == '__main__':
    unittest.main()
