"""Bootstrap portability regressions; never import JPype or start an engine."""
import ast
import builtins
import importlib.util
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('ig5_native_bootstrap', ROOT / 'adapters/ghidra/native_bootstrap.py')
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


def pe_file(filename, bits=64):
    data = bytearray(256)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<H', data, 132, 0x8664 if bits == 64 else 0x14c)
    struct.pack_into('<H', data, 152, 0x20b if bits == 64 else 0x10b)
    filename.write_bytes(data)


class FakeLoader:
    def __init__(self, fail_directory=None, fail_library=None, close_failure=None):
        self.events = []
        self.fail_directory = fail_directory
        self.fail_library = fail_library
        self.close_failure = close_failure

    def add_directory(self, directory):
        self.events.append(('add', directory))
        if len([e for e in self.events if e[0] == 'add']) == self.fail_directory:
            raise OSError('directory fixture failure')
        backend = self
        class Cookie:
            def close(self):
                backend.events.append(('close', directory))
                if directory.name == backend.close_failure:
                    raise OSError('close fixture failure')
        return Cookie()

    def load(self, filename):
        self.events.append(('load', filename))
        if filename.name == self.fail_library:
            raise OSError('library fixture failure')
        return filename


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='ig5-dll-bootstrap-')
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name) / '中文 JDK'
        (self.root / 'bin/server').mkdir(parents=True)
        for name in bootstrap.CRT_NAMES:
            pe_file(self.root / 'bin' / name)
        self.callbacks = []

    def run_bootstrap(self, loader):
        return bootstrap.bootstrap_windows_dlls(self.root, platform='nt', loader=loader,
                                               register_exit=self.callbacks.append)

    def test_all_native_dependencies_bound_before_import(self):
        loader = FakeLoader()
        before = dict(os.environ)
        search = self.run_bootstrap(loader)
        self.assertEqual([e[0] for e in loader.events], ['add', 'add', 'load', 'load', 'load'])
        self.assertEqual(search.libraries, [self.root.resolve() / 'bin' / name for name in bootstrap.CRT_NAMES])
        self.assertEqual(len(search.directory_handles), 2)
        self.assertTrue(all(path.is_absolute() for _, path in loader.events))
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(len(self.callbacks), 1)
        self.callbacks[0]()
        self.assertEqual([e[1].name for e in loader.events if e[0] == 'close'], ['server', 'bin'])
        self.assertEqual(len(search.libraries), 3, 'closing search cookies must not unload an active JVM CRT')
        search.close()
        self.assertEqual(len([e for e in loader.events if e[0] == 'close']), 2)

    def test_non_windows_needs_no_jdk_or_loader(self):
        loader = FakeLoader()
        search = bootstrap.bootstrap_windows_dlls(self.root / 'absent', platform='posix', loader=loader,
                                                 register_exit=self.callbacks.append)
        self.assertEqual(loader.events, [])
        self.assertEqual(self.callbacks, [])
        search.close()

    def test_missing_dependencies_fail_before_loader_mutation(self):
        for name in bootstrap.CRT_NAMES:
            with self.subTest(name=name):
                filename = self.root / 'bin' / name
                content = filename.read_bytes()
                filename.unlink()
                loader = FakeLoader()
                with self.assertRaises(FileNotFoundError):
                    self.run_bootstrap(loader)
                self.assertEqual(loader.events, [])
                self.assertEqual(self.callbacks, [])
                filename.write_bytes(content)

    def test_wrong_architecture_fails_before_loader_mutation(self):
        pe_file(self.root / 'bin/msvcp140.dll', bits=32)
        loader = FakeLoader()
        with self.assertRaisesRegex(ValueError, 'x64'):
            self.run_bootstrap(loader)
        self.assertEqual(loader.events, [])

    def test_invalid_header_offset_is_bounded(self):
        filename = self.root / 'bin/msvcp140.dll'
        data = bytearray(filename.read_bytes())
        struct.pack_into('<I', data, 60, 0xffffffff)
        filename.write_bytes(data)
        loader = FakeLoader()
        with self.assertRaisesRegex(ValueError, 'header'):
            self.run_bootstrap(loader)
        self.assertEqual(loader.events, [])

    def test_external_symlink_is_rejected_before_loading(self):
        outside = Path(self.scratch.name) / 'external.dll'
        pe_file(outside)
        filename = self.root / 'bin/msvcp140.dll'
        filename.unlink()
        try:
            filename.symlink_to(outside)
        except OSError as error:
            self.skipTest('host cannot create an isolated symlink: ' + str(error))
        loader = FakeLoader()
        with self.assertRaisesRegex(ValueError, 'escapes'):
            self.run_bootstrap(loader)
        self.assertEqual(loader.events, [])

    def test_directory_failure_closes_earlier_cookie(self):
        loader = FakeLoader(fail_directory=2)
        with self.assertRaisesRegex(OSError, 'directory fixture'):
            self.run_bootstrap(loader)
        self.assertEqual([e[0] for e in loader.events], ['add', 'add', 'close'])
        self.assertEqual(loader.events[-1][1].name, 'bin')
        self.assertEqual(self.callbacks, [])

    def test_library_failure_closes_both_directories(self):
        loader = FakeLoader(fail_library='msvcp140.dll')
        with self.assertRaisesRegex(OSError, 'library fixture'):
            self.run_bootstrap(loader)
        self.assertEqual([e[1].name for e in loader.events if e[0] == 'close'], ['server', 'bin'])
        self.assertEqual(self.callbacks, [])

    def test_cleanup_failure_preserves_startup_error(self):
        loader = FakeLoader(fail_library='msvcp140.dll', close_failure='server')
        with self.assertRaisesRegex(OSError, 'library fixture'):
            self.run_bootstrap(loader)
        self.assertEqual([e[1].name for e in loader.events if e[0] == 'close'], ['server', 'bin'])

    def test_exit_registration_failure_cleans_directories(self):
        loader = FakeLoader()
        def fail_registration(callback):
            raise RuntimeError('exit fixture failure')
        with self.assertRaisesRegex(RuntimeError, 'exit fixture'):
            bootstrap.bootstrap_windows_dlls(self.root, platform='nt', loader=loader, register_exit=fail_registration)
        self.assertEqual([e[1].name for e in loader.events if e[0] == 'close'], ['server', 'bin'])

    def test_worker_import_failure_cleans_bootstrap(self):
        tree = ast.parse((ROOT / 'adapters/ghidra/worker.py').read_text(encoding='utf-8'))
        worker_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Worker')
        initializer = next(node for node in worker_class.body if isinstance(node, ast.FunctionDef) and node.name == '__init__')
        isolated_class = ast.ClassDef(name='Worker', bases=[], keywords=[], body=[initializer], decorator_list=[])
        isolated = ast.fix_missing_locations(ast.Module(body=[isolated_class], type_ignores=[]))
        loader = FakeLoader()
        state = []
        def create_bootstrap(java_home):
            search = self.run_bootstrap(loader)
            state.append(search)
            return search
        def import_fixture(name, *args, **kwargs):
            if name == 'native_bootstrap':
                return types.SimpleNamespace(bootstrap_windows_dlls=create_bootstrap)
            if name == 'pyghidra':
                self.assertEqual(len(state), 1)
                self.assertEqual(len(state[0].libraries), 3, 'all bundled CRTs must load before the first PyGhidra import')
                raise ImportError('pyghidra fixture failure')
            return builtins.__import__(name, *args, **kwargs)
        namespace = {'protect_child_processes': lambda: None, 'os': types.SimpleNamespace(environ={}),
                     'Path': Path, '__builtins__': {**vars(builtins), '__import__': import_fixture}}
        exec(compile(isolated, str(ROOT / 'adapters/ghidra/worker.py'), 'exec'), namespace)
        with self.assertRaisesRegex(ImportError, 'pyghidra fixture'):
            namespace['Worker'](self.root, self.root, self.root / 'projects')
        self.assertTrue(state[0].closed)
        self.assertEqual([e[1].name for e in loader.events if e[0] == 'close'], ['server', 'bin'])

    def test_missing_server_directory_rejects_before_mutation(self):
        (self.root / 'bin/server').rmdir()
        loader = FakeLoader()
        with self.assertRaises(FileNotFoundError):
            self.run_bootstrap(loader)
        self.assertEqual(loader.events, [])

    def test_server_directory_symlink_escape_rejected(self):
        outside = Path(self.scratch.name) / 'external-server'
        outside.mkdir()
        server = self.root / 'bin/server'
        server.rmdir()
        try:
            server.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest('host cannot create an isolated directory symlink: ' + str(error))
        loader = FakeLoader()
        with self.assertRaisesRegex(ValueError, 'escapes'):
            self.run_bootstrap(loader)
        self.assertEqual(loader.events, [])


class EmulationColdStartTests(unittest.TestCase):
    """Use production setup/import resolution, but never call native emulation."""

    def setUp(self):
        shared = ROOT / 'worker'
        original_path = list(sys.path)
        original_modules = {name: sys.modules.pop(name, None) for name in ('cpu_emulator', 'memory_image')}
        sys.path[:] = [entry for entry in sys.path if Path(entry or '.').resolve() != shared.resolve()]
        def restore_import_state():
            sys.path[:] = original_path
            for name, module in original_modules.items():
                sys.modules.pop(name, None)
                if module is not None:
                    sys.modules[name] = module
        self.addCleanup(restore_import_state)

        self.events = []
        self.calls = []
        native_import = builtins.__import__
        def capture_emulation(image, params):
            self.events.append('emulate_image')
            self.calls.append((image, params))
            return {'ok': True, 'result': 'offline fixture'}
        def guarded_import(name, *args, **kwargs):
            if name.split('.')[0] in ('jpype', '_jpype', 'pyghidra', 'unicorn'):
                raise AssertionError('offline regression attempted a native import: ' + name)
            module = native_import(name, *args, **kwargs)
            if name == 'cpu_emulator':
                self.assertEqual(Path(module.__file__).resolve(), (shared / 'cpu_emulator.py').resolve())
                self.events.append('cpu_emulator import')
                module.emulate_image = capture_emulation
            return module
        guard = patch('builtins.__import__', guarded_import)
        guard.start()
        self.addCleanup(guard.stop)

        tree = ast.parse((ROOT / 'adapters/ghidra/worker.py').read_text(encoding='utf-8'))
        worker_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Worker')
        methods = [node for node in worker_class.body if isinstance(node, ast.FunctionDef)
                   and node.name in ('m_emulate', 'emulation_setup')]
        self.assertEqual(len(methods), 2)
        isolated_class = ast.ClassDef(name='Worker', bases=[], keywords=[], body=methods, decorator_list=[])
        isolated = ast.fix_missing_locations(ast.Module(body=[isolated_class], type_ignores=[]))
        self.platform = types.SimpleNamespace(name='nt')
        namespace = {'os': self.platform, 'sys': sys, 'ADAPTER_ROOT': ROOT / 'adapters/ghidra',
                     'UnsupportedError': RuntimeError}
        exec(compile(isolated, str(ROOT / 'adapters/ghidra/worker.py'), 'exec'), namespace)
        self.worker = namespace['Worker']()
        self.worker.revision = 17
        self.worker.require = lambda: self.events.append('require')

        ns = types.SimpleNamespace
        space = object()
        def address(offset):
            return ns(getOffset=lambda: offset, getAddressSpace=lambda: space,
                      add=lambda delta: address(offset + delta))
        block = ns(getStart=lambda: address(0x1000), getSize=lambda: 16, getName=lambda: '.text',
                   isInitialized=lambda: True, isRead=lambda: True, isWrite=lambda: False,
                   isExecute=lambda: True)
        self.worker.program = ns(
            getLanguage=lambda: ns(getDefaultSpace=lambda: ns(getSize=lambda: 64), getProcessor=lambda: 'x86'),
            getCompilerSpec=lambda: ns(getCompilerSpecID=lambda: 'windows'),
            getMemory=lambda: ns(getBlocks=lambda: [block]),
            getAddressFactory=lambda: ns(getDefaultAddressSpace=lambda: space))
        self.worker.function = lambda params: ns(getEntryPoint=lambda: address(0x1000))
        self.worker.read_bytes = lambda start, size: b'\x90' * size

    def test_cold_function_import_uses_shared_worker_after_setup(self):
        params = {'mode': 'function', 'ea': '0x1000', 'args': ['0x123'], 'max_instructions': 31}
        result = self.worker.m_emulate(params)
        self.assertEqual(result, {'ok': True, 'result': 'offline fixture', 'idb_modified': False, 'revision': 17})
        self.assertEqual(self.events, ['require', 'cpu_emulator import', 'emulate_image'])
        self.assertEqual(len(self.calls), 1)
        image, execution = self.calls[0]
        self.assertIsInstance(image, sys.modules['memory_image'].MemoryImage)
        self.assertEqual((image.arch, image.bits, image.entry, image.source), ('x86', 64, 0x1000, 'ghidra'))
        self.assertEqual(image.regions[0].permissions, 5)
        self.assertEqual(list(image.chunks()), [(0x1000, b'\x90' * 16, 0)])
        self.assertEqual(execution, {'ea': '0x1000', 'args': ['0x123'], 'max_instructions': 31, 'abi': 'win64'})
        self.assertEqual(params['mode'], 'function', 'setup must not mutate caller parameters')
        self.assertNotIn('abi', params)

    def test_unsupported_host_rejects_before_cpu_import(self):
        self.platform.name = 'posix'
        with self.assertRaisesRegex(RuntimeError, 'validated native Unicorn runtime'):
            self.worker.m_emulate({})
        self.assertEqual(self.events, ['require'])
        self.assertNotIn('cpu_emulator', sys.modules)
        self.assertEqual(self.calls, [])

    def test_unloaded_program_rejects_before_cpu_import(self):
        def unloaded():
            raise RuntimeError('program is not loaded')
        self.worker.require = unloaded
        with self.assertRaisesRegex(RuntimeError, 'program is not loaded'):
            self.worker.m_emulate({})
        self.assertEqual(self.events, [])
        self.assertNotIn('cpu_emulator', sys.modules)
        self.assertEqual(self.calls, [])

    def test_invalid_mode_rejects_without_setup_or_cpu_import(self):
        with self.assertRaisesRegex(ValueError, 'mode must be function or decode_strings'):
            self.worker.m_emulate({'mode': 'invalid'})
        self.assertEqual(self.events, [])
        self.assertNotIn('cpu_emulator', sys.modules)
        self.assertEqual(self.calls, [])

    def test_decode_strings_dispatches_without_function_setup(self):
        params = {'mode': 'decode_strings', 'ea': '0x1000'}
        decoded = {'ok': True, 'strings': ['offline fixture']}
        def decode(received):
            self.assertIs(received, params)
            return decoded
        self.worker.decode_strings = decode
        self.assertIs(self.worker.m_emulate(params), decoded)
        self.assertEqual(self.events, [])
        self.assertNotIn('cpu_emulator', sys.modules)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
