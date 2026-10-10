"""Bootstrap portability regressions; never import JPype or start an engine."""
import ast
import builtins
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import types
import unittest


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
