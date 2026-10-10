"""Process-local Windows DLL bootstrap for the bundled JPype and JVM.

JPype imports its extension before it starts Java. JDK/bin contains its C++
runtime dependencies, so a system Visual C++ installation must not supply them.
No vendor file, environment PATH, or machine DLL-search setting is changed.
"""
import atexit
import os
from pathlib import Path
import struct


CRT_NAMES = ('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll')


class _WindowsLoader:
    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.ctypes = ctypes
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.GetModuleFileNameW.argtypes = [wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
        self.kernel.GetModuleFileNameW.restype = wintypes.DWORD

    def add_directory(self, directory):
        return os.add_dll_directory(str(directory))

    def load(self, filename):
        # An absolute filename binds the dependency to this JDK rather than a
        # same-named DLL in System32; LOAD_DIR resolves its own dependencies.
        library = self.ctypes.WinDLL(str(filename), winmode=0x100 | 0x1000)
        buffer = self.ctypes.create_unicode_buffer(32768)
        length = self.kernel.GetModuleFileNameW(library._handle, buffer, len(buffer))
        if not length or length >= len(buffer):
            raise OSError('Unable to verify the loaded bundled C++ runtime')
        if os.path.normcase(str(Path(buffer.value).resolve(strict=True))) != os.path.normcase(str(filename)):
            raise OSError('Loaded C++ runtime does not belong to the configured JDK')
        return library


class DllSearch:
    def __init__(self):
        self.directory_handles = []
        self.libraries = []
        self.closed = False

    def close(self):
        if self.closed:
            return
        self.closed = True
        # Keep loaded libraries alive. Do not unload a CRT used by Python/JVM.
        # Directory cookies are removed in reverse order, even after a failure.
        for handle in reversed(self.directory_handles):
            try:
                handle.close()
            except Exception:
                pass
        self.directory_handles.clear()


def _contained(root, candidate, kind):
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError('JDK native dependency escapes the configured JDK') from None
    if resolved == root or not (resolved.is_dir() if kind == 'directory' else resolved.is_file()):
        raise ValueError('JDK native dependency has an invalid file type')
    return resolved


def _require_x64_pe(filename):
    with filename.open('rb') as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b'MZ':
            raise ValueError('Bundled JDK C++ runtime must be a Windows x64 DLL')
        offset = struct.unpack_from('<I', header, 60)[0]
        if offset < 64 or offset > 1024 * 1024:
            raise ValueError('Bundled JDK C++ runtime has an invalid PE header')
        stream.seek(offset)
        native = stream.read(26)
        if (len(native) != 26 or native[:4] != b'PE\0\0'
                or struct.unpack_from('<H', native, 4)[0] != 0x8664
                or struct.unpack_from('<H', native, 24)[0] != 0x20b):
            raise ValueError('Bundled JDK C++ runtime must be a Windows x64 DLL')


def bootstrap_windows_dlls(java_home, *, platform=None, loader=None, register_exit=atexit.register):
    """Retain JDK DLL directories and explicit CRT loads until process exit.

    The injectable loader is only for isolated bootstrap tests. All paths and
    architecture headers are checked before the first loader mutation.
    """
    search = DllSearch()
    if (os.name if platform is None else platform) != 'nt':
        return search
    root = Path(java_home).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Configured JDK must be a directory')
    directories = [_contained(root, root / 'bin', 'directory'),
                   _contained(root, root / 'bin' / 'server', 'directory')]
    libraries = [_contained(root, directories[0] / name, 'file') for name in CRT_NAMES]
    for filename in libraries:
        _require_x64_pe(filename)
    backend = loader if loader is not None else _WindowsLoader()
    try:
        for directory in directories:
            search.directory_handles.append(backend.add_directory(directory))
        for filename in libraries:
            search.libraries.append(backend.load(filename))
        # JPype registers JVM shutdown afterwards. atexit therefore shuts Java
        # down before removing these process-local search directories.
        register_exit(search.close)
        return search
    except BaseException:
        search.close()
        raise
