"""Independent Ghidra JSONL worker. Product writes are gated by the DSH host.

Only this process owns its generated project. Ghidra/native output is redirected
before JVM startup; the saved protocol descriptor is the only stdout writer.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import traceback
import uuid

# Isolated Python intentionally ignores the host PYTHONPATH; import only the
# plugin-owned adapter and shared execution modules from verified relative roots.
ADAPTER_ROOT = Path(__file__).resolve().parent
if str(ADAPTER_ROOT) not in sys.path:
    sys.path.insert(0, str(ADAPTER_ROOT))

PROTOCOL = os.fdopen(os.dup(sys.stdout.fileno()), 'w', encoding='utf-8', buffering=1)
os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
sys.stdout = sys.stderr
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stdin, 'reconfigure'):
    sys.stdin.reconfigure(encoding='utf-8', errors='strict')


class UnsupportedError(Exception):
    pass


class PersistenceError(Exception):
    def __init__(self, message, **details):
        super().__init__(message)
        self.details = details


def emit(value):
    PROTOCOL.write(json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def bounded(params, key='limit', default=100, maximum=2000):
    return max(1, min(int(params.get(key, default)), maximum))


def number(value):
    return int(str(value), 16 if str(value).lower().startswith('0x') else 10)


def addrstr(address):
    return '0x' + (address.toString(False).lstrip('0') or '0') if address.getAddressSpace().isMemorySpace() else str(address)


def each(iterator):
    while iterator.hasNext():
        yield iterator.next()


def protect_child_processes():
    """An uninherited Windows job handle kills native children on worker exit."""
    if os.name != 'nt':
        return None
    import ctypes
    from ctypes import wintypes
    class BasicLimits(ctypes.Structure):
        _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                    ('flags', wintypes.DWORD), ('min_working', ctypes.c_size_t),
                    ('max_working', ctypes.c_size_t), ('active_processes', wintypes.DWORD),
                    ('affinity', ctypes.c_size_t), ('priority', wintypes.DWORD), ('scheduling', wintypes.DWORD)]
    class IOCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]
    class ExtendedLimits(ctypes.Structure):
        _fields_ = [('basic', BasicLimits), ('io', IOCounters), ('process_memory', ctypes.c_size_t),
                    ('job_memory', ctypes.c_size_t), ('peak_process_memory', ctypes.c_size_t), ('peak_job_memory', ctypes.c_size_t)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateJobObjectW(None, None)
    limits = ExtendedLimits()
    limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if handle and kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)) and kernel.AssignProcessToJobObject(handle, kernel.GetCurrentProcess()):
        return handle
    error = ctypes.get_last_error()
    if handle:
        kernel.CloseHandle(handle)
    print('Windows job unavailable; host must terminate process tree; error=' + str(error), file=sys.stderr)
    return None


def start_launcher(launcher, jpype):
    """Start the pinned JPype without an ASCII installation-path requirement.

    JPype 1.5.2 rejects a Unicode classpath with Ghidra's system classloader.
    Its support JAR path is calculated from _core.__file__ (without resolve),
    so ASCII relative JAR paths resolve normally from the Unicode package CWD.
    Only process-local metadata changes; vendor files are never rewritten.
    Bootstrap is single-threaded and every temporary Python value is restored.
    """
    if os.name != 'nt':
        launcher.start()
        return 'native'
    original_classpath = launcher.class_path
    original_vm_args = launcher.vm_args[:]
    import jpype._core as core
    core_file = core.__file__
    if jpype.__version__ != '1.5.2' and all(str(value).isascii() for value in [core_file, *original_classpath]):
        launcher.start()
        return 'native'
    if jpype.__version__ != '1.5.2':
        raise RuntimeError('Unicode runtime paths require the bundled JPype 1.5.2 bootstrap')
    package_root = Path(core_file).resolve().parent.parent
    cwd = os.getcwd()
    classpath = [os.path.relpath(value, package_root) for value in original_classpath]
    relative_core = os.path.relpath(core_file, package_root)
    if not all(value.isascii() for value in [relative_core, *classpath]):
        raise RuntimeError('Runtime JAR component paths must be ASCII relative to the Python package root')
    # PyGhidra removes CWD from sys.path after JVM startup. Here CWD is our
    # intentional isolated package root, so preserve that entry and its order.
    package_entry = str(package_root)
    package_index = next((i for i, value in enumerate(sys.path)
                          if os.path.normcase(value) == os.path.normcase(package_entry)), None)
    if package_index is not None:
        package_entry = sys.path[package_index]
    try:
        os.chdir(package_root)
        core.__file__ = relative_core
        launcher.class_path = classpath
        # The bundled Context shim bypasses JPype's ANSI self-library filename
        # using Java's Unicode CWD and this single allowlisted basename.
        launcher.vm_args.append('-Dig5.jpype.native_filename=_jpype.cp312-win_amd64.pyd')
        launcher.start()
    finally:
        core.__file__ = core_file
        launcher.class_path = original_classpath
        launcher.vm_args[:] = original_vm_args
        os.chdir(cwd)
        if package_index is not None and package_entry not in sys.path:
            sys.path.insert(min(package_index, len(sys.path)), package_entry)
    return 'relative-classpath'


class Worker:
    def __init__(self, ghidra_home, java_home, project_root):
        self.job_handle = protect_child_processes()
        os.environ['JAVA_HOME'] = str(java_home)
        os.environ['JAVA_HOME_OVERRIDE'] = str(java_home)
        os.environ['GHIDRA_INSTALL_DIR'] = str(ghidra_home)
        from native_bootstrap import bootstrap_windows_dlls
        self.native_dll_search = bootstrap_windows_dlls(java_home)
        try:
            import pyghidra
            import jpype
            from pyghidra.launcher import HeadlessPyGhidraLauncher
            self.pyghidra, self.jpype = pyghidra, jpype
            self.root = Path(project_root).resolve()
            self.root.mkdir(parents=True, exist_ok=True)
            launcher = HeadlessPyGhidraLauncher(install_dir=Path(ghidra_home))
            # Never discover a system JDK or invoke a PATH/shell-based Java lookup.
            launcher.java_home = Path(java_home)
            launcher.vm_args += ['-Xmx2G', '-XX:ActiveProcessorCount=2', '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2']
            self.jvm_bootstrap = start_launcher(launcher, jpype)
        except BaseException:
            self.native_dll_search.close()
            raise
        self.program = self.project = self.consumer = self.decompiler = None
        self.target = self.project_name = self.source_hash = None
        self.journal = []
        self.revision = 0
        self.durable_revision = 0
        self.pending_record = self.last_record = self.persistence_error = None
        self.recovery = None
        self.request_id = None
        self.monitors = []

    def analyze_native(self, params):
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.program.model.listing import Program
        profile = params.get('analysis_profile') or self.program.getOptions('IG5').getString('analysisProfile', 'interactive')
        if profile not in ('interactive', 'full'):
            raise ValueError('analysis_profile must be interactive or full')
        scoped = params.get('ea') not in (None, '') or bool(params.get('name'))
        previous_complete = bool(GhidraProgramUtilities.isAnalyzed(self.program))
        previous_profile = str(self.program.getOptions('IG5').getString('analysisProfile', 'unknown'))
        previous_parameter_id = self.program.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean('Decompiler Parameter ID', False)
        monitor = self.monitor(params)
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            manager = AutoAnalysisManager.getAnalysisManager(self.program)
            self.program.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean('Decompiler Parameter ID', profile == 'full')
            if not scoped:
                self.program.getOptions(Program.PROGRAM_INFO).setBoolean(Program.ANALYZED_OPTION_NAME, False)
            manager.initializeOptions()
            restricted = None
            if scoped:
                from ghidra.program.model.address import AddressSet
                address = self.address(params)
                end = self.address({'ea': params['end']}).subtract(1) if params.get('end') else address.add(bounded(params, 'size', 4096, 65536) - 1)
                if end.compareTo(address) < 0:
                    raise ValueError('end must be after ea')
                restricted = AddressSet(address, end)
            manager.reAnalyzeAll(restricted)
            manager.startAnalysis(monitor, True)
            partial = bool(monitor.isCancelled())
            if not scoped:
                if not partial:
                    GhidraProgramUtilities.markProgramAnalyzed(self.program)
                self.program.getOptions('IG5').setString('analysisProfile', profile)
            else:
                # A range pass cannot certify coverage or change the selected
                # whole-program profile, even when its own monitor completes.
                self.program.getOptions(Program.PROGRAM_INFO).setBoolean(Program.ANALYZED_OPTION_NAME, previous_complete)
                self.program.getOptions('IG5').setString('analysisProfile', previous_profile)
            return {'partial': not previous_complete if scoped else partial,
                    'scopePartial': partial, 'analysisProfile': previous_profile if scoped else profile,
                    'analysisComplete': previous_complete if scoped else not partial,
                    'analysisScope': 'range' if scoped else 'program', 'scopeComplete': not partial,
                    'requestedAnalysisProfile': profile,
                    'scopeSkippedAnalyzers': ['Decompiler Parameter ID'] if profile == 'interactive' else [],
                    'skippedAnalyzers': ['Decompiler Parameter ID'] if (previous_profile if scoped else profile) == 'interactive' else [],
                    'log': str(manager.getMessageLog())[-4000:]}
        finally:
            if scoped:
                self.program.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean('Decompiler Parameter ID', previous_parameter_id)
                self.program.getOptions(Program.PROGRAM_INFO).setBoolean(Program.ANALYZED_OPTION_NAME, previous_complete)
                self.program.getOptions('IG5').setString('analysisProfile', previous_profile)
            monitor.cancel()
            GhidraScriptUtil.releaseBundleHostReference()

    def monitor(self, params=None):
        monitor = self.pyghidra.task_monitor(max(1, min(int((params or {}).get('timeout', 120)), 600)))
        self.monitors.append(monitor)
        return monitor

    def cancel_monitors(self):
        for monitor in self.monitors:
            monitor.cancel()
        self.monitors.clear()

    def progress(self, stage, pct, **extra):
        emit({'ig5': 'progress', 'id': self.request_id, 'payload': {'stage': stage, 'pct': pct, **extra}})

    def require(self):
        if self.program is None:
            raise ValueError('no Ghidra database open; call open first')

    def address(self, params):
        self.require()
        if params.get('ea') not in (None, ''):
            address = self.program.getAddressFactory().getAddress(str(params['ea']).removeprefix('0x'))
            if address is None:
                raise ValueError('invalid address')
            return address
        if params.get('name'):
            symbols = self.program.getSymbolTable().getSymbols(str(params['name']))
            for symbol in each(symbols):
                return symbol.getAddress()
            raise ValueError('symbol not found: ' + str(params['name']))
        raise ValueError('ea or name is required')

    def function(self, params):
        address = self.address(params)
        function = self.program.getFunctionManager().getFunctionContaining(address)
        if function is None:
            raise ValueError('address is not inside a function')
        return function

    def info(self):
        if self.program is None:
            return {'open': False, 'engine': 'Ghidra', 'revision': self.revision}
        program = self.program
        from ghidra.program.util import GhidraProgramUtilities
        profile = str(program.getOptions('IG5').getString('analysisProfile', 'unknown'))
        segments = [{'start': addrstr(block.getStart()), 'end': addrstr(block.getEnd().add(1)),
                     'name': str(block.getName()), 'size': int(block.getSize()),
                     'perm': (4 if block.isRead() else 0) | (2 if block.isWrite() else 0) | (1 if block.isExecute() else 0)}
                    for block in program.getMemory().getBlocks()]
        return {'open': True, 'engine': 'Ghidra', 'target': self.target, 'sourceHash': self.source_hash,
                'project': self.project_name, 'program': str(program.getName()),
                'databasePath': str(self.root / (self.project_name + '.gpr')), 'programPath': '/sample',
                'analysisProfile': profile, 'analysisComplete': bool(GhidraProgramUtilities.isAnalyzed(program)),
                'partial': not bool(GhidraProgramUtilities.isAnalyzed(program)),
                'skippedAnalyzers': ['Decompiler Parameter ID'] if profile == 'interactive' else [],
                'revision': self.revision, 'modificationNumber': int(program.getModificationNumber()), 'unsavedChanges': bool(program.isChanged()),
                'durableRevision': self.durable_revision, 'recoveryRequired': self.persistence_error is not None,
                'recovery': self.recovery,
                'bits': int(program.getLanguage().getDefaultSpace().getSize()),
                'proc': str(program.getLanguage().getProcessor()), 'languageId': str(program.getLanguageID()),
                'compilerSpec': str(program.getCompilerSpec().getCompilerSpecID()),
                'imageBase': addrstr(program.getImageBase()), 'segments': segments,
                'n_funcs': int(program.getFunctionManager().getFunctionCount()),
                'entries': [{'ea': addrstr(ea), 'name': str(program.getSymbolTable().getPrimarySymbol(ea))}
                            for ea in each(program.getSymbolTable().getExternalEntryPointIterator())]}

    def m_doctor(self, params):
        from ghidra.framework import Application
        return {'ok': True, 'engine': 'Ghidra', 'version': str(Application.getApplicationVersion()),
                'python': sys.version.split()[0], 'pyghidra': self.pyghidra.__version__,
                'jpype': self.jpype.__version__, 'capabilities': sorted(METHODS),
                'jvmBootstrap': self.jvm_bootstrap,
                'analysisProfiles': {'default': 'interactive', 'interactive': {'skippedAnalyzers': ['Decompiler Parameter ID']}, 'full': {'skippedAnalyzers': []}},
                'childProcessCleanup': 'Windows kill-on-job-close' if self.job_handle else 'host process-tree termination required',
                'unsupported': ['dbg'] + ([] if os.name == 'nt' else ['emulate']),
                'emulation': {'available': os.name == 'nt', 'targetArchitectures': ['x86', 'x64', 'ARM64'],
                              'scope': 'CPU-only copied memory; no operating system, imports, TLS or native process'},
                'journal': 'rename/comment/patch saved immediately with session inverse undo; other writes remain session-only with native undo until a save/close; intent and database markers reconcile interrupted persistence',
                'analysisProfileScope': 'full enables batch Decompiler Parameter ID; other analyzer settings retain their configured defaults'}

    def m_open(self, params):
        profile = params.get('analysis_profile') or 'interactive'
        if profile not in ('interactive', 'full'):
            raise ValueError('analysis_profile must be interactive or full')
        path = Path(params.get('path') or os.environ.get('IG5_TARGET', '')).resolve()
        if not path.is_file():
            raise ValueError('target file not found')
        self.m_close({})
        self.target = str(path)
        with path.open('rb') as stream:
            self.source_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
        identity = digest([str(params.get('database_key') or path), self.source_hash, '12.1.4', params.get('language'), params.get('compiler')])[:20]
        self.project_name = 'ig5-' + identity + ('-' + uuid.uuid4().hex[:8] if params.get('fresh') else '')
        started = time.monotonic()
        self.progress('loading', 0, detail=path.name)
        self.project = self.pyghidra.open_project(str(self.root), self.project_name, create=True)
        existing = self.project.getProjectData().getFile('/sample')
        reused = existing is not None
        if not reused:
            loader = self.pyghidra.program_loader().source(str(path)).project(self.project).name('sample')
            if params.get('language'):
                loader = loader.language(str(params['language']))
            if params.get('compiler'):
                loader = loader.compiler(str(params['compiler']))
            with loader.load() as results:
                results.save(self.monitor(params))
        self.program, self.consumer = self.pyghidra.consume_program(self.project, '/sample')
        self.journal = []
        self.recover_persistence()
        self.progress('loaded', 5)
        from ghidra.program.util import GhidraProgramUtilities
        partial = not bool(GhidraProgramUtilities.isAnalyzed(self.program))
        stored_profile = str(self.program.getOptions('IG5').getString('analysisProfile', 'unknown'))
        if self.persistence_error is None and params.get('auto', True) and (not reused or partial or stored_profile != profile):
            self.progress('analyzing', 10)
            with self.pyghidra.transaction(self.program, 'IG5 initial analysis'):
                partial = self.analyze_native({**params, 'analysis_profile': profile})['partial']
            self.program.save('IG5 imported analysis', self.pyghidra.task_monitor())
        self.progress('done', 100, functions=self.program.getFunctionManager().getFunctionCount())
        return {**self.info(), 'elapsedMs': int((time.monotonic() - started) * 1000),
                'reusedProject': reused, 'partial': partial}

    def m_stats(self, params):
        return self.info()

    def m_close(self, params):
        if self.decompiler is not None:
            self.decompiler.dispose()
            self.decompiler = None
        if self.program is not None:
            if self.program.isChanged() or self.pending_record is not None or self.revision != self.durable_revision:
                record = self.pending_record or self.last_record
                if record is not None:
                    try:
                        self.save_program(record)
                        if self.pending_record is not None:
                            self.finish_persistence(record, True)
                        else:
                            self.save_revision()
                    except Exception as error:
                        raise self.persistence_failure(error, record, self.durable_revision >= record['revision'], 'close checkpoint') from error
                else:
                    self.program.save('IG5 session checkpoint', self.pyghidra.task_monitor())
            self.program.release(self.consumer)
            self.program = self.consumer = None
        if self.project is not None:
            self.project.close()
            self.project = None
        self.journal = []
        self.pending_record = self.last_record = self.persistence_error = None
        return {'ok': True, 'closed': True, 'engine': 'Ghidra'}

    def m_funcs(self, params):
        self.require()
        offset, limit = max(0, int(params.get('offset', 0))), bounded(params)
        matches = []
        needle = str(params.get('filter', '')).lower()
        for function in each(self.program.getFunctionManager().getFunctions(True)):
            is_lib = bool(function.isExternal() or function.isThunk())
            if needle not in str(function.getName()).lower() or (params.get('user_only') and is_lib):
                continue
            matches.append({'ea': addrstr(function.getEntryPoint()), 'name': str(function.getName()),
                            'size': int(function.getBody().getNumAddresses()), 'is_lib': is_lib})
        return {'total': len(matches), 'offset': offset, 'funcs': matches[offset:offset + limit],
                'libraryClassification': 'external or thunk; not a standard-library equivalence claim'}

    def m_strings(self, params):
        self.require()
        from ghidra.program.util import DefinedDataIterator
        rows = []
        needle = str(params.get('filter', '')).lower()
        predicate = self.jpype.JProxy('java.util.function.Predicate', dict(test=lambda data: bool(data.hasStringValue())))
        for data in each(DefinedDataIterator.byDataInstance(self.program, predicate)):
            text = str(data.getValue())
            if needle in text.lower():
                rows.append({'ea': addrstr(data.getAddress()), 'length': int(data.getLength()), 'text': text[:2000]})
        offset, limit = max(0, int(params.get('offset', 0))), bounded(params)
        return {'total': len(rows), 'offset': offset, 'strings': rows[offset:offset + limit]}

    def m_scan(self, params):
        """The same bounded static-indicator schema as the Reverse provider."""
        self.require()
        shared = ADAPTER_ROOT.parent.parent / 'worker'
        if str(shared) not in sys.path:
            sys.path.insert(0, str(shared))
        from scan_analysis import scan_image, scan_limits, api_category
        from ghidra.program.util import DefinedDataIterator, GhidraProgramUtilities
        limits = scan_limits(params)
        default_space = self.program.getAddressFactory().getDefaultAddressSpace()
        bits = int(default_space.getSize())

        def segments():
            for block in self.program.getMemory().getBlocks():
                source = block.getStart()
                same_space = source.getAddressSpace() == default_space
                initialized = bool(block.isInitialized())
                yield {'name': str(block.getName()), 'start': int(source.getOffset()) & ((1 << bits) - 1),
                       'addressSpace': 'memory' if same_space else str(source.getAddressSpace().getName()),
                       'sourceAddress': str(source),
                       'size': int(block.getSize()), 'readable': same_space and initialized,
                       'skipReason': 'non-default address space' if not same_space else 'uninitialized memory' if not initialized else None,
                       'read': lambda offset, size, base=source: self.read_bytes(base.add(offset), size)}

        def imports():
            for symbol in each(self.program.getSymbolTable().getExternalSymbols()):
                address, name = symbol.getAddress(), str(symbol.getName())
                row = {'module': str(symbol.getParentNamespace()), 'api': name,
                       'externalAddress': str(address), 'addressSpace': str(address.getAddressSpace().getName())}
                if api_category(name):
                    references = []
                    refs = self.program.getReferenceManager().getReferencesTo(address)
                    for _ in range(9):
                        if not refs.hasNext():
                            break
                        reference = refs.next().getFromAddress()
                        if reference.getAddressSpace() == default_space:
                            references.append(addrstr(reference))
                    row['referenceEas'] = references[:8]
                    row['referencesTruncated'] = len(references) > 8 or bool(refs.hasNext())
                    if references:
                        row.update(ea=references[0], addressSpace='memory', addressRole='import-reference')
                yield row

        def strings():
            predicate = self.jpype.JProxy('java.util.function.Predicate', dict(test=lambda data: bool(data.hasStringValue())))
            for data in each(DefinedDataIterator.byDataInstance(self.program, predicate)):
                # Avoid materializing arbitrary megabyte-sized Java strings.
                # Short defined values preserve Ghidra's decoded character set.
                if int(data.getLength()) > limits['max_string_chars'] * 4:
                    yield {'text': '', 'truncated': True}
                else:
                    yield str(data.getValue())

        result = scan_image(segments(), imports(), strings(), source_engine='ghidra', params=params)
        return {**result, 'revision': self.revision, 'sourceHash': self.source_hash,
                'analysisComplete': bool(GhidraProgramUtilities.isAnalyzed(self.program))}

    def decompile(self, params):
        from ghidra.app.decompiler import DecompInterface
        if self.decompiler is None:
            self.decompiler = DecompInterface()
            if not self.decompiler.openProgram(self.program):
                raise RuntimeError('Ghidra decompiler unavailable: ' + str(self.decompiler.getLastMessage()))
        function = self.function(params)
        result = self.decompiler.decompileFunction(function, bounded(params, 'timeout', 30, 120), self.monitor(params))
        if not result.decompileCompleted():
            raise RuntimeError('Ghidra decompile failed: ' + str(result.getErrorMessage()))
        return function, result

    def m_decompile(self, params):
        function, result = self.decompile(params)
        code = str(result.getDecompiledFunction().getC())
        return {'ea': addrstr(function.getEntryPoint()), 'name': str(function.getName()),
                'size': int(function.getBody().getNumAddresses()), 'lines': len(code.splitlines()), 'code': code,
                'engine': 'Ghidra', 'revision': self.revision}

    def read_bytes(self, address, size):
        if size < 1 or size > 16 * 1024 * 1024:
            raise ValueError('invalid read size')
        memory = self.program.getMemory()
        end = address.add(size - 1)
        if not memory.getLoadedAndInitializedAddressSet().contains(address, end):
            raise ValueError('range is not fully loaded and initialized')
        array = self.jpype.JArray(self.jpype.JByte)(size)
        count = memory.getBytes(address, array)
        if count != size:
            raise ValueError('range is not fully readable')
        return bytes(array)

    def m_bytes(self, params):
        address = self.address(params)
        data = self.read_bytes(address, bounded(params, 'size', 64, 4096))
        return {'ea': addrstr(address), 'size': len(data), 'hex': data.hex()}

    def m_fileoffset(self, params):
        shared = ADAPTER_ROOT.parent.parent / 'worker'
        if str(shared) not in sys.path:
            sys.path.insert(0, str(shared))
        from memory_image import integer
        address = self.address(params)
        size = integer(params.get('size', 1), 'file mapping size')
        if not 1 <= size <= 4096:
            raise ValueError('file mapping size must be 1..4096')
        memory = self.program.getMemory()
        info = memory.getAddressSourceInfo(address)
        first = int(info.getFileOffset()) if info is not None else -1
        bits = int(address.getAddressSpace().getSize())
        base = int(address.getOffset()) & ((1 << bits) - 1)
        contiguous = first >= 0 and base + size <= (1 << bits)
        if contiguous:
            for offset in range(1, size):
                info = memory.getAddressSourceInfo(address.add(offset))
                if info is None or int(info.getFileOffset()) != first + offset:
                    contiguous = False
                    break
        return {'ea': addrstr(address), 'fileOffset': first if contiguous else -1,
                'size': size, 'contiguous': contiguous}

    def m_inspect(self, params):
        from ghidra.program.model.listing import CodeUnit
        address = self.address(params)
        size = bounded(params, 'size', 1, 4096)
        symbol = self.program.getSymbolTable().getPrimarySymbol(address)
        comment = self.program.getListing().getComment(CodeUnit.EOL_COMMENT, address)
        return {'ea': addrstr(address), 'name': str(symbol.getName()) if symbol is not None else '',
                'comment': str(comment) if comment is not None else '',
                'hex': self.read_bytes(address, size).hex(), 'size': size,
                'fileOffset': self.m_fileoffset(params)['fileOffset']}

    def m_disasm(self, params):
        address = self.address(params)
        limit, size = bounded(params, default=30), bounded(params, 'size', 256, 65536)
        rows = []
        for instruction in each(self.program.getListing().getInstructions(address, True)):
            if instruction.getAddress().subtract(address) >= size or len(rows) >= limit:
                break
            rows.append({'ea': addrstr(instruction.getAddress()), 'size': int(instruction.getLength()),
                         'bytes': bytes(instruction.getBytes()).hex(), 'text': str(instruction),
                         'mnemonic': str(instruction.getMnemonicString())})
        return {'ea': addrstr(address), 'rows': rows, 'count': len(rows)}

    def m_xrefs(self, params):
        manager = self.program.getReferenceManager() if self.program is not None else None
        self.require()
        targets = [self.address(params)] if not params.get('str') else [self.address({'ea': row['ea']})
                    for row in self.m_strings({'filter': params['str'], 'limit': 8})['strings']]
        direction, rows = params.get('direction', 'to'), []
        for target in targets:
            refs = manager.getReferencesTo(target) if direction == 'to' else iter(manager.getReferencesFrom(target))
            refs = each(refs) if hasattr(refs, 'hasNext') else refs
            for ref in refs:
                other = ref.getFromAddress() if direction == 'to' else ref.getToAddress()
                fn = self.program.getFunctionManager().getFunctionContaining(other)
                rows.append({'target': addrstr(target), 'other': addrstr(other), 'type': str(ref.getReferenceType()),
                             'func': str(fn.getName()) if fn else None, 'func_ea': addrstr(fn.getEntryPoint()) if fn else None})
        return {'total': len(rows), 'hits': rows[:bounded(params)], 'targets': list(map(addrstr, targets))}

    def m_calls(self, params):
        function, direction = self.function(params), params.get('direction', 'callees')
        functions = function.getCallingFunctions(self.monitor(params)) if direction == 'callers' else function.getCalledFunctions(self.monitor(params))
        rows = [{'ea': addrstr(fn.getEntryPoint()), 'name': str(fn.getName()), 'refs': 1} for fn in functions]
        return {'ea': addrstr(function.getEntryPoint()), 'name': str(function.getName()), 'direction': direction,
                'total': len(rows), 'calls': rows[:bounded(params)], 'refsMeaning': 'unique function relationship'}

    def m_search(self, params):
        self.require()
        tokens = str(params.get('pattern', '')).replace(',', ' ').split()
        pattern = []
        for token in tokens:
            if token in ('?', '??'):
                pattern.append(None)
            else:
                pattern.extend(bytes.fromhex(token))
        if not pattern or len(pattern) > 4096:
            raise ValueError('pattern must contain 1..4096 bytes')
        start = number(params['start']) if params.get('start') else 0
        end = number(params['end']) if params.get('end') else 2 ** 64
        hits, limit = [], bounded(params, default=30)
        for block in self.program.getMemory().getBlocks():
            if not block.isInitialized() or not block.isLoaded():
                continue
            low, high = max(start, int(block.getStart().getOffset())), min(end, int(block.getEnd().getOffset()) + 1)
            cursor = low
            while cursor < high:
                length = min(1024 * 1024 + len(pattern) - 1, high - cursor)
                data = self.read_bytes(block.getStart().getNewAddress(cursor), length)
                for index in range(max(0, len(data) - len(pattern) + 1)):
                    if all(value is None or data[index + step] == value for step, value in enumerate(pattern)):
                        hits.append(hex(cursor + index))
                        if len(hits) >= limit:
                            return {'pattern': params['pattern'], 'hits': hits, 'total': len(hits), 'truncated': True, 'size': len(pattern)}
                cursor += min(1024 * 1024, high - cursor)
        return {'pattern': params['pattern'], 'hits': hits, 'total': len(hits), 'truncated': False, 'size': len(pattern)}

    def m_listing(self, params):
        self.require()
        kind, rows = params.get('kind', 'segments'), []
        if kind == 'segments':
            rows = self.info()['segments']
        elif kind in ('imports', 'exports', 'entries', 'names'):
            table = self.program.getSymbolTable()
            symbols = table.getExternalSymbols() if kind == 'imports' else table.getAllSymbols(True) if kind == 'names' else (table.getPrimarySymbol(ea) for ea in each(table.getExternalEntryPointIterator()))
            symbols = each(symbols) if hasattr(symbols, 'hasNext') else symbols
            rows = [{'ea': addrstr(symbol.getAddress()), 'name': str(symbol.getName()), 'module': str(symbol.getParentNamespace())}
                    for symbol in symbols if symbol is not None]
        else:
            raise ValueError('listing kind must be segments/imports/exports/entries/names')
        needle = str(params.get('filter', '')).lower()
        rows = [row for row in rows if needle in str(row.get('name', '')).lower()]
        offset, limit = max(0, int(params.get('offset', 0))), bounded(params)
        return {'kind': kind, 'total': len(rows), 'offset': offset, 'rows': rows[offset:offset + limit]}

    def cfg(self, params):
        from ghidra.program.model.block import BasicBlockModel
        function = self.function(params)
        monitor = self.monitor(params)
        native = list(each(BasicBlockModel(self.program).getCodeBlocksContaining(function.getBody(), monitor)))
        at = {str(block.getFirstStartAddress()): index for index, block in enumerate(native)}
        rows = []
        for index, block in enumerate(native):
            instructions = list(each(self.program.getListing().getInstructions(block, True)))
            successors = [at[str(ref.getDestinationAddress())] for ref in each(block.getDestinations(monitor)) if str(ref.getDestinationAddress()) in at]
            rows.append({'id': index, 'start': addrstr(block.getMinAddress()), 'end': addrstr(block.getMaxAddress().add(1)),
                         'insns': len(instructions), 'succs': sorted(set(successors)), 'preds': [],
                         'first': str(instructions[0]) if instructions else '', 'last': str(instructions[-1]) if instructions else ''})
        for block in rows:
            for destination in block['succs']:
                rows[destination]['preds'].append(block['id'])
        return function, rows

    def m_cfg(self, params):
        function, blocks = self.cfg(params)
        edges = [{'from': block['id'], 'to': dest} for block in blocks for dest in block['succs']]
        mermaid = ['flowchart TD'] + ['  B%d["%s"]' % (block['id'], block['start']) for block in blocks]
        mermaid += ['  B%d --> B%d' % (edge['from'], edge['to']) for edge in edges]
        return {'ea': addrstr(function.getEntryPoint()), 'name': str(function.getName()), 'blocks': blocks,
                'func': str(function.getName()), 'start_ea': addrstr(function.getEntryPoint()),
                'edges': edges, 'mermaid': '\n'.join(mermaid), 'total_blocks': len(blocks), 'total_edges': len(edges)}

    def m_fingerprint(self, params):
        rows = self.m_funcs({'limit': 2000})
        # Count all functions, independently of response pagination.
        library_count = sum(bool(fn.isExternal() or fn.isThunk()) for fn in each(self.program.getFunctionManager().getFunctions(True)))
        library = [row for row in rows['funcs'] if row['is_lib']]
        return {'abi': str(self.program.getCompilerSpec().getCompilerSpecID()), 'total_functions': rows['total'],
                'bits': int(self.program.getLanguage().getDefaultSpace().getSize()),
                'library_functions_count': library_count, 'user_functions_count': rows['total'] - library_count,
                'library_ratio': library_count / max(1, rows['total']), 'sample_library_funcs': library[:30],
                'sample_user_funcs': [row for row in rows['funcs'] if not row['is_lib']][:30],
                'classification': 'external or thunk only; no standard-library proof'}

    def m_stack(self, params):
        from ghidra.program.model.listing import Parameter
        function = self.function(params)
        frame = function.getStackFrame()
        members = [{'name': str(var.getName()), 'offset': int(var.getStackOffset()), 'size': int(var.getLength()),
                    'type': str(var.getDataType().getDisplayName()), 'kind': 'args' if isinstance(var, Parameter) else 'locals'}
                   for var in frame.getStackVariables()]
        return {'ok': True, 'ea': addrstr(function.getEntryPoint()), 'has_frame': bool(frame.getFrameSize() or members),
                'frame_size': int(frame.getFrameSize()), 'local_size': int(frame.getLocalSize()),
                'total_members': len(members), 'members': members, 'engine': 'Ghidra'}

    def m_switches(self, params):
        from switch_analysis import read_switches
        return read_switches(self, params)

    def m_switch_repair(self, params):
        from switch_analysis import repair_switch
        return repair_switch(self, params)

    def m_vtables(self, params):
        self.require()
        shared = ADAPTER_ROOT.parent.parent / 'worker'
        if str(shared) not in sys.path: sys.path.insert(0, str(shared))
        from kernel_rtti import analyze_vtables
        worker = self
        default_space = worker.program.getAddressFactory().getDefaultAddressSpace()
        class Provider:
            pointer_size = int(worker.program.getDefaultPointerSize())
            byteorder = 'big' if worker.program.getLanguage().isBigEndian() else 'little'
            imagebase = int(addrstr(worker.program.getImageBase()), 16)
            ranges = [{'start': int(addrstr(block.getStart()), 16), 'end': int(addrstr(block.getEnd()), 16) + 1,
                       'executable': bool(block.isExecute())} for block in worker.program.getMemory().getBlocks()
                      if block.isInitialized() and block.isRead() and block.getStart().getAddressSpace() == default_space]
            def read(self, ea, size): return worker.read_bytes(worker.address({'ea': hex(ea)}), size)
            def is_executable(self, ea):
                block = worker.program.getMemory().getBlock(worker.address({'ea': hex(ea)}))
                return block is not None and bool(block.isExecute())
            def symbol(self, ea):
                symbol = worker.program.getSymbolTable().getPrimarySymbol(worker.address({'ea': hex(ea)}))
                return str(symbol.getName(True)) if symbol else ''
            def symbols(self):
                for index, symbol in enumerate(each(worker.program.getSymbolTable().getAllSymbols(True))):
                    if index >= 8192: break
                    address = symbol.getAddress()
                    if address.getAddressSpace() == default_space: yield int(addrstr(address), 16), str(symbol.getName(True))
        result = analyze_vtables(Provider(), params)
        return {**result, 'engine': 'Ghidra', 'revision': self.revision,
                'source': {'provider': 'Ghidra memory/symbols', 'analysis': 'IG5 kernel RTTI', 'artifactSHA256': self.source_hash}}

    def m_ir(self, params):
        from pcode_view import operation_view
        kind = params.get('kind', params.get('level', 'high'))
        maximum = bounded(params, 'max_instructions', 1000, 10000)
        function = self.function(params)
        rows, blocks, total, varnodes = [], [], 0, 0
        varnode_maximum = min(20000, maximum * 8)
        def append_operation(operation, address, index=None):
            nonlocal varnodes
            row = operation_view(self.program, operation, address, index, varnode_maximum - varnodes)
            varnodes += len(row['inputs']) + int(row['output'] is not None)
            rows.append(row)
        if kind == 'raw':
            for instruction in each(self.program.getListing().getInstructions(function.getBody(), True)):
                for index, op in enumerate(instruction.getPcode()):
                    total += 1
                    if len(rows) < maximum:
                        append_operation(op, addrstr(instruction.getAddress()), index)
            blocks = self.m_cfg(params)['blocks']
        elif kind == 'high':
            _, result = self.decompile(params)
            high = result.getHighFunction()
            if high is None:
                raise RuntimeError('Ghidra high p-code unavailable')
            for op in each(high.getPcodeOps()):
                total += 1
                if len(rows) < maximum:
                    append_operation(op, addrstr(op.getSeqnum().getTarget()))
            for block in high.getBasicBlocks():
                blocks.append({'id': int(block.getIndex()), 'start': addrstr(block.getStart()), 'end': addrstr(block.getStop()),
                               'succs': [int(block.getOut(index).getIndex()) for index in range(block.getOutSize())]})
        else:
            raise ValueError('Ghidra ir kind must be raw or high')
        return {'ok': True, 'engine': 'Ghidra', 'kind': 'ghidra-' + kind + '-pcode', 'ea': addrstr(function.getEntryPoint()),
                'instructions': rows, 'blocks': blocks, 'idb_modified': False, 'revision': self.revision,
                'count': len(rows), 'total': total, 'truncated': total > maximum,
                'varnodeCount': varnodes, 'varnodeLimit': varnode_maximum,
                'varnodesTruncated': any(row['inputsTruncated'] or row['outputOmitted'] for row in rows),
                'source': {'engine': 'Ghidra', 'representation': 'PcodeOp' if kind == 'raw' else 'HighFunction SSA',
                           'language': str(self.program.getLanguageID()), 'artifactSHA256': self.source_hash,
                           'function': addrstr(function.getEntryPoint()), 'revision': self.revision}}

    def m_emulate(self, params):
        self.require()
        if os.name != 'nt':
            raise UnsupportedError('CPU emulation requires a validated native Unicorn runtime for this host platform')
        shared = ADAPTER_ROOT.parent.parent / 'worker'
        if str(shared) not in sys.path:
            sys.path.insert(0, str(shared))
        from memory_image import MemoryImage, MemoryRegion, PERM_READ, PERM_WRITE, PERM_EXEC
        from cpu_emulator import emulate_image
        bits = int(self.program.getLanguage().getDefaultSpace().getSize())
        processor = str(self.program.getLanguage().getProcessor()).lower()
        arch = 'arm64' if processor in ('aarch64', 'arm64') else 'x86' if processor in ('x86', 'i386') else None
        if arch is None or (arch == 'arm64' and self.program.getLanguage().isBigEndian()):
            raise UnsupportedError('CPU emulation supports little-endian x86/x64 and ARM64 targets only')
        execution = dict(params)
        if not execution.get('abi'):
            compiler = str(self.program.getCompilerSpec().getCompilerSpecID()).lower()
            if arch == 'arm64':
                execution['abi'] = 'aapcs64'
            elif bits == 32:
                execution['abi'] = 'cdecl'
            elif compiler == 'windows':
                execution['abi'] = 'win64'
            elif compiler in ('gcc', 'clang'):
                execution['abi'] = 'sysv64'
            else:
                raise ValueError('Specify abi explicitly for this unclassified x64 compiler specification')
        entry = self.function(params).getEntryPoint()
        regions = []
        for block in self.program.getMemory().getBlocks():
            # Non-default/overlay address spaces cannot be flattened into native
            # VA without aliasing. Keep the snapshot physically unambiguous.
            if block.getStart().getAddressSpace() != self.program.getAddressFactory().getDefaultAddressSpace():
                continue
            base = int(block.getStart().getOffset()) & ((1 << bits) - 1)
            def reader(offset, size, source=block):
                if not source.isInitialized():
                    return None
                return self.read_bytes(source.getStart().add(offset), size)
            regions.append(MemoryRegion(base, int(block.getSize()), reader,
                                        name=str(block.getName()), zero_fill=not bool(block.isInitialized()),
                                        permissions=(PERM_READ if block.isRead() else 0) |
                                                    (PERM_WRITE if block.isWrite() else 0) |
                                                    (PERM_EXEC if block.isExecute() else 0)))
        image = MemoryImage(arch, bits, int(entry.getOffset()) & ((1 << bits) - 1), regions, source='ghidra')
        return {**emulate_image(image, execution), 'idb_modified': False, 'revision': self.revision}

    def m_slice(self, params):
        function, result = self.decompile(params)
        high = result.getHighFunction()
        variables = []
        if high is not None:
            for symbol in each(high.getLocalSymbolMap().getSymbols()):
                variables.append({'name': str(symbol.getName()), 'type': str(symbol.getDataType().getDisplayName()),
                                  'size': int(symbol.getSize()), 'width': int(symbol.getSize()) * 8})
        code = str(result.getDecompiledFunction().getC())
        variable = params.get('variable', params.get('var'))
        lines = [{'line': index + 1, 'text': text} for index, text in enumerate(code.splitlines())
                 if variable is None or re.search(r'\b' + re.escape(str(variable)) + r'\b', text)]
        return {'ok': True, 'ea': addrstr(function.getEntryPoint()), 'name': str(function.getName()),
                'locals': variables, 'variables': variables, 'lines': lines, 'code': code,
                'total_variables': len(variables), 'slice_variable': variable,
                'slice_lines': [{'line_no': row['line'], 'code': row['text']} for row in lines] if variable else None,
                'scope': 'HighFunction symbols and lexical C-line filtering; not a dependency-complete program slice'}

    def m_semantics(self, params):
        functions = self.m_funcs({**params, 'limit': bounded(params, default=500), 'user_only': params.get('user_only', True)})
        rows = []
        for record in functions['funcs']:
            function, blocks = self.cfg({'ea': record['ea']})
            normalized, mnemonics, constants, byte_parts, calls, strings = [], [], set(), [], [], set()
            block_at = {block['start']: block['id'] for block in blocks}
            for block in blocks:
                values, names = [], []
                start = self.address({'ea': block['start']})
                for instruction in each(self.program.getListing().getInstructions(start, True)):
                    if int(instruction.getAddress().getOffset()) >= number(block['end']):
                        break
                    mnemonic = str(instruction.getMnemonicString()).lower()
                    operand_text = []
                    for index in range(instruction.getNumOperands()):
                        text = str(instruction.getDefaultOperandRepresentation(index))
                        for obj in instruction.getOpObjects(index):
                            if hasattr(obj, 'getUnsignedValue'):
                                value = int(obj.getUnsignedValue())
                                if not self.program.getMemory().contains(self.program.getAddressFactory().getDefaultAddressSpace().getAddress(value)):
                                    constants.add(hex(value))
                        operand_text.append(str(instruction.getOperandType(index)) + ':' + text)
                    for ref in instruction.getReferencesFrom():
                        dest = ref.getToAddress()
                        symbol = self.program.getSymbolTable().getPrimarySymbol(dest)
                        destination = addrstr(dest)
                        label = 'block:' + str(block_at[destination]) if destination in block_at else ('symbol:' + str(symbol.getName()) if symbol else 'mapped')
                        operand_text = [text.replace(str(dest), label).replace(destination, label) for text in operand_text]
                        if ref.getReferenceType().isCall():
                            called = self.program.getFunctionManager().getFunctionAt(dest)
                            calls.append(str(called.getName()) if called else 'indirect')
                        data = self.program.getListing().getDefinedDataAt(dest)
                        if data is not None and data.hasStringValue():
                            strings.add(hashlib.sha256(str(data.getValue()).encode()).hexdigest())
                    values.append(mnemonic + ' ' + ','.join(operand_text))
                    names.append(mnemonic)
                    byte_parts.append(bytes(instruction.getBytes()).hex())
                block['hash'], block['shape'] = digest(values), digest(names)
                normalized.extend(values)
                mnemonics.extend(names)
            labels = {block['id']: digest([block['shape'], len(block['succs']), len(block['preds'])]) for block in blocks}
            for _ in range(3):
                labels = {block['id']: digest([labels[block['id']], sorted(labels[other] for other in block['succs']),
                                               sorted(labels[other] for other in block['preds'])]) for block in blocks}
            rows.append({**record, 'instructions': len(mnemonics), 'mnemonics': dict(collections.Counter(mnemonics)),
                         'constants': sorted(constants), 'strings': sorted(strings), 'calls': calls, 'call_degree': len(calls),
                         'blocks': blocks, 'topology': sorted(labels.values()), 'bytes_hash': digest(byte_parts),
                         'semantic_hash': digest([normalized, [(block['id'], block['succs']) for block in blocks], sorted(strings), sorted(calls)])})
        offset = max(0, int(params.get('offset', 0)))
        return {'total': functions['total'], 'offset': offset, 'count': len(rows), 'functions': rows,
                'truncated': functions['total'] > offset + len(rows), 'algorithm': 'Ghidra typed operands + CFG neighborhoods'}

    def append_audit(self, record):
        with (self.root / (self.project_name + '-journal.jsonl')).open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + '\n')
            stream.flush()
            os.fsync(stream.fileno())

    def save_revision(self):
        destination = self.root / (self.project_name + '-state.json')
        self.atomic_json(destination, {'revision': self.revision, 'durableRevision': self.durable_revision,
                                       'sourceHash': self.source_hash})

    def atomic_json(self, destination, value):
        temporary = destination.with_suffix('.tmp')
        with temporary.open('w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)

    def intent_path(self):
        return self.root / (self.project_name + '-intent.json')

    def persistence_failure(self, error, record, saved, stage, committed=True):
        self.pending_record = record if committed else self.pending_record
        failure = PersistenceError('Ghidra persistence failed after ' + stage + ': ' + str(error),
            code='partial_commit' if committed else 'persistence_unavailable', committed=committed,
            saved=bool(saved), recoveryRequired=True, journalId=record['id'], revision=self.revision,
            durableRevision=self.durable_revision, stage=stage,
            result=record.get('result'))
        self.persistence_error = failure
        return failure

    def prepare_record(self, method, params, inverse=None):
        if self.persistence_error is not None:
            raise self.persistence_error
        record = {'id': uuid.uuid4().hex, 'method': method, 'args': params,
                  'description': 'IG5 ' + method + ' ' + uuid.uuid4().hex[:8],
                  'revision': self.revision + 1, 'ts': time.time(),
                  'undoMode': 'inverse' if inverse is not None else 'native', 'inverse': inverse,
                  'committed': False, 'saved': False}
        try:
            self.atomic_json(self.intent_path(), record)
        except Exception as error:
            raise self.persistence_failure(error, record, False, 'intent preparation', False) from error
        return record

    def save_program(self, record):
        # The marker is saved in the same native database as the mutation. The
        # external intent/audit/state files deliberately are not called atomic
        # with Ghidra's save. A subsequent open can reconcile from this marker.
        with self.pyghidra.transaction(self.program, 'IG5 persistence checkpoint'):
            options = self.program.getOptions('IG5')
            options.setString('durableRevision', str(self.revision))
            options.setString('durableRecord', json.dumps({**record, 'saved': True}, ensure_ascii=False))
        self.program.save(record['description'], self.pyghidra.task_monitor())
        self.durable_revision = self.revision

    def audit_contains(self, journal_id):
        journal = self.root / (self.project_name + '-journal.jsonl')
        if not journal.is_file():
            return False
        with journal.open(encoding='utf-8') as stream:
            return any(json.loads(line).get('id') == journal_id for line in stream if line.strip())

    def finish_persistence(self, record, saved):
        record['saved'] = saved
        if not self.audit_contains(record['id']):
            self.append_audit(record)
        self.save_revision()
        self.intent_path().unlink(missing_ok=True)
        self.pending_record = self.persistence_error = None

    def recover_persistence(self):
        self.pending_record = self.last_record = self.persistence_error = None
        self.recovery = None
        state_path = self.root / (self.project_name + '-state.json')
        state = json.loads(state_path.read_text(encoding='utf-8')) if state_path.is_file() else {}
        options = self.program.getOptions('IG5')
        marker = options.getString('durableRevision', '')
        # Legacy projects did not have a DB marker. Retain their existing
        # revision without pretending to reconstruct historical native saves.
        self.durable_revision = int(marker) if marker else int(state.get('durableRevision', state.get('revision', 0)))
        self.revision = max(self.durable_revision, int(state.get('revision', 0)))
        intent = self.intent_path()
        record = json.loads(intent.read_text(encoding='utf-8')) if intent.is_file() else None
        saved_record = json.loads(str(options.getString('durableRecord', 'null')))
        if record is not None:
            self.revision = max(self.revision, int(record['revision']))
            if saved_record and saved_record['id'] == record['id'] and self.durable_revision >= record['revision']:
                record = saved_record
                self.last_record = record
                try:
                    self.finish_persistence(record, True)
                    self.recovery = {'status': 'reconciled', 'journalId': record['id'], 'saved': True}
                except Exception as error:
                    self.persistence_failure(error, record, True, 'recovery reconciliation')
                    self.recovery = {'status': 'blocked', 'journalId': record['id'], 'saved': True, 'message': str(error)}
            else:
                # No matching native commit marker: do not replay any write.
                # The operation either never ran or was session-only when the
                # process stopped. Keep monotonic revisions and expose the loss.
                self.recovery = {'status': 'not_durable', 'journalId': record['id'], 'saved': False,
                                 'note': 'interrupted operation was not confirmed saved; no mutation was replayed'}
                self.save_revision()
                intent.unlink()
        elif self.revision > self.durable_revision:
            self.recovery = {'status': 'session_changes_lost', 'saved': False,
                             'revision': self.revision, 'durableRevision': self.durable_revision}

    def commit(self, method, params, body, inverse=None):
        self.require()
        record = self.prepare_record(method, params, inverse)
        try:
            with self.pyghidra.transaction(self.program, record['description']):
                result = body()
        except Exception as error:
            self.intent_path().unlink(missing_ok=True)
            from script_api import ScriptExecutionError
            if isinstance(error, ScriptExecutionError):
                error.details['transactionRolledBack'] = True
            raise
        self.revision = record['revision']
        record.update(result=result, committed=True)
        self.last_record = self.pending_record = record
        self.journal.append(record)
        try:
            if self.decompiler is not None:
                self.decompiler.flushCache()
            self.atomic_json(self.intent_path(), record)
            # save() clears native undo; advanced writes remain explicitly
            # session-only until close or the next common primitive save.
            if inverse is not None:
                self.save_program(record)
            self.finish_persistence(record, inverse is not None)
        except Exception as error:
            raise self.persistence_failure(error, record, self.durable_revision >= self.revision, 'transaction commit') from error
        return {**result, 'revision': self.revision, 'journalId': record['id'],
                'committed': True, 'saved': inverse is not None, 'undoMode': record['undoMode'],
                'durableRevision': self.durable_revision, 'recoveryRequired': False,
                'persistence': 'saved' if inverse is not None else 'session-only'}

    def m_microcode(self, params):
        from microcode_analysis import run_microcode
        return run_microcode(self, params)

    def m_idapython(self, params):
        from script_api import run_script
        self.require()
        return self.commit('idapython', params, lambda: run_script(self, params))

    def m_rename(self, params):
        from ghidra.program.model.symbol import SourceType
        address, new_name = self.address(params), str(params.get('new_name', '')).strip()
        if not new_name:
            raise ValueError('new_name is required')
        symbol = self.program.getSymbolTable().getPrimarySymbol(address)
        old = str(symbol.getName()) if symbol else ''
        def write():
            if symbol:
                symbol.setName(new_name, SourceType.USER_DEFINED)
            else:
                self.program.getSymbolTable().createLabel(address, new_name, SourceType.USER_DEFINED)
            return {'ok': True, 'ea': addrstr(address), 'old': old, 'new': new_name}
        return self.commit('rename', params, write, {'ea': addrstr(address), 'old': old, 'new': new_name,
            'source': str(symbol.getSource()) if symbol is not None else None})

    def m_comment(self, params):
        from ghidra.program.model.listing import CodeUnit
        address = self.address(params)
        text = str(params.get('text', ''))
        kind = CodeUnit.REPEATABLE_COMMENT if params.get('repeatable') else CodeUnit.EOL_COMMENT
        old = self.program.getListing().getComment(kind, address)
        def write():
            self.program.getListing().setComment(address, kind, text or None)
            return {'ok': True, 'ea': addrstr(address), 'old': str(old) if old else '', 'text': text}
        return self.commit('comment', params, write, {'ea': addrstr(address), 'old': str(old) if old else '',
            'new': text, 'repeatable': bool(params.get('repeatable'))})

    def patch_units(self, address, size):
        listing = self.program.getListing()
        rows, cursor, end = [], address, address.add(size - 1)
        while cursor.compareTo(end) <= 0:
            unit = listing.getCodeUnitContaining(cursor)
            if unit is None:
                cursor = cursor.add(1)
                continue
            from ghidra.program.model.listing import Instruction
            record = {'start': addrstr(unit.getMinAddress()), 'end': addrstr(unit.getMaxAddress()),
                      'kind': 'instruction' if isinstance(unit, Instruction) else 'data', 'length': int(unit.getLength())}
            if record['kind'] == 'data':
                record['typePath'] = str(unit.getDataType().getPathName())
            rows.append(record)
            cursor = unit.getMaxAddress().add(1)
        return rows

    def write_patch(self, address, payload, units):
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.program.model.address import AddressSet
        listing = self.program.getListing()
        # Ghidra rejects memory writes over defined instructions. Clear/redecode
        # just the intersecting code units within the same transaction.
        listing.clearCodeUnits(address, address.add(len(payload) - 1), False)
        self.program.getMemory().setBytes(address, self.jpype.JArray(self.jpype.JByte)(payload))
        for unit in units:
            start, end = self.address({'ea': unit['start']}), self.address({'ea': unit['end']})
            if unit['kind'] == 'instruction':
                command = DisassembleCommand(start, AddressSet(start, end), True)
                command.applyTo(self.program, self.pyghidra.task_monitor())
            else:
                datatype = self.program.getDataTypeManager().getDataType(unit['typePath'])
                if datatype is not None:
                    listing.createData(start, datatype, unit['length'])

    def m_patch(self, params):
        address = self.address(params)
        payload = bytes.fromhex(re.sub(r'\s|,|0x', '', str(params.get('hex', ''))))
        if not payload or len(payload) > 4096:
            raise ValueError('patch must contain 1..4096 bytes')
        before = self.read_bytes(address, len(payload))
        if params.get('expected') is not None and before != bytes.fromhex(re.sub(r'\s|,|0x', '', str(params['expected']))):
            raise ValueError('original bytes no longer match expected; patch was not applied')
        units = self.patch_units(address, len(payload))
        def write():
            self.write_patch(address, payload, units)
            after = self.read_bytes(address, len(payload))
            if after != payload:
                raise RuntimeError('patch verification failed')
            return {'ok': True, 'applied': True, 'ea': addrstr(address), 'before': before.hex(), 'after': after.hex(),
                    'size': len(payload), 'fileOffset': self.m_fileoffset(params)['fileOffset']}
        return self.commit('patch', params, write, {'ea': addrstr(address), 'before': before.hex(), 'after': payload.hex(), 'units': units})

    def m_undo(self, params):
        self.require()
        if params.get('action') == 'list':
            native_names = {str(name) for name in self.program.getAllUndoNames()}
            return {'ok': True, 'journal': [{**record, 'undoAvailable': record['inverse'] is not None or record['description'] in native_names}
                                          for record in reversed(self.journal[-30:])], 'revision': self.revision}
        if params.get('action', 'undo') != 'undo':
            raise UnsupportedError('undo action must be list or undo')
        if not self.journal:
            return {'ok': False, 'action': 'undo', 'note': 'no session operation to undo'}
        latest = self.journal[-1]
        inverse = latest.get('inverse')
        if inverse is not None:
            from ghidra.program.model.symbol import SourceType
            from ghidra.program.model.listing import CodeUnit
            address = self.address({'ea': inverse['ea']})
            if latest['method'] == 'patch' and self.read_bytes(address, len(bytes.fromhex(inverse['after']))).hex() != inverse['after']:
                raise ValueError('current bytes no longer match journal; undo refused')
            if latest['method'] == 'rename':
                symbol = self.program.getSymbolTable().getPrimarySymbol(address)
                if symbol is None or str(symbol.getName()) != inverse['new']:
                    raise ValueError('current name no longer matches journal; undo refused')
            if latest['method'] == 'comment':
                kind = CodeUnit.REPEATABLE_COMMENT if inverse['repeatable'] else CodeUnit.EOL_COMMENT
                current = self.program.getListing().getComment(kind, address)
                if str(current or '') != inverse['new']:
                    raise ValueError('current comment no longer matches journal; undo refused')
            record = self.prepare_record('undo', params, inverse)
            with self.pyghidra.transaction(self.program, 'IG5 inverse undo'):
                if latest['method'] == 'rename':
                    if inverse['old']:
                        source = getattr(SourceType, inverse['source'], SourceType.USER_DEFINED)
                        symbol.setName(inverse['old'], source)
                    else:
                        symbol.delete()
                elif latest['method'] == 'comment':
                    self.program.getListing().setComment(address, kind, inverse['old'] or None)
                elif latest['method'] == 'patch':
                    self.write_patch(address, bytes.fromhex(inverse['before']), inverse['units'])
        else:
            if not self.program.canUndo() or str(self.program.getUndoName()) != latest['description']:
                raise UnsupportedError('native undo expired at a save/close; only common primitive inverses remain available in this session')
            record = self.prepare_record('undo', params)
            self.program.undo()
        self.journal.pop()
        self.revision = record['revision']
        result = {'ok': True, 'action': 'undo', 'kind': latest['method'], 'revision': self.revision,
                  'journalId': latest['id'], 'saved': inverse is not None}
        record.update(result=result, committed=True, undoneJournalId=latest['id'])
        self.last_record = self.pending_record = record
        try:
            if self.decompiler is not None:
                self.decompiler.flushCache()
            self.atomic_json(self.intent_path(), record)
            if inverse is not None:
                self.save_program(record)
            self.finish_persistence(record, inverse is not None)
        except Exception as error:
            raise self.persistence_failure(error, record, self.durable_revision >= self.revision, 'undo commit') from error
        return {**result, 'committed': True, 'durableRevision': self.durable_revision, 'recoveryRequired': False,
                'persistence': 'saved' if inverse is not None else 'session-only'}

    def m_set_type(self, params):
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.app.util.cparser.C import CParserUtils
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.model.data import FunctionDefinition
        from ghidra.app.util.cparser.C import CParser
        address = self.address(params)
        declaration = str(params.get('type', params.get('decl', '')))
        typename = str(params.get('typename', '')).strip()
        if not declaration and not typename:
            raise ValueError('decl or typename is required')
        manager = self.program.getDataTypeManager()
        function = self.program.getFunctionManager().getFunctionAt(address)
        old = str(function.getSignature()) if function is not None else ''
        def write():
            if typename:
                matches = [datatype for datatype in each(manager.getAllDataTypes()) if str(datatype.getName()) == typename]
                if len(matches) != 1:
                    raise ValueError('typename must resolve to exactly one local data type')
                datatype = matches[0]
            elif '(' in declaration:
                datatype = CParserUtils.parseSignature(None, self.program, declaration, False)
            else:
                datatype = CParser(manager, False, [manager]).parse(declaration.rstrip(';') + ';')
            if datatype is None:
                raise ValueError('invalid C declaration')
            if isinstance(datatype, FunctionDefinition):
                if function is None:
                    raise ValueError('function prototype requires an exact function entry')
                command = ApplyFunctionSignatureCmd(function.getEntryPoint(), datatype, SourceType.USER_DEFINED)
                if not command.applyTo(self.program, self.monitor(params)):
                    raise ValueError(str(command.getStatusMsg()))
                applied = str(function.getSignature())
            else:
                if function is not None:
                    raise UnsupportedError('non-function data types cannot replace a function entry; provide a C function prototype')
                size = int(datatype.getLength())
                if size < 1 or size > 4096:
                    raise UnsupportedError('data type must have a fixed length of 1..4096 bytes')
                self.read_bytes(address, size)
                self.program.getListing().clearCodeUnits(address, address.add(size - 1), False)
                self.program.getListing().createData(address, datatype)
                applied = str(datatype.getDisplayName())
            return {'ok': True, 'ea': addrstr(address), 'old': old, 'type': applied, 'decl': declaration or typename}
        return self.commit('set_type', params, write)

    def m_struct(self, params):
        self.require()
        from ghidra.program.model.data import Composite, Structure, Union, DataType, DataTypeConflictHandler, DataTypeWriter
        manager = self.program.getDataTypeManager()
        action, name = params.get('action', 'list'), str(params.get('name', ''))
        def lookup():
            for datatype in each(manager.getAllDataTypes()):
                if isinstance(datatype, Composite) and str(datatype.getName()) == name:
                    return datatype
            raise ValueError('structure not found: ' + name)
        if action == 'list':
            needle = str(params.get('filter', '')).lower()
            rows = [{'name': str(datatype.getName()), 'size': int(datatype.getLength()), 'is_struct': isinstance(datatype, Structure)} for datatype in each(manager.getAllDataTypes()) if isinstance(datatype, Composite) and needle in str(datatype.getName()).lower()]
            return {'total': len(rows), 'total_types': len(rows), 'types': rows[:bounded(params)], 'structs': rows[:bounded(params)], 'items': rows[:bounded(params)]}
        if action == 'get':
            datatype = lookup()
            members = [{'name': str(member.getFieldName() or member.getDefaultFieldName()), 'offset': int(member.getOffset()),
                        'size': int(member.getLength()), 'type': str(member.getDataType().getDisplayName())} for member in datatype.getComponents()]
            from java.io import StringWriter
            writer = StringWriter()
            DataTypeWriter(manager, writer).write(self.jpype.JArray(DataType)([datatype]), self.pyghidra.task_monitor())
            return {'name': name, 'size': int(datatype.getLength()), 'members': members, 'fields': members,
                    'is_struct': isinstance(datatype, Structure), 'is_union': isinstance(datatype, Union), 'is_enum': False, 'decl': str(writer)}
        if action == 'define':
            from ghidra.app.util.cparser.C import CParser
            declaration = str(params.get('decl', params.get('declaration', '')))
            if not declaration:
                raise ValueError('decl is required')
            def write():
                parser = CParser(manager, False, [manager])
                datatype = parser.parse(declaration)
                if not isinstance(datatype, Composite):
                    raise ValueError('declaration must define a structure or union')
                resolved = manager.resolve(datatype, DataTypeConflictHandler.REPLACE_HANDLER)
                return {'ok': True, 'status': 'ok', 'action': action, 'name': str(resolved.getName()), 'size': int(resolved.getLength()),
                        'details': {'size': int(resolved.getLength())}}
            return self.commit('struct_define', params, write)
        if action == 'apply':
            datatype, address = lookup(), self.address(params)
            self.read_bytes(address, int(datatype.getLength()))
            def write():
                self.program.getListing().clearCodeUnits(address, address.add(int(datatype.getLength()) - 1), False)
                self.program.getListing().createData(address, datatype)
                return {'ok': True, 'status': 'ok', 'applied': True, 'action': action, 'ea': addrstr(address), 'name': name}
            return self.commit('struct_apply', params, write)
        raise UnsupportedError('unsupported struct action: ' + str(action))

    def m_analyze(self, params):
        self.require()
        action = params.get('action', 'reanalyze')
        if action not in ('reanalyze', 'create_function', 'delete_function', 'mark_code', 'undefine'):
            raise UnsupportedError('unsupported Ghidra analyze action: ' + str(action))
        def write():
            if action != 'reanalyze':
                from ghidra.app.cmd.disassemble import DisassembleCommand
                from ghidra.app.cmd.function import CreateFunctionCmd
                from ghidra.program.model.address import AddressSet
                address = self.address(params)
                size = bounded(params, 'size', 16 if action == 'undefine' else 4096, 65536)
                end = self.address({'ea': params['end']}).subtract(1) if params.get('end') else address.add(size - 1)
                if end.compareTo(address) < 0:
                    raise ValueError('end must be after ea')
                if action == 'create_function':
                    if params.get('end') or params.get('size'):
                        from ghidra.program.model.symbol import SourceType
                        command = CreateFunctionCmd(None, address, AddressSet(address, end), SourceType.USER_DEFINED)
                    else:
                        command = CreateFunctionCmd(address)
                    if not command.applyTo(self.program, self.monitor(params)):
                        raise ValueError(str(command.getStatusMsg()))
                elif action == 'delete_function':
                    function = self.function(params)
                    if not self.program.getFunctionManager().removeFunction(function.getEntryPoint()):
                        raise ValueError('function deletion failed')
                elif action == 'mark_code':
                    command = DisassembleCommand(address, AddressSet(address, end), True)
                    if not command.applyTo(self.program, self.monitor(params)):
                        raise ValueError(str(command.getStatusMsg()))
                else:
                    self.program.getListing().clearCodeUnits(address, end, False)
                return {'ok': True, 'action': action, 'ea': addrstr(address), 'end': addrstr(end.add(1))}
            analysis = self.analyze_native(params)
            return {'ok': not analysis['scopePartial'], 'action': action, **analysis, 'n_funcs': int(self.program.getFunctionManager().getFunctionCount())}
        return self.commit('analyze', params, write)


METHODS = {name[2:]: name for name in vars(Worker) if name.startswith('m_')}
METHODS.update({'status': 'm_stats', 'patch_bytes': 'm_patch', 'ping': 'm_stats'})
if os.name != 'nt':
    # Do not advertise emulation before a matching portable Unicorn runtime has
    # been built and validated. A Windows DLL is not a Linux/phone dependency.
    METHODS.pop('emulate', None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ghidra-home', default=os.getenv('IG5_GHIDRA_HOME'))
    parser.add_argument('--java-home', default=os.getenv('IG5_JAVA_HOME'))
    parser.add_argument('--project-root', default=os.getenv('IG5_GHIDRA_PROJECT_ROOT', str(Path.home() / '.dsh/ig5/artifacts/ghidra-projects')))
    args = parser.parse_args()
    if not args.ghidra_home or not args.java_home:
        raise ValueError('IG5_GHIDRA_HOME and IG5_JAVA_HOME are required')
    worker = Worker(args.ghidra_home, args.java_home, args.project_root)
    emit({'ig5': 'ready', 'pid': os.getpid(), 'engine': 'Ghidra', 'capabilities': sorted(METHODS)})
    try:
        for line in sys.stdin:
            request = {}
            try:
                request = json.loads(line)
                worker.request_id = request.get('id')
                method = request.get('method')
                if method not in METHODS:
                    raise UnsupportedError('Ghidra does not support method: ' + str(method))
                emit({'id': request.get('id'), 'result': getattr(worker, METHODS[method])(request.get('params') or {})})
            except Exception as error:
                traceback.print_exc(file=sys.stderr)
                emit({'id': request.get('id'), 'error': {'message': str(error),
                      'code': 'unsupported' if isinstance(error, UnsupportedError) else 'operation_failed',
                      **(error.details if isinstance(error, PersistenceError) or error.__class__.__name__ == 'ScriptExecutionError' else {})}})
            finally:
                worker.cancel_monitors()
    finally:
        worker.m_close({})


if __name__ == '__main__':
    main()
