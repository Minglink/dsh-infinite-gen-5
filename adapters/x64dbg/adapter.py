"""IG5-owned x64dbg supervisor. Internal JSONL transport; the host owns approvals.

Starting this module, doctor and open never execute a target. dbg/load launches an
empty debugger; dbg/start is the only target launch operation. The default native
transport is a current-user-only named pipe; it exposes no network listener.
"""
from __future__ import annotations

import collections
import contextlib
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import uuid

OPS = ["load", "start", "bpt", "unbpt", "regs", "setreg", "step", "stepover",
       "cont", "suspend", "readmem", "writemem", "stop", "state", "event", "modules", "trace"]
CAPABILITIES = ["doctor", "open", "close", "dbg", *["dbg." + op for op in OPS], "cancel"]
EVENT_NAMES = {"EVENT_BREAKPOINT": "breakpoint", "EVENT_SYSTEMBREAKPOINT": "system-breakpoint",
               "EVENT_STEPPED": "step", "EVENT_PAUSE_DEBUG": "paused", "EVENT_RESUME_DEBUG": "running",
               "EVENT_EXCEPTION": "exception", "EVENT_CREATE_PROCESS": "process-started",
               "EVENT_EXIT_PROCESS": "process-exited", "EVENT_STOP_DEBUG": "stopped"}


class RpcError(Exception):
    def __init__(self, code, message, **detail):
        super().__init__(message)
        self.code, self.detail = code, detail


def integer(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("expected an integer or integer string")
    return int(value, 0) if isinstance(value, str) else int(value)


def plain(value):
    if hasattr(value, "model_dump"):
        return plain(value.model_dump())
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, int) and abs(value) > 2**53 - 1:
        return hex(value)
    return value


def inspect_pe(path):
    path = Path(path).expanduser().resolve(strict=True)
    with path.open("rb") as f:
        data = f.read(0x1000)
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise ValueError("target is not a PE executable")
    off = struct.unpack_from("<I", data, 0x3C)[0]
    if off > 0x100000:
        raise ValueError("invalid PE header offset")
    if off + 0x100 > len(data):
        with path.open("rb") as f:
            f.seek(off)
            header = f.read(0x100)
    else:
        header = data[off:]
    if header[:4] != b"PE\0\0" or len(header) < 0x50:
        raise ValueError("invalid PE header")
    machine = struct.unpack_from("<H", header, 4)[0]
    bits = {0x8664: 64, 0x14C: 32}.get(machine)
    if not bits:
        raise ValueError("x64dbg supports only x86 and x64 targets")
    magic = struct.unpack_from("<H", header, 24)[0]
    if magic != (0x20B if bits == 64 else 0x10B):
        raise ValueError("PE machine and optional header disagree")
    entry = struct.unpack_from("<I", header, 40)[0]
    base = struct.unpack_from("<Q" if bits == 64 else "<I", header, 48 if bits == 64 else 52)[0]
    with path.open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    return {"path": str(path), "bits": bits, "databaseBase": hex(base), "entryRVA": hex(entry), "sha256": digest}


class KillJob:
    """A kernel job makes forced adapter termination close its debugger tree too."""
    def __init__(self, proc):
        self.handle = None
        if os.name != "nt":
            return
        from ctypes import wintypes as w
        class Basic(ctypes.Structure):
            _fields_ = [("p", ctypes.c_int64), ("j", ctypes.c_int64), ("flags", w.DWORD),
                        ("min", ctypes.c_size_t), ("max", ctypes.c_size_t), ("active", w.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]
        class Io(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("ro", "wo", "oo", "rt", "wt", "ot")]
        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", Io), ("processMemory", ctypes.c_size_t),
                        ("jobMemory", ctypes.c_size_t), ("peakProcess", ctypes.c_size_t), ("peakJob", ctypes.c_size_t)]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        kernel.CreateJobObjectW.restype = w.HANDLE
        kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        kernel.CloseHandle.argtypes = [w.HANDLE]
        handle = kernel.CreateJobObjectW(None, None)
        info = Extended()
        info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not handle or not kernel.SetInformationJobObject(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            if handle:
                kernel.CloseHandle(handle)
            raise RpcError("EJOB", "could not create debugger cleanup job")
        if not kernel.AssignProcessToJobObject(handle, int(proc._handle)):
            kernel.CloseHandle(handle)
            raise RpcError("EJOB", "could not assign debugger to cleanup job")
        self.handle, self.kernel = handle, kernel

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class NativeClient:
    """Small stdlib client for the IG5 SDK named pipe, with bounded reads."""
    def __init__(self, adapter):
        from ctypes import wintypes as w
        self.adapter, self.handle, self.sequence, self.event_sequence = adapter, None, 0, 0
        self.incoming = bytearray()
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
        self.kernel.CreateFileW.restype = w.HANDLE
        self.kernel.ReadFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
        self.kernel.WriteFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
        self.kernel.PeekNamedPipe.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.c_void_p, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.listeners = {}

    def connect(self, pid):
        name = rf"\\.\pipe\ig5-x64dbg-{pid}"
        while True:
            self.adapter.check()
            handle = self.kernel.CreateFileW(name, 0xC0000000, 0, None, 3, 0, None)
            if handle != ctypes.c_void_p(-1).value:
                self.handle = handle
                break
            time.sleep(0.025)
        hello = self.request("hello")
        if hello.get("pid") != pid or hello.get("protocol") != 1:
            raise RpcError("ETRANSPORT", "native bridge handshake mismatch")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    def request(self, method, **params):
        from ctypes import wintypes as w
        self.adapter.check()
        self.sequence += 1
        data = json.dumps({"id": self.sequence, "method": method, "params": params}, ensure_ascii=False).encode("utf-8") + b"\n"
        sent = w.DWORD()
        if not self.kernel.WriteFile(self.handle, data, len(data), ctypes.byref(sent), None) or sent.value != len(data):
            raise RpcError("ETRANSPORT", "native bridge request write failed")
        while b"\n" not in self.incoming:
            self.adapter.check()
            available = w.DWORD()
            if not self.kernel.PeekNamedPipe(self.handle, None, 0, None, ctypes.byref(available), None):
                raise RpcError("ETRANSPORT", "native bridge disconnected")
            if available.value:
                buffer = ctypes.create_string_buffer(min(available.value, 65536))
                got = w.DWORD()
                if not self.kernel.ReadFile(self.handle, buffer, len(buffer), ctypes.byref(got), None):
                    raise RpcError("ETRANSPORT", "native bridge response read failed")
                self.incoming.extend(buffer.raw[:got.value])
                if len(self.incoming) > 4 * 1024 * 1024:
                    raise RpcError("ETRANSPORT", "native bridge response limit exceeded")
            else:
                time.sleep(0.005)
        line, _, remaining = self.incoming.partition(b"\n")
        self.incoming = bytearray(remaining)
        reply = json.loads(line)
        if reply.get("id") != self.sequence:
            raise RpcError("ETRANSPORT", "native bridge response sequence mismatch")
        result = reply.get("result")
        if isinstance(result, dict) and "error" in result:
            raise RpcError("EBACKEND", str(result["error"]))
        return result

    def drain(self):
        result = self.request("events", after=self.event_sequence)
        if result.get("truncated"):
            raise RpcError("ETRANSPORT", "native event history overflowed")
        for event in result["events"]:
            self.event_sequence = event["seq"]
            evt = SimpleNamespace(event_type=event["type"], event_data=event["data"])
            for listener in self.listeners.get(event["type"], []):
                listener(evt)

    def watch_debug_event(self, kind, callback):
        self.listeners.setdefault(str(kind), []).append(callback)

    def is_debugging(self):
        self.drain()
        state = self.request("state")
        self.adapter.pid, self.adapter.tid = state["pid"], state["tid"]
        return state["debugging"]

    def is_running(self):
        return self.request("state")["running"]

    def get_debugger_pid(self):
        return self.request("hello")["pid"]

    def eval_sync(self, expression):
        if not re.fullmatch(r"(?:[re]?(?:ax|bx|cx|dx|si|di|ip|sp|bp)|r(?:[89]|1[0-5])|eflags|cip|mod\.main\(\)|mod\.size\(0x[0-9a-f]+\)|\$tracecounter)", expression):
            raise ValueError("expression is outside the typed bridge contract")
        return integer(self.request("eval", expression=expression)["value"]), True

    def cmd_sync(self, command):
        match = re.fullmatch(r"ticnd (0|cip==0x[0-9a-f]+), (0x[0-9a-f]+)", command)
        if match:
            params = {"count": integer(match[2])}
            if match[1] != "0":
                params["until"] = match[1].split("==")[1]
            return self.request("trace", **params)
        if command not in ("run", "sti", "sto", "pause", "stop"):
            raise ValueError("command is outside the typed bridge contract")
        return self.request("cmd", command=command)

    def start_target(self, path, args, directory):
        return self.request("start", path=path, args=args, dir=directory)

    def set_reg(self, name, value):
        return self.request("setreg", reg=name, value=hex(value))

    def set_breakpoint(self, ea):
        return self.request("bpt", ea=hex(ea))

    def clear_breakpoint(self, ea):
        return self.request("unbpt", ea=hex(ea))

    def get_regs(self):
        data = {k: integer(v) for k, v in self.request("regs").items()}
        return SimpleNamespace(context=SimpleNamespace(model_dump=lambda: data))

    def read_memory(self, ea, size):
        return bytes.fromhex(self.request("memread", ea=hex(ea), size=size))

    def write_memory(self, ea, data):
        return self.request("memwrite", ea=hex(ea), hex=data.hex())

    def memmap(self):
        return [SimpleNamespace(**{k: integer(v) if k in ("base_address", "allocation_base") else v for k, v in p.items()}) for p in self.request("memmap")]

    def module_info(self, ea):
        return self.request("module", ea=hex(ea))


class Adapter:
    def __init__(self, config_path=None, client_factory=None):
        bundled = Path(__file__).resolve().parents[2] / "runtimes/x64dbg/runtime.json"
        loc = Path(config_path or os.environ.get("IG5_X64DBG_RUNTIME") or bundled)
        self.config_path = loc / "runtime.json" if loc.is_dir() else loc
        self.config = json.loads(self.config_path.read_text(encoding="utf-8-sig")) if self.config_path.is_file() else {}
        self.root = self.config_path.parent
        data_home = Path(os.environ.get("IG5_HOME") or Path.home() / ".dsh/ig5")
        self.state_root = Path(os.environ.get("IG5_X64DBG_STATE_ROOT") or data_home / "state/x64dbg").expanduser().resolve()
        self.client_factory = client_factory
        self.client = self.proc = self.job = self.log = None
        self.target = None
        self.run_id = None
        self.stop_seq = self.event_seq = 0
        self.pid = self.tid = None
        self.events = collections.deque(maxlen=256)
        self.event_lock = threading.Lock()
        self.cancel = threading.Event()
        self.deadline = None
        self.mode = self.config.get("mode", "headless")
        self.closed = False
        self.requests = queue.Queue(maxsize=32)
        self.controls = queue.Queue(maxsize=16)
        self.wake = object()
        self.request_lock = threading.Lock()
        self.queued_ids, self.cancelled_ids, self.active_ids = set(), set(), set()
        self.shutting_down = False
        self.respond = None
        self.request_serial = 0
        self.regular_head = self.control_head = None

    def resolve(self, key):
        value = self.config.get(key)
        if not value:
            return None
        p = Path(value)
        return p if p.is_absolute() else self.root / p

    def doctor(self):
        required = ["pythonExe", "x64dbgExe", "x32dbgExe", "headlessExe", "headless32Exe"]
        paths = {key: bool(self.resolve(key) and self.resolve(key).is_file()) for key in required}
        native = self.config.get("bridge") == "ig5-native"
        plugins = {str(bits): (self.root / f"snapshot/release/x{bits}/plugins/ig5-bridge.dp{bits}").is_file() for bits in (32, 64)}
        usable = paths["pythonExe"] and paths["x64dbgExe"] and paths["x32dbgExe"]
        if self.mode == "headless":
            usable = usable and paths["headlessExe"] and paths["headless32Exe"]
        if native:
            usable = usable and all(plugins.values())
        return {"ok": usable,
                "engine": "x64dbg", "mode": self.mode, "runtime": str(self.root), "stateRoot": str(self.state_root), "files": paths,
                "bridge": self.config.get("bridge"), "nativePlugins": plugins,
                "clientRequired": not native, "clientInstalled": (self.root / "clientdeps/x64dbg_automate/__init__.py").is_file(),
                "capabilities": CAPABILITIES, "transport": "named-pipe" if native else "local-zmq", "targetExecuted": False}

    def check(self):
        if self.cancel.is_set():
            raise RpcError("ECANCELLED", "debug request cancelled")
        if self.deadline and time.monotonic() >= self.deadline:
            raise RpcError("ETIMEDOUT", "debug request timed out")
        if self.proc and self.proc.poll() is not None:
            raise RpcError("EEXIT", "debugger process exited", exitCode=self.proc.returncode)

    def call(self, name, *args):
        self.check()
        sock = getattr(self.client, "req_socket", None)
        if sock is not None:
            import zmq
            remaining = max(1, int(((self.deadline or time.monotonic() + 10) - time.monotonic()) * 1000))
            sock.setsockopt(zmq.RCVTIMEO, min(remaining, 10000))
            sock.setsockopt(zmq.SNDTIMEO, min(remaining, 2000))
        return getattr(self.client, name)(*args)

    def record_event(self, evt):
        typ = str(evt.event_type)
        data = plain(evt.event_data) if evt.event_data is not None else {}
        if isinstance(data, dict):
            for key in list(data):
                if key in ("addr", "lpStartAddress", "lpBaseOfDll", "ExceptionAddress", "ExceptionRecord", "lpThreadLocalBase") and isinstance(data[key], int):
                    data[key] = hex(data[key])
            if "ExceptionCode" in data and isinstance(data["ExceptionCode"], int):
                data["ExceptionCode"] = hex(data["ExceptionCode"])
            if "ExceptionInformation" in data:
                data["ExceptionInformation"] = [hex(v) if isinstance(v, int) else v for v in data["ExceptionInformation"]]
        with self.event_lock:
            self.event_seq += 1
            if typ == "EVENT_PAUSE_DEBUG":
                self.stop_seq += 1
            if typ == "EVENT_CREATE_PROCESS":
                self.pid, self.tid = data.get("dwProcessId"), data.get("dwThreadId")
            self.events.append({"seq": self.event_seq, "eventName": EVENT_NAMES.get(typ, typ.lower().replace("event_", "").replace("_", "-")),
                                "type": typ, "data": data, "stopSeq": self.stop_seq, "runId": self.run_id})

    def event_list(self, after=0):
        with self.event_lock:
            return [dict(e) for e in self.events if e["seq"] > after]

    def state(self):
        if self.client is None:
            return {"state": "no-task", "stateCode": -1, "runId": self.run_id, "stopSeq": self.stop_seq, "mode": self.mode}
        debugging = bool(self.call("is_debugging"))
        running = bool(self.call("is_running")) if debugging else False
        return {"state": "running" if running else "suspended" if debugging else "no-task",
                "stateCode": 1 if running else 0 if debugging else -1, "debuggerPid": self.proc.pid if self.proc else None,
                "pid": self.pid if debugging else None, "tid": self.tid if debugging else None,
                "runId": self.run_id, "stopSeq": self.stop_seq, "mode": self.mode}

    def evaluate(self, expression):
        value, ok = self.call("eval_sync", expression)
        if not ok:
            raise RpcError("EEVAL", "debugger expression failed")
        return int(value)

    def context(self, ea=None):
        result = self.state()
        if self.target:
            result.update(bits=self.target["bits"], databaseBase=self.target["databaseBase"])
        if result["state"] != "no-task":
            base = self.evaluate("mod.main()")
            size = self.evaluate(f"mod.size({hex(base)})") if base else 0
            result.update(mainModuleBase=hex(base), mainModuleSize=size,
                          mainModule=Path(self.target["path"]).name if self.target else None)
            if result["state"] == "running" and ea is None:
                return result  # An executing thread has no stable register snapshot.
            va = self.evaluate("cip") if ea is None else ea
            result["runtimeVA"] = hex(va)
            info = self.call("module_info", va) if hasattr(self.client, "module_info") else {
                "found": bool(base and base <= va < base + size), "base": hex(base), "size": size,
                "name": Path(self.target["path"]).name if self.target else None,
                "path": self.target["path"] if self.target else None}
            if info.get("found"):
                module_base = integer(info["base"])
                result.update(moduleBase=hex(module_base), module=info.get("name"), path=info.get("path"), modulePath=info.get("path"),
                              moduleSize=info.get("size"), RVA=hex(va - module_base))
            else:
                result.update(moduleBase=None, module=None)
        return result

    def address(self, params, span=1):
        relative = None
        if "rva" in params:
            relative = integer(params["rva"])
            addr = self.evaluate("mod.main()") + relative
            space = "runtime"
        else:
            if "ea" not in params:
                raise ValueError("ea or rva is required")
            addr = integer(params["ea"])
            space = params.get("addressSpace", "runtime")
        if space == "database":
            relative = addr - integer(self.target["databaseBase"])
            addr = self.evaluate("mod.main()") + relative
        elif space == "rva":
            relative = addr
            addr += self.evaluate("mod.main()")
        elif space != "runtime":
            raise ValueError("addressSpace must be runtime, database or rva")
        if relative is not None:
            base = self.evaluate("mod.main()")
            size = self.evaluate(f"mod.size({hex(base)})") if base else 0
            if relative < 0 or span < 1 or relative + span > size:
                raise ValueError("RVA access is outside the main module")
        if span < 1 or addr < 0 or addr + span > 1 << self.target["bits"]:
            raise ValueError("address is outside target pointer width")
        return addr

    def require_pause(self):
        if self.state()["state"] != "suspended":
            raise RpcError("ESTATE", "operation requires a suspended process")

    def launch(self):
        if self.client:
            return
        if not self.target:
            raise ValueError("open a target before loading the debugger")
        bits = self.target["bits"]
        key = ("headlessExe" if bits == 64 else "headless32Exe") if self.mode == "headless" else ("x64dbgExe" if bits == 64 else "x32dbgExe")
        exe = self.resolve(key)
        if not exe or not exe.is_file():
            raise RpcError("ERUNTIME", "configured debugger executable is unavailable", mode=self.mode, bits=bits)
        if self.mode not in ("headless", "gui-hidden"):
            raise ValueError("runtime mode must be headless or gui-hidden")
        sys.path.insert(0, str(self.root / "clientdeps"))
        user_dir = self.state_root / "sessions" / uuid.uuid4().hex
        user_dir.mkdir(parents=True)
        # The pinned headless host supports -userdir. Explicit local mode prevents
        # a user-edited automate remote setting from opening a network listener.
        (user_dir / "headless.ini").write_text("[Engine]\nNoConsoleWindow=1\n[Events]\nSystemBreakpoint=1\nEntryBreakpoint=1\nTlsCallbacks=0\n[XAutomate]\nMode=local\n", encoding="utf-8")
        self.log = (user_dir / "debugger.log").open("ab", buffering=0)
        startup = subprocess.STARTUPINFO() if os.name == "nt" else None
        if startup:
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = 0
        args = [str(exe), "-userdir", str(user_dir)]
        self.proc = subprocess.Popen(args, cwd=exe.parent, stdin=subprocess.PIPE, stdout=self.log, stderr=self.log,
                                     startupinfo=startup, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.job = KillJob(self.proc)
        if self.config.get("bridge") == "ig5-native":
            self.client = NativeClient(self)
            self.client.connect(self.proc.pid)
            for evt in ("EVENT_INIT_DEBUG", "EVENT_CREATE_PROCESS", "EVENT_EXIT_PROCESS", "EVENT_STOP_DEBUG", "EVENT_SYSTEMBREAKPOINT", "EVENT_PAUSE_DEBUG", "EVENT_RESUME_DEBUG", "EVENT_STEPPED", "EVENT_BREAKPOINT", "EVENT_EXCEPTION", "EVENT_LOAD_DLL", "EVENT_UNLOAD_DLL"):
                self.client.watch_debug_event(evt, self.record_event)
            return
        from x64dbg_automate import X64DbgClient
        from x64dbg_automate.events import EventType
        self.client = (self.client_factory or X64DbgClient)(str(exe))
        temp = ctypes.create_unicode_buffer(32768)
        ctypes.windll.kernel32.GetTempPathW(len(temp), temp)
        lock_path = Path(temp.value) / f"xauto_session.{self.proc.pid}.lock"
        while not lock_path.is_file():
            self.check()
            time.sleep(0.05)
        ports = lock_path.read_text().splitlines()
        if len(ports) < 2 or (len(ports) > 2 and ports[2].strip() not in ("", "localhost", "127.0.0.1")):
            raise RpcError("ETRANSPORT", "automate did not bind a local session")
        self.client.session_pid = self.proc.pid
        self.client.sess_req_rep_port, self.client.sess_pub_sub_port = map(int, ports[:2])
        self.client._init_connection()
        self.client._assert_connection_compat()
        for evt in EventType:
            if str(evt) != "EVENT_LOG_MESSAGE":
                self.client.watch_debug_event(evt, self.record_event)
        # Give the SUB subscription time to reach the publisher before init.
        time.sleep(0.25)
        if self.call("get_debugger_pid") != self.proc.pid:
            raise RpcError("ETRANSPORT", "debugger session PID mismatch")

    @staticmethod
    def timeout_seconds(params):
        seconds = float(params.get("timeout", 15))
        if not math.isfinite(seconds):
            raise ValueError("timeout must be finite")
        return max(0.1, min(seconds, 60))

    def enqueue(self, request):
        """The reader never waits on a full queue, so cancel remains readable."""
        ident = request["id"]
        with self.request_lock:
            if ident in self.queued_ids or ident in self.active_ids:
                raise RpcError("EPROTOCOL", "duplicate active request id")
            self.queued_ids.add(ident)
            self.request_serial += 1
            request["_ig5_order"] = self.request_serial
        params = request.get("params")
        priority = request["method"] == "dbg" and isinstance(params, dict) and params.get("op") in ("suspend", "stop")
        try:
            (self.controls if priority else self.requests).put_nowait(request)
        except queue.Full as error:
            with self.request_lock:
                self.queued_ids.discard(ident)
            raise RpcError("EQUEUE", "debug request queue is full") from error
        if priority:
            with contextlib.suppress(queue.Full):
                self.requests.put_nowait(self.wake)

    def next_request(self):
        """Preserve arrival order while idle; controls preempt only active waits.

        This prevents an immediately queued stop from overtaking a start before
        that start has even begun, and then accidentally launching it afterward.
        """
        while not self.shutting_down:
            if self.control_head is None:
                with contextlib.suppress(queue.Empty):
                    self.control_head = self.controls.get_nowait()
            while self.regular_head is None:
                try:
                    item = self.requests.get_nowait()
                except queue.Empty:
                    break
                if item is not self.wake:
                    self.regular_head = item
            if self.control_head is not None and (self.regular_head is None or self.control_head["_ig5_order"] < self.regular_head["_ig5_order"]):
                request, self.control_head = self.control_head, None
                return request
            if self.regular_head is not None:
                request, self.regular_head = self.regular_head, None
                return request
            item = self.requests.get()
            if item is not self.wake:
                self.regular_head = item
        return None

    def claim_request(self, request, nested=False):
        with self.request_lock:
            ident = request["id"]
            self.queued_ids.discard(ident)
            if ident in self.cancelled_ids or self.shutting_down:
                self.cancelled_ids.discard(ident)
                return False
            if not nested:
                self.cancel.clear()
            self.active_ids.add(ident)
            return True

    def finish_request(self, ident):
        with self.request_lock:
            self.active_ids.discard(ident)

    def cancel_request(self, params):
        """A wrong id must never cancel the active debugger operation."""
        requested = params.get("requestId")
        with self.request_lock:
            if requested is None:
                accepted = bool(self.active_ids)
                if accepted:
                    self.cancel.set()
                return {"ok": True, "cancelRequested": accepted, "queued": False}
            if isinstance(requested, bool) or not isinstance(requested, (str, int)):
                raise RpcError("EINVAL", "requestId must be an integer or string")
            if requested in self.active_ids:
                self.cancel.set()
                return {"ok": True, "cancelRequested": True, "requestId": requested, "queued": False}
            if requested in self.queued_ids:
                self.cancelled_ids.add(requested)
                return {"ok": True, "cancelRequested": True, "requestId": requested, "queued": True}
            return {"ok": True, "cancelRequested": False, "requestId": requested, "queued": False}

    def error_result(self, error):
        if error.code in ("ETIMEDOUT", "ECANCELLED", "EEXIT", "EJOB", "ETRANSPORT"):
            self.cleanup()
            error.detail.update(cleanedUp=True, **self.state(), debuggerPid=None, pid=None, tid=None)
        return {"code": error.code, "message": str(error), **error.detail}

    def service_controls(self):
        """Only the execution thread touches NativeClient, including controls."""
        completed = []
        while True:
            if self.control_head is not None:
                request, self.control_head = self.control_head, None
            else:
                try:
                    request = self.controls.get_nowait()
                except queue.Empty:
                    return completed
            if not self.claim_request(request, nested=True):
                if self.respond:
                    self.respond({"id": request["id"], "error": {"code": "ECANCELLED", "message": "queued request cancelled", "cancelledBeforeExecution": True, "cleanedUp": False}})
                continue
            previous_deadline = self.deadline
            try:
                params = request["params"]
                self.deadline = time.monotonic() + self.timeout_seconds(params)
                result = self.dbg(params)
                if result.get("ok"):
                    completed.append(result)
                if self.respond:
                    self.respond({"id": request["id"], "result": result})
            except (ValueError, TypeError, KeyError) as error:
                if self.respond:
                    self.respond({"id": request["id"], "error": {"code": "EINVAL", "message": str(error)}})
            except RpcError as error:
                payload = self.error_result(error)
                if self.respond:
                    self.respond({"id": request["id"], "error": payload})
                if payload.get("cleanedUp"):
                    raise
            except Exception as error:
                self.cleanup()
                failure = RpcError("EBACKEND", str(error), cleanedUp=True, **self.state(), debuggerPid=None, pid=None, tid=None)
                if self.respond:
                    self.respond({"id": request["id"], "error": {"code": failure.code, "message": str(failure), **failure.detail}})
                raise failure from error
            finally:
                self.deadline = previous_deadline
                self.finish_request(request["id"])

    def wait_result(self, mark, expected, state, context):
        observed = self.event_list(mark)
        # Classify the final pause epoch, never an earlier exception/breakpoint
        # from another stop that happened during a high-priority control.
        resumes = [e["seq"] for e in observed if e["type"] == "EVENT_RESUME_DEBUG"]
        epoch = max(resumes, default=mark)
        candidates = [e for e in observed if e["seq"] > epoch]
        if state["state"] == "no-task":
            candidates = [e for e in candidates if e["type"] in ("EVENT_EXIT_PROCESS", "EVENT_STOP_DEBUG")]
        rank = {"exception": 6, "breakpoint": 5, "step": 4, "system-breakpoint": 3, "process-exited": 2, "stopped": 2, "paused": 1}
        event = max(candidates, key=lambda e: (rank.get(e["eventName"], 0), e["seq"]), default=None)
        if event and event["eventName"] == "exception":
            context["exception"] = {"code": event["data"].get("ExceptionCode"), "ea": event["data"].get("ExceptionAddress"),
                                    "firstChance": event["data"].get("dwFirstChance"), "information": event["data"].get("ExceptionInformation", [])}
        return {"ok": state["state"] == expected, "event": {**event, "stopSeq": self.stop_seq} if event else None,
                "eventName": event["eventName"] if event else "paused" if state["state"] == "suspended" else "stopped",
                "observedEvents": observed[-32:], "context": context, **state}

    def wait_state(self, mark, expected="suspended"):
        while True:
            controlled = self.service_controls()
            if controlled:
                self.deadline = max(self.deadline or 0, time.monotonic() + 0.5)
                final = controlled[-1]
                state = {k: final[k] for k in ("state", "stateCode", "debuggerPid", "pid", "tid", "runId", "stopSeq", "mode") if k in final}
                context = dict(final.get("context", state))
                result = self.wait_result(mark, expected, state, context)
                result["interruptedBy"] = final["op"]
                if state["state"] == "no-task" and expected != "no-task":
                    result["terminalReason"] = "stopped-by-control"
                return result
            self.check()
            observed = self.event_list(mark)
            state = self.state()
            fresh_stop = any(e["type"] in ("EVENT_PAUSE_DEBUG", "EVENT_STEPPED", "EVENT_EXCEPTION", "EVENT_BREAKPOINT", "EVENT_SYSTEMBREAKPOINT") for e in observed)
            fresh_exit = any(e["type"] in ("EVENT_EXIT_PROCESS", "EVENT_STOP_DEBUG") for e in observed)
            if (state["state"] == expected and (fresh_stop if expected == "suspended" else fresh_exit)) or (fresh_exit and state["state"] == "no-task"):
                time.sleep(0.06)
                state = self.state()  # drain events published after the pause callback
                return self.wait_result(mark, expected, state, self.context())
            time.sleep(0.025)

    def dbg(self, p):
        op = str(p.get("op", ""))
        if op not in OPS:
            raise ValueError("unsupported debug operation")
        if op == "load":
            self.launch()
            return {"ok": True, "op": op, "debugger": "x64dbg", "targetExecuted": False, **self.state()}
        if op == "state":
            return {"ok": True, **self.context()}
        if op == "event":
            state = self.state()  # drain the native callback ring first
            events = self.event_list(integer(p.get("after", 0)))
            return {"ok": True, "events": events[-128:], "eventSeq": self.event_seq,
                    "truncated": len(events) > 128 or (bool(self.events) and integer(p.get("after", 0)) + 1 < self.events[0]["seq"]), **state}
        if op == "stop" and (not self.client or self.state()["state"] == "no-task"):
            return {"ok": True, "op": op, **self.state()}
        if op == "start":
            if p.get("path"):
                target = inspect_pe(p["path"])
                if self.client and self.target and target["bits"] != self.target["bits"]:
                    self.cleanup()
                self.target = target
            self.launch()
            if self.state()["state"] != "no-task":
                raise RpcError("ESTATE", "a debuggee is already active")
            self.run_id, self.stop_seq = uuid.uuid4().hex, 0
            with self.event_lock:
                self.events.clear()
            mark = self.event_seq
            def quoted(value):
                return str(value).replace('"', '\\"').replace("\r", "").replace("\n", "")
            command = 'init "{}", "{}", "{}"'.format(quoted(self.target["path"]), quoted(p.get("args", "")), quoted(p.get("dir") or Path(self.target["path"]).parent))
            accepted = self.call("start_target", self.target["path"], str(p.get("args", "")), str(p.get("dir") or Path(self.target["path"]).parent)) if isinstance(self.client, NativeClient) else self.call("cmd_sync", command)
            if not accepted:
                return {"ok": False, "op": op, "error": "debugger rejected target launch", **self.state()}
            return {"op": op, **self.wait_state(mark)}
        if not self.client:
            raise RpcError("ESTATE", "debugger is not loaded")
        if op in ("regs", "setreg", "bpt", "unbpt", "step", "stepover", "cont", "readmem", "writemem", "modules", "trace"):
            self.require_pause()
        if op == "regs":
            dump = self.call("get_regs")
            regs = {k: hex(v) for k, v in dump.context.model_dump().items() if isinstance(v, int)}
            return {"ok": bool(regs), "op": op, "regs": regs, "bits": self.target["bits"], "context": self.context(), **self.state()}
        if op == "setreg":
            name = str(p.get("reg", "")).lower()
            allowed = ("rax rbx rcx rdx rsi rdi rip rsp rbp r8 r9 r10 r11 r12 r13 r14 r15" if self.target["bits"] == 64 else "eax ebx ecx edx esi edi eip esp ebp").split() + ["eflags"]
            if name not in allowed:
                raise ValueError("unsupported target register")
            value = integer(p["value"])
            if value < 0 or value >= 1 << (32 if name == "eflags" else self.target["bits"]):
                raise ValueError("register value is outside target width")
            before = self.evaluate(name)
            if "expected" in p and before != integer(p["expected"]):
                return {"ok": False, "error": "register expected value mismatch", "before": hex(before)}
            ok = bool(self.call("set_reg", name, value))
            after = self.evaluate(name)
            return {"ok": ok and after == value, "op": op, "reg": name, "before": hex(before), "after": hex(after), **self.state()}
        if op in ("bpt", "unbpt"):
            ea = self.address(p)
            ok = bool(self.call("set_breakpoint" if op == "bpt" else "clear_breakpoint", ea))
            return {"ok": ok, "op": op, "ea": hex(ea), "context": self.context(ea), **self.state()}
        if op in ("readmem", "writemem"):
            if op == "readmem":
                size = integer(p.get("size", 64))
                if not 1 <= size <= 4096:
                    raise ValueError("memory read size must be 1..4096")
                ea = self.address(p, size)
                data = self.call("read_memory", ea, size)
                return {"ok": len(data) == size, "op": op, "ea": hex(ea), "size": len(data), "hex": data.hex(), "context": self.context(ea), **self.state()}
            data = bytes.fromhex(str(p.get("hex", "")))
            if not 1 <= len(data) <= 4096:
                raise ValueError("memory writes require 1..4096 bytes")
            ea = self.address(p, len(data))
            before = self.call("read_memory", ea, len(data))
            if len(before) != len(data):
                return {"ok": False, "error": "memory region is not fully readable"}
            if "expected" in p and before != bytes.fromhex(str(p["expected"])):
                return {"ok": False, "error": "memory expected bytes mismatch", "before": before.hex()}
            ok = bool(self.call("write_memory", ea, data))
            after = self.call("read_memory", ea, len(data))
            return {"ok": ok and after == data, "op": op, "ea": hex(ea), "written": len(data) if after == data else 0,
                    "before": before.hex(), "after": after.hex(), **self.state()}
        if op == "modules":
            main = self.evaluate("mod.main()")
            pages = self.call("memmap")
            grouped = {}
            for page in pages:
                if page.type != 0x1000000:
                    continue
                grouped.setdefault(page.allocation_base, {"base": hex(page.allocation_base), "moduleBase": hex(page.allocation_base),
                                                         "name": page.info, "source": "memory-map", "mappedBytes": 0})["mappedBytes"] += page.region_size
            if hasattr(self.client, "module_info"):
                for module_base, module in grouped.items():
                    info = self.call("module_info", module_base)
                    if info.get("found"):
                        module.update(name=info.get("name"), path=info.get("path"), size=info.get("size"), source="module-api+memory-map")
            grouped[main] = {**grouped.get(main, {}), "base": hex(main), "moduleBase": hex(main), "name": Path(self.target["path"]).name,
                             "path": self.target["path"], "size": self.evaluate(f"mod.size({hex(main)})"), "isMain": True, "source": "mod.main+memory-map"}
            return {"ok": True, "modules": list(grouped.values()), "context": self.context(), **self.state()}
        if op == "suspend" and self.state()["state"] == "suspended":
            return {"ok": True, "op": op, "context": self.context(), **self.state()}
        if op == "suspend" and self.state()["state"] == "no-task":
            raise RpcError("ESTATE", "debuggee is not active")
        mark = self.event_seq
        command = {"step": "sti", "stepover": "sto", "cont": "run", "suspend": "pause", "stop": "stop"}.get(op)
        if op == "trace":
            count = integer(p.get("count", 100))
            if not 1 <= count <= 10000:
                raise ValueError("trace count must be 1..10000")
            # Conditions remain typed addresses; no arbitrary user command surface.
            condition = "0" if "until" not in p else f"cip=={hex(integer(p['until']))}"
            command = f"ticnd {condition}, {hex(count)}"
        if not self.call("cmd_sync", command):
            return {"ok": False, "op": op, "error": "debugger rejected operation", **self.state()}
        result = self.wait_state(mark, "no-task" if op == "stop" else "suspended")
        if op == "trace":
            result.update(maxSteps=count, traceCounter=self.evaluate("$tracecounter") if result["state"] != "no-task" else None, recording=False)
        return {"op": op, **result}

    def cleanup(self):
        client, proc = self.client, self.proc
        self.client = None
        if client:
            if isinstance(client, NativeClient):
                client.close()
            for name in ("req_socket", "sub_socket"):
                sock = getattr(client, name, None)
                if sock is not None:
                    with contextlib.suppress(Exception):
                        sock.close(linger=0)
                    setattr(client, name, None)
            thread = getattr(client, "sub_thread", None)
            if thread and thread is not threading.current_thread():
                thread.join(timeout=1)
            ctx = getattr(client, "context", None)
            if ctx:
                with contextlib.suppress(Exception):
                    ctx.destroy(linger=0)
        if self.job:
            self.job.close()
            self.job = None
        if proc and proc.poll() is None:
            with contextlib.suppress(Exception):
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=4, creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    proc.kill()
            with contextlib.suppress(Exception):
                proc.wait(timeout=2)
        if proc and proc.stdin:
            with contextlib.suppress(Exception):
                proc.stdin.close()
        if self.log:
            self.log.close()
            self.log = None
        self.proc = None
        self.pid = self.tid = None

    def dispatch(self, method, params, reset_cancel=True):
        if reset_cancel:
            self.cancel.clear()
        try:
            self.deadline = time.monotonic() + self.timeout_seconds(params)
            if method == "doctor":
                return self.doctor()
            if method == "open":
                target = inspect_pe(params.get("path") or params.get("target"))
                if self.client:
                    raise RpcError("ESTATE", "close the debugger before changing the registered target")
                self.target = target
                return {"ok": True, "engine": "x64dbg", "target": target, "targetExecuted": False, "mode": self.mode}
            if method == "dbg":
                return self.dbg(params)
            if method == "close":
                self.cleanup()
                self.target = None
                return {"ok": True, "engine": "x64dbg", "closed": True}
            raise RpcError("ENOMETHOD", "unknown adapter method")
        except RpcError as error:
            self.error_result(error)
            raise
        except (ValueError, KeyError, TypeError, FileNotFoundError) as error:
            raise RpcError("EINVAL", str(error)) from error
        except Exception as error:
            # A timed out ZMQ REQ socket cannot safely issue another request.
            self.cleanup()
            raise RpcError("EBACKEND", str(error), cleanedUp=True, **self.state(), debuggerPid=None, pid=None, tid=None) from error
        finally:
            self.deadline = None


def main():
    sys.stdin.reconfigure(encoding="utf-8", errors="strict")
    sys.stdout.reconfigure(encoding="utf-8", errors="strict", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    output_lock = threading.Lock()
    def send(value):
        with output_lock:
            print(json.dumps(plain(value), ensure_ascii=False, separators=(",", ":")), flush=True)
    adapter = Adapter()
    adapter.respond = send
    def reader():
        for line in sys.stdin:
            try:
                request = json.loads(line)
                if not isinstance(request, dict) or isinstance(request.get("id"), bool) or not isinstance(request.get("id"), (str, int)) or not isinstance(request.get("method"), str):
                    raise ValueError("expected {id,method,params}")
                if request["method"] == "cancel":
                    params = request.get("params") or {}
                    if not isinstance(params, dict):
                        raise RpcError("EINVAL", "params must be an object")
                    send({"id": request["id"], "result": adapter.cancel_request(params)})
                else:
                    adapter.enqueue(request)
            except RpcError as error:
                send({"id": request.get("id"), "error": {"code": error.code, "message": str(error), **error.detail}})
            except Exception as error:
                send({"id": None, "error": {"code": "EPROTOCOL", "message": str(error)}})
        with adapter.request_lock:
            adapter.shutting_down = True
            adapter.cancel.set()
        with contextlib.suppress(queue.Full):
            adapter.requests.put_nowait(adapter.wake)
    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    send({"ig5": "ready", "engine": "x64dbg", "capabilities": CAPABILITIES})
    try:
        while True:
            if adapter.shutting_down:
                break
            request = adapter.next_request()
            if request is None:
                break
            if not adapter.claim_request(request):
                send({"id": request["id"], "error": {"code": "ECANCELLED", "message": "queued request cancelled", "cancelledBeforeExecution": True, "cleanedUp": False}})
                continue
            try:
                params = request.get("params") or {}
                if not isinstance(params, dict):
                    raise RpcError("EINVAL", "params must be an object")
                result = adapter.dispatch(request["method"], params, reset_cancel=False)
                send({"id": request["id"], "result": result})
            except RpcError as error:
                send({"id": request["id"], "error": {"code": error.code, "message": str(error), **error.detail}})
            finally:
                adapter.finish_request(request["id"])
    finally:
        adapter.cleanup()


if __name__ == "__main__":
    main()
