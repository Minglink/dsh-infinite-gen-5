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

# -I omits the script directory. Only this fixed owned helper directory is added.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_policy import read_block, component_key, assert_launch_permitted, record_block, RuntimePolicyBlocked

OPS = ["load", "start", "bpt", "unbpt", "regs", "setreg", "step", "stepover",
       "cont", "suspend", "readmem", "writemem", "stop", "state", "event", "modules", "trace", "threads", "callstack",
       "apitrace"]
CAPABILITIES = ["doctor", "open", "close", "dbg", *["dbg." + op for op in OPS], "dbg.hardware_breakpoint", "dbg.record_trace", "dbg.record_events", "dbg.api_trace", "cancel"]
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
        """True only when the job handle is gone. A failed CloseHandle keeps the handle so the caller can retry."""
        if not self.handle:
            return True
        if self.kernel.CloseHandle(self.handle):
            self.handle = None
            return True
        return False


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
        if hello.get("pid") != pid or hello.get("protocol") != 2 or hello.get("eventHistoryVersion") != 2:
            raise RpcError("ETRANSPORT", "native bridge handshake mismatch; IG5 bridge protocol 2 with event history recovery is required")

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
                time.sleep(0.001)
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
            self.adapter.note_history_gap(result)
        for event in result["events"]:
            self.event_sequence = event["seq"]
            evt = SimpleNamespace(event_type=event["type"], event_data=event["data"],
                                  native_seq=event["seq"], native_stop_seq=event.get("stopSeq"),
                                  native_run_epoch=event.get("nativeRunEpoch"))
            for listener in self.listeners.get(event["type"], []):
                listener(evt)
        self.event_sequence = max(self.event_sequence, integer(result["eventSeq"]))

    def watch_debug_event(self, kind, callback):
        self.listeners.setdefault(str(kind), []).append(callback)

    def is_debugging(self):
        self.drain()
        state = self.request("state")
        self.adapter.sync_native_state(state)
        return state["debugging"]

    def is_running(self):
        snapshot = self.request("state")
        self.adapter.sync_native_state(snapshot)
        return snapshot["running"]

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

    def set_breakpoint(self, ea, kind="software", access="execute", size=1):
        return self.request("bpt", ea=hex(ea), kind=kind, access=access, size=size)

    def clear_breakpoint(self, ea, kind="software", access="execute", size=1):
        return self.request("unbpt", ea=hex(ea), kind=kind, access=access, size=size)

    def get_threads(self):
        return self.request("threads")

    def get_callstack(self):
        return self.request("callstack")

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
        self.runtime_policy_root = data_home / 'runtime-policy-blocks'
        self.runtime_policy_denied = {}
        self.state_root = Path(os.environ.get("IG5_X64DBG_STATE_ROOT") or data_home / "state/x64dbg").expanduser().resolve()
        self.client_factory = client_factory
        self.client = self.proc = self.job = self.log = None
        self.target = None
        self.run_id = None
        self.stop_seq = self.event_seq = 0
        self.native_run_epoch = None
        self.expected_native_run_epoch = None
        self.history_gap = None
        self.pending_history_gap = False
        self.gap_serial = 0
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
        launch = {}
        for bits in (32, 64):
            key = ('headlessExe' if bits == 64 else 'headless32Exe') if self.mode == 'headless' else ('x64dbgExe' if bits == 64 else 'x32dbgExe')
            component = self.resolve(key)
            try:
                blocked = (self.runtime_policy_denied.get(component_key(component)) or read_block(self.runtime_policy_root, component)) if component else None
                launch[str(bits)] = {'state': 'blocked-by-application-control' if blocked else 'not-probed', 'block': blocked, 'nativeLaunchAttempted': False}
            except RuntimePolicyBlocked as error:
                launch[str(bits)] = {'state': 'unknown-policy-state', 'reason': str(error), 'nativeLaunchAttempted': False}
        files_ready = usable
        usable = usable and all(row['state'] == 'not-probed' for row in launch.values())
        return {"ok": usable,
                'filesReady': files_ready, 'launchReadiness': launch, 'launchVerified': False,
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
            self.event_seq = integer(evt.native_seq) if hasattr(evt, "native_seq") else self.event_seq + 1
            if getattr(evt, "native_stop_seq", None) is not None:
                self.stop_seq = integer(evt.native_stop_seq)
            elif typ == "EVENT_PAUSE_DEBUG":
                self.stop_seq += 1
            if typ == "EVENT_CREATE_PROCESS":
                self.pid, self.tid = data.get("dwProcessId"), data.get("dwThreadId")
            event = {"seq": self.event_seq, "eventName": EVENT_NAMES.get(typ, typ.lower().replace("event_", "").replace("_", "-")),
                     "type": typ, "data": data, "stopSeq": self.stop_seq, "runId": self.run_id}
            if getattr(evt, "native_run_epoch", None) is not None:
                event["nativeRunEpoch"] = integer(evt.native_run_epoch)
            self.events.append(event)

    def note_history_gap(self, snapshot):
        """History loss invalidates evidence, not the pipe or the owned process."""
        with self.event_lock:
            self.events.clear()
            self.gap_serial += 1
            self.history_gap = {"reason": "event-history-overflow", "dropped": dict(snapshot.get("dropped") or {}),
                                "firstAvailableSeq": snapshot.get("firstAvailableSeq"),
                                "nativeEventSeq": snapshot.get("eventSeq"), "serial": self.gap_serial}
            self.pending_history_gap = True

    def sync_native_state(self, snapshot):
        """Resynchronize epochs from native counters, including lost pause callbacks."""
        epoch = snapshot.get("nativeRunEpoch")
        if epoch is not None:
            epoch = integer(epoch)
            approved_start = self.expected_native_run_epoch is not None and epoch == self.expected_native_run_epoch
            if approved_start:
                self.expected_native_run_epoch = None
            if self.native_run_epoch is not None and epoch != self.native_run_epoch and not approved_start:
                self.run_id = uuid.uuid4().hex
                self.note_history_gap({"eventSeq": snapshot.get("eventSeq")})
                self.history_gap["reason"] = "native-run-changed"
            self.native_run_epoch = epoch
        if "stopSeq" in snapshot:
            self.stop_seq = integer(snapshot["stopSeq"])
        self.pid = snapshot.get("pid") if snapshot.get("debugging") else None
        self.tid = snapshot.get("tid") if snapshot.get("debugging") else None

    def history_gap_result(self, state=None, safe_pause=False):
        """A missing stop event must never be reported as a breakpoint/step hit.

        An active execution wait is brought to a bounded pause when possible.
        Read-only state refreshes never implicitly control a running target.
        """
        state = state or self.state()
        pause_attempted, recovery_error = False, None
        previous_deadline = self.deadline
        try:
            if safe_pause and state["state"] == "running":
                pause_attempted = True
                self.deadline = time.monotonic() + 2
                if not self.call("cmd_sync", "pause"):
                    recovery_error = "debugger rejected the recovery pause"
                else:
                    end = time.monotonic() + 1.5
                    while time.monotonic() < end:
                        state = self.state()
                        if state["state"] != "running":
                            break
                        time.sleep(0.025)
                    if state["state"] == "running":
                        recovery_error = "recovery pause was not confirmed"
            context = self.context() if state["state"] != "running" else dict(state)
        except RpcError as error:
            if error.code != "ETIMEDOUT":
                raise
            recovery_error = "recovery state could not be confirmed within its budget"
            context = dict(state)
        finally:
            self.deadline = previous_deadline
        context["exception"] = None
        for key in ("state", "stateCode", "debuggerPid", "pid", "tid", "runId", "stopSeq", "mode", "nativeRunEpoch"):
            if key in context:
                state[key] = context[key]
        result = {"ok": False, "event": None, "eventName": "history-gap", "historyGap": dict(self.history_gap or {}),
                  "cacheInvalidated": True, "context": context, "regs": None, "exception": None,
                  "cleanedUp": False, "resynced": recovery_error is None,
                  "recoveryRequired": recovery_error is not None or state["state"] == "running",
                  "pauseAttempted": pause_attempted, **state}
        if recovery_error:
            result["recoveryError"] = recovery_error
        return result

    def event_list(self, after=0):
        with self.event_lock:
            return [dict(e) for e in self.events if e["seq"] > after]

    def state(self):
        if self.client is None:
            return {"state": "no-task", "stateCode": -1, "runId": self.run_id, "stopSeq": self.stop_seq, "mode": self.mode}
        if isinstance(self.client, NativeClient):
            # One atomic native snapshot prevents mixed process-state reads and
            # avoids a redundant pipe round trip on every recorded instruction.
            self.check()
            self.client.drain()
            snapshot = self.client.request('state')
            self.sync_native_state(snapshot)
            debugging = bool(snapshot['debugging'])
            running = bool(snapshot['running']) if debugging else False
        else:
            debugging = bool(self.call("is_debugging"))
            running = bool(self.call("is_running")) if debugging else False
        result = {"state": "running" if running else "suspended" if debugging else "no-task",
                "stateCode": 1 if running else 0 if debugging else -1, "debuggerPid": self.proc.pid if self.proc else None,
                "pid": self.pid if debugging else None, "tid": self.tid if debugging else None,
                "runId": self.run_id, "stopSeq": self.stop_seq, "mode": self.mode}
        if self.native_run_epoch is not None:
            result["nativeRunEpoch"] = self.native_run_epoch
        if self.pending_history_gap:
            result.update(historyGap=dict(self.history_gap), cacheInvalidated=True)
        return result

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
                mod_path_str = info.get("path")
                mod_sha256 = None
                try:
                    if mod_path_str and Path(mod_path_str).is_file() and Path(mod_path_str).stat().st_size <= 64 * 1024 * 1024:
                        mod_sha256 = hashlib.sha256(Path(mod_path_str).read_bytes()).hexdigest()
                except Exception:
                    mod_sha256 = None
                result.update(moduleBase=hex(module_base), module=info.get("name"), path=mod_path_str, modulePath=mod_path_str,
                              moduleSha256=mod_sha256, moduleSize=info.get("size"), RVA=hex(va - module_base))
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
        if self.proc is not None and self.proc.poll() is None:
            raise RpcError("ESTATE", "the previous debugger process is not confirmed exited; close it before starting another", **self.cleanup_detail(False))
        if not self.target:
            raise ValueError("open a target before loading the debugger")
        bits = self.target["bits"]
        key = ("headlessExe" if bits == 64 else "headless32Exe") if self.mode == "headless" else ("x64dbgExe" if bits == 64 else "x32dbgExe")
        exe = self.resolve(key)
        if exe:
            try:
                if component_key(exe) in self.runtime_policy_denied:
                    raise RuntimePolicyBlocked(self.runtime_policy_denied[component_key(exe)])
                assert_launch_permitted(self.runtime_policy_root, exe)
            except RuntimePolicyBlocked as error:
                raise RpcError('ERUNTIME_POLICY', str(error), runtimePolicyBlock=error.record, nativeLaunchAttempted=False) from error
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
        try:
            self.proc = subprocess.Popen(args, cwd=exe.parent, stdin=subprocess.PIPE, stdout=self.log, stderr=self.log,
                                         startupinfo=startup, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError as error:
            if getattr(error, 'winerror', None) == 4551:
                self.runtime_policy_denied[component_key(exe)] = {'component': component_key(exe), 'winError': 4551, 'source': 'observed-launch-error-not-persisted', 'automaticRetryAllowed': False}
                try:
                    block = record_block(self.runtime_policy_root, exe, error)
                    self.runtime_policy_denied[component_key(exe)] = block
                except Exception as state_error:
                    raise RpcError('ERUNTIME_POLICY', 'Application control blocked debugger launch; block state could not be persisted; do not retry',
                                   runtimePolicyBlock=self.runtime_policy_denied[component_key(exe)], policyStateError=str(state_error)[:256],
                                   nativeLaunchAttempted=True, nativeTargetExecuted=False) from error
                raise RpcError('ERUNTIME_POLICY', 'Application control blocked debugger launch; automatic retry retained as blocked',
                               runtimePolicyBlock=block, nativeLaunchAttempted=True, nativeTargetExecuted=False) from error
            raise
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
        maximum = 120 if params.get('op') == 'cont' else 60
        return max(0.1, min(seconds, maximum))

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
            error.detail.update(self.cleanup_detail(self.cleanup()))
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
                failure = RpcError("EBACKEND", str(error), **self.cleanup_detail(self.cleanup()))
                if self.respond:
                    self.respond({"id": request["id"], "error": {"code": failure.code, "message": str(failure), **failure.detail}})
                raise failure from error
            finally:
                self.deadline = previous_deadline
                self.finish_request(request["id"])

    def wait_result(self, mark, expected, state, context):
        if self.pending_history_gap:
            result = self.history_gap_result(state)
            if expected == "no-task" and result["state"] == "no-task":
                result["ok"] = True
            return result
        observed = [e for e in self.event_list(mark) if e.get("nativeRunEpoch") in (None, self.native_run_epoch)]
        # Classify the final pause epoch, never an earlier exception/breakpoint
        # from another stop that happened during a high-priority control.
        resumes = [e["seq"] for e in observed if e["type"] == "EVENT_RESUME_DEBUG"]
        if isinstance(self.client, NativeClient) and state['state'] == 'suspended':
            pauses = [e['seq'] for e in observed if e['type'] == 'EVENT_PAUSE_DEBUG' and e.get('stopSeq') == state.get('stopSeq')]
            if pauses:
                # The pinned core unlocks RUN before publishing RESUME. A very
                # fast instruction may publish PAUSE/STEPPED first. A resume
                # callback delivered after that authoritative pause is not a
                # second command or proof that the process is now running.
                resumes = [seq for seq in resumes if seq < max(pauses)]
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

    def wait_state(self, mark, expected="suspended", recording=False, recording_deadline=None, recording_start_stop=None):
        start_stop = self.stop_seq if recording_start_stop is None else recording_start_stop
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
            state = self.state()
            observed = [e for e in self.event_list(mark) if e.get("nativeRunEpoch") in (None, self.native_run_epoch)]
            if self.pending_history_gap:
                result = self.history_gap_result(state, safe_pause=expected != "no-task")
                if expected == "no-task" and result["state"] == "no-task":
                    result["ok"] = True  # termination is authoritative; no hit is claimed
                return result
            fresh_stop = any(e["type"] in ("EVENT_PAUSE_DEBUG", "EVENT_STEPPED", "EVENT_EXCEPTION", "EVENT_BREAKPOINT", "EVENT_SYSTEMBREAKPOINT") for e in observed)
            fresh_exit = any(e["type"] in ("EVENT_EXIT_PROCESS", "EVENT_STOP_DEBUG") for e in observed)
            if recording_deadline is not None and time.monotonic() >= recording_deadline:
                result = self.wait_result(mark, expected, state, dict(state))
                result.update(ok=False, stepConfirmed=False, recordingWaitExpired=True)
                return result
            if recording and isinstance(self.client, NativeClient) and expected == 'suspended' and state['state'] == 'suspended':
                final_events = [e for e in observed if e['seq'] > mark]
                competing = any(e['type'] in ('EVENT_EXCEPTION', 'EVENT_BREAKPOINT', 'EVENT_SYSTEMBREAKPOINT') for e in final_events)
                pauses = [e for e in final_events if e['type'] == 'EVENT_PAUSE_DEBUG' and e.get('stopSeq') == state['stopSeq']]
                steps = [e for e in final_events if e['type'] == 'EVENT_STEPPED' and e.get('stopSeq') == state['stopSeq']]
                # The pinned core publishes PAUSE, then STEPPED, then waits.
                # Require both callbacks in the same pause epoch; a pause alone
                # never establishes execution. This avoids general-event settle
                # delay and repeated module lookups for every recorded step.
                if not competing and state['stopSeq'] == start_stop + 1 and pauses and steps and max(e['seq'] for e in steps) > max(e['seq'] for e in pauses):
                    result = self.wait_result(mark, expected, state, dict(state))
                    result['lateResumeObserved'] = any(e['type'] == 'EVENT_RESUME_DEBUG' and e['seq'] > max(item['seq'] for item in steps) for e in final_events)
                    return result
                if not competing and not fresh_exit:
                    time.sleep(0.001)
                    continue
            if (state["state"] == expected and (fresh_stop if expected == "suspended" else fresh_exit)) or (fresh_exit and state["state"] == "no-task"):
                time.sleep(0.06)
                state = self.state()  # drain events published after the pause callback
                return self.wait_result(mark, expected, state, self.context())
            time.sleep(0.025)

    def interrupt_owned_debuggee(self):
        """Standard Windows breakpoint interrupt, only inside our owned job.

        This remains an approved suspend operation. It is never a PID-selectable
        attach/injection surface; the debugger must already own a live run.
        """
        if os.name != 'nt' or not isinstance(self.client, NativeClient) or not self.job or not self.job.handle:
            raise RpcError('ENOTSUPPORTED', 'Process breakpoint interrupt requires the owned native Windows debugger job')
        before = self.state()
        if before['state'] != 'running' or not before.get('pid'): raise RpcError('ESTATE', 'Process interrupt requires an active running debuggee')
        from ctypes import wintypes as w
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]; kernel.OpenProcess.restype = w.HANDLE
        kernel.CloseHandle.argtypes = [w.HANDLE]
        kernel.GetProcessId.argtypes = [w.HANDLE]; kernel.GetProcessId.restype = w.DWORD
        kernel.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)]
        kernel.CheckRemoteDebuggerPresent.argtypes = [w.HANDLE, ctypes.POINTER(w.BOOL)]
        kernel.DebugBreakProcess.argtypes = [w.HANDLE]; kernel.DebugBreakProcess.restype = w.BOOL
        # Windows debugger process access, restricted to the verified owned job.
        handle = kernel.OpenProcess(0x1fffff, False, before['pid'])
        if not handle: raise RpcError('EBACKEND', 'Could not open owned debuggee for interrupt', winError=ctypes.get_last_error())
        try:
            in_job, debugged = w.BOOL(), w.BOOL()
            if kernel.GetProcessId(handle) != before['pid'] or not kernel.IsProcessInJob(handle, self.job.handle, ctypes.byref(in_job)) or not in_job.value:
                raise RpcError('ESTATE', 'Interrupt target is outside the owned debugger job')
            if not kernel.CheckRemoteDebuggerPresent(handle, ctypes.byref(debugged)) or not debugged.value:
                raise RpcError('ESTATE', 'Interrupt target is not currently debugged')
            after = self.state()
            if any(after.get(key) != before.get(key) for key in ['pid', 'runId', 'nativeRunEpoch']) or after['state'] != 'running':
                raise RpcError('ESTATE', 'Debugger run changed before interrupt')
            if not kernel.DebugBreakProcess(handle): raise RpcError('EBACKEND', 'Owned process interrupt was rejected', winError=ctypes.get_last_error())
            return True
        finally: kernel.CloseHandle(handle)

    def dbg(self, p):
        op = str(p.get("op", ""))
        anti_debug_profile = p.get('anti_debug_profile') or 'none'
        if anti_debug_profile not in ('none', 'scyllahide-thread-context') or (anti_debug_profile != 'none' and op != 'start'):
            raise ValueError('anti_debug_profile is a typed native-start-only choice')
        scylla_bundle = None
        if anti_debug_profile != 'none':
            if self.mode != 'headless' or self.config.get('bridge') != 'ig5-native' or not self.target or self.target['bits'] != 64:
                raise RpcError('ENOTSUPPORTED', 'ScyllaHide requires the owned native x64 headless debugger')
            if p.get('path') and inspect_pe(p['path'])['bits'] != 64:
                raise RpcError('ENOTSUPPORTED', 'ScyllaHide start override must be x64')
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from scylla_hide import load_bundle
            scylla_bundle = load_bundle()
        disposition = p.get('exception_disposition', 'preserve')
        if disposition not in ('preserve', 'handled') or (disposition != 'preserve' and op != 'cont'):
            raise ValueError('exception_disposition is a typed cont-only choice')
        interrupt_method = p.get('interrupt_method', 'native-pause')
        if interrupt_method not in ('native-pause', 'break-process') or ('interrupt_method' in p and op != 'suspend'):
            raise ValueError('interrupt_method is a typed suspend-only choice')
        if 'thread_id' in p and p['thread_id'] is not None and (op != 'regs' or isinstance(p['thread_id'], bool) or not isinstance(p['thread_id'], int) or not 1 <= p['thread_id'] < 1 << 32):
            raise ValueError('thread_id requires op=regs and a positive DWORD thread ID')
        if op not in OPS:
            raise ValueError("unsupported debug operation")
        if op == "load":
            self.launch()
            return {"ok": True, "op": op, "debugger": "x64dbg", "targetExecuted": False, **self.state()}
        if op == "state":
            context = self.context()
            result = {"ok": True, **context, "context": context}
            # A fresh authoritative state is an explicit recovery acknowledgement.
            # The response still carries the gap so host caches clear old evidence.
            self.pending_history_gap = False
            return result
        if op == "event":
            state = self.state()  # drain the native callback ring first
            after = integer(p.get("after", 0))
            events = self.event_list(after)
            first = self.events[0]["seq"] if self.events else self.event_seq + 1
            dropped = {"from": after + 1, "to": first - 1, "count": first - after - 1} if after + 1 < first else None
            return {"ok": not self.pending_history_gap, "events": events[-128:], "eventSeq": self.event_seq,
                    "dropped": dropped, "truncated": len(events) > 128 or dropped is not None, **state}
        if op == "stop":
            current = self.state()
            # init starts a native thread. A high-priority stop must not declare
            # success in its transient no-task window and then allow that thread
            # to launch the target after the stop response.
            while self.client and current["state"] == "no-task" and self.expected_native_run_epoch is not None:
                self.check()
                time.sleep(0.01)
                current = self.state()
            if not self.client or current["state"] == "no-task":
                return {"ok": True, "op": op, **current}
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
            # init is asynchronous: native state may still expose the old epoch
            # before CB_INITDEBUG arrives. Exactly the next epoch is approved;
            # later or unrelated epoch changes still invalidate the run.
            self.expected_native_run_epoch = self.native_run_epoch + 1 if self.native_run_epoch is not None else None
            self.pending_history_gap, self.history_gap = False, None
            with self.event_lock:
                self.events.clear()
            mark = self.event_seq
            def quoted(value):
                return str(value).replace('"', '\\"').replace("\r", "").replace("\n", "")
            launch_args = str(p.get("args", ""))
            launch_dir = str(p.get("dir") or Path(self.target["path"]).parent)
            command = 'init "{}", "{}", "{}"'.format(quoted(self.target["path"]), quoted(launch_args), quoted(launch_dir))
            accepted = self.call("start_target", self.target["path"], launch_args, launch_dir) if isinstance(self.client, NativeClient) else self.call("cmd_sync", command)
            if not accepted:
                self.expected_native_run_epoch = None
                return {"ok": False, "op": op, "error": "debugger rejected target launch", **self.state()}
            started_result = {
                "op": op,
                "launchScenario": {
                    "argv": list(p.get("argv") or []),
                    "commandLine": launch_args,
                    "cwd": launch_dir,
                },
                **self.wait_state(mark),
            }
            if scylla_bundle is not None:
                from scylla_hide import apply_profile
                try:
                    if not isinstance(self.client, NativeClient) or started_result.get('state') != 'suspended':
                        raise RpcError('ESTATE', 'ScyllaHide requires confirmed native startup pause')
                    started_result['antiDebugEnvironment'] = apply_profile(self, scylla_bundle, RpcError)
                except Exception:
                    self.cleanup()
                    raise
            return started_result
        if not self.client:
            raise RpcError("ESTATE", "debugger is not loaded")
        if op in ("regs", "setreg", "bpt", "unbpt", "step", "stepover", "cont", "readmem", "writemem", "modules", "trace", "threads", "callstack", "apitrace"):
            self.require_pause()
            if self.pending_history_gap:
                return {"op": op, **self.history_gap_result()}
        if op in ("threads", "callstack"):
            name = "get_threads" if op == "threads" else "get_callstack"
            if not hasattr(self.client, name):
                raise RpcError("ENOTSUPPORTED", "operation requires the IG5 native bridge")
            data = self.call(name)
            return {"ok": True, "op": op, **data, "native": True, "context": self.context(), **self.state()}
        if op == 'trace' and p.get('record_trace') is True:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from trace_recorder import record
            return record(self, p)
        if op == 'apitrace':
            if not isinstance(self.client, NativeClient):
                raise RpcError('ENOTSUPPORTED', 'API tracing requires the owned native x64dbg bridge')
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from api_trace import trace
            return trace(self, p)
        if op == "regs":
            if p.get('thread_id') is not None:
                if not isinstance(self.client, NativeClient): raise RpcError('ENOTSUPPORTED', 'Selected thread context requires the owned native debugger')
                sys.path.insert(0, str(Path(__file__).resolve().parent))
                from native_thread_context import read_thread
                selected = read_thread(self, p['thread_id'], RpcError, include_debug_status=True)
                return {'ok': True, 'op': op, 'selectedThreadId': p['thread_id'], 'selectedThreadRegs': selected['registers'],
                        'selectedThreadDebuggerVisibility': selected['debuggerVisibility'],
                        'selectedThreadRegisterObservationScope': 'GetThreadContext observation under a stable debugger pause epoch; hidden-thread suspension/coherence is not independently proved',
                        'activeDebuggerThreadChanged': False, 'source': 'Windows-AMD64-GetThreadContext', 'context': self.context(), **self.state()}
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
            kind, access = str(p.get("kind", "software")), str(p.get("access", "execute"))
            size = integer(p.get("size", 1))
            if kind not in ("software", "hardware") or access not in ("execute", "write", "readwrite"):
                raise ValueError("invalid breakpoint kind or access")
            if kind == "software" and (access != "execute" or size != 1):
                raise ValueError("software breakpoints require execute access and size 1")
            if size not in ((1, 2, 4, 8) if self.target["bits"] == 64 else (1, 2, 4)) or (access == "execute" and size != 1):
                raise ValueError("invalid hardware breakpoint size")
            ea = self.address(p, size)
            if ea % size:
                raise ValueError("hardware breakpoint address must be aligned to size")
            name = "set_breakpoint" if op == "bpt" else "clear_breakpoint"
            if isinstance(self.client, NativeClient):
                result = self.call(name, ea, kind, access, size)
                ok = bool(result.get("ok"))
                detail = {"breakpoint": result}
            else:
                if kind != "software":
                    raise RpcError("ENOTSUPPORTED", "hardware breakpoints require the IG5 native bridge")
                ok, detail = bool(self.call(name, ea)), {}
            return {"ok": ok, "op": op, "ea": hex(ea), "kind": kind, "access": access, "size": size, **detail, "context": self.context(ea), **self.state()}
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
                        mp = info.get("path")
                        msha = None
                        try:
                            if mp and "windows\\system32" not in mp.lower() and Path(mp).is_file() and Path(mp).stat().st_size <= 16 * 1024 * 1024:
                                msha = hashlib.sha256(Path(mp).read_bytes()).hexdigest()
                        except Exception:
                            msha = None
                        module.update(name=info.get("name"), path=mp, sha256=msha, size=info.get("size"), source="module-api+memory-map")
            grouped[main] = {**grouped.get(main, {}), "base": hex(main), "moduleBase": hex(main), "name": Path(self.target["path"]).name,
                             "path": self.target["path"], "size": self.evaluate(f"mod.size({hex(main)})"), "isMain": True, "source": "mod.main+memory-map"}
            return {"ok": True, "modules": list(grouped.values()), "context": self.context(), **self.state()}
        if op == "suspend" and self.state()["state"] == "suspended":
            return {"ok": True, "op": op, "context": self.context(), **self.state()}
        if op == "suspend" and self.state()["state"] == "no-task":
            raise RpcError("ESTATE", "debuggee is not active")
        mark = self.event_seq
        command = {"step": "sti", "stepover": "sto", "cont": "run", "suspend": "pause", "stop": "stop"}.get(op)
        continued_exception = None
        if disposition == 'handled':
            if not isinstance(self.client, NativeClient):
                raise RpcError('ENOTSUPPORTED', 'Explicit exception handling requires the owned native bridge')
            paused_context = self.context()
            stops = [event for event in self.event_list(0) if event.get('stopSeq') == paused_context['stopSeq']
                     and event.get('runId') == paused_context['runId']
                     and event.get('nativeRunEpoch') == paused_context.get('nativeRunEpoch')
                     and event.get('eventName') in ('exception', 'breakpoint', 'step', 'system-breakpoint')]
            exception_event = max(stops, key=lambda event: event['seq'], default=None)
            if not exception_event or exception_event['eventName'] != 'exception':
                raise RpcError('ESTATE', 'Explicit exception handling requires an observed exception pause')
            info = exception_event['data']
            continued_exception = {'code': info.get('ExceptionCode'), 'ea': info.get('ExceptionAddress'),
                'firstChance': info.get('dwFirstChance'), 'information': info.get('ExceptionInformation', []),
                'runId': paused_context['runId'], 'stopSeq': paused_context['stopSeq'], 'threadId': paused_context['tid']}
            command = 'serun'  # Native x64dbg: DBG_CONTINUE for this exception, then run.
        if op == "trace":
            count = integer(p.get("count", 100))
            if not 1 <= count <= 10000:
                raise ValueError("trace count must be 1..10000")
            # Conditions remain typed addresses; no arbitrary user command surface.
            condition = "0" if "until" not in p else f"cip=={hex(integer(p['until']))}"
            command = f"ticnd {condition}, {hex(count)}"
        if continued_exception is not None:
            # The immutable bridge only exposes run/step/pause/stop. The pinned
            # headless host also has a standard-input command loop. Send this
            # ONE constant line through its private owned pipe; never accept a
            # command, expression or script from the caller. Acceptance is not
            # execution proof: wait_state below still requires real callbacks.
            if self.mode != 'headless' or not self.proc or not self.proc.stdin or not self.job or not self.job.handle:
                raise RpcError('ESTATE', 'Handled exception requires the owned headless command pipe')
            self.check()
            self.proc.stdin.write(b'serun\n'); self.proc.stdin.flush()
            accepted = True
        else:
            accepted = self.interrupt_owned_debuggee() if op == 'suspend' and interrupt_method == 'break-process' else self.call('cmd_sync', command)
        if not accepted:
            return {"ok": False, "op": op, "error": "debugger rejected operation", **self.state()}
        result = self.wait_state(mark, "no-task" if op == "stop" else "suspended")
        if continued_exception is not None:
            result.update(exceptionDisposition='handled', continuedException=continued_exception,
                exceptionContinuationTransport='owned-headless-stdin-fixed-serun')
        if op == 'suspend': result['interruptMethod'] = interrupt_method
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
        job_closed = True
        if self.job:
            job_closed = bool(self.job.close())
            if job_closed:
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
        exited = proc is None or proc.poll() is not None
        if proc and proc.stdin:
            with contextlib.suppress(Exception):
                proc.stdin.close()
        if self.log:
            self.log.close()
            self.log = None
        if not (job_closed and exited):
            # 没有退出证据：保留进程与 Job 引用。调用方据此不得释放调试所有权，之后可以重试清理。
            return False
        self.proc = None
        self.pid = self.tid = None
        self.native_run_epoch = None
        self.expected_native_run_epoch = None
        self.pending_history_gap, self.history_gap = False, None
        # Native event sequence numbers belong to the debugger process. A new
        # headless process starts at zero; retaining the old wait mark would
        # reject every callback from a subsequent approved start after cleanup.
        with self.event_lock:
            self.events.clear()
            self.event_seq = 0
        return True

    def cleanup_detail(self, confirmed):
        """Error-detail fields for a cleanup. cleanedUp may only be true with process-exit and job-close evidence."""
        if confirmed:
            return dict(cleanedUp=True, cleanupConfirmed=True, **self.state(), debuggerPid=None, pid=None, tid=None)
        return dict(cleanedUp=False, cleanupConfirmed=False, state="cleanup-unconfirmed", stateCode=-2, runId=self.run_id,
                    stopSeq=self.stop_seq, mode=self.mode, debuggerPid=getattr(self.proc, "pid", None))

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
                confirmed = self.cleanup()
                if not confirmed:
                    raise RpcError("ECLEANUP", "debugger process exit could not be confirmed; ownership is retained, retry close", **self.cleanup_detail(False))
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
            raise RpcError("EBACKEND", str(error), **self.cleanup_detail(self.cleanup())) from error
        finally:
            self.deadline = None


def main():
    sys.stdin.reconfigure(encoding="utf-8", errors="strict")
    sys.stdout.reconfigure(encoding="utf-8", errors="strict", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    # Keep optional native decoder diagnostics away from the JSONL protocol.
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), 'w', encoding='utf-8', buffering=1)
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    sys.stdout = sys.stderr
    output_lock = threading.Lock()
    def send(value):
        with output_lock:
            protocol.write(json.dumps(plain(value), ensure_ascii=False, separators=(",", ":")) + '\n')
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
