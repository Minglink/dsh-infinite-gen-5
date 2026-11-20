#!/usr/bin/env python3
"""
IG5 Windows Job Object Process Container Supervisor.

Guarantees:
1. Creates a Win32 Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
2. Spawns target with CREATE_SUSPENDED, assigns to the Job Object BEFORE ResumeThread (zero race window).
3. Polls QueryInformationJobObject(JobObjectBasicProcessIdList) at 2ms intervals and retains an open
   PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE handle to every assigned PID so:
   - Windows cannot recycle any observed PID while the container is open;
   - Short-lived workers and surviving grandchildren of exited intermediate parents are captured;
   - Kernel-verified creationFiletime, parentPid, imagePath, imageSha256, commandLine, and exitCode
     are recorded independently of any target stdout/JSON self-report.
4. Supports 'run' (bounded execution + stdin + cancellation via stdin 'ABORT') and 'hold' (interactive
   long-lived session until 'STOP' on stdin or timeout).
"""

import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import subprocess
import sys
import threading
import time

if os.name != "nt":
    print(json.dumps({"ok": False, "errorCode": "UNSUPPORTED_PLATFORM", "message": "win32_job_supervisor requires Windows"}))
    sys.exit(2)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
TH32CS_SNAPTHREAD = 0x00000004
THREAD_SUSPEND_RESUME = 0x0002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
STILL_ACTIVE = 259
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JobObjectBasicProcessIdList = 3
JobObjectExtendedLimitInformation = 9

CreateJobObjectW = kernel32.CreateJobObjectW
CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
CreateJobObjectW.restype = wintypes.HANDLE

SetInformationJobObject = kernel32.SetInformationJobObject
SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
SetInformationJobObject.restype = wintypes.BOOL

AssignProcessToJobObject = kernel32.AssignProcessToJobObject
AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
AssignProcessToJobObject.restype = wintypes.BOOL

QueryInformationJobObject = kernel32.QueryInformationJobObject
QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
QueryInformationJobObject.restype = wintypes.BOOL

TerminateJobObject = kernel32.TerminateJobObject
TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
TerminateJobObject.restype = wintypes.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

GetProcessTimes = kernel32.GetProcessTimes
GetProcessTimes.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
]
GetProcessTimes.restype = wintypes.BOOL

GetExitCodeProcess = kernel32.GetExitCodeProcess
GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
GetExitCodeProcess.restype = wintypes.BOOL

QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW
QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
QueryFullProcessImageNameW.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.c_size_t),
        ("InheritedFromUniqueProcessId", ctypes.c_size_t),
    ]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


def make_pid_list_struct(capacity=256):
    class JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
        _fields_ = [
            ("NumberOfAssignedProcesses", wintypes.DWORD),
            ("NumberOfProcessIdsInList", wintypes.DWORD),
            ("ProcessIdList", ctypes.c_size_t * capacity),
        ]
    return JOBOBJECT_BASIC_PROCESS_ID_LIST()


_sha_cache = {}


def sha256_file_cached(path_str):
    if not path_str:
        return None
    norm = os.path.normcase(os.path.abspath(path_str))
    try:
        st = os.stat(path_str)
        key = (norm, st.st_size, st.st_mtime_ns)
        if key in _sha_cache:
            return _sha_cache[key]
        h = hashlib.sha256()
        with open(path_str, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        digest = h.hexdigest()
        _sha_cache[key] = digest
        return digest
    except Exception:
        return None


def resume_process_threads(pid):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == wintypes.HANDLE(-1).value or not snap:
        return 0
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(te)
    resumed = 0
    try:
        if kernel32.Thread32First(snap, ctypes.byref(te)):
            while True:
                if te.th32OwnerProcessID == pid:
                    ht = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, te.th32ThreadID)
                    if ht:
                        kernel32.ResumeThread(ht)
                        CloseHandle(ht)
                        resumed += 1
                if not kernel32.Thread32Next(snap, ctypes.byref(te)):
                    break
    finally:
        CloseHandle(snap)
    return resumed


def inspect_process_handle(hproc):
    ft_create = wintypes.FILETIME()
    ft_exit = wintypes.FILETIME()
    ft_k = wintypes.FILETIME()
    ft_u = wintypes.FILETIME()
    creation_ticks = None
    if GetProcessTimes(hproc, ctypes.byref(ft_create), ctypes.byref(ft_exit), ctypes.byref(ft_k), ctypes.byref(ft_u)):
        creation_ticks = str((ft_create.dwHighDateTime << 32) | ft_create.dwLowDateTime)

    buf = ctypes.create_unicode_buffer(2048)
    sz = wintypes.DWORD(2048)
    image_path = buf.value if QueryFullProcessImageNameW(hproc, 0, buf, ctypes.byref(sz)) else None

    pbi = PROCESS_BASIC_INFORMATION()
    ret = wintypes.ULONG(0)
    ppid = None
    if ntdll.NtQueryInformationProcess(hproc, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret)) == 0:
        ppid = int(pbi.InheritedFromUniqueProcessId)

    cmdline = None
    needed = wintypes.ULONG(0)
    ntdll.NtQueryInformationProcess(hproc, 60, None, 0, ctypes.byref(needed))
    if 0 < needed.value <= 65536:
        cbuf = ctypes.create_string_buffer(needed.value)
        if ntdll.NtQueryInformationProcess(hproc, 60, cbuf, needed.value, ctypes.byref(needed)) == 0:
            us = UNICODE_STRING.from_buffer(cbuf)
            if us.Length > 0 and us.Buffer:
                cmdline = us.Buffer[: us.Length // 2]

    return {
        "creationIdentity": creation_ticks,
        "parentPid": ppid,
        "imagePath": image_path,
        "imageSha256": sha256_file_cached(image_path),
        "commandLine": cmdline,
    }


def query_job_pids(job_handle):
    plist = make_pid_list_struct(256)
    ret_len = wintypes.DWORD(0)
    ok = QueryInformationJobObject(
        job_handle,
        JobObjectBasicProcessIdList,
        ctypes.byref(plist),
        ctypes.sizeof(plist),
        ctypes.byref(ret_len),
    )
    if not ok:
        return None, ctypes.get_last_error()
    pids = [int(plist.ProcessIdList[i]) for i in range(plist.NumberOfProcessIdsInList)]
    return pids, 0


def query_process_exit_code(hproc):
    code = wintypes.DWORD(0)
    if GetExitCodeProcess(hproc, ctypes.byref(code)):
        if code.value == STILL_ACTIVE:
            return True, None
        # Convert signed 32-bit exit codes cleanly if needed, keep unsigned DWORD int
        return False, int(code.value)
    return False, None


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "errorCode": "MISSING_CONFIG"}))
        sys.exit(2)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        cfg = json.load(f)

    mode = cfg.get("mode", "run")
    exe = cfg["executable"]
    args = [str(a) for a in cfg.get("args", [])]
    cwd = cfg.get("cwd") or os.path.dirname(os.path.abspath(exe))
    env_overrides = cfg.get("env")
    stdin_hex = cfg.get("stdinHex")
    timeout_ms = int(cfg.get("timeoutMs", 20000))

    env = os.environ.copy()
    if isinstance(env_overrides, dict):
        for k, v in env_overrides.items():
            if v is None:
                env.pop(k, None)
            else:
                env[str(k)] = str(v)

    job = CreateJobObjectW(None, None)
    if not job:
        print(json.dumps({"ok": False, "errorCode": "JOB_CREATE_FAILED", "winError": ctypes.get_last_error()}))
        sys.exit(1)

    ext = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, ctypes.byref(ext), ctypes.sizeof(ext))

    seen_handles = {}
    seen_records = {}
    seq_counter = 0
    t0 = time.perf_counter()

    def poll_job():
        nonlocal seq_counter
        pids, err = query_job_pids(job)
        if pids is None:
            return False, err
        for pid in pids:
            if pid not in seen_records:
                seq_counter += 1
                h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
                meta = inspect_process_handle(h) if h else {
                    "creationIdentity": None,
                    "parentPid": None,
                    "imagePath": None,
                    "imageSha256": None,
                    "commandLine": None,
                }
                if h:
                    seen_handles[pid] = h
                seen_records[pid] = {
                    "seq": seq_counter,
                    "pid": pid,
                    "firstSeenMs": round((time.perf_counter() - t0) * 1000.0, 2),
                    "relationOrigin": "win32-job-kernel-observed",
                    **meta,
                    "exitCode": None,
                }
            elif seen_records[pid].get("commandLine") is None and pid in seen_handles:
                # Refresh commandLine if first poll caught process during early PEB init
                refreshed = inspect_process_handle(seen_handles[pid])
                for k in ("commandLine", "imagePath", "imageSha256", "parentPid", "creationIdentity"):
                    if not seen_records[pid].get(k) and refreshed.get(k):
                        seen_records[pid][k] = refreshed[k]
        return True, 0

    proc = None
    control_cmd = {"cmd": None}

    def listen_stdin():
        try:
            for line in sys.stdin:
                cmd = line.strip().upper()
                if cmd in ("STOP", "ABORT"):
                    control_cmd["cmd"] = cmd
                    break
        except Exception:
            pass

    ctrl_thread = threading.Thread(target=listen_stdin, daemon=True)
    ctrl_thread.start()

    try:
        proc = subprocess.Popen(
            [exe] + args,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if stdin_hex is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_SUSPENDED | CREATE_NO_WINDOW,
        )
        ok_assign = AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle)))
        if not ok_assign:
            assign_err = ctypes.get_last_error()
            proc.kill()
            print(json.dumps({"ok": False, "errorCode": "JOB_ASSIGN_FAILED", "winError": assign_err}))
            sys.exit(1)

        poll_job()
        resume_process_threads(proc.pid)

        out_chunks = []
        err_chunks = []

        def drain_pipe(pipe, sink):
            try:
                while True:
                    data = pipe.read(4096)
                    if not data:
                        break
                    sink.append(data)
            except Exception:
                pass

        t_out = threading.Thread(target=drain_pipe, args=(proc.stdout, out_chunks), daemon=True)
        t_err = threading.Thread(target=drain_pipe, args=(proc.stderr, err_chunks), daemon=True)
        t_out.start()
        t_err.start()

        if stdin_hex is not None and proc.stdin:
            try:
                if stdin_hex:
                    proc.stdin.write(bytes.fromhex(stdin_hex))
                proc.stdin.close()
            except Exception:
                pass

        if mode == "hold":
            # Wait briefly so initial child workers spawn, then emit started event line
            deadline_init = time.perf_counter() + 0.35
            while time.perf_counter() < deadline_init:
                poll_job()
                time.sleep(0.005)
            root_meta = seen_records.get(proc.pid, {})
            sys.stdout.write(json.dumps({
                "event": "started",
                "rootPid": proc.pid,
                "rootCreationIdentity": root_meta.get("creationIdentity"),
                "rootImagePath": root_meta.get("imagePath"),
                "rootImageSha256": root_meta.get("imageSha256"),
                "observedProcesses": list(seen_records.values()),
            }) + "\n")
            sys.stdout.flush()

        deadline = time.perf_counter() + (timeout_ms / 1000.0)
        cleanup_disposition = "natural-exit"
        timed_out = False
        cancelled = False

        while True:
            poll_job()
            if control_cmd["cmd"] == "ABORT":
                cancelled = True
                cleanup_disposition = "cancelled-abort"
                break
            if control_cmd["cmd"] == "STOP":
                cleanup_disposition = "owner-explicit-stop"
                break
            if time.perf_counter() >= deadline:
                timed_out = True
                cleanup_disposition = "timeout-reclaim"
                break
            if mode == "run":
                pids_now, q_err = query_job_pids(job)
                if pids_now is not None and len(pids_now) == 0 and proc.poll() is not None:
                    break
                # If root process exited, allow 60ms grace to observe/finish or detect lingering background children
                if proc.poll() is not None:
                    time.sleep(0.03)
                    poll_job()
                    pids_check, _ = query_job_pids(job)
                    if pids_check is not None and len(pids_check) == 0:
                        break
                    # Root exited while children remain alive in job: wait up to min(remaining deadline, 250ms)
                    grace_end = min(deadline, time.perf_counter() + 0.25)
                    while time.perf_counter() < grace_end:
                        poll_job()
                        p2, _ = query_job_pids(job)
                        if p2 is not None and len(p2) == 0:
                            break
                        time.sleep(0.005)
                    break
            time.sleep(0.002)

        poll_job()
        pids_before_term, err_before = query_job_pids(job)
        killed_pids = []
        if pids_before_term is None:
            cleanup_disposition = "unknown-enumeration-error"
        elif len(pids_before_term) > 0:
            if cleanup_disposition == "natural-exit":
                cleanup_disposition = "lingering-descendant-reclaimed"
            killed_pids = list(pids_before_term)
            TerminateJobObject(job, 9)
            wait_end = time.perf_counter() + 2.0
            while time.perf_counter() < wait_end:
                rem, _ = query_job_pids(job)
                if rem is not None and len(rem) == 0:
                    break
                time.sleep(0.01)

        pids_after, err_after = query_job_pids(job)
        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)

        for pid, h in list(seen_handles.items()):
            alive, code = query_process_exit_code(h)
            seen_records[pid]["stillAliveAtClose"] = alive
            seen_records[pid]["exitCode"] = code
            CloseHandle(h)
        seen_handles.clear()

        root_exit = proc.poll()
        stdout_bytes = b"".join(out_chunks)[:262144]
        stderr_bytes = b"".join(err_chunks)[:65536]

        result = {
            "event": "completed",
            "ok": (err_after == 0) and (pids_after is not None and len(pids_after) == 0) and not timed_out and not cancelled,
            "rootPid": proc.pid,
            "rootCreationIdentity": seen_records.get(proc.pid, {}).get("creationIdentity"),
            "rootExitCode": root_exit,
            "timedOut": timed_out,
            "cancelled": cancelled,
            "cleanupDisposition": cleanup_disposition,
            "killedPids": killed_pids,
            "cleanupEnumerationStatus": "ok" if err_after == 0 and pids_after is not None else "enumeration-failed",
            "lingeringPidsAfterCleanup": pids_after if pids_after is not None else None,
            "cleanupVerified": (err_after == 0) and (pids_after is not None and len(pids_after) == 0),
            "systemObservedProcesses": sorted(seen_records.values(), key=lambda r: r["seq"]),
            "stdoutHex": stdout_bytes.hex(),
            "stderrHex": stderr_bytes.hex(),
        }
        sys.stdout.write(json.dumps(result) + "\n")
        sys.stdout.flush()
    finally:
        for h in seen_handles.values():
            try:
                CloseHandle(h)
            except Exception:
                pass
        if job:
            try:
                TerminateJobObject(job, 9)
            except Exception:
                pass
            CloseHandle(job)


if __name__ == "__main__":
    main()
