"""Live native bridge boundary checks. Loads an empty debugger, never a debuggee."""
import ctypes
from ctypes import wintypes as w
import importlib.util
from pathlib import Path

source = Path(__file__).resolve().parents[1] / "adapters/x64dbg/adapter.py"
spec = importlib.util.spec_from_file_location("ig5_x64dbg_security", source)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
adapter = mod.Adapter()
adapter.target = {"bits": 64}  # Loading an empty host only needs target architecture.
adv = ctypes.WinDLL("advapi32", use_last_error=True)
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
adv.GetSecurityInfo.argtypes = [w.HANDLE, ctypes.c_int, w.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
adv.GetSecurityInfo.restype = w.DWORD
adv.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, w.DWORD, ctypes.c_int]
adv.GetAce.argtypes = [ctypes.c_void_p, w.DWORD, ctypes.c_void_p]
adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
adv.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.c_void_p]
adv.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p]
kernel.GetCurrentProcess.restype = w.HANDLE
kernel.LocalFree.argtypes = [ctypes.c_void_p]
kernel.CloseHandle.argtypes = [w.HANDLE]


def sid_text(sid):
    value = w.LPWSTR()
    assert adv.ConvertSidToStringSidW(sid, ctypes.byref(value))
    try: return value.value
    finally: kernel.LocalFree(value)


try:
    result = adapter.dispatch("dbg", {"op": "load", "timeout": 15})
    assert result["state"] == "no-task" and result["targetExecuted"] is False
    hello = adapter.client.request("hello")
    assert hello["ownerOnly"] and hello["remoteClientsRejected"] and hello["typedRequests"]
    descriptor, dacl = ctypes.c_void_p(), ctypes.c_void_p()
    assert adv.GetSecurityInfo(adapter.client.handle, 6, 4, None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0
    try:
        control, revision = w.WORD(), w.DWORD()
        assert adv.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision))
        assert control.value & 0x1000  # SE_DACL_PROTECTED: no inherited broad access.
        info = (w.DWORD * 3)()
        assert adv.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2)
        assert info[0] == 1
        ace = ctypes.c_void_p(); assert adv.GetAce(dacl, 0, ctypes.byref(ace))
        assert ctypes.c_ubyte.from_address(ace.value).value == 0  # ACCESS_ALLOWED_ACE
        allowed_sid = sid_text(ace.value + 8)
        token, needed = w.HANDLE(), w.DWORD()
        assert adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token))
        try:
            adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            buf = ctypes.create_string_buffer(needed.value)
            assert adv.GetTokenInformation(token, 1, buf, len(buf), ctypes.byref(needed))
            current_sid = sid_text(ctypes.c_void_p.from_buffer(buf).value)
        finally: kernel.CloseHandle(token)
        assert allowed_sid == current_sid
    finally: kernel.LocalFree(descriptor)
    rejected = 0
    for method, params in (("cmd", {"command": "run; quit"}), ("cmd", {"command": 'init "anything.exe"'}),
                           ("eval", {"expression": "mem.write(0,1)"}), ("cmd", {"command": "ticnd 0, 1; quit"})):
        try: adapter.client.request(method, **params)
        except mod.RpcError as error:
            assert error.code == "EBACKEND"; rejected += 1
        else: raise AssertionError("untyped command accepted")
    assert adapter.state()["state"] == "no-task"
    print(f"PASS: protected single-current-user ACE, remote-client rejection flag, {rejected} untyped commands rejected, no target executed")
finally:
    adapter.cleanup()
