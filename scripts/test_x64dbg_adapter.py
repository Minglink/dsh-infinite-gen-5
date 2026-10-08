"""Transport/state regressions with a fake debugger; never launches a target."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "adapters/x64dbg/adapter.py"
spec = importlib.util.spec_from_file_location("ig5_x64dbg_adapter", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class FakeClient:
    def __init__(self, adapter):
        self.adapter = adapter
        self.debugging, self.running = True, False
        self.regs = {"rip": 0x140001000, "rax": 1, "eflags": 0x202}
        self.memory = bytearray(b"\x01\x02\x03\x04")
        self.writes = []
        self.commands = []
        self.command_result, self.step_events, self.exit_on_command = True, True, False

    def is_debugging(self): return self.debugging
    def is_running(self): return self.running
    def eval_sync(self, value):
        return (0x140000000 if value == "mod.main()" else 0x4000 if value.startswith("mod.size(")
                else self.regs.get("rip", self.regs.get("eip")) if value == "cip" else self.regs[value]), True
    def get_regs(self): return SimpleNamespace(context=SimpleNamespace(model_dump=lambda: self.regs.copy()))
    def read_memory(self, ea, size): return bytes(self.memory[:size])
    def write_memory(self, ea, data): self.writes.append((ea, data)); self.memory[:len(data)] = data; return True
    def set_reg(self, name, value): self.writes.append((name, value)); self.regs[name] = value; return True
    def set_breakpoint(self, ea): self.writes.append(("bpt", ea)); return True
    def clear_breakpoint(self, ea): self.writes.append(("unbpt", ea)); return True
    def cmd_sync(self, command):
        self.commands.append(command)
        if self.exit_on_command:
            self.debugging = False
            self.adapter.record_event(SimpleNamespace(event_type="EVENT_EXIT_PROCESS", event_data={"dwExitCode": 1}))
        elif self.step_events:
            self.regs["rip"] += 1
            for typ in ("EVENT_PAUSE_DEBUG", "EVENT_STEPPED"):
                self.adapter.record_event(SimpleNamespace(event_type=typ, event_data={}))
        return self.command_result


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ig5-x64dbg-fake-")
        self.adapter = mod.Adapter(Path(self.temp.name) / "runtime.json")
        self.adapter.target = {"path": "fake.exe", "bits": 64, "databaseBase": "0x140000000", "entryRVA": "0x1000"}
        self.adapter.run_id = "test-run"
        self.client = self.adapter.client = FakeClient(self.adapter)

    def tearDown(self):
        self.adapter.cleanup()
        self.temp.cleanup()

    def dbg(self, op, **params): return self.adapter.dispatch("dbg", {"op": op, **params})

    def test_open_registers_without_execution(self):
        self.adapter.client = None
        p = Path(self.temp.name) / "空白.exe"
        data = bytearray(0x200); data[:2] = b"MZ"; struct.pack_into("<I", data, 0x3c, 0x80)
        data[0x80:0x84] = b"PE\0\0"; struct.pack_into("<H", data, 0x84, 0x8664)
        struct.pack_into("<H", data, 0x98, 0x20b); struct.pack_into("<I", data, 0xa8, 0x1000); struct.pack_into("<Q", data, 0xb0, 0x140000000)
        p.write_bytes(data)
        opened = self.adapter.dispatch("open", {"path": str(p)})
        self.assertFalse(opened["targetExecuted"]); self.assertIsNone(self.adapter.proc)
        self.assertEqual(opened["target"]["bits"], 64)
        data[0x98:0x9a] = b"\x0b\x01"; p.write_bytes(data)
        with self.assertRaises(mod.RpcError) as error: self.adapter.dispatch("open", {"path": str(p)})
        self.assertEqual(error.exception.code, "EINVAL")

    def test_integer_rejects_lossy_and_boolean(self):
        for value in (True, 1.2, None, [], "1.2"):
            with self.assertRaises((ValueError, TypeError)): mod.integer(value)
        self.assertEqual(mod.integer("0x123"), 0x123)

    def test_expected_memory_rejects_without_write(self):
        result = self.dbg("writemem", ea="0x140001000", hex="ffff", expected="0000")
        self.assertFalse(result["ok"]); self.assertEqual(self.client.writes, [])
        self.assertTrue(self.dbg("writemem", ea="0x140001000", hex="ffff", expected="0102")["ok"])
        self.assertEqual(self.client.memory[:2], b"\xff\xff")

    def test_register_width_and_expected(self):
        self.assertFalse(self.dbg("setreg", reg="rax", value="0x9", expected="0x2")["ok"])
        self.assertEqual(self.client.writes, [])
        self.assertTrue(self.dbg("setreg", reg="rax", value="0x9", expected="0x1")["ok"])
        for reg, value in (("rip", -1), ("rax", 1 << 64), ("eflags", 1 << 32), ("foo", 1)):
            with self.assertRaises(mod.RpcError) as error: self.dbg("setreg", reg=reg, value=value)
            self.assertEqual(error.exception.code, "EINVAL")

    def test_32bit_address_and_register_contract(self):
        self.adapter.target["bits"] = 32
        self.client.regs = {"eip": 0x401000, "eax": 0, "eflags": 0x202}
        with self.assertRaises(mod.RpcError): self.dbg("readmem", ea="0x100000000", size=1)
        with self.assertRaises(mod.RpcError): self.dbg("setreg", reg="rax", value=1)
        result = self.dbg("regs"); self.assertEqual(result["bits"], 32); self.assertIn("eip", result["regs"])

    def test_no_stale_pause_success(self):
        self.adapter.record_event(SimpleNamespace(event_type="EVENT_PAUSE_DEBUG", event_data={}))
        self.client.step_events = False
        with self.assertRaises(mod.RpcError) as error: self.dbg("step", timeout=0.1)
        self.assertEqual(error.exception.code, "ETIMEDOUT"); self.assertTrue(error.exception.detail["cleanedUp"])
        self.assertEqual(error.exception.detail["state"], "no-task"); self.assertIsNone(error.exception.detail["pid"])
        self.assertIsNone(self.adapter.client)

    def test_fresh_step_and_run_context(self):
        result = self.dbg("step")
        self.assertTrue(result["ok"]); self.assertEqual(result["eventName"], "step")
        self.assertEqual(result["stopSeq"], 1); self.assertEqual(result["context"]["runId"], "test-run")
        self.assertEqual(result["context"]["RVA"], "0x1001")

    def test_exit_is_not_step_success(self):
        self.client.exit_on_command = True
        result = self.dbg("step")
        self.assertFalse(result["ok"]); self.assertEqual(result["state"], "no-task")
        self.assertEqual(result["eventName"], "process-exited")

    def test_read_bounds_and_running_guard(self):
        for size in (0, 4097):
            with self.assertRaises(mod.RpcError): self.dbg("readmem", ea=1, size=size)
        self.client.running = True
        with self.assertRaises(mod.RpcError) as error: self.dbg("regs")
        self.assertEqual(error.exception.code, "ESTATE"); self.assertEqual(self.client.writes, [])

    def test_cancellation_cleans_transport(self):
        self.client.step_events = False
        timer = threading.Timer(0.03, self.adapter.cancel.set); timer.start()
        try:
            with self.assertRaises(mod.RpcError) as error: self.dbg("step", timeout=2)
            self.assertEqual(error.exception.code, "ECANCELLED"); self.assertTrue(error.exception.detail["cleanedUp"])
        finally: timer.join()

    def test_events_are_bounded_and_exceptions_are_structured(self):
        for _ in range(300): self.adapter.record_event(SimpleNamespace(event_type="EVENT_RESUME_DEBUG", event_data={}))
        self.assertEqual(len(self.adapter.events), 256)
        self.assertTrue(self.dbg("event", after=0)["truncated"])
        self.adapter.record_event(SimpleNamespace(event_type="EVENT_EXCEPTION", event_data={"ExceptionCode": 0xc0000005, "ExceptionAddress": 0, "ExceptionInformation": [8, 0]}))
        data = self.adapter.events[-1]["data"]
        self.assertEqual(data["ExceptionCode"], "0xc0000005"); self.assertEqual(data["ExceptionInformation"], ["0x8", "0x0"])

    def test_native_command_surface_is_typed(self):
        client = object.__new__(mod.NativeClient)
        requests = []
        client.request = lambda method, **params: requests.append((method, params)) or True
        for cmd in ('run; quit', 'init "anything.exe"', 'ticnd 0, 1; quit', 'unknown'):
            with self.assertRaises(ValueError): client.cmd_sync(cmd)
        client.cmd_sync("ticnd cip==0x1000, 0x5")
        self.assertEqual(requests, [("trace", {"count": 5, "until": "0x1000"})])

    def test_runtime_database_and_rva_address_conversion(self):
        original = self.client.eval_sync
        self.client.eval_sync = lambda expr: (0x150000000, True) if expr == "mod.main()" else original(expr)
        self.assertEqual(self.adapter.address({"rva": "0x1000"}), 0x150001000)
        self.assertEqual(self.adapter.address({"ea": "0x140001000", "addressSpace": "database"}), 0x150001000)
        self.assertEqual(self.adapter.address({"ea": "0x1000", "addressSpace": "rva"}), 0x150001000)
        self.assertEqual(self.adapter.address({"ea": "0x150001000"}), 0x150001000)

    def test_invalid_timeouts_remain_protocol_errors(self):
        for value in ("invalid", float("nan"), float("inf"), None):
            with self.assertRaises(mod.RpcError) as error: self.dbg("state", timeout=value)
            self.assertEqual(error.exception.code, "EINVAL")
        self.assertIs(self.adapter.client, self.client)

    def test_rva_rejects_negative_and_full_span_outside_module(self):
        for rva, size in (("-0x1", 1), ("0x4000", 1), ("0x3fff", 2)):
            with self.assertRaises(mod.RpcError) as error: self.dbg("readmem", rva=rva, size=size)
            self.assertEqual(error.exception.code, "EINVAL")
        with self.assertRaises(mod.RpcError): self.dbg("writemem", rva="0x3fff", hex="abcd")
        with self.assertRaises(ValueError): self.adapter.address({"ea": "0xffffffffffffffff"}, 2)
        self.assertEqual(self.adapter.address({"rva": "0x3fff"}, 1), 0x140003fff)
        self.assertEqual(self.client.writes, [])

    def test_context_resolves_current_module_and_keeps_main_identity(self):
        self.client.regs["rip"] = 0x7ff00123
        self.client.module_info = lambda ea: {"found": True, "base": "0x7ff00000", "size": 0x2000, "name": "ntdll.dll", "path": "C:/Windows/ntdll.dll"}
        context = self.adapter.context()
        self.assertEqual(context["module"], "ntdll.dll"); self.assertEqual(context["RVA"], "0x123")
        self.assertEqual(context["moduleBase"], "0x7ff00000"); self.assertEqual(context["mainModuleBase"], "0x140000000")
        self.client.module_info = lambda ea: {"found": False}
        context = self.adapter.context()
        self.assertIsNone(context["module"]); self.assertIsNone(context["moduleBase"]); self.assertNotIn("RVA", context)

    def test_directed_cancel_never_cancels_wrong_request(self):
        request = {"id": 11, "method": "dbg", "params": {"op": "cont"}}
        self.assertTrue(self.adapter.claim_request(request))
        self.assertFalse(self.adapter.cancel_request({"requestId": 12})["cancelRequested"])
        self.assertFalse(self.adapter.cancel.is_set())
        self.assertTrue(self.adapter.cancel_request({"requestId": 11})["cancelRequested"])
        self.assertTrue(self.adapter.cancel.is_set())
        self.adapter.finish_request(11)

    def test_queued_cancel_is_skipped_and_does_not_touch_active_request(self):
        self.adapter.claim_request({"id": 11})
        queued = {"id": 22, "method": "dbg", "params": {"op": "setreg", "reg": "rax", "value": 3}}
        self.adapter.enqueue(queued)
        self.assertTrue(self.adapter.cancel_request({"requestId": 22})["queued"])
        self.assertFalse(self.adapter.claim_request(self.adapter.requests.get_nowait()))
        self.assertFalse(self.adapter.cancel.is_set()); self.assertEqual(self.client.writes, [])
        self.adapter.finish_request(11)

    def test_full_regular_queue_does_not_block_control_or_cancel(self):
        self.adapter.claim_request({"id": "active"})
        for i in range(32): self.adapter.enqueue({"id": i, "method": "doctor", "params": {}})
        with self.assertRaises(mod.RpcError) as error: self.adapter.enqueue({"id": 100, "method": "doctor", "params": {}})
        self.assertEqual(error.exception.code, "EQUEUE")
        self.adapter.enqueue({"id": "pause", "method": "dbg", "params": {"op": "suspend"}})
        self.assertEqual(self.adapter.controls.qsize(), 1)
        self.assertTrue(self.adapter.cancel_request({"requestId": "active"})["cancelRequested"])

    def test_high_priority_suspend_preserves_transport_and_one_stop_epoch(self):
        responses = []; self.adapter.respond = responses.append
        self.client.running = True
        def command(cmd):
            self.client.commands.append(cmd); self.client.running = False
            self.adapter.record_event(SimpleNamespace(event_type="EVENT_PAUSE_DEBUG", event_data={}))
            return True
        self.client.cmd_sync = command
        self.adapter.enqueue({"id": 20, "method": "dbg", "params": {"op": "suspend"}})
        self.adapter.deadline = time.monotonic() + 1
        result = self.adapter.wait_state(0)
        self.assertTrue(result["ok"]); self.assertEqual(result["interruptedBy"], "suspend")
        self.assertEqual(result["stopSeq"], 1); self.assertEqual(responses[0]["result"]["stopSeq"], 1)
        self.assertIs(self.adapter.client, self.client)

    def test_stop_does_not_overtake_an_unstarted_launch(self):
        start = {"id": 10, "method": "dbg", "params": {"op": "start"}}
        stop = {"id": 11, "method": "dbg", "params": {"op": "stop"}}
        self.adapter.enqueue(start); self.adapter.enqueue(stop)
        self.assertEqual(self.adapter.next_request()["id"], 10)
        # A cached control stays available to the active start's wait loop.
        self.assertEqual(self.adapter.control_head["id"], 11)
        self.assertEqual(self.adapter.next_request()["id"], 11)


if __name__ == "__main__": unittest.main(verbosity=2)
