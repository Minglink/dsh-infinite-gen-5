"""Debug adapter regression tests. Fake modules never load or execute a debuggee."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


worker_path = Path(__file__).resolve().parents[1] / "worker" / "ig5_worker.py"
spec = importlib.util.spec_from_file_location("ig5_debug_test_worker", worker_path)
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class FakeDebugger(types.ModuleType):
    DSTATE_NOTASK, DSTATE_RUN, DSTATE_SUSP = 0, 1, -1
    DEC_NOTASK, DEC_ERROR, DEC_TIMEOUT = -2, -1, 0
    WFNE_ANY, WFNE_SUSP, WFNE_SILENT = 1, 2, 4

    def __init__(self):
        super().__init__("ida_dbg")
        self.state = self.DSTATE_SUSP
        self.events = []
        self.waits = []
        self.actions = []
        self.registers = []
        self.start_rc = 1
        self.accept = True
        self.values = {"rax": 0x1234, "rip": 0x140001000,
                       "eax": 0x1234, "eip": 0x401000, "ax": 0x1234, "ip": 0x1000}

    def get_process_state(self):
        return self.state

    def get_reg_val(self, name):
        self.registers.append(name)
        return self.values[name]

    def start_process(self, path, args, directory):
        self.actions.append(("start", path, args, directory))
        if self.start_rc == 1:
            self.state = self.DSTATE_RUN
        return self.start_rc

    def action(self, name):
        self.actions.append(name)
        if self.accept:
            self.state = self.DSTATE_RUN
        return self.accept

    def step_into(self):
        return self.action("step")

    def step_over(self):
        return self.action("stepover")

    def continue_process(self):
        return self.action("cont")

    def suspend_process(self):
        return self.action("suspend")

    def exit_process(self):
        return self.action("stop")

    def wait_for_next_event(self, flags, seconds):
        self.waits.append((flags, seconds))
        if not self.events:
            return self.DEC_TIMEOUT
        event, self.state = self.events.pop(0)
        if isinstance(event, Exception):
            raise event
        return event


class DebugApiTests(unittest.TestCase):
    def setUp(self):
        self.dbg = FakeDebugger()
        self.idd = types.ModuleType("ida_idd")
        for name, value in {"PROCESS_STARTED": 1, "PROCESS_EXITED": 2,
                            "THREAD_EXITED": 8, "BREAKPOINT": 16, "STEP": 32,
                            "EXCEPTION": 64, "PROCESS_SUSPENDED": 4096}.items():
            setattr(self.idd, name, value)
        self.memory = b"\x90\xc3"
        self.reads = []

        def read_memory(ea, size):
            self.reads.append((ea, size))
            return self.memory

        self.idd.dbg_read_memory = read_memory
        self.bits = 64
        ida = types.ModuleType("ida_ida")
        ida.inf_is_64bit = lambda: self.bits == 64
        ida.inf_is_32bit_exactly = lambda: self.bits == 32
        idaapi = types.ModuleType("ida_idaapi")
        idaapi.BADADDR = (1 << 64) - 1
        self.modules = patch.dict(sys.modules, {"ida_dbg": self.dbg, "ida_idd": self.idd,
                                                "ida_ida": ida, "ida_idaapi": idaapi})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        worker._open = True

    def call(self, op, **params):
        return worker.m_dbg({"op": op, **params})

    def test_registers_use_python_api_and_target_width(self):
        for bits, ip, excluded in ((64, "rip", "eip"), (32, "eip", "rip"), (16, "ip", "rip")):
            with self.subTest(bits=bits):
                self.bits = bits
                self.dbg.registers.clear()
                result = self.call("regs")
                self.assertTrue(result["ok"])
                self.assertEqual(result["bits"], bits)
                self.assertEqual(result["regs"][ip], hex(self.dbg.values[ip]))
                self.assertNotIn(excluded, self.dbg.registers)

    def test_registers_require_suspension_and_report_empty_reads(self):
        self.dbg.state = self.dbg.DSTATE_RUN
        result = self.call("regs")
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "running")
        self.assertEqual(self.dbg.registers, [])
        self.dbg.state = self.dbg.DSTATE_SUSP
        self.dbg.values.clear()
        result = self.call("regs")
        self.assertFalse(result["ok"])
        self.assertIn("error", result)

    def test_read_memory_returns_actual_bytes_and_partial_size(self):
        result = self.call("readmem", ea="140001000", size=4)
        self.assertTrue(result["ok"])
        self.assertEqual(self.reads, [(0x140001000, 4)])
        self.assertEqual(result["hex"], "90c3")
        self.assertEqual(result["size"], 2)
        self.call("readmem", ea="140001000", size=100000)
        self.assertEqual(self.reads[-1][1], 4096)

    def test_read_memory_failure_is_not_empty_success(self):
        for memory in (None, b""):
            with self.subTest(memory=memory):
                self.memory = memory
                result = self.call("readmem", ea="140001000")
                self.assertFalse(result["ok"])
                self.assertIn("error", result)

    def test_start_waits_for_suspension(self):
        self.dbg.events = [(self.idd.BREAKPOINT, self.dbg.DSTATE_SUSP)]
        result = self.call("start", path="fixture.exe", timeout=2)
        self.assertTrue(result["ok"])
        self.assertEqual(result["eventName"], "breakpoint")
        self.assertEqual(result["state"], "suspended")
        self.assertEqual(self.dbg.actions[0], ("start", "fixture.exe", None, None))
        flags, seconds = self.dbg.waits[0]
        self.assertTrue(flags & self.dbg.WFNE_SUSP)
        self.assertTrue(flags & self.dbg.WFNE_SILENT)
        self.assertEqual(seconds, 2)

    def test_failed_start_does_not_wait(self):
        self.dbg.start_rc = -1
        result = self.call("start")
        self.assertFalse(result["ok"])
        self.assertEqual(result["rc"], -1)
        self.assertEqual(self.dbg.waits, [])

    def test_event_errors_never_report_success(self):
        for op in ("start", "step", "stepover", "cont", "suspend", "stop"):
            for event in (self.dbg.DEC_TIMEOUT, self.dbg.DEC_ERROR, self.dbg.DEC_NOTASK):
                with self.subTest(op=op, event=event):
                    self.dbg.state = self.dbg.DSTATE_RUN if op == "suspend" else self.dbg.DSTATE_SUSP
                    self.dbg.events = [(event, self.dbg.DSTATE_RUN)]
                    result = self.call(op, timeout=1)
                    self.assertFalse(result["ok"])
                    self.assertEqual(result["event"], event)
                    self.assertIn("error", result)

    def test_positive_event_requires_expected_state(self):
        for op in ("start", "step", "stepover", "cont", "suspend"):
            with self.subTest(op=op):
                self.dbg.state = self.dbg.DSTATE_RUN if op == "suspend" else self.dbg.DSTATE_SUSP
                self.dbg.events = [(self.idd.PROCESS_STARTED, self.dbg.DSTATE_RUN)]
                result = self.call(op, timeout=1)
                self.assertFalse(result["ok"])
                self.assertEqual(result["state"], "running")

    def test_accepted_steps_wait_and_rejected_steps_do_not_wait(self):
        for op in ("step", "stepover"):
            with self.subTest(op=op):
                self.dbg.state = self.dbg.DSTATE_SUSP
                self.dbg.events = [(self.idd.STEP, self.dbg.DSTATE_SUSP)]
                result = self.call(op)
                self.assertTrue(result["ok"])
                self.assertEqual(result["eventName"], "step")
        self.dbg.accept = False
        self.dbg.waits.clear()
        result = self.call("step")
        self.assertFalse(result["ok"])
        self.assertEqual(self.dbg.waits, [])

    def test_running_process_cannot_step(self):
        self.dbg.state = self.dbg.DSTATE_RUN
        for op in ("step", "stepover"):
            self.assertFalse(self.call(op)["ok"])
        self.assertEqual(self.dbg.actions, [])

    def test_suspend_waits_for_real_pause(self):
        self.dbg.state = self.dbg.DSTATE_RUN
        self.dbg.events = [(self.idd.PROCESS_SUSPENDED, self.dbg.DSTATE_SUSP)]
        result = self.call("suspend")
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "suspended")
        self.assertEqual(len(self.dbg.waits), 1)

    def test_stop_waits_through_intermediate_events_for_no_task(self):
        self.dbg.events = [(self.idd.THREAD_EXITED, self.dbg.DSTATE_RUN),
                           (self.idd.PROCESS_EXITED, self.dbg.DSTATE_NOTASK)]
        result = self.call("stop", timeout=2)
        self.assertTrue(result["ok"])
        self.assertEqual(self.dbg.actions, ["stop"])
        self.assertEqual(result["state"], "no-task")
        self.assertEqual(result["eventName"], "process-exited")
        self.assertEqual(len(self.dbg.waits), 2)
        self.assertTrue(all(flags & self.dbg.WFNE_ANY for flags, _ in self.dbg.waits))

    def test_wait_exception_reports_failure(self):
        self.dbg.events = [(RuntimeError("fake wait failure"), self.dbg.DSTATE_RUN)]
        result = self.call("start")
        self.assertFalse(result["ok"])
        self.assertIn("fake wait failure", result["error"])

    def test_timeout_is_bounded_and_validated_before_execution(self):
        for value, expected in ((-1, 1), (0, 1), (999, 60)):
            with self.subTest(timeout=value):
                self.dbg.events = [(self.idd.BREAKPOINT, self.dbg.DSTATE_SUSP)]
                self.call("start", timeout=value)
                self.assertEqual(self.dbg.waits[-1][1], expected)
        self.dbg.actions.clear()
        with self.assertRaises((TypeError, ValueError)):
            self.call("start", timeout="not-a-number")
        self.assertEqual(self.dbg.actions, [])

    def test_exit_event_loop_obeys_total_deadline(self):
        self.dbg.events = [(self.idd.THREAD_EXITED, self.dbg.DSTATE_RUN)]
        with patch.object(worker.time, "monotonic", side_effect=[10, 10, 12]):
            result = self.call("stop", timeout=1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["eventName"], "timeout")
        self.assertEqual(len(self.dbg.waits), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
