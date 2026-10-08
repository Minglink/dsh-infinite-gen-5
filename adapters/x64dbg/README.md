# IG5 x64dbg adapter

Internal supervisor transport; all product actions pass through the host's approval and ownership checks.

The complete distribution already includes the pinned official debugger snapshot, embedded Python and IG5 dp32/dp64 bridge under the plugin's `runtimes/x64dbg`. Default `install.ps1` verifies and copies this pack offline; users do not run setup or depend on an external `.dsh/ig5/runtimes` folder. No compiler, pip, Qt development package or global Python is required in this native mode. `scripts/setup_x64dbg_runtime.ps1` is a maintainer asset-rebuild tool: it downloads and verifies pinned archives, copies the bridge, and keeps automate experiments disabled. Rebuilding the IG5 bridge requires MSVC and the pinned snapshot SDK; the supplemental `dbghelp` header comes from the explicitly selected source checkout passed as `HeaderRoot`.

`third_party/sources/x64dbg-runtime` contains the official runtime source commit `9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87` and its recursively pinned gitlinks. `x64dbg-development` separately preserves the desktop source archive; its original revision is unknown and its formerly empty submodules are explicitly supplemented from the pinned runtime tree. [Source provenance](../../third_party/sources/manifest.json) records archive/file hashes, submodule commits, materialized relative symlinks and missing build inputs. The bundled debugger is an official prebuilt snapshot plus the separately built IG5 bridge; it is not claimed to have been rebuilt from the desktop archive. Source vendoring does not imply every upstream feature is exposed or that all compiler/SDK/Qt and transitive prebuilt dependency sources form an offline rebuild environment.

Start `python/python.exe -I -B adapters/x64dbg/adapter.py`. `IG5_X64DBG_RUNTIME` may name a relocated runtime directory or its runtime.json. Config paths are relative to that JSON. The process announces `{ig5:"ready",engine:"x64dbg",capabilities:[...]}`. Every other stdout line is `{id,result}` or `{id,error}`; errors have code/message. stderr is diagnostic only. `doctor` and `open` do not start a debugger or execute the target. `dbg/load` starts an empty native headless host. `dbg/start` launches the registered PE under its architecture-matched debugger.

Supported operations: load, start, bpt, unbpt, regs, setreg, step, stepover, cont, suspend, readmem, writemem, stop, state, event, modules and trace. This set is also advertised by ready/doctor. The bridge itself accepts only typed launch/trace parameters, a fixed execution command set, typed register/memory/breakpoint requests, and a strict expression allowlist. Its single named pipe has a protected current-user SID DACL and rejects remote clients. It exposes no TCP listener. A local process running as the same Windows user remains within that user's trust boundary.

The supervisor polls the copied callback ring and actual debugger state together. A previously suspended state or accepted command alone cannot satisfy a new step/continue request. Stops return runId, stopSeq, debugger/target PID, thread ID and ASLR context: runtimeVA, moduleBase, RVA where the address lies inside the main image, and PE databaseBase. Exception stops add context.exception and the raw copied exception record. `ea` defaults to runtime VA; `rva` or addressSpace=database/rva explicitly converts addresses. setreg/writemem support expected-value rejection and verify readback. Memory access is limited to 4096 bytes per request. trace is native bounded instruction tracing, 1–10000 steps, with optional typed until address; it reports traceCounter and recording:false, and does not claim a recorded instruction artifact.

Timeouts and cancellation discard the owned session and close its kernel Job object. Killing the adapter also closes that Job and terminates its debugger/debuggee tree. No unrelated debugger processes are scanned or terminated. JSONL `cancel` is consumed on the reader thread while a bounded operation runs. Native GUI is a separate optional startup mode (`gui-hidden`); true headless mode uses headless.exe and cannot transform the existing process into a GUI session.

Validation commands (live tests explicitly execute only generated temporary PE files):

```powershell
& ".\runtimes\x64dbg\python\python.exe" -I -B scripts/test_x64dbg_adapter.py
& ".\runtimes\x64dbg\python\python.exe" -I -B scripts/test_x64dbg_native_security.py
node scripts/test_x64dbg_runtime.mjs
node scripts/test_x64dbg_runtime.mjs --x86
node scripts/test_x64dbg_cleanup.mjs
```

The live x64/x86 tests prove start, breakpoint, registers, memory write/readback and expected rejection, step/stepover, bounded trace, structured access violation, event/state/modules and stop. Security validation reads the actual pipe DACL and rejects untyped commands while no debuggee is active. Cleanup validation proves timeout/cancel/forced-adapter-exit terminate both owned PIDs. See licenses/NOTICE.txt before distributing the separate runtime. Automate client files/requirements retained from the investigated PoC are not runtime prerequisites and must not be enabled by default.
