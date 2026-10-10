# IG5 maintained x64dbg headless build

This build uses the exact `x64dbg-runtime` source inventory and its four fixed
gitlinks. `build-lock.json` records the upstream commit and source checksums.
The original upstream directory is never patched in place.

`scripts/build_x64dbg_core.ps1` verifies every upstream file, copies it into the
excluded development `.downloads/x64dbg-build/checkout` directory, and applies
`0001-headless-only.patch`. The patch removes Qt/GUI/test/launcher configure-time
dependencies from the generated CMake file and links the source-built TitanEngine
target. `0002-hardware-callback-replacement.patch` fixes a native callback race:
if the paused consumer replaces a hardware slot, the returning callback must not
temporarily delete that new slot and miss its first access. Original snapshots
are retained, and the before/after generated-PE regression exercises this case.
`0003-one-shot-pause-breakpoint.patch` makes the temporary pause breakpoint one-shot.
The pause callback already deletes this breakpoint; allowing the engine to
schedule software-breakpoint restoration afterward can consume a requested
single-step forever on a self-jump. `UE_SINGLESHOOT` uses the existing native
one-shot lifecycle and avoids that restoration without changing other software
breakpoints. Generated x86/x64 self-loop tests retain the failing baseline and
verify pause, step, step-over, repeated pause, and history-gap recovery afterward.
The mature disassembler and debugger algorithms otherwise remain upstream.

Build requirements: Windows x64, Visual Studio 2026 MSVC C++/Windows SDK, CMake,
Git, and the bundled Python. The build itself downloads nothing. MSVC/toolchain
installation is a development prerequisite, not a normal end-user requirement.

Run `scripts/build_x64dbg_core.ps1 -InstallBuiltRuntime` to build x86 and x64
`headless.exe`, debugger DLL, bridge DLL, TitanEngine, and `loaddll.exe` into the
source plugin's runtime. Then run `adapters/x64dbg/build_bridge.ps1` to build the
IG5 dp32/dp64 SDK extensions against the resulting import libraries.
Re-seal the runtime manifest before the product-wide install/package validation.

The generated `build-proof.json` records actual product SHA-256, architecture,
toolchain and patch identity. A copy is retained as runtime/source-build-proof.json.
The build still links the pinned upstream prebuilt dependency libraries listed
in the lock. It does not claim the GUI, every dependency, or mobile debugging was
built from source. All original upstream licenses and notices remain under
third_party/sources/x64dbg-runtime; deployed dependency licenses remain under
runtimes/x64dbg/licenses. IG5's own license does not replace them.
