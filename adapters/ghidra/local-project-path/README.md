Ghidra 12.1.4 rejects every local project directory containing a leading-dot
element through `ProjectLocator -> GhidraURL.checkLocalAbsolutePath ->
NamingUtilities.checkName`. Therefore the default `.dsh/ig5/projects` fails
before a project can be opened. No public ProjectLocator constructor bypasses
that validation.

The maintained patch changes the two local OS path call sites to a dedicated
helper. `.dsh` and other valid dot directories retain the upstream character
whitelist; dot/space-only segments (including `.` and `..`) are rejected.
The existing helper is unchanged for project names, internal project paths and
repository names/paths. The immutable third-party source tree is never edited.

Rebuild offline using `scripts/patch_ghidra_project_paths.ps1`. It compiles exactly
one Java class with the bundled JDK 21, verifies every other uncompressed ZIP
entry, keeps original JAR/ZIP backups under the selected artifact root, and
installs the patched class plus matching source in the source runtime. A repeat
build preserves the resulting JAR/ZIP hashes. The final package runtime manifest
must be resealed by the maintainer after the patch and regression checks pass.

Source and patch copies, the full Apache license, modification notice and
hash-based build proof are preserved at `runtimes/ghidra/licenses/ig5-local-project-path`.
The original full-build archive hash describes the original distribution, and
the additional patch proof describes the two modified runtime files.
The original runtime's authenticity comes from the authenticated release/full
source build and its sealed inventory. This patch checks a pinned source entry
and preservation of unrelated payloads; it does not authenticate the whole
original JAR independently. Once a patch proof exists, any JAR/source/class or
upstream/patched Java source and patch-file mismatch is rejected, including restoring the old source while changing
the JAR. A missing runtime.json patch field can be recovered only from the
independent proof after its actual contents pass those checks.

Run `node scripts/test_ghidra_project_paths.mjs` for real Java path validation
plus open, mutation, close, process restart, reopen and native decompilation in
the actual default hidden-directory layout. The test analyzes a generated PE
copy and does not execute it.
