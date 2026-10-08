# JPype 1.5.2 Windows Unicode bootstrap

Ghidra requires its own system classloader. JPype 1.5.2 rejects Unicode
classpath entries with a custom system classloader, and its Windows native
`getShared()` additionally obtains an ANSI module filename and passes it to a
UTF-8 Java string conversion. Paths containing Chinese characters can therefore
fail twice during JVM startup.

IG5 starts its single JVM from the bundled Python `pylib` directory using ASCII
relative JAR paths. During this synchronous call it temporarily changes
`jpype._core.__file__` to its relative name so the support JAR uses the same
relative path. Original CWD, metadata, classpath and Python import path are
restored after startup. JVM `user.dir` remains the package directory; subsequent
IG5 target/project operations use absolute paths.

The included `JPypeContext.java` change allows one fixed Windows extension
filename, guarded by an IG5-specific property. Java constructs its Unicode
absolute path from `user.dir`, avoiding the defective ANSI path supplied by the
native extension. No ASCII external directory, junction, 8.3 name, temporary
runtime copy or system PATH is needed. The property is supplied only by IG5's
relative bootstrap. Other upstream behavior is retained.

The upstream file is pinned to
`https://raw.githubusercontent.com/jpype-project/jpype/v1.5.2/native/java/org/jpype/JPypeContext.java`.
Its SHA-256 is `29d79d69c508d9c520c13e29dbbd0d987bab3a586e93aaab91785dec901fc0f7`.
The original JAR is from the pinned official JPype wheel recorded in runtime.json.
`upstream/` retains both original inputs. `unicode-bootstrap.patch` records the
source difference. Apache-2.0 LICENSE, upstream NOTICE and modification NOTICE
are retained alongside the runtime provenance.

To rebuild without downloading or using a system compiler:

```powershell
& .\scripts\patch_ghidra_jpype.ps1 -RuntimeRoot .\runtimes\ghidra
& .\scripts\seal_runtime_bundle.ps1
```

The script compiles the single source and its nested classes with the bundled
JDK (`--release 8`), replaces only those entries in a copy of the pinned support
JAR, fixes their ZIP timestamps, and records input/output hashes. Its temporary
build directory is retained for inspection. The startup workaround is pinned to
JPype 1.5.2; a future dependency upgrade requires revalidation rather than
silently assuming private implementation details remain compatible.
