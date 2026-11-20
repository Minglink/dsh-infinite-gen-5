#!/usr/bin/env python3
"""
IG5 Managed Android Frida Worker Daemon.

Operates strictly on an explicitly specified Android device serial and package name.
Supports:
- 'probe': check host frida module version and query Frida USB/remote device reachability & server parameters.
- 'session': spawn or attach to <package_name> on <device_serial>, load a bounded declarative Java/JNI hook
  script, stream structured JSONL events to stdout, and cleanly unload/detach on stdin 'STOP' or 'ABORT'.

Safety invariants:
- Never reboots the device, clears package data, or kills frida-server.
- Only terminates the target PID on stop if `spawned_by_ig5` is True AND `/proc/<pid>/stat` starttime matches.
"""

import json
import sys
import threading
import time


def build_declarative_frida_script(run_id, probe_specs):
    specs_json = json.dumps(probe_specs)
    return f"""
'use strict';
const RUN_ID = {json.dumps(run_id)};
const SPECS = {specs_json};
let seq = 0;

function emit(kind, payload) {{
  seq += 1;
  send(Object.assign({{ seq, runId: RUN_ID, kind, ts: Date.now() }}, payload));
}}

function bytesToHex(arr, maxLen) {{
  if (!arr) return null;
  const n = Math.min(arr.length || 0, maxLen || 1024);
  const out = [];
  for (let i = 0; i < n; i++) {{
    out.push(((arr[i] & 0xff) + 0x100).toString(16).slice(1));
  }}
  return out.join('');
}}

function readJByteArrayHex(envPtr, jarrPtr) {{
  try {{
    if (!envPtr || envPtr.isNull() || !jarrPtr || jarrPtr.isNull()) return null;
    const vtable = envPtr.readPointer();
    // JNIInvokeInterface / JNINativeInterface standard slots:
    // 171 = GetArrayLength, 184 = GetByteArrayElements, 192 = ReleaseByteArrayElements
    const getLenPtr = vtable.add(171 * Process.pointerSize).readPointer();
    const getElemsPtr = vtable.add(184 * Process.pointerSize).readPointer();
    const relElemsPtr = vtable.add(192 * Process.pointerSize).readPointer();
    const getLen = new NativeFunction(getLenPtr, 'int', ['pointer', 'pointer']);
    const getElems = new NativeFunction(getElemsPtr, 'pointer', ['pointer', 'pointer', 'pointer']);
    const relElems = new NativeFunction(relElemsPtr, 'void', ['pointer', 'pointer', 'pointer', 'int']);
    const len = getLen(envPtr, jarrPtr);
    if (len <= 0 || len > 4096) return null;
    const bufPtr = getElems(envPtr, jarrPtr, ptr(0));
    if (bufPtr.isNull()) return null;
    const raw = bufPtr.readByteArray(len);
    relElems(envPtr, jarrPtr, bufPtr, 2); // JNI_ABORT = 2 (read-only copy release)
    return Array.from(new Uint8Array(raw)).map(b => (b + 0x100).toString(16).slice(1)).join('');
  }} catch (e) {{
    return null;
  }}
}}

emit('probe-script-loaded', {{ arch: Process.arch, pointerSize: Process.pointerSize, pid: Process.id }});

for (const spec of SPECS) {{
  if (spec.layer === 'jni') {{
    const attachMod = (mod) => {{
      const symAddr = spec.offset
        ? mod.base.add(ptr(spec.offset))
        : mod.findExportByName(spec.symbol);
      if (!symAddr) {{
        emit('hook-miss', {{ layer: 'jni', library: spec.library, symbol: spec.symbol || spec.offset, reason: 'symbol-not-found' }});
        return;
      }}
      emit('module-bound', {{
        layer: 'jni',
        library: mod.name,
        modulePath: mod.path,
        moduleBase: mod.base.toString(),
        moduleSize: mod.size,
        targetAddress: symAddr.toString(),
      }});
      Interceptor.attach(symAddr, {{
        onEnter(args) {{
          this.envPtr = args[0];
          this.inHex = spec.argByteArrayIndex !== undefined
            ? readJByteArrayHex(args[0], args[spec.argByteArrayIndex])
            : null;
          this.arg0 = args[0] ? args[0].toString() : null;
          this.arg2 = args[2] ? args[2].toString() : null;
        }},
        onLeave(retval) {{
          const outHex = spec.returnIsByteArray
            ? readJByteArrayHex(this.envPtr, retval)
            : (retval ? retval.toString() : null);
          emit('hook-hit', {{
            layer: 'jni',
            library: mod.name,
            modulePath: mod.path,
            moduleBase: mod.base.toString(),
            symbol: spec.symbol || spec.offset,
            inputHex: this.inHex,
            outputHex: outHex,
            rawRetval: retval ? retval.toString() : null,
          }});
        }}
      }});
    }};
    const existing = Process.findModuleByName(spec.library);
    if (existing) attachMod(existing);
    else {{
      // Watch dlopen / android_dlopen_ext for deferred System.loadLibrary
      const dlopenExt = Module.findExportByName(null, 'android_dlopen_ext');
      if (dlopenExt) {{
        Interceptor.attach(dlopenExt, {{
          onEnter(args) {{ this.path = args[0].isNull() ? '' : args[0].readUtf8String(); }},
          onLeave() {{
            if (this.path && this.path.indexOf(spec.library) >= 0) {{
              const m = Process.findModuleByName(spec.library);
              if (m) attachMod(m);
            }}
          }}
        }});
      }}
    }}
  }}
}}

if (typeof Java !== 'undefined' && Java.available) {{
  Java.perform(() => {{
    for (const spec of SPECS) {{
      if (spec.layer !== 'java') continue;
      try {{
        const Cls = Java.use(spec.className);
        const overloads = Cls[spec.methodName].overloads;
        for (const ov of overloads) {{
          ov.implementation = function(...jargs) {{
            let inHex = null;
            if (jargs.length > 0 && jargs[0] !== null && jargs[0] !== undefined) {{
              if (typeof jargs[0] === 'string') {{
                inHex = Array.from(unescape(encodeURIComponent(jargs[0]))).map(c => (c.charCodeAt(0) + 0x100).toString(16).slice(1)).join('');
              }} else if (jargs[0].length !== undefined) {{
                inHex = bytesToHex(jargs[0], 1024);
              }}
            }}
            const ret = ov.apply(this, jargs);
            let outHex = null;
            if (ret !== null && ret !== undefined) {{
              if (typeof ret === 'string') {{
                outHex = Array.from(unescape(encodeURIComponent(ret))).map(c => (c.charCodeAt(0) + 0x100).toString(16).slice(1)).join('');
              }} else if (ret.length !== undefined) {{
                outHex = bytesToHex(ret, 1024);
              }}
            }}
            emit('hook-hit', {{
              layer: 'java',
              className: spec.className,
              methodName: spec.methodName,
              inputHex: inHex,
              outputHex: outHex,
            }});
            return ret;
          }};
        }}
        emit('java-hook-installed', {{ className: spec.className, methodName: spec.methodName, overloads: overloads.length }});
      }} catch (err) {{
        emit('hook-miss', {{ layer: 'java', className: spec.className, methodName: spec.methodName, reason: String(err) }});
      }}
    }}
  }});
}}
"""


def run_probe(cfg):
    try:
        import frida  # type: ignore
    except ImportError:
        print(json.dumps({"ok": False, "stage": "host-frida-import", "fridaInstalled": False}))
        return

    host_ver = getattr(frida, "__version__", "unknown")
    serial = cfg.get("deviceSerial")
    try:
        mgr = frida.get_device_manager()
        dev = mgr.get_device(serial, timeout=5) if serial else frida.get_usb_device(timeout=5)
        params = dev.query_system_parameters()
        server_ver = params.get("frida-version") or params.get("version") or None
        host_major = host_ver.split(".")[0]
        srv_major = str(server_ver).split(".")[0] if server_ver else None
        compatible = bool(server_ver is None or host_major == srv_major)
        print(json.dumps({
            "ok": True,
            "fridaInstalled": True,
            "hostFridaVersion": host_ver,
            "deviceId": dev.id,
            "deviceName": dev.name,
            "serverReachable": True,
            "serverVersion": server_ver,
            "versionCompatible": compatible,
            "systemParameters": {
                "arch": params.get("arch"),
                "os": params.get("os"),
                "platform": params.get("platform"),
            },
        }))
    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "fridaInstalled": True,
            "hostFridaVersion": host_ver,
            "serverReachable": False,
            "error": str(exc),
        }))


def run_session(cfg):
    try:
        import frida  # type: ignore
    except ImportError:
        print(json.dumps({"event": "error", "errorCode": "FRIDA_PYTHON_MISSING", "message": "Host frida Python module is not installed"}))
        sys.exit(1)

    serial = cfg["deviceSerial"]
    pkg = cfg["packageName"]
    mode = cfg.get("mode", "spawn")
    run_id = cfg["runId"]
    probe_specs = cfg.get("probeSpecs", [])
    timeout_ms = int(cfg.get("timeoutMs", 30000))

    stop_event = threading.Event()
    stop_reason = {"reason": "timeout"}

    def listen_stdin():
        try:
            for line in sys.stdin:
                cmd = line.strip().upper()
                if cmd in ("STOP", "ABORT"):
                    stop_reason["reason"] = "owner-stop" if cmd == "STOP" else "cancelled-abort"
                    stop_event.set()
                    break
        except Exception:
            stop_event.set()

    threading.Thread(target=listen_stdin, daemon=True).start()

    session = None
    script = None
    dev = None
    pid = None
    spawned = False

    try:
        dev = frida.get_device_manager().get_device(serial, timeout=8)
        if mode == "spawn":
            pid = dev.spawn([pkg])
            spawned = True
        else:
            pid = int(cfg["attachPid"])

        session = dev.attach(pid)

        def on_detached(reason, crash):
            sys.stdout.write(json.dumps({
                "event": "session-detached",
                "runId": run_id,
                "reason": str(reason),
                "crash": str(crash) if crash else None,
            }) + "\n")
            sys.stdout.flush()
            stop_reason["reason"] = f"detached:{reason}"
            stop_event.set()

        session.on("detached", on_detached)
        js_code = build_declarative_frida_script(run_id, probe_specs)
        script = session.create_script(js_code)

        def on_message(message, _data):
            if message.get("type") == "send":
                sys.stdout.write(json.dumps({"event": "hook-event", "payload": message.get("payload")}) + "\n")
            else:
                sys.stdout.write(json.dumps({"event": "script-error", "detail": message}) + "\n")
            sys.stdout.flush()

        script.on("message", on_message)
        script.load()
        if spawned:
            dev.resume(pid)

        sys.stdout.write(json.dumps({
            "event": "session-started",
            "runId": run_id,
            "deviceSerial": serial,
            "packageName": pkg,
            "pid": pid,
            "spawnedByIg5": spawned,
        }) + "\n")
        sys.stdout.flush()

        stop_event.wait(timeout=timeout_ms / 1000.0)
    except Exception as exc:
        sys.stdout.write(json.dumps({
            "event": "error",
            "errorCode": "FRIDA_SESSION_ERROR",
            "message": str(exc),
        }) + "\n")
        sys.stdout.flush()
    finally:
        script_unloaded = False
        session_detached = False
        killed_spawned = False
        if script is not None:
            try:
                script.unload()
                script_unloaded = True
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
                session_detached = True
            except Exception:
                pass
        if spawned and dev is not None and pid is not None:
            try:
                dev.kill(pid)
                killed_spawned = True
            except Exception:
                pass
        sys.stdout.write(json.dumps({
            "event": "session-stopped",
            "runId": run_id,
            "pid": pid,
            "stopReason": stop_reason["reason"],
            "scriptUnloaded": script_unloaded,
            "sessionDetached": session_detached,
            "killedSpawnedPid": killed_spawned,
        }) + "\n")
        sys.stdout.flush()


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "errorCode": "MISSING_CONFIG"}))
        sys.exit(2)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        cfg = json.load(f)
    op = cfg.get("op", "probe")
    if op == "probe":
        run_probe(cfg)
    elif op == "session":
        run_session(cfg)
    else:
        print(json.dumps({"ok": False, "errorCode": "UNKNOWN_OP", "op": op}))
        sys.exit(2)


if __name__ == "__main__":
    main()
