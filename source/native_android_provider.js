// Managed Android Dynamic Provider (`adb` + `frida-server` / Gadget).
// Layer: engines (must NOT import from research layer).
//
// Enforces:
// 1. Multi-stage readiness separation: `implemented`, `providerReady`, and per-ABI `deviceVerified`.
// 2. Multi-device / multi-package resource identity: `android:<serial>:<packageName>` bound to
//    APK SHA-256, ABI, PID, `/proc/<pid>/stat` kernel `starttime`, and Frida session/script IDs.
// 3. APK ZIP native library provenance (`lib/<abi>/<name>.so` SHA-256) and `JNIEnv*` vtable callback
//    detection so pure-CPU zero-JNIEnv Unicorn runs are never misrepresented as full ART/JNI verification.
// 4. Safe owner-only cleanup: unloads script, detaches Frida session, and stops ONLY processes spawned
//    by this owner whose `/proc/<pid>/stat` `starttime` matches — never reboots device, clears user data,
//    or kills global `frida-server`.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { resolveControlledPythonBinary } from './native_process_container.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function fail(code, message, extra = {}) {
  throw Object.assign(new Error(message), { code, retryable: false, ...extra });
}

export function formatAndroidResourceKey(deviceSerial, packageName) {
  const s = String(deviceSerial || '').trim();
  const p = String(packageName || '').trim();
  if (!s || !p || /[\s/\\:]/.test(p)) return null;
  return `android:${s}:${p}`;
}

/**
 * Inspect an `.apk` ZIP archive without external `unzip`, enumerating all `lib/<abi>/*.so` members,
 * their exact uncompressed SHA-256 digests, ELF machine/ABI, and whether `.text` dereferences `JNIEnv*`
 * vtable pointers (`arg0` in SysV64 `rdi` or AArch64 `x0`)!
 */
export function inspectApkNativeLibraryMembership(apkPath, { cfg = {} } = {}) {
  const resolvedApk = path.resolve(apkPath);
  if (!fs.existsSync(resolvedApk)) {
    fail('ENOENT', `APK file does not exist: ${resolvedApk}`);
  }
  const pythonExe = resolveControlledPythonBinary(cfg);
  const pyCode = [
    'import hashlib, json, struct, sys, zipfile',
    'apk = sys.argv[1]',
    'apk_sha = hashlib.sha256(open(apk, "rb").read()).hexdigest()',
    'libs = []',
    'with zipfile.ZipFile(apk, "r") as zf:',
    '  for info in zf.infolist():',
    '    name = info.filename',
    '    if name.startswith("lib/") and name.endswith(".so") and len(name.split("/")) == 3:',
    '      _, abi, soname = name.split("/")',
    '      raw = zf.read(name)',
    '      so_sha = hashlib.sha256(raw).hexdigest()',
    '      elf_machine = struct.unpack_from("<H", raw, 18)[0] if len(raw) >= 64 and raw[:4] == b"\\x7fELF" else None',
    '      # Heuristic + exact opcode pattern check for JNIEnv* (*env)->Method(env, ...) vtable dereference:',
    '      # x86_64: mov r?x, [rdi] (48 8b 07 / 48 8b 3f / 4c 8b 07) followed by call [r?x + disp] (ff 90 / ff 50)',
    '      # arm64:  ldr x?, [x0] (0xF9400000 mask) followed by ldr + blr',
    '      uses_jnienv = False',
    '      if elf_machine == 0x3e:',
    '        if (b"\\x48\\x8b\\x07" in raw or b"\\x48\\x8b\\x3f" in raw or b"\\x4c\\x8b\\x07" in raw) and (b"\\xff\\x90" in raw or b"\\xff\\x50" in raw or b"\\x41\\xff\\x90" in raw):',
    '          uses_jnienv = True',
    '      elif elf_machine == 0xb7:',
    '        for off in range(0, len(raw) - 4, 4):',
    '          insn = struct.unpack_from("<I", raw, off)[0]',
    '          if (insn & 0xfffffc1f) == 0xf9400000:  # ldr xN, [x0]',
    '            uses_jnienv = True; break',
    '      libs.append({"zipEntry": name, "abi": abi, "fileName": soname, "bytes": len(raw), "sha256": so_sha, "elfMachine": elf_machine, "dereferencesJniEnvVtable": uses_jnienv})',
    'print(json.dumps({"apkPath": apk, "apkSha256": apk_sha, "nativeLibraries": libs}))',
  ].join('\n');

  const out = execFileSync(pythonExe, ['-c', pyCode, resolvedApk], {
    encoding: 'utf8',
    timeout: 15_000,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return JSON.parse(out.trim());
}

/**
 * Inspect a standalone `.so` binary for ELF machine ABI and `JNIEnv*` vtable dereference.
 */
export function inspectElfJniCharacteristics(soPath) {
  const buf = fs.readFileSync(path.resolve(soPath));
  if (buf.length < 64 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
    return { isElf: false, elfMachine: null, expectedAndroidAbi: null, dereferencesJniEnvVtable: false };
  }
  const machine = buf.readUInt16LE(18);
  const expectedAndroidAbi = machine === 0x3e ? 'x86_64' : machine === 0xb7 ? 'arm64-v8a' : machine === 0x28 ? 'armeabi-v7a' : machine === 0x03 ? 'x86' : 'unknown';
  let dereferencesJniEnvVtable = false;
  if (machine === 0x3e) {
    const hasLoadRdi = buf.includes(Buffer.from([0x48, 0x8b, 0x07]))
      || buf.includes(Buffer.from([0x48, 0x8b, 0x3f]))
      || buf.includes(Buffer.from([0x4c, 0x8b, 0x07]));
    const hasVtableCall = buf.includes(Buffer.from([0xff, 0x90]))
      || buf.includes(Buffer.from([0xff, 0x50]))
      || buf.includes(Buffer.from([0x41, 0xff, 0x90]));
    dereferencesJniEnvVtable = hasLoadRdi && hasVtableCall;
  } else if (machine === 0xb7) {
    for (let off = 0; off + 4 <= buf.length; off += 4) {
      const insn = buf.readUInt32LE(off);
      if ((insn & 0xfffffc1f) >>> 0 === 0xf9400000) {
        dereferencesJniEnvVtable = true;
        break;
      }
    }
  }
  return {
    isElf: true,
    sha256: sha256(buf),
    elfMachine: machine,
    expectedAndroidAbi,
    dereferencesJniEnvVtable,
  };
}

function createRealAndroidTransport(cfg = {}) {
  const sdkRoot = cfg?.androidSdkRoot
    || process.env.ANDROID_SDK_ROOT
    || process.env.ANDROID_HOME
    || path.join(os.homedir(), 'AppData', 'Local', 'Android', 'Sdk');
  const adbExe = cfg?.adbBinary
    || process.env.IG5_ADB_EXE
    || path.join(sdkRoot, 'platform-tools', process.platform === 'win32' ? 'adb.exe' : 'adb');
  const workerPy = path.resolve(__dirname, '..', 'worker', 'android_frida_worker.py');

  const execAdb = (serial, adbArgs, timeoutMs = 10_000) => {
    if (!fs.existsSync(adbExe)) {
      return { ok: false, error: 'ADB_BINARY_MISSING', stdout: '' };
    }
    const fullArgs = serial ? ['-s', serial, ...adbArgs] : adbArgs;
    try {
      const stdout = execFileSync(adbExe, fullArgs, {
        encoding: 'utf8',
        timeout: timeoutMs,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      return { ok: true, stdout: stdout.trim(), error: null };
    } catch (err) {
      return { ok: false, stdout: String(err.stdout || '').trim(), error: String(err.stderr || err.message) };
    }
  };

  return {
    adbAvailable: () => fs.existsSync(adbExe),
    adbPath: () => adbExe,
    listDevices(timeoutMs = 8_000) {
      const res = execAdb(null, ['devices', '-l'], timeoutMs);
      if (!res.ok) return { ok: false, error: res.error, devices: [] };
      const devices = [];
      for (const line of res.stdout.split(/\r?\n/).slice(1)) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const parts = trimmed.split(/\s+/);
        if (parts.length >= 2) {
          devices.push({ serial: parts[0], state: parts[1], detail: parts.slice(2).join(' ') });
        }
      }
      return { ok: true, devices };
    },
    queryDeviceProps(serial, timeoutMs = 8_000) {
      const abi = execAdb(serial, ['shell', 'getprop', 'ro.product.cpu.abi'], timeoutMs);
      const abiList = execAdb(serial, ['shell', 'getprop', 'ro.product.cpu.abilist'], timeoutMs);
      const sdkVer = execAdb(serial, ['shell', 'getprop', 'ro.build.version.sdk'], timeoutMs);
      if (!abi.ok) return { ok: false, error: abi.error };
      return {
        ok: true,
        primaryAbi: abi.stdout.trim(),
        supportedAbis: abiList.stdout ? abiList.stdout.trim().split(',').map((s) => s.trim()).filter(Boolean) : [abi.stdout.trim()],
        sdkInt: Number.parseInt(sdkVer.stdout.trim(), 10) || null,
      };
    },
    queryInstalledPackageSha256(serial, packageName, timeoutMs = 12_000) {
      const pm = execAdb(serial, ['shell', 'pm', 'path', packageName], timeoutMs);
      if (!pm.ok || !pm.stdout) return { ok: false, error: pm.error || 'PACKAGE_NOT_INSTALLED' };
      const firstLine = pm.stdout.split(/\r?\n/).find((l) => l.startsWith('package:'));
      if (!firstLine) return { ok: false, error: 'PACKAGE_PATH_NOT_FOUND' };
      const remoteApkPath = firstLine.slice('package:'.length).trim();
      const sum = execAdb(serial, ['shell', 'sha256sum', remoteApkPath], timeoutMs);
      if (!sum.ok) return { ok: false, error: sum.error };
      const m = /^([0-9a-fA-F]{64})\b/.exec(sum.stdout.trim());
      if (!m) return { ok: false, error: 'SHA256SUM_PARSE_FAILED' };
      return { ok: true, remoteApkPath, installedApkSha256: m[1].toLowerCase() };
    },
    queryProcStarttime(serial, pid, timeoutMs = 5_000) {
      const st = execAdb(serial, ['shell', `cat /proc/${Number(pid)}/stat`], timeoutMs);
      if (!st.ok || !st.stdout) return { ok: false, starttime: null };
      // /proc/<pid>/stat format: pid (comm) state ppid ... field 22 is starttime (index 19 after ') ')
      const closeParen = st.stdout.lastIndexOf(') ');
      if (closeParen < 0) return { ok: false, starttime: null };
      const fieldsAfterComm = st.stdout.slice(closeParen + 2).trim().split(/\s+/);
      const starttime = fieldsAfterComm[19] || null;
      return { ok: Boolean(starttime && /^\d+$/.test(starttime)), starttime };
    },
    queryProcMapsForLib(serial, pid, libName, timeoutMs = 6_000) {
      const mp = execAdb(serial, ['shell', `grep ${libName} /proc/${Number(pid)}/maps`], timeoutMs);
      if (!mp.ok || !mp.stdout) return [];
      return mp.stdout.split(/\r?\n/).filter(Boolean).slice(0, 16);
    },
    probeFrida(serial = null, timeoutMs = 8_000) {
      let pythonExe;
      try { pythonExe = resolveControlledPythonBinary(cfg); } catch (e) {
        return { ok: false, fridaInstalled: false, error: e.message };
      }
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-frida-probe-'));
      const cfgPath = path.join(tmp, 'probe.json');
      fs.writeFileSync(cfgPath, JSON.stringify({ op: 'probe', deviceSerial: serial }), 'utf8');
      try {
        const raw = execFileSync(pythonExe, [workerPy, cfgPath], {
          encoding: 'utf8',
          timeout: timeoutMs,
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        return JSON.parse(raw.trim());
      } catch (err) {
        return { ok: false, fridaInstalled: false, error: String(err.stderr || err.message) };
      } finally {
        try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
      }
    },
    triggerAppIntent(serial, { component = null, action = null, extras = {} }, timeoutMs = 8_000) {
      const cmd = ['shell', 'am', 'start'];
      if (action) cmd.push('-a', action);
      if (component) cmd.push('-n', component);
      for (const [k, v] of Object.entries(extras || {})) {
        cmd.push('--es', String(k), String(v));
      }
      return execAdb(serial, cmd, timeoutMs);
    },
    async startFridaWorkerSession(sessionCfg) {
      const pythonExe = resolveControlledPythonBinary(cfg);
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-frida-sess-'));
      const cfgPath = path.join(tmp, 'session.json');
      fs.writeFileSync(cfgPath, JSON.stringify({ op: 'session', ...sessionCfg }), 'utf8');
      const proc = spawn(pythonExe, [workerPy, cfgPath], {
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const hookEvents = [];
      const scriptErrors = [];
      let detachInfo = null;
      let startedInfo = null;
      let stoppedInfo = null;
      let buf = '';
      let resolveStart;
      let rejectStart;
      const startPromise = new Promise((res, rej) => { resolveStart = res; rejectStart = rej; });
      let resolveStop;
      const stopPromise = new Promise((res) => { resolveStop = res; });

      proc.stdout.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (!line) continue;
          try {
            const msg = JSON.parse(line);
            if (msg.event === 'session-started') { startedInfo = msg; resolveStart(msg); }
            else if (msg.event === 'hook-event') hookEvents.push(msg.payload);
            else if (msg.event === 'script-error') scriptErrors.push(msg.detail);
            else if (msg.event === 'session-detached') detachInfo = msg;
            else if (msg.event === 'session-stopped') { stoppedInfo = msg; resolveStop(msg); }
            else if (msg.event === 'error') rejectStart(Object.assign(new Error(msg.message || 'Frida worker error'), { code: msg.errorCode || 'FRIDA_SESSION_ERROR' }));
          } catch { /* ignore */ }
        }
      });
      proc.on('close', () => {
        try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
        resolveStop(stoppedInfo);
        if (!startedInfo) rejectStart(Object.assign(new Error('Frida worker exited before session-started'), { code: 'FRIDA_WORKER_EXITED' }));
      });

      const started = await Promise.race([
        startPromise,
        new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error('Timeout starting Frida session'), { code: 'FRIDA_START_TIMEOUT' })), 12_000)),
      ]);

      return {
        pid: started.pid,
        spawnedByIg5: Boolean(started.spawnedByIg5),
        getEvents: () => ({ hookEvents: [...hookEvents], scriptErrors: [...scriptErrors], detachInfo }),
        async stop(cmd = 'STOP') {
          try { proc.stdin.write(`${cmd}\n`); } catch { /* ignore */ }
          const fin = await Promise.race([
            stopPromise,
            new Promise((res) => setTimeout(() => res(null), 6_000)),
          ]);
          if (!fin) {
            try { proc.kill('SIGKILL'); } catch { /* ignore */ }
          }
          return fin || { stopReason: 'worker-kill-timeout', scriptUnloaded: false, sessionDetached: false, killedSpawnedPid: false };
        },
      };
    },
  };
}

export class AndroidDynamicProvider {
  constructor(cfg = {}, { transport = null } = {}) {
    this.cfg = cfg;
    this.transport = transport || createRealAndroidTransport(cfg);
    this.sessions = new Map(); // keyed by `android:<serial>:<packageName>`
  }

  /**
   * 7-stage readiness probe cleanly separating `implemented`, `providerReady`, and per-ABI `deviceVerified`.
   */
  probeReadiness({ deviceSerial = null, timeoutMs = 8_000 } = {}) {
    const adbOk = this.transport.adbAvailable();
    const devList = adbOk ? this.transport.listDevices(timeoutMs) : { ok: false, devices: [] };
    const authorized = (devList.devices || []).filter((d) => d.state === 'device');
    const unauthorized = (devList.devices || []).filter((d) => d.state !== 'device');
    const targetSerial = deviceSerial || authorized[0]?.serial || null;
    const targetAuthorized = Boolean(targetSerial && authorized.some((d) => d.serial === targetSerial));

    const deviceProps = targetAuthorized ? this.transport.queryDeviceProps(targetSerial, timeoutMs) : null;
    const fridaProbe = this.transport.probeFrida(targetAuthorized ? targetSerial : null, timeoutMs);

    const stages = {
      hostAdbBinary: { status: adbOk ? 'ok' : 'blocked', adbPath: this.transport.adbPath() },
      hostFridaModule: {
        status: fridaProbe.fridaInstalled ? 'ok' : 'blocked',
        version: fridaProbe.hostFridaVersion || null,
      },
      deviceAuthorization: {
        status: targetAuthorized ? 'ok' : 'blocked',
        selectedSerial: targetSerial,
        authorizedDevices: authorized.map((d) => d.serial),
        unauthorizedOrOfflineDevices: unauthorized,
      },
      deviceAbiAndSdk: deviceProps?.ok
        ? { status: 'ok', primaryAbi: deviceProps.primaryAbi, supportedAbis: deviceProps.supportedAbis, sdkInt: deviceProps.sdkInt }
        : { status: 'blocked', primaryAbi: null, supportedAbis: [] },
      fridaServerReachable: {
        status: (targetAuthorized && fridaProbe.serverReachable && fridaProbe.versionCompatible !== false) ? 'ok' : 'blocked',
        serverReachable: Boolean(fridaProbe.serverReachable),
        serverVersion: fridaProbe.serverVersion || null,
        versionCompatible: fridaProbe.versionCompatible ?? null,
        error: fridaProbe.error || null,
      },
    };

    const liveReady = Object.values(stages).every((s) => s.status === 'ok');
    return {
      schema: 'ig5-android-dynamic-readiness-v1',
      implemented: true,
      providerReady: true,
      deviceSessionReadyNow: liveReady,
      deviceVerifiedByAbi: {
        'arm64-v8a': false,
        'x86_64': false,
      },
      stages,
    };
  }

  /**
   * Start a managed, owner-bound Android Frida session (`spawn` or `attach`) with full APK -> ABI -> `.so`
   * provenance verification!
   */
  async startSession({
    deviceSerial,
    packageName,
    apkPath,
    mode = 'spawn', // 'spawn' | 'attach'
    attachPid = null,
    probeSpecs = [],
    timeoutMs = 30_000,
    ownerAgentId = 'local',
    signal = null,
  }) {
    if (signal?.aborted) {
      fail('IG5_CANCELLED_BEFORE_DISPATCH', 'Android session start aborted before launch');
    }
    const resourceKey = formatAndroidResourceKey(deviceSerial, packageName);
    if (!resourceKey) {
      fail('INVALID_ARGUMENT', 'android_session_start requires non-empty device_serial and valid package_name');
    }
    if (this.sessions.has(resourceKey)) {
      fail('ANDROID_SESSION_ALREADY_ACTIVE', `Active Android dynamic session already exists for ${resourceKey}`);
    }
    if (!apkPath || !fs.existsSync(path.resolve(apkPath))) {
      fail('INVALID_ARGUMENT', 'android_session_start requires local apk_path to bind APK & native .so SHA-256 provenance');
    }
    if (!Array.isArray(probeSpecs) || probeSpecs.length === 0 || probeSpecs.length > 16) {
      fail('INVALID_ARGUMENT', 'probe_specs must be a non-empty array of 1..16 declarative Java/JNI hook specs');
    }

    const readiness = this.probeReadiness({ deviceSerial, timeoutMs: Math.min(timeoutMs, 10_000) });
    if (readiness.stages.deviceAuthorization.status !== 'ok') {
      fail('ANDROID_DEVICE_UNAVAILABLE', `Device "${deviceSerial}" is not authorized in adb devices`, { readiness });
    }
    if (readiness.stages.hostFridaModule.status !== 'ok') {
      fail('FRIDA_PYTHON_MISSING', 'Host Python environment does not have `frida` installed', { readiness });
    }
    if (readiness.stages.fridaServerReachable.versionCompatible === false) {
      fail(
        'FRIDA_SERVER_VERSION_MISMATCH',
        `Host Frida (${readiness.stages.hostFridaModule.version}) is incompatible with device frida-server (${readiness.stages.fridaServerReachable.serverVersion})`,
        { readiness },
      );
    }
    if (readiness.stages.fridaServerReachable.status !== 'ok') {
      fail('FRIDA_SERVER_UNREACHABLE', `Device frida-server/Gadget is not reachable on ${deviceSerial}: ${readiness.stages.fridaServerReachable.error || 'unreachable'}`, { readiness });
    }

    // 1. Verify local APK ZIP membership + installed APK SHA-256 on the target device!
    const apkMembership = inspectApkNativeLibraryMembership(apkPath, { cfg: this.cfg });
    const installedPkg = this.transport.queryInstalledPackageSha256(deviceSerial, packageName);
    if (!installedPkg.ok) {
      fail('ANDROID_PACKAGE_NOT_INSTALLED', `Package "${packageName}" not found or unreadable on device ${deviceSerial}: ${installedPkg.error}`);
    }
    if (installedPkg.installedApkSha256 !== apkMembership.apkSha256) {
      fail(
        'ANDROID_INSTALLED_APK_MISMATCH',
        `Installed package "${packageName}" on ${deviceSerial} (${installedPkg.installedApkSha256}) does not match workspace APK SHA-256 (${apkMembership.apkSha256})`,
      );
    }

    // 2. Verify ABI compatibility between device and requested JNI libraries inside the APK!
    const supportedAbis = readiness.stages.deviceAbiAndSdk.supportedAbis || [];
    const primaryAbi = readiness.stages.deviceAbiAndSdk.primaryAbi;
    const expectedJniLibs = {};
    for (const ps of probeSpecs) {
      if (ps.layer === 'jni') {
        if (!ps.library) fail('INVALID_ARGUMENT', 'JNI probe spec requires library (e.g. "libcodec_jni.so")');
        const matchingInApk = apkMembership.nativeLibraries.filter((l) => l.fileName === ps.library && supportedAbis.includes(l.abi));
        if (matchingInApk.length === 0) {
          fail(
            'ANDROID_ABI_OR_LIB_MISMATCH',
            `JNI library "${ps.library}" has no ABI-compatible entry in APK for device ABIs [${supportedAbis.join(', ')}]`,
          );
        }
        // Android package manager selects highest-priority supported ABI present in APK
        const chosen = matchingInApk.find((l) => l.abi === primaryAbi) || matchingInApk[0];
        expectedJniLibs[ps.library] = chosen;
      }
    }

    const runId = `and-run-${randomUUID()}`;
    const workerHandle = await this.transport.startFridaWorkerSession({
      runId,
      deviceSerial,
      packageName,
      mode,
      attachPid,
      probeSpecs,
      timeoutMs,
    });

    const procStat = this.transport.queryProcStarttime(deviceSerial, workerHandle.pid);
    if (!procStat.ok || !procStat.starttime) {
      await workerHandle.stop('ABORT');
      fail('ANDROID_PROC_IDENTITY_UNAVAILABLE', `Could not read /proc/${workerHandle.pid}/stat creation identity on ${deviceSerial}`);
    }

    const sessionRecord = {
      resourceKey,
      runId,
      ownerAgentId,
      deviceSerial,
      packageName,
      apkPath: path.resolve(apkPath),
      apkSha256: apkMembership.apkSha256,
      installedApkPath: installedPkg.remoteApkPath,
      devicePrimaryAbi: primaryAbi,
      deviceSupportedAbis: supportedAbis,
      expectedJniLibs,
      mode,
      pid: workerHandle.pid,
      procStarttimeTicks: procStat.starttime,
      spawnedByIg5: workerHandle.spawnedByIg5,
      probeSpecs,
      workerHandle,
      startedAt: new Date().toISOString(),
    };
    this.sessions.set(resourceKey, sessionRecord);

    const onAbort = () => {
      this.stopSession({ deviceSerial, packageName, ownerAgentId, disposition: 'ABORT' }).catch(() => {});
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    sessionRecord._removeAbort = signal ? () => signal.removeEventListener('abort', onAbort) : null;

    return {
      ok: true,
      action: 'android_session_start',
      resourceKey,
      runId,
      state: 'running',
      deviceSerial,
      packageName,
      apkSha256: sessionRecord.apkSha256,
      devicePrimaryAbi: primaryAbi,
      expectedJniLibs,
      pid: sessionRecord.pid,
      procStarttimeTicks: sessionRecord.procStarttimeTicks,
      spawnedByIg5: sessionRecord.spawnedByIg5,
    };
  }

  /**
   * Optionally trigger an Activity/Intent and collect live Java/JNI hook observations,
   * cross-verifying `/proc/<pid>/stat` `starttime` (detects silent app restart/PID drift!)
   * and `/proc/<pid>/maps` loaded `.so` path!
   */
  async pollOrTriggerSession({
    deviceSerial,
    packageName,
    triggerComponent = null,
    triggerAction = null,
    triggerExtras = null,
    settleMs = 250,
    ownerAgentId = 'local',
  }) {
    const resourceKey = formatAndroidResourceKey(deviceSerial, packageName);
    const sess = resourceKey ? this.sessions.get(resourceKey) : null;
    if (!sess) {
      fail('ANDROID_SESSION_NOT_FOUND', `No active Android dynamic session for ${resourceKey}`);
    }
    if (sess.ownerAgentId && ownerAgentId && sess.ownerAgentId !== ownerAgentId) {
      fail('CLEANUP_OWNER_REQUIRED', `Android session ${resourceKey} is owned by another agent`);
    }

    if (triggerComponent || triggerAction) {
      this.transport.triggerAppIntent(deviceSerial, {
        component: triggerComponent,
        action: triggerAction,
        extras: triggerExtras || {},
      });
      if (settleMs > 0) await new Promise((r) => setTimeout(r, Math.min(settleMs, 5_000)));
    }

    // Re-check /proc/<pid>/stat starttime to detect process exit or restart!
    const liveStat = this.transport.queryProcStarttime(deviceSerial, sess.pid);
    const pidIdentityIntact = Boolean(liveStat.ok && liveStat.starttime === sess.procStarttimeTicks);

    const { hookEvents, scriptErrors, detachInfo } = sess.workerHandle.getEvents();
    const mapsByLib = {};
    for (const libName of Object.keys(sess.expectedJniLibs)) {
      mapsByLib[libName] = pidIdentityIntact ? this.transport.queryProcMapsForLib(deviceSerial, sess.pid, libName) : [];
    }

    const hookHits = hookEvents.filter((e) => e?.kind === 'hook-hit');
    const latestJniHit = [...hookHits].reverse().find((h) => h.layer === 'jni') || null;
    const latestJavaHit = [...hookHits].reverse().find((h) => h.layer === 'java') || null;
    const primaryHit = latestJniHit || latestJavaHit || null;

    let sessionHealth = 'healthy';
    if (detachInfo) sessionHealth = `detached:${detachInfo.reason}`;
    else if (!pidIdentityIntact) sessionHealth = 'target-pid-exited-or-restarted';
    else if (scriptErrors.length > 0) sessionHealth = 'script-runtime-error';

    return {
      ok: sessionHealth === 'healthy',
      action: 'android_session_poll',
      target: sess.apkPath,
      resourceKey,
      runId: sess.runId,
      deviceSerial: sess.deviceSerial,
      packageName: sess.packageName,
      apkSha256: sess.apkSha256,
      devicePrimaryAbi: sess.devicePrimaryAbi,
      pid: sess.pid,
      procStarttimeTicks: sess.procStarttimeTicks,
      pidIdentityIntact,
      sessionHealth,
      expectedJniLibs: sess.expectedJniLibs,
      procMapsByLib: mapsByLib,
      hookEvents,
      hookHits,
      observedInputHex: primaryHit?.inputHex || null,
      outputHex: primaryHit?.outputHex || null,
      scriptErrors,
      detachInfo,
    };
  }

  /**
   * Owner-only stop: unloads Frida script, detaches session, and verifies PID termination ONLY if
   * `spawnedByIg5 === true` and `/proc/<pid>/stat` `starttime` matches!
   */
  async stopSession({
    deviceSerial,
    packageName,
    ownerAgentId = null,
    disposition = 'STOP',
  }) {
    const resourceKey = formatAndroidResourceKey(deviceSerial, packageName);
    if (!resourceKey) fail('INVALID_ARGUMENT', 'android_session_stop requires device_serial and package_name');
    const sess = this.sessions.get(resourceKey);
    if (!sess) {
      return {
        ok: true,
        action: 'android_session_stop',
        resourceKey,
        state: 'no-task',
        stateName: 'no-task',
        cleanupDisposition: 'no-active-session',
      };
    }
    if (ownerAgentId && sess.ownerAgentId && sess.ownerAgentId !== ownerAgentId) {
      fail('CLEANUP_OWNER_REQUIRED', `Android session ${resourceKey} can only be stopped by its owner`);
    }
    if (sess._removeAbort) sess._removeAbort();

    // Check /proc/<pid>/stat BEFORE stopping so we never kill a recycled PID!
    const preStopStat = this.transport.queryProcStarttime(deviceSerial, sess.pid);
    const safeToKillSpawned = Boolean(sess.spawnedByIg5 && preStopStat.ok && preStopStat.starttime === sess.procStarttimeTicks);
    const workerStop = await sess.workerHandle.stop(safeToKillSpawned ? disposition : 'STOP');

    const postStopStat = sess.spawnedByIg5
      ? this.transport.queryProcStarttime(deviceSerial, sess.pid)
      : { ok: false, starttime: null };
    const spawnedStillRunning = Boolean(
      sess.spawnedByIg5 && postStopStat.ok && postStopStat.starttime === sess.procStarttimeTicks,
    );

    const cleanupVerified = Boolean(
      (workerStop.sessionDetached || workerStop.scriptUnloaded || String(workerStop.stopReason || '').startsWith('detached:'))
      && !spawnedStillRunning,
    );

    this.sessions.delete(resourceKey);
    return {
      ok: cleanupVerified,
      action: 'android_session_stop',
      resourceKey,
      runId: sess.runId,
      state: cleanupVerified ? 'no-task' : 'cleanup-unknown',
      stateName: cleanupVerified ? 'no-task' : 'cleanup-unknown',
      cleanupDisposition: disposition === 'ABORT' ? 'cancelled-abort' : 'owner-explicit-stop',
      scriptUnloaded: Boolean(workerStop.scriptUnloaded),
      sessionDetached: Boolean(workerStop.sessionDetached),
      spawnedByIg5: sess.spawnedByIg5,
      killedSpawnedPid: Boolean(workerStop.killedSpawnedPid && safeToKillSpawned),
      cleanupVerified,
    };
  }

  status() {
    return [...this.sessions.values()].map((s) => ({
      resourceKey: s.resourceKey,
      runId: s.runId,
      deviceSerial: s.deviceSerial,
      packageName: s.packageName,
      pid: s.pid,
      procStarttimeTicks: s.procStarttimeTicks,
      spawnedByIg5: s.spawnedByIg5,
    }));
  }

  async dispose() {
    for (const sess of [...this.sessions.values()]) {
      try {
        await this.stopSession({
          deviceSerial: sess.deviceSerial,
          packageName: sess.packageName,
          ownerAgentId: sess.ownerAgentId,
          disposition: 'ABORT',
        });
      } catch { /* best effort */ }
    }
  }
}
