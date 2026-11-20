// Android / APK / DEX / JNI capability closure, DEX integrity verifier, owned-fixture repack/sign,
// and bounded ADB probe adapter.
// Capability dependency closure & benign symptom diagnostics adapted from apk-reverse (MIT License,
// Copyright (c) 2026 apk-reverse contributors), with IG5 fixes for explicit timeout enforcement,
// non-swallowed cleanup errors, and truthful blocked status when device/Frida is absent.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { resolveControlledPythonBinary } from './native_process_container.js';
import {
  AndroidDynamicProvider,
  formatAndroidResourceKey,
  inspectApkNativeLibraryMembership,
  inspectElfJniCharacteristics,
} from './native_android_provider.js';

export {
  AndroidDynamicProvider,
  formatAndroidResourceKey,
  inspectApkNativeLibraryMembership,
  inspectElfJniCharacteristics,
};

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function fail(code, message, extra = {}) {
  throw Object.assign(new Error(message), { code, retryable: false, ...extra });
}

/** Compute DEX Adler-32 checksum over bytes [12..end] per Dalvik DEX specification. */
export function computeDexAdler32(dexBuf, startOffset = 12) {
  const MOD_ADLER = 65521;
  let a = 1;
  let b = 0;
  for (let i = startOffset; i < dexBuf.length; i += 1) {
    a = (a + dexBuf[i]) % MOD_ADLER;
    b = (b + a) % MOD_ADLER;
  }
  return ((b << 16) | a) >>> 0;
}

/** Validate (and optionally repair on owned fixture buffer) DEX header magic, file_size, SHA-1, and Adler-32. */
export function verifyOrRepairDexIntegrity(dexBytes, { repair = false } = {}) {
  if (!Buffer.isBuffer(dexBytes) || dexBytes.length < 112) {
    return { valid: false, reason: 'dex-too-short' };
  }
  const buf = repair ? Buffer.from(dexBytes) : dexBytes;
  const magic = buf.subarray(0, 8).toString('latin1');
  if (!/^dex\n03[5-9]\0$/.test(magic)) {
    return { valid: false, reason: `invalid-dex-magic(${JSON.stringify(magic)})` };
  }
  const declaredFileSize = buf.readUInt32LE(32);
  if (repair && declaredFileSize !== buf.length) {
    buf.writeUInt32LE(buf.length >>> 0, 32);
  }
  const expectedSha1 = createHash('sha1').update(buf.subarray(32)).digest();
  const actualSha1 = Buffer.from(buf.subarray(12, 32));
  const sha1Match = actualSha1.equals(expectedSha1);
  if (repair && !sha1Match) {
    expectedSha1.copy(buf, 12);
  }
  // Adler-32 MUST be computed AFTER SHA-1 (bytes 12..31) is finalized!
  const expectedAdler = computeDexAdler32(buf, 12);
  const actualAdler = buf.readUInt32LE(8);
  const adlerMatch = actualAdler === expectedAdler;
  if (repair && !adlerMatch) {
    buf.writeUInt32LE(expectedAdler >>> 0, 8);
  }
  const sizeMatch = buf.readUInt32LE(32) === buf.length;
  const valid = sizeMatch && (repair || (sha1Match && adlerMatch));
  return {
    valid,
    repaired: Boolean(repair && (!sha1Match || !adlerMatch || declaredFileSize !== buf.length)),
    dexVersion: magic.slice(4, 7),
    fileSize: buf.length,
    adler32Hex: '0x' + buf.readUInt32LE(8).toString(16).padStart(8, '0'),
    sha1Hex: buf.subarray(12, 32).toString('hex'),
    ...(repair ? { buffer: buf, sha256: sha256(buf) } : {}),
  };
}

function resolveAndroidSdkPaths() {
  const sdkRoot = process.env.ANDROID_SDK_ROOT
    || process.env.ANDROID_HOME
    || path.join(os.homedir(), 'AppData', 'Local', 'Android', 'Sdk');
  let buildToolsDir = null;
  const btParent = path.join(sdkRoot, 'build-tools');
  if (fs.existsSync(btParent)) {
    const vers = fs.readdirSync(btParent).sort().reverse();
    if (vers.length > 0) buildToolsDir = path.join(btParent, vers[0]);
  }
  return {
    sdkRoot,
    adbExe: path.join(sdkRoot, 'platform-tools', process.platform === 'win32' ? 'adb.exe' : 'adb'),
    emulatorExe: path.join(sdkRoot, 'emulator', process.platform === 'win32' ? 'emulator.exe' : 'emulator'),
    buildToolsDir,
    aapt2Exe: buildToolsDir ? path.join(buildToolsDir, process.platform === 'win32' ? 'aapt2.exe' : 'aapt2') : null,
    zipalignExe: buildToolsDir ? path.join(buildToolsDir, process.platform === 'win32' ? 'zipalign.exe' : 'zipalign') : null,
    d8Jar: buildToolsDir ? path.join(buildToolsDir, 'lib', 'd8.jar') : null,
    apksignerJar: buildToolsDir ? path.join(buildToolsDir, 'lib', 'apksigner.jar') : null,
  };
}

function runBoundedCmd(exe, args, timeoutMs = 10_000) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 120_000) {
    fail('INVALID_TIMEOUT', `Android command timeoutMs (${timeoutMs}) must be 500..120000`);
  }
  try {
    const stdout = execFileSync(exe, args, {
      encoding: 'utf8',
      timeout: timeoutMs,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { ok: true, exitCode: 0, timedOut: false, stdout: stdout.trim(), error: null };
  } catch (err) {
    const timedOut = Boolean(err.killed || err.code === 'ETIMEDOUT');
    return {
      ok: false,
      exitCode: typeof err.status === 'number' ? err.status : -1,
      timedOut,
      stdout: String(err.stdout || '').trim(),
      stderr: String(err.stderr || '').trim(),
      error: err.message || String(err),
    };
  }
}

/**
 * Probe Android capability atoms and evaluate recursive `dependsOn` capability closure
 * without importing/executing Frida or launching emulators/targets.
 */
export function probeAndroidCapabilityClosure({ timeoutMs = 8_000, cfg = {} } = {}) {
  const sdk = resolveAndroidSdkPaths();
  let pythonBin = 'python';
  try { pythonBin = resolveControlledPythonBinary(cfg); } catch { /* fallback */ }
  const javaRes = runBoundedCmd('java', ['-version'], timeoutMs);
  const javacRes = runBoundedCmd('javac', ['-version'], timeoutMs);
  const keytoolRes = runBoundedCmd('keytool', ['-help'], timeoutMs);
  const pySpecRes = runBoundedCmd(pythonBin, [
    '-c',
    'import importlib.util, json; print(json.dumps({"frida": importlib.util.find_spec("frida") is not None}))',
  ], timeoutMs);
  let pyFridaPresent = false;
  if (pySpecRes.ok) {
    try { pyFridaPresent = Boolean(JSON.parse(pySpecRes.stdout).frida); } catch { pyFridaPresent = false; }
  }

  let adbPresent = Boolean(sdk.adbExe && fs.existsSync(sdk.adbExe));
  let authorizedDevices = [];
  let unauthorizedDevices = [];
  if (adbPresent) {
    const devRes = runBoundedCmd(sdk.adbExe, ['devices'], timeoutMs);
    if (devRes.ok) {
      for (const line of devRes.stdout.split(/\r?\n/).slice(1)) {
        const m = /^(\S+)\s+(\S+)$/.exec(line.trim());
        if (!m) continue;
        if (m[2] === 'device') authorizedDevices.push(m[1]);
        else unauthorizedDevices.push({ serial: m[1], state: m[2] });
      }
    } else {
      adbPresent = false;
    }
  }

  const atoms = {
    'tool:java': { ok: javaRes.ok || javaRes.exitCode === 0, detail: javaRes.stderr || javaRes.stdout },
    'tool:javac': { ok: javacRes.ok, detail: javacRes.stdout || javacRes.stderr },
    'tool:keytool': { ok: keytoolRes.ok || keytoolRes.exitCode === 0 },
    'tool:aapt2': { ok: Boolean(sdk.aapt2Exe && fs.existsSync(sdk.aapt2Exe)), path: sdk.aapt2Exe },
    'tool:zipalign': { ok: Boolean(sdk.zipalignExe && fs.existsSync(sdk.zipalignExe)), path: sdk.zipalignExe },
    'jar:d8': { ok: Boolean(sdk.d8Jar && fs.existsSync(sdk.d8Jar)), path: sdk.d8Jar },
    'jar:apksigner': { ok: Boolean(sdk.apksignerJar && fs.existsSync(sdk.apksignerJar)), path: sdk.apksignerJar },
    'tool:adb': { ok: adbPresent, path: sdk.adbExe },
    'device:adb-authorized': {
      ok: authorizedDevices.length > 0,
      authorizedDevices,
      unauthorizedDevices,
      nextAction: 'Connect an authorized Android device or booted AVD (`adb devices` showing `device`).',
    },
    'module:frida': {
      ok: pyFridaPresent,
      nextAction: 'Install matching host `frida` Python package and device `frida-server` in an authorized environment.',
    },
  };

  const capabilityDefs = [
    {
      id: 'android_static_apk_dex_jni',
      description: 'Static APK manifest/DEX/signature parsing + Ghidra/Unicorn JNI .so analysis',
      atoms: ['tool:java'],
      dependsOn: [],
    },
    {
      id: 'android_repack_unsigned',
      description: 'Owned-fixture DEX integrity repair + zipalign repackaging',
      atoms: ['tool:java', 'tool:zipalign', 'jar:d8'],
      dependsOn: ['android_static_apk_dex_jni'],
    },
    {
      id: 'android_repack_signed_fixture',
      description: 'Owned-fixture APK v2/v3 test-key signing and apksigner verification',
      atoms: ['tool:keytool', 'jar:apksigner'],
      dependsOn: ['android_repack_unsigned'],
    },
    {
      id: 'android_adb_device_session',
      description: 'Bounded ADB interaction with an authorized Android device/emulator',
      atoms: ['tool:adb', 'device:adb-authorized'],
      dependsOn: [],
    },
    {
      id: 'android_dynamic_frida_hook',
      description: 'Live Frida Java/JNI dynamic instrumentation on an authorized Android target',
      atoms: ['module:frida'],
      dependsOn: ['android_adb_device_session'],
    },
  ];

  const resolved = new Map();
  const evaluateCap = (id) => {
    if (resolved.has(id)) return resolved.get(id);
    const def = capabilityDefs.find((c) => c.id === id);
    const missingAtoms = def.atoms.filter((a) => !atoms[a]?.ok);
    const blockedDeps = [];
    for (const depId of def.dependsOn) {
      const depRes = evaluateCap(depId);
      if (depRes.status !== 'ok') {
        blockedDeps.push(depId);
        for (const ma of depRes.missingAtoms) {
          if (!missingAtoms.includes(ma)) missingAtoms.push(ma);
        }
      }
    }
    const entry = {
      id: def.id,
      description: def.description,
      status: missingAtoms.length === 0 && blockedDeps.length === 0 ? 'ok' : 'blocked',
      missingAtoms,
      blockedDependencies: blockedDeps,
    };
    resolved.set(id, entry);
    return entry;
  };

  for (const c of capabilityDefs) evaluateCap(c.id);
  return {
    schema: 'ig5-android-capability-closure-v1',
    probedAt: new Date().toISOString(),
    sdkPaths: sdk,
    atoms,
    capabilities: Object.fromEntries(resolved.entries()),
  };
}

/** Benign symptom diagnostic routing table for Android APK / JNI cross-layer investigations. */
export function diagnoseAndroidSymptom(symptomCode, context = {}) {
  const table = {
    JNI_SYMBOL_NOT_EXPORTED: {
      stopSignal: true,
      diagnosis: 'Java `native` method has no matching `Java_<pkg>_<cls>_<method>` export in `.dynsym`.',
      nextCheck: 'Inspect `JNI_OnLoad` in the `.so` via Ghidra (`ig5_decompile`) to locate `RegisterNatives` table registration.',
    },
    ABI_LIBRARY_MISMATCH: {
      stopSignal: true,
      diagnosis: 'APK ships multiple `lib/<abi>/` directories or lacks host-emulatable ABI.',
      nextCheck: 'Check `ig5_package(action="apk")` `nativeLibraries` list and bind exact `.so` SHA-256 per ABI before static/emulation handoff.',
    },
    DEX_CHECKSUM_INVALID_AFTER_EDIT: {
      stopSignal: true,
      diagnosis: 'Modified `classes.dex` fails ART `DexFileVerifier` if SHA-1 (`[12..32)`) is not updated BEFORE Adler-32 (`[8..12)`).',
      nextCheck: 'Run `verifyOrRepairDexIntegrity(dexBuf, { repair: true })` in strict SHA-1 -> Adler-32 order before `zipalign` + `apksigner`.',
    },
    DEVICE_OR_FRIDA_UNAVAILABLE: {
      stopSignal: true,
      diagnosis: 'Dynamic on-device hook requested while `device:adb-authorized` or `module:frida` is blocked.',
      nextCheck: 'Do NOT fabricate dynamic device receipts; use `ig5_emulate` for pure CPU-bound JNI functions and mark device-dependent acceptance `blocked`.',
    },
  };
  const entry = table[symptomCode] || {
    stopSignal: false,
    diagnosis: `Unclassified Android symptom: ${symptomCode}`,
    nextCheck: 'Run `probeAndroidCapabilityClosure` and inspect `ig5_package(action="apk")` static report.',
  };
  return { symptomCode, ...entry, context };
}

/**
 * Repack and test-sign an owned fixture APK in an isolated temporary directory,
 * explicitly tracking and returning any cleanup errors rather than swallowing them!
 */
export function repackAndSignOwnedFixtureApk({
  inputApkPath,
  outputApkPath,
  updatedClassesDex = null,
  timeoutMs = 30_000,
  cfg = {},
}) {
  const sdk = resolveAndroidSdkPaths();
  let pythonBin = 'python';
  try { pythonBin = resolveControlledPythonBinary(cfg); } catch { /* fallback */ }
  if (!sdk.zipalignExe || !fs.existsSync(sdk.zipalignExe) || !sdk.apksignerJar || !fs.existsSync(sdk.apksignerJar)) {
    fail('ANDROID_SIGN_TOOLS_MISSING', 'zipalign and apksigner.jar are required for owned-fixture repack/sign');
  }
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-apk-repack-'));
  const cleanupErrors = [];
  let dexIntegrity = null;
  try {
    const workingUnsigned = path.join(tmpDir, 'working_unsigned.apk');
    if (updatedClassesDex) {
      dexIntegrity = verifyOrRepairDexIntegrity(updatedClassesDex, { repair: true });
      if (!dexIntegrity.valid) fail('DEX_INTEGRITY_FAILED', `Invalid classes.dex: ${dexIntegrity.reason}`);
      const dexFile = path.join(tmpDir, 'classes.dex');
      fs.writeFileSync(dexFile, dexIntegrity.buffer);
      // Copy all entries from inputApkPath except META-INF/* signature files and classes.dex, then write updated classes.dex
      const pyRes = runBoundedCmd(pythonBin, [
        '-c',
        [
          'import sys, zipfile',
          'src, dst, new_dex = sys.argv[1], sys.argv[2], sys.argv[3]',
          'with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w") as zout:',
          '  for info in zin.infolist():',
          '    n = info.filename',
          '    if n == "classes.dex" or (n.startswith("META-INF/") and n.upper().endswith((".SF", ".RSA", ".DSA", ".EC", "MANIFEST.MF"))): continue',
          '    zout.writestr(info, zin.read(n))',
          '  zout.write(new_dex, "classes.dex", compress_type=zipfile.ZIP_DEFLATED)',
        ].join('\n'),
        path.resolve(inputApkPath),
        workingUnsigned,
        dexFile,
      ], timeoutMs);
      if (!pyRes.ok) fail('APK_REPACK_FAILED', `ZIP repack failed: ${pyRes.stderr || pyRes.error}`);
    } else {
      fs.copyFileSync(path.resolve(inputApkPath), workingUnsigned);
    }

    const alignedApk = path.join(tmpDir, 'aligned.apk');
    const alignRes = runBoundedCmd(sdk.zipalignExe, ['-f', '-p', '4', workingUnsigned, alignedApk], timeoutMs);
    if (!alignRes.ok) fail('ZIPALIGN_FAILED', `zipalign failed: ${alignRes.stderr || alignRes.error}`);

    const ksPath = path.join(tmpDir, 'disposable-test.keystore');
    const ktRes = runBoundedCmd('keytool', [
      '-genkeypair', '-keystore', ksPath, '-storepass', 'ig5repackpass', '-keypass', 'ig5repackpass',
      '-alias', 'ig5repack', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '365',
      '-dname', 'CN=IG5 Fixture Repack Test, OU=QA, O=IG5, L=Local, S=Local, C=US',
    ], timeoutMs);
    if (!ktRes.ok && !fs.existsSync(ksPath)) fail('KEYTOOL_FAILED', `keytool failed: ${ktRes.stderr || ktRes.error}`);

    fs.mkdirSync(path.dirname(path.resolve(outputApkPath)), { recursive: true });
    const signRes = runBoundedCmd('java', [
      '-jar', sdk.apksignerJar,
      'sign', '--ks', ksPath, '--ks-pass', 'pass:ig5repackpass', '--key-pass', 'pass:ig5repackpass',
      '--out', path.resolve(outputApkPath), alignedApk,
    ], timeoutMs);
    if (!signRes.ok) fail('APKSIGNER_SIGN_FAILED', `apksigner sign failed: ${signRes.stderr || signRes.error}`);

    const verifyRes = runBoundedCmd('java', ['-jar', sdk.apksignerJar, 'verify', '--verbose', path.resolve(outputApkPath)], timeoutMs);
    if (!verifyRes.ok) fail('APKSIGNER_VERIFY_FAILED', `apksigner verify failed: ${verifyRes.stderr || verifyRes.error}`);

    const outBytes = fs.readFileSync(path.resolve(outputApkPath));
    return {
      ok: true,
      outputApkPath: path.resolve(outputApkPath),
      outputSha256: sha256(outBytes),
      outputBytes: outBytes.length,
      signatureVerified: true,
      dexIntegrity,
      cleanupErrors,
    };
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (cleanupErr) {
      cleanupErrors.push({ path: tmpDir, code: cleanupErr.code || 'CLEANUP_ERROR', message: cleanupErr.message });
    }
  }
}
