// Pinned REA 6.4.0 static JS/Electron bridge + IG5 non-cooperative Electron & generic process-chain observer.
// Layer: engines (must NOT import from research layer).
//
// Key portability & trust invariants:
// 1. ZERO hardcoded developer Desktop paths: REA & Electron runtimes resolve strictly via explicit config,
//    controlled environment variables (`IG5_REA_ROOT`/`IG5_REA_CLI`, `IG5_ELECTRON_EXE`, `IG5_RUNTIME_ROOT`),
//    vendored runtime directories, or the target's own packaged executable.
// 2. Full REA distribution verification: checks `package.json`, `scripts/rea.mjs`, `dist/cli.js`,
//    `dist/cliCommandNames.js`, `dist/composition/javascriptAnalysisWorkerProcess.js`, `release-manifest.json`
//    entries for `dist/*javascriptApplication*`, and critical runtime dependency versions.
// 3. Strict separation of untrusted `applicationReported` stdout/JSON from kernel-verified
//    `verifiedProcessLineage` (Win32 Job Object + GetProcessTimes + QueryFullProcessImageNameW) and
//    framed observer boundary logs.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  queryWin32ProcessLineageStrict,
  collectVerifiedOwnedProcessTree,
  terminateVerifiedOwnedProcessesStrict,
  runInWin32JobContainer,
  startHeldWin32JobContainer,
} from './native_process_container.js';
import { analyzeJsApplicationBuiltin } from './native_js_static.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const PINNED_REA_MJS_SHA256 = '3554288a08c455fa419dad662d73710fb17debe94b9e71dd1282761117c5981e';
export const PINNED_REA_FILES = Object.freeze({
  'package.json': 'faafbb7a9a4a340ec9b91a5acf79567fd537401dc8d98da9b0ea6d26a9853ca1',
  'scripts/rea.mjs': PINNED_REA_MJS_SHA256,
  'dist/cli.js': 'de0b36933b83e904a3689b367f5a047898f73bc9cc118ff58cf50ce7adfd443e',
  'dist/cliCommandNames.js': '2904d9aeee7b669bf0c9aa2d8a54698b2f5d172901242bd3d024afb50e374c10',
  'dist/composition/javascriptAnalysisWorkerProcess.js': '53140aa10c4c8d30eb2e1a68504569907d7ad740253e3cf37c200773cce51848',
});
export const PINNED_REA_RELEASE_MANIFEST_SHA256 = '564b1ac6e260bf81a7d2ef8743fdb9352a99d97991e8b0b8cc0f45bae96ac678';
export const PINNED_REA_DEPENDENCIES = Object.freeze({
  '@babel/parser': '8.0.4',
  '@babel/types': '8.0.4',
  '@electron/asar': '4.2.0',
  'incur': '0.6.1',
  'parse5': '8.0.1',
  'zod': '4.4.3',
});

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function fail(code, message, extra = {}) {
  throw Object.assign(new Error(message), { code, retryable: false, ...extra });
}

/**
 * Verify complete REA 6.4.0 package root: entry wrapper, `package.json`, core `dist/` modules,
 * `release-manifest.json` JS analyzer entries, and critical dependency versions.
 */
export function verifyReaDistributionIntegrity(reaRoot) {
  const root = path.resolve(reaRoot);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    fail('REA_CLI_UNAVAILABLE', `REA distribution directory does not exist: ${root}`, {
      missingAtom: 'runtime:rea-agents@6.4.0',
    });
  }

  const verifiedFiles = {};
  for (const [relPath, expectedSha] of Object.entries(PINNED_REA_FILES)) {
    const full = path.join(root, relPath);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) {
      fail('REA_DIST_INCOMPLETE', `REA distribution at ${root} is missing required file "${relPath}"`, {
        missingFile: relPath,
      });
    }
    const actualSha = sha256(fs.readFileSync(full));
    if (actualSha !== expectedSha) {
      fail('REA_PIN_MISMATCH', `REA file "${relPath}" SHA-256 mismatch at ${full}: expected ${expectedSha}, got ${actualSha}`, {
        file: relPath,
        expectedSha256: expectedSha,
        actualSha256: actualSha,
      });
    }
    verifiedFiles[relPath] = actualSha;
  }

  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  if (pkg.name !== 'rea-agents' || pkg.version !== '6.4.0') {
    fail('REA_VERSION_MISMATCH', `Expected rea-agents@6.4.0, got ${pkg.name}@${pkg.version}`);
  }

  // Verify release-manifest.json and all dist/*javascript* modules it indexes when present
  const relManifestPath = path.join(root, 'release-manifest.json');
  let manifestCheckedCount = 0;
  if (fs.existsSync(relManifestPath)) {
    const manifestBytes = fs.readFileSync(relManifestPath);
    const actualManifestSha = sha256(manifestBytes);
    if (actualManifestSha !== PINNED_REA_RELEASE_MANIFEST_SHA256) {
      fail('REA_PIN_MISMATCH', `REA release-manifest.json SHA-256 mismatch: expected ${PINNED_REA_RELEASE_MANIFEST_SHA256}, got ${actualManifestSha}`);
    }
    const relManifest = JSON.parse(manifestBytes.toString('utf8'));
    for (const entry of relManifest.files || []) {
      if (typeof entry.path === 'string' && entry.path.startsWith('dist/') && /javascript|cli/i.test(entry.path)) {
        const fp = path.join(root, entry.path);
        if (!fs.existsSync(fp)) {
          fail('REA_DIST_INCOMPLETE', `REA dist module missing from disk: ${entry.path}`);
        }
        const fSha = sha256(fs.readFileSync(fp));
        if (fSha !== entry.sha256) {
          fail('REA_PIN_MISMATCH', `REA dist module "${entry.path}" SHA-256 mismatch against release-manifest.json`);
        }
        manifestCheckedCount += 1;
      }
    }
  }

  // Verify pinned runtime dependencies in node_modules
  const verifiedDependencies = {};
  for (const [depName, expectedVersion] of Object.entries(PINNED_REA_DEPENDENCIES)) {
    const depPkgPath = path.join(root, 'node_modules', ...depName.split('/'), 'package.json');
    if (!fs.existsSync(depPkgPath)) {
      fail('REA_DEPENDENCY_MISSING', `REA runtime dependency "${depName}@${expectedVersion}" is missing under ${root}/node_modules`, {
        dependency: depName,
        expectedVersion,
      });
    }
    const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf8'));
    if (depPkg.version !== expectedVersion) {
      fail('REA_DEPENDENCY_MISMATCH', `REA dependency "${depName}" version mismatch: expected ${expectedVersion}, got ${depPkg.version}`, {
        dependency: depName,
        expectedVersion,
        actualVersion: depPkg.version,
      });
    }
    verifiedDependencies[depName] = depPkg.version;
  }

  return {
    root,
    path: path.join(root, 'scripts', 'rea.mjs'),
    sha256: verifiedFiles['scripts/rea.mjs'],
    version: '6.4.0',
    verifiedFilesCount: Object.keys(verifiedFiles).length + manifestCheckedCount,
    verifiedDependencies,
  };
}

/**
 * Controlled REA CLI discovery with ZERO hardcoded author Desktop paths.
 */
export function resolveReaCliPath(pluginRoot = path.resolve(__dirname, '..'), cfg = {}) {
  const runtimeRoot = cfg?.runtimeRoot || process.env.IG5_RUNTIME_ROOT || null;
  if (process.env.IG5_REA_CLI || cfg?.reaCli) {
    const cliFile = path.resolve(cfg?.reaCli || process.env.IG5_REA_CLI);
    if (!fs.existsSync(cliFile) || !fs.statSync(cliFile).isFile()) {
      fail('REA_CLI_UNAVAILABLE', `Configured IG5_REA_CLI does not exist: ${cliFile}`, {
        missingAtom: 'runtime:rea-agents@6.4.0',
      });
    }
    const actualSha = sha256(fs.readFileSync(cliFile));
    if (actualSha !== PINNED_REA_MJS_SHA256) {
      fail('REA_PIN_MISMATCH', `REA CLI SHA-256 mismatch at ${cliFile}: expected ${PINNED_REA_MJS_SHA256}, got ${actualSha}`);
    }
    const candidateRoot = path.basename(path.dirname(cliFile)) === 'scripts'
      ? path.resolve(path.dirname(cliFile), '..')
      : path.dirname(cliFile);
    return verifyReaDistributionIntegrity(candidateRoot);
  }

  const candidateRoots = [
    cfg?.reaRoot,
    process.env.IG5_REA_ROOT,
    runtimeRoot ? path.join(runtimeRoot, 'rea-agents') : null,
    path.join(pluginRoot, 'vendor', 'rea-agents'),
    path.join(pluginRoot, 'vendor', 'rea'),
  ].filter(Boolean);

  for (const candidateRoot of candidateRoots) {
    const resolved = path.resolve(candidateRoot);
    if (fs.existsSync(path.join(resolved, 'scripts', 'rea.mjs')) && fs.existsSync(path.join(resolved, 'dist', 'cli.js'))) {
      return verifyReaDistributionIntegrity(resolved);
    }
  }

  fail(
    'REA_CLI_UNAVAILABLE',
    'Verified rea-agents@6.4.0 runtime is not configured. Set IG5_REA_ROOT (or config.reaRoot / runtimes/rea-agents) to an intact rea-agents@6.4.0 directory.',
    {
      missingAtom: 'runtime:rea-agents@6.4.0',
      checkedLocations: candidateRoots.map((p) => path.resolve(p)),
    },
  );
}

/**
 * Controlled Electron launch resolution:
 * 1. If target is a packaged Electron `.exe` or packaged directory containing `<App>.exe` + `resources/app(.asar)`,
 *    prefer the target's own packaged executable!
 * 2. Otherwise, use explicit `electronExe` / `cfg.electronBinary` / `IG5_ELECTRON_EXE` / `<IG5_RUNTIME_ROOT>/electron/electron.exe`.
 * 3. Never fall back to hardcoded developer Desktop paths.
 */
export function resolveElectronLaunchTarget(targetPath, { explicitElectronExe = null, cfg = {} } = {}) {
  const resolvedTarget = path.resolve(targetPath);
  if (!fs.existsSync(resolvedTarget)) {
    fail('ENOENT', `Electron target does not exist: ${resolvedTarget}`);
  }

  if (fs.statSync(resolvedTarget).isFile() && resolvedTarget.toLowerCase().endsWith('.exe')) {
    return {
      executable: resolvedTarget,
      launchArgs: [],
      appWorkingDir: path.dirname(resolvedTarget),
      runtimeSelection: 'target-packaged-executable',
    };
  }

  if (fs.statSync(resolvedTarget).isDirectory()) {
    const resourcesDir = path.join(resolvedTarget, 'resources');
    const hasPackagedResources = fs.existsSync(path.join(resourcesDir, 'app.asar'))
      || fs.existsSync(path.join(resourcesDir, 'app'));
    if (hasPackagedResources && !explicitElectronExe) {
      const topExes = fs.readdirSync(resolvedTarget)
        .filter((f) => f.toLowerCase().endsWith('.exe') && !/^(?:uninstall|crashpad|squirrel|update)/i.test(f));
      if (topExes.length === 1) {
        const packagedExe = path.join(resolvedTarget, topExes[0]);
        return {
          executable: packagedExe,
          launchArgs: [],
          appWorkingDir: resolvedTarget,
          runtimeSelection: 'target-packaged-executable',
        };
      }
    }
  }

  const pluginRoot = cfg?.pluginRoot || path.resolve(__dirname, '..');
  const runtimeRoot = cfg?.runtimeRoot || process.env.IG5_RUNTIME_ROOT || path.join(pluginRoot, 'runtimes');
  const electronCandidates = [
    explicitElectronExe,
    cfg?.electronBinary,
    process.env.IG5_ELECTRON_EXE,
    runtimeRoot ? path.join(runtimeRoot, 'electron', process.platform === 'win32' ? 'electron.exe' : 'electron') : null,
  ].filter(Boolean);

  for (const c of electronCandidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) {
      return {
        executable: path.resolve(c),
        launchArgs: [resolvedTarget],
        appWorkingDir: fs.statSync(resolvedTarget).isDirectory() ? resolvedTarget : path.dirname(resolvedTarget),
        runtimeSelection: 'configured-electron-host',
      };
    }
  }

  fail(
    'ELECTRON_RUNTIME_UNAVAILABLE',
    'Unpackaged Electron directory requires an explicit Electron runtime (`IG5_ELECTRON_EXE`, `config.electronBinary`, or `runtimes/electron/electron.exe`), or pass a packaged Electron application with its own `.exe` entry.',
    {
      missingAtom: 'runtime:electron',
      target: resolvedTarget,
    },
  );
}

/** Backwards-compatible helper returning configured host Electron binary or null. */
export function resolveElectronBinary(cfg = {}) {
  try {
    const pluginRoot = cfg?.pluginRoot || path.resolve(__dirname, '..');
    const runtimeRoot = cfg?.runtimeRoot || process.env.IG5_RUNTIME_ROOT || path.join(pluginRoot, 'runtimes');
    for (const c of [cfg?.electronBinary, process.env.IG5_ELECTRON_EXE, runtimeRoot ? path.join(runtimeRoot, 'electron', 'electron.exe') : null].filter(Boolean)) {
      if (fs.existsSync(c) && fs.statSync(c).isFile()) return path.resolve(c);
    }
  } catch { /* ignore */ }
  return null;
}

/** Static, non-executing JS / Electron application graph reconstruction via verified rea-agents@6.4.0 or built-in static fallback. */
export function analyzeJsApplicationStatic(appPath, { pluginRoot, cfg = {}, timeoutMs = 45_000, signal, requireExternalRea = false } = {}) {
  const resolvedApp = path.resolve(appPath);
  if (!fs.existsSync(resolvedApp)) {
    fail('ENOENT', `JS/Electron application path does not exist: ${resolvedApp}`);
  }
  const hasExplicitExternalRea = Boolean(
    cfg?.reaCli || process.env.IG5_REA_CLI || cfg?.reaRoot || process.env.IG5_REA_ROOT,
  );
  let rea = null;
  try {
    rea = resolveReaCliPath(pluginRoot || cfg?.pluginRoot, cfg);
  } catch (err) {
    if (err?.code === 'REA_CLI_UNAVAILABLE' && !hasExplicitExternalRea && !requireExternalRea) {
      return analyzeJsApplicationBuiltin(resolvedApp, { timeoutMs, signal });
    }
    throw err;
  }
  let rawOut;
  try {
    rawOut = execFileSync(process.execPath, [rea.path, 'analyze-javascript-application', resolvedApp, '--format', 'json'], {
      encoding: 'utf8',
      timeout: timeoutMs,
      maxBuffer: 32 * 1024 * 1024,
      windowsHide: true,
      signal,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    fail('REA_STATIC_ANALYSIS_FAILED', `REA static JS/Electron analysis failed: ${err.stderr || err.message}`);
  }

  const lines = rawOut.trim().split(/\r?\n/).filter(Boolean);
  let parsed = null;
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    try {
      const candidate = JSON.parse(lines[i]);
      if (candidate && !candidate.rea_progress) {
        parsed = candidate;
        break;
      }
    } catch { /* fallback below */ }
  }
  if (!parsed) {
    const firstBrace = rawOut.indexOf('{\n');
    parsed = JSON.parse(firstBrace >= 0 ? rawOut.slice(firstBrace) : rawOut);
  }

  const nativeArtifacts = [];
  if (fs.statSync(resolvedApp).isDirectory()) {
    const walk = (dir, depth = 0) => {
      if (depth > 4) return;
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        if (ent.name === 'node_modules' || ent.name === '.git') continue;
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) walk(full, depth + 1);
        else if (ent.isFile() && /\.(?:exe|dll|so|node)$/i.test(ent.name)) {
          const b = fs.readFileSync(full);
          nativeArtifacts.push({
            relativePath: path.relative(resolvedApp, full).replaceAll('\\', '/'),
            absolutePath: full,
            bytes: b.length,
            sha256: sha256(b),
          });
        }
      }
    };
    walk(resolvedApp);
  }

  return {
    schema: 'ig5-js-app-static-report-v2',
    executionPerformed: false,
    reaEngine: {
      version: rea.version,
      cliSha256: rea.sha256,
      verifiedFilesCount: rea.verifiedFilesCount,
      verifiedDependencies: rea.verifiedDependencies,
    },
    targetAppPath: resolvedApp,
    nativeArtifacts,
    reaAnalysis: parsed,
  };
}

// Re-export fail-closed ownership helpers for unit tests and legacy callers
export {
  queryWin32ProcessLineageStrict,
  collectVerifiedOwnedProcessTree,
  terminateVerifiedOwnedProcessesStrict,
};

export function collectOwnedProcessTree(enumOrList, rootPid, rootCreationTicks = null) {
  const wrapped = Array.isArray(enumOrList)
    ? { status: 'ok', processes: enumOrList }
    : enumOrList;
  return collectVerifiedOwnedProcessTree(wrapped, rootPid, rootCreationTicks);
}

export function terminateVerifiedOwnedProcesses(ownedRecords, opts = {}) {
  return terminateVerifiedOwnedProcessesStrict(ownedRecords, opts);
}

/**
 * Parse and strictly verify framed JSONL observer boundary log (`observer-log-open` .. `observer-log-close`,
 * monotonic `seq`, matching `runId`). Missing, truncated, or corrupt logs NEVER degrade to `[]`!
 */
export function parseFramedObserverLog(logPath, expectedRunId) {
  if (!logPath || !fs.existsSync(logPath)) {
    return { integrity: 'missing', events: [], reason: 'observer-log-file-missing' };
  }
  let raw;
  try {
    raw = fs.readFileSync(logPath, 'utf8');
  } catch (err) {
    return { integrity: 'corrupt', events: [], reason: `observer-log-unreadable:${err.code || err.message}` };
  }
  if (!raw.trim()) {
    return { integrity: 'missing', events: [], reason: 'observer-log-empty' };
  }
  const rawLines = raw.split(/\r?\n/);
  // If non-empty file does not end with newline, last record was truncated mid-write
  if (!raw.endsWith('\n')) {
    return { integrity: 'truncated', events: [], reason: 'observer-log-missing-trailing-newline' };
  }
  const events = [];
  let expectedSeq = 1;
  for (const line of rawLines) {
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      return { integrity: 'corrupt', events, reason: `observer-log-invalid-json-at-seq-${expectedSeq}` };
    }
    if (parsed.runId !== expectedRunId) {
      return { integrity: 'corrupt', events, reason: `observer-log-run-id-mismatch(expected=${expectedRunId},actual=${parsed.runId})` };
    }
    if (parsed.seq !== expectedSeq) {
      return { integrity: 'truncated', events, reason: `observer-log-seq-gap(expected=${expectedSeq},actual=${parsed.seq})` };
    }
    expectedSeq += 1;
    events.push(parsed);
  }
  if (events.length === 0 || events[0].kind !== 'observer-log-open') {
    return { integrity: 'corrupt', events, reason: 'observer-log-missing-open-header' };
  }
  if (events.at(-1).kind !== 'observer-log-close') {
    return { integrity: 'truncated', events, reason: 'observer-log-missing-close-footer' };
  }
  return { integrity: 'verified', events, reason: null };
}

/**
 * Write IG5's documented preload instrumentation (`NODE_OPTIONS=--require ...`) supporting:
 * 1. Non-cooperative `discover` mode (enumerates real BrowserWindow titles/URLs, DOM controls, ipcMain channels).
 * 2. Non-cooperative `execute` mode with real Chromium BrowserWindow DOM interaction (`ui-click`: fill/select/click/read-dom
 *    with boundingRect + DOM mutation witness) OR discovered `ipc-invoke` channel invocation.
 * 3. `child_process` (`spawn`, `spawnSync`, `execFile`, `execFileSync`, `fork`) and `fs` cache/output boundary hooks.
 * 4. Framed JSONL log (`observer-log-open` .. `observer-log-close` with monotonic `seq`).
 */
function writeGenericElectronObserverScript(hookPath) {
  const code = `'use strict';
if (process.argv.some((a) => String(a).startsWith('--type=')) || (process.type && process.type !== 'browser')) return;
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const Module = require('node:module');

const planPath = process.env.IG5_OBSERVER_PLAN_FILE;
if (!planPath || !fs.existsSync(planPath)) return;
const plan = JSON.parse(fs.readFileSync(planPath, 'utf8'));
// Prevent child processes from inheriting observer plan or re-running this preload!
delete process.env.IG5_OBSERVER_PLAN_FILE;
if (process.env.NODE_OPTIONS && plan.hookMarker) {
  const cleaned = process.env.NODE_OPTIONS.replace(plan.hookMarker, '').trim();
  if (cleaned) process.env.NODE_OPTIONS = cleaned;
  else delete process.env.NODE_OPTIONS;
}
const logFile = plan.logPath;
const runId = plan.runId;

let seq = 0;
let closedLog = false;
function appendFramed(ev) {
  if (!logFile || closedLog) return;
  seq += 1;
  try {
    fs.appendFileSync(logFile, JSON.stringify({
      seq,
      ts: new Date().toISOString(),
      observerPid: process.pid,
      runId,
      ...ev,
    }) + '\\n', 'utf8');
  } catch {}
}

function closeFramed(reason) {
  if (closedLog) return;
  appendFramed({ kind: 'observer-log-close', reason });
  closedLog = true;
}

appendFramed({ kind: 'observer-log-open', scenarioMode: plan.scenarioMode, triggerMode: plan.triggerMode });
process.on('exit', (code) => closeFramed('process-exit:' + code));

function shaFileSafe(p) {
  try {
    const resolved = path.isAbsolute(p) ? p : path.resolve(process.cwd(), p);
    if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
      return { resolved, sha256: crypto.createHash('sha256').update(fs.readFileSync(resolved)).digest('hex') };
    }
  } catch {}
  return { resolved: String(p), sha256: null };
}

function toHexPreview(val) {
  if (val === undefined || val === null) return null;
  const b = Buffer.isBuffer(val) ? val : (val instanceof Uint8Array ? Buffer.from(val) : Buffer.from(String(val), 'utf8'));
  return b.subarray(0, 8192).toString('hex');
}

// Observe fs reads/writes inside app directory (for cache-hit / file-channel evidence)
const appRootLower = String(plan.appDir || '').toLowerCase();
const origReadFileSync = fs.readFileSync;
fs.readFileSync = function patchedReadFileSync(file, ...rest) {
  const res = origReadFileSync.call(this, file, ...rest);
  if (typeof file === 'string' && appRootLower && path.resolve(file).toLowerCase().startsWith(appRootLower)) {
    const base = path.basename(file);
    if (!base.endsWith('.js') && !base.endsWith('.html') && !base.endsWith('.asar') && base !== 'package.json') {
      appendFramed({ kind: 'fs-read', path: path.resolve(file), bytes: Buffer.isBuffer(res) ? res.length : Buffer.byteLength(String(res)) });
    }
  }
  return res;
};

const origWriteFileSync = fs.writeFileSync;
fs.writeFileSync = function patchedWriteFileSync(file, data, ...rest) {
  const res = origWriteFileSync.call(this, file, data, ...rest);
  if (typeof file === 'string' && appRootLower && path.resolve(file).toLowerCase().startsWith(appRootLower)) {
    appendFramed({ kind: 'fs-write', path: path.resolve(file), dataHex: toHexPreview(data) });
  }
  return res;
};

function recordSyncSpawn(kindLabel, file, args, opts, res) {
  const info = shaFileSafe(String(file));
  appendFramed({
    kind: kindLabel,
    executable: info.resolved,
    executableSha256: info.sha256,
    argv: Array.isArray(args) ? args.map(String) : [],
    cwd: (opts && opts.cwd) ? String(opts.cwd) : process.cwd(),
    stdinHex: toHexPreview(opts && opts.input),
    stdoutHex: toHexPreview(res && res.stdout),
    stderrPreview: res && res.stderr ? Buffer.from(res.stderr).toString('utf8').slice(0, 512) : null,
    childPid: res && res.pid ? res.pid : null,
    exitCode: res && typeof res.status === 'number' ? res.status : null,
  });
}

const origSpawnSync = cp.spawnSync;
cp.spawnSync = function patchedSpawnSync(file, args, options) {
  const actualArgs = Array.isArray(args) ? args : [];
  const actualOpts = (Array.isArray(args) ? options : args) || {};
  const res = origSpawnSync.apply(this, arguments);
  recordSyncSpawn('child-spawn-sync', file, actualArgs, actualOpts, res);
  return res;
};

const origExecFileSync = cp.execFileSync;
cp.execFileSync = function patchedExecFileSync(file, args, options) {
  const actualArgs = Array.isArray(args) ? args : [];
  const actualOpts = (Array.isArray(args) ? options : args) || {};
  try {
    const stdout = origExecFileSync.apply(this, arguments);
    recordSyncSpawn('child-execfile-sync', file, actualArgs, actualOpts, { stdout, status: 0, pid: null });
    return stdout;
  } catch (err) {
    recordSyncSpawn('child-execfile-sync', file, actualArgs, actualOpts, { stdout: err.stdout, stderr: err.stderr, status: err.status ?? -1, pid: err.pid ?? null });
    throw err;
  }
};

function instrumentAsyncChild(kindLabel, file, actualArgs, actualOpts, child) {
  const info = shaFileSafe(String(file));
  const inChunks = [];
  const outChunks = [];
  if (child && child.stdin && typeof child.stdin.write === 'function') {
    const origWrite = child.stdin.write.bind(child.stdin);
    child.stdin.write = function(chunk, enc, cb) {
      if (chunk) inChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof enc === 'string' ? enc : 'utf8'));
      return origWrite(chunk, enc, cb);
    };
    const origEnd = child.stdin.end.bind(child.stdin);
    child.stdin.end = function(chunk, enc, cb) {
      if (chunk && typeof chunk !== 'function') {
        inChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof enc === 'string' ? enc : 'utf8'));
      }
      return origEnd(chunk, enc, cb);
    };
  }
  if (child && child.stdout) child.stdout.on('data', (c) => outChunks.push(Buffer.from(c)));
  if (child && typeof child.on === 'function') {
    child.on('close', (code) => {
      appendFramed({
        kind: kindLabel,
        executable: info.resolved,
        executableSha256: info.sha256,
        argv: actualArgs.map(String),
        cwd: actualOpts.cwd ? String(actualOpts.cwd) : process.cwd(),
        stdinHex: toHexPreview(Buffer.concat(inChunks)),
        stdoutHex: toHexPreview(Buffer.concat(outChunks)),
        childPid: child.pid || null,
        exitCode: typeof code === 'number' ? code : null,
      });
    });
  }
  return child;
}

const origSpawn = cp.spawn;
cp.spawn = function patchedSpawn(file, args, options) {
  const actualArgs = Array.isArray(args) ? args : [];
  const actualOpts = (Array.isArray(args) ? options : args) || {};
  const child = origSpawn.apply(this, arguments);
  return instrumentAsyncChild('child-spawn-async', file, actualArgs, actualOpts, child);
};

const origExecFile = cp.execFile;
cp.execFile = function patchedExecFile(file, args, options, callback) {
  const actualArgs = Array.isArray(args) ? args : [];
  const actualOpts = (!Array.isArray(args) && typeof args === 'object' && args !== null) ? args : (typeof options === 'object' && options !== null ? options : {});
  const child = origExecFile.apply(this, arguments);
  return instrumentAsyncChild('child-execfile-async', file, actualArgs, actualOpts, child);
};

const registeredIpcChannels = new Set();
let electronHookInstalled = false;

function installElectronHooks(electron) {
  if (electronHookInstalled || !electron || typeof electron !== 'object' || !electron.app || !electron.ipcMain) return;
  electronHookInstalled = true;
  try {
    if (typeof electron.ipcMain.handle === 'function') {
      const origHandle = electron.ipcMain.handle.bind(electron.ipcMain);
      electron.ipcMain.handle = function patchedHandle(channel, listener) {
        registeredIpcChannels.add(String(channel));
        appendFramed({ kind: 'ipc-channel-registered', method: 'handle', channel: String(channel) });
        return origHandle(channel, async function(ev, ...ipcArgs) {
          const out = await listener(ev, ...ipcArgs);
          appendFramed({ kind: 'ipc-handle', channel: String(channel), ipcArgs, result: out });
          return out;
        });
      };
    }
    if (typeof electron.ipcMain.on === 'function') {
      const origOn = electron.ipcMain.on.bind(electron.ipcMain);
      electron.ipcMain.on = function patchedOn(channel, listener) {
        registeredIpcChannels.add(String(channel));
        appendFramed({ kind: 'ipc-channel-registered', method: 'on', channel: String(channel) });
        return origOn(channel, function(ev, ...ipcArgs) {
          appendFramed({ kind: 'ipc-on', channel: String(channel), ipcArgs });
          return listener.apply(this, arguments);
        });
      };
    }

    // Non-cooperative window discovery & structured UI/IPC driver (only in main process!)
    if (plan.scenarioMode !== 'legacy-cooperative-fixture') {
      let driven = false;
      electron.app.on('browser-window-created', (_ev, win) => {
        if (driven) return;
        driven = true;
        win.webContents.once('did-finish-load', async () => {
          try {
            await new Promise((r) => setTimeout(r, 120));
            if (plan.scenarioMode === 'discover') {
              const domSchema = await win.webContents.executeJavaScript(\`(() => {
                const controls = Array.from(document.querySelectorAll('input, textarea, select, button, [id], [data-testid]')).slice(0, 64).map((el) => ({
                  selector: el.id ? ('#' + el.id) : (el.getAttribute('data-testid') ? ('[data-testid="' + el.getAttribute('data-testid') + '"]') : el.tagName.toLowerCase()),
                  tag: el.tagName.toLowerCase(),
                  id: el.id || null,
                  type: el.getAttribute('type') || null,
                  name: el.getAttribute('name') || null,
                  testId: el.getAttribute('data-testid') || null,
                  text: (el.innerText || el.value || '').trim().slice(0, 120),
                  placeholder: el.getAttribute('placeholder') || null,
                }));
                const customGlobals = Object.keys(window).filter((k) => !/^(?:webkit|chrome|on|speech|caches|indexedDB|localStorage|sessionStorage|performance|navigator|location|history|document|window|self|top|parent|frames|visualViewport|screen|inner|outer|page|scroll|client|devicePixelRatio|styleMedia|isSecureContext|origin|crossOriginIsolated|trustedTypes|scheduler|cookieStore|launchQueue|navigation)/.test(k)).slice(0, 48);
                const bridgeApis = {};
                for (const k of customGlobals) {
                  try {
                    if (window[k] && typeof window[k] === 'object') {
                      bridgeApis[k] = Object.keys(window[k]).slice(0, 16);
                    }
                  } catch {}
                }
                return { title: document.title, url: location.href, controls, bridgeApis };
              })()\`);
              appendFramed({
                kind: 'window-discovered',
                windowId: win.id,
                domSchema,
                ipcChannels: Array.from(registeredIpcChannels),
              });
              closeFramed('discover-complete');
              electron.app.quit();
              return;
            }

            if (plan.triggerMode === 'ui-click') {
              const actionsJson = JSON.stringify(plan.uiActions || []);
              const settleMs = Number(plan.settleMs || 350);
              const uiWitness = await win.webContents.executeJavaScript(\`(async () => {
                const actions = \${actionsJson};
                const stepWitnesses = [];
                let readOutputText = null;
                const domSnapshotBefore = document.body ? document.body.innerText.slice(0, 512) : '';
                for (const act of actions) {
                  const el = document.querySelector(act.selector);
                  if (!el) {
                    return { ok: false, error: 'SELECTOR_NOT_FOUND:' + act.selector, stepWitnesses };
                  }
                  const rect = el.getBoundingClientRect();
                  if (act.op === 'fill' || act.op === 'select') {
                    el.focus();
                    el.value = String(act.value ?? '');
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                    stepWitnesses.push({ op: act.op, selector: act.selector, tag: el.tagName.toLowerCase(), valueLength: String(act.value ?? '').length });
                  } else if (act.op === 'click') {
                    if (el.disabled) return { ok: false, error: 'ELEMENT_DISABLED:' + act.selector, stepWitnesses };
                    el.focus();
                    el.click();
                    stepWitnesses.push({
                      op: 'click',
                      selector: act.selector,
                      tag: el.tagName.toLowerCase(),
                      boundingRect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
                    });
                    await new Promise((r) => setTimeout(r, \${settleMs}));
                  } else if (act.op === 'read-dom') {
                    const deadline = Date.now() + 1500;
                    while (Date.now() < deadline) {
                      const val = act.property === 'value' ? el.value : (el.textContent || el.value || '');
                      if (val && String(val).trim() && String(val).trim() !== (act.ignorePlaceholder || '')) {
                        readOutputText = String(val).trim();
                        break;
                      }
                      await new Promise((r) => setTimeout(r, 40));
                    }
                    if (readOutputText === null) {
                      readOutputText = String(act.property === 'value' ? (el.value || '') : (el.textContent || el.value || '')).trim();
                    }
                    stepWitnesses.push({ op: 'read-dom', selector: act.selector, tag: el.tagName.toLowerCase(), textLength: readOutputText.length });
                  }
                }
                const domSnapshotAfter = document.body ? document.body.innerText.slice(0, 512) : '';
                return {
                  ok: true,
                  windowTitle: document.title,
                  windowUrl: location.href,
                  domMutated: domSnapshotBefore !== domSnapshotAfter,
                  stepWitnesses,
                  readOutputText,
                };
              })()\`);
              appendFramed({ kind: 'ui-click-witness', windowId: win.id, uiWitness });
              await new Promise((r) => setTimeout(r, 80));
              closeFramed('ui-click-complete');
              electron.app.quit();
              return;
            }

            if (plan.triggerMode === 'ipc-invoke') {
              const invokeCfg = JSON.stringify({ bridgeGlobal: plan.bridgeGlobal, bridgeMethod: plan.bridgeMethod, ipcArgs: plan.ipcArgs || [] });
              const ipcWitness = await win.webContents.executeJavaScript(\`(async () => {
                const cfg = \${invokeCfg};
                if (cfg.bridgeGlobal && cfg.bridgeMethod && window[cfg.bridgeGlobal] && typeof window[cfg.bridgeGlobal][cfg.bridgeMethod] === 'function') {
                  const res = await window[cfg.bridgeGlobal][cfg.bridgeMethod](...cfg.ipcArgs);
                  return { ok: true, via: 'preload-bridge', bridge: cfg.bridgeGlobal + '.' + cfg.bridgeMethod, returnValue: res };
                }
                return { ok: false, error: 'BRIDGE_METHOD_NOT_FOUND' };
              })()\`);
              appendFramed({ kind: 'ipc-invoke-witness', windowId: win.id, ipcWitness });
              await new Promise((r) => setTimeout(r, 80));
              closeFramed('ipc-invoke-complete');
              electron.app.quit();
            }
          } catch (err) {
            appendFramed({ kind: 'driver-error', message: String(err && err.message || err) });
            closeFramed('driver-error');
            electron.app.quit();
          }
        });
      });
    }
  } catch (err) {
    appendFramed({ kind: 'hook-install-error', message: String(err && err.message || err) });
  }
}

const origModuleLoad = Module._load;
Module._load = function patchedModuleLoad(request, parent, isMain) {
  const loaded = origModuleLoad.apply(this, arguments);
  if (!electronHookInstalled && (request === 'electron' || request === 'electron/main')) {
    installElectronHooks(loaded);
  }
  return loaded;
};
try { installElectronHooks(require('electron')); } catch {}
`;
  fs.writeFileSync(hookPath, code, 'utf8');
}

function normalizeExtractedHex(rawVal) {
  if (rawVal === undefined || rawVal === null) return null;
  if (typeof rawVal === 'string') {
    const clean = rawVal.trim().replace(/^0x/i, '').replace(/[\s:-]+/g, '').toLowerCase();
    if (clean.length >= 2 && clean.length % 2 === 0 && /^[0-9a-f]+$/.test(clean)) return clean;
    // Try regex extraction if DOM label has prefix like "Sealed Frame: a1b2c3..."
    const m = /([0-9a-fA-F]{4,512})\b/.exec(rawVal.trim());
    if (m && m[1].length % 2 === 0) return m[1].toLowerCase();
    return null;
  }
  if (typeof rawVal === 'object') {
    for (const k of ['outputHex', 'frameHex', 'sealedHex', 'digestHex', 'hex', 'resultHex', 'data']) {
      if (typeof rawVal[k] === 'string') {
        const h = normalizeExtractedHex(rawVal[k]);
        if (h) return h;
      }
    }
  }
  return null;
}

export class NativeAppObserver {
  constructor(cfg = {}) {
    this.cfg = cfg;
    this.activeSessions = new Map();
  }

  /**
   * Discover or execute an Electron -> Native Helper scenario inside a Win32 Job Object container:
   * - Default (`scenarioMode = 'execute'` or `'discover'`) is 100% NON-COOPERATIVE (zero `IG5_AUTO_CLICK_*` env vars!).
   * - Legacy cooperative mode (`legacyFixtureProtocol = true`) is explicitly isolated and stamped `fixtureOnlyProtocol: true`.
   */
  async runElectronScenario({
    target,
    scenarioMode = 'execute', // 'discover' | 'execute' | 'legacy-cooperative-fixture'
    payload = null,
    inputEncoding = null, // 'hex' | 'utf8' | 'ascii'
    uiActions = null,
    bridgeGlobal = null,
    bridgeMethod = null,
    ipcArgs = null,
    outputChannel = null, // { kind: 'dom' | 'ipc-return' | 'child-stdout' | 'file', selector?, path? }
    bypassCache = false,
    triggerMode = 'ui-click', // 'ui-click' | 'ipc-invoke' | 'headless-ipc'
    legacyFixtureProtocol = false,
    timeoutMs = 30_000,
    electronExe = null,
    signal = null,
  }) {
    if (signal?.aborted) {
      fail('IG5_CANCELLED_BEFORE_DISPATCH', 'Electron scenario aborted before launch');
    }
    const launch = resolveElectronLaunchTarget(target, { explicitElectronExe: electronExe, cfg: this.cfg });
    const appDir = launch.appWorkingDir;
    const effectiveMode = legacyFixtureProtocol ? 'legacy-cooperative-fixture' : scenarioMode;

    let observedInputHex = null;
    if (effectiveMode !== 'discover') {
      if (typeof payload === 'string' && payload.length > 0) {
        const clean = payload.trim();
        const enc = inputEncoding || (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0 ? 'hex' : 'utf8');
        observedInputHex = (enc === 'hex' ? Buffer.from(clean, 'hex') : Buffer.from(clean, enc)).toString('hex').toLowerCase();
      } else if (Array.isArray(uiActions)) {
        const fillStep = uiActions.find((a) => a.op === 'fill' && typeof a.value === 'string');
        if (fillStep) {
          const clean = fillStep.value.trim();
          const enc = inputEncoding || (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0 ? 'hex' : 'utf8');
          observedInputHex = (enc === 'hex' ? Buffer.from(clean, 'hex') : Buffer.from(clean, enc)).toString('hex').toLowerCase();
        }
      }
      if (!observedInputHex) {
        fail('INVALID_ARGUMENT', 'Electron execute scenario requires payload or a fill uiAction with input value');
      }
    }

    // Build default structured uiActions if caller provided selector shorthand or uiActions
    let resolvedUiActions = Array.isArray(uiActions) ? uiActions : null;
    if (!resolvedUiActions && effectiveMode === 'execute' && triggerMode === 'ui-click') {
      fail('INVALID_ARGUMENT', 'Non-cooperative Electron ui-click requires structured ui_actions ([{op:"fill",selector,...},{op:"click",selector},{op:"read-dom",selector}]) discovered from the app UI, or explicit legacy_fixture_protocol=true for legacy fixtures');
    }

    const runId = `el-run-${randomUUID()}`;
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-el-obs-'));
    const hookPath = path.join(scratch, 'ig5-el-observer.cjs');
    const planPath = path.join(scratch, 'ig5-el-plan.json');
    const logPath = path.join(scratch, 'observer-events.jsonl');
    const userDataDir = path.join(scratch, 'electron-user-data');
    fs.mkdirSync(userDataDir, { recursive: true });
    const hookMarker = `--require "${hookPath.replaceAll('\\', '/')}"`;
    writeGenericElectronObserverScript(hookPath);

    fs.writeFileSync(planPath, JSON.stringify({
      runId,
      appDir,
      logPath,
      hookMarker,
      scenarioMode: effectiveMode,
      triggerMode,
      uiActions: resolvedUiActions,
      bridgeGlobal,
      bridgeMethod,
      ipcArgs: ipcArgs ?? (payload !== null ? [payload] : []),
      settleMs: 350,
    }), 'utf8');

    const envOverrides = {
      ELECTRON_RUN_AS_NODE: null,
      NODE_OPTIONS: `${process.env.NODE_OPTIONS ? process.env.NODE_OPTIONS + ' ' : ''}${hookMarker}`,
      IG5_OBSERVER_PLAN_FILE: planPath,
    };
    const environmentModifications = [
      'NODE_OPTIONS:--require ig5-el-observer.cjs',
      'IG5_OBSERVER_PLAN_FILE:<temp>',
      '--user-data-dir=<temp>',
    ];

    if (effectiveMode === 'legacy-cooperative-fixture') {
      if (bypassCache) {
        envOverrides.IG5_BYPASS_CACHE = '1';
        environmentModifications.push('IG5_BYPASS_CACHE=1');
      }
      if (triggerMode === 'headless-ipc') {
        envOverrides.IG5_HEADLESS_IPC_PAYLOAD = String(payload || '');
        environmentModifications.push('IG5_HEADLESS_IPC_PAYLOAD');
      } else {
        envOverrides.IG5_AUTO_CLICK_PAYLOAD = String(payload || '');
        environmentModifications.push('IG5_AUTO_CLICK_PAYLOAD');
      }
    }

    try {
      const jobReport = await runInWin32JobContainer({
        executable: launch.executable,
        args: [`--user-data-dir=${userDataDir}`, ...launch.launchArgs],
        cwd: appDir,
        env: envOverrides,
        timeoutMs,
        signal,
        watchDir: appDir,
        cfg: this.cfg,
      });

      const logParsed = parseFramedObserverLog(logPath, runId);
      const hookEvents = logParsed.integrity === 'verified' ? logParsed.events : [];
      const childSpawns = hookEvents.filter((e) => e.kind.startsWith('child-'));
      const ipcEvents = hookEvents.filter((e) => e.kind === 'ipc-handle' || e.kind === 'ipc-on');
      const fsReads = hookEvents.filter((e) => e.kind === 'fs-read');
      const fsWrites = hookEvents.filter((e) => e.kind === 'fs-write');
      const uiWitnessEvent = hookEvents.find((e) => e.kind === 'ui-click-witness') || null;
      const ipcInvokeEvent = hookEvents.find((e) => e.kind === 'ipc-invoke-witness') || null;
      const discoveryEvent = hookEvents.find((e) => e.kind === 'window-discovered') || null;

      // Cross-verify preload child spawns against kernel Job Object observed processes!
      const jobProcs = jobReport.systemObservedProcesses || [];
      const jobByPid = new Map(jobProcs.map((p) => [Number(p.pid), p]));
      const jobBySha = new Map();
      for (const p of jobProcs) {
        if (p.imageSha256) jobBySha.set(p.imageSha256.toLowerCase(), p);
      }

      const handoffEdges = childSpawns.map((s, idx) => {
        const kernelMatch = (s.childPid && jobByPid.get(Number(s.childPid)))
          || (s.executableSha256 && jobBySha.get(s.executableSha256.toLowerCase()))
          || null;
        return {
          edgeIndex: idx,
          relationOrigin: kernelMatch ? 'kernel-job-and-boundary-verified' : 'preload-boundary-observed',
          kernelProcessVerified: Boolean(kernelMatch),
          parentPid: s.observerPid,
          childPid: kernelMatch?.pid ?? s.childPid ?? null,
          childCreationIdentity: kernelMatch?.creationIdentity || null,
          executable: kernelMatch?.imagePath || s.executable,
          executableSha256: kernelMatch?.imageSha256 || s.executableSha256,
          argv: s.argv,
          cwd: s.cwd,
          stdinHex: s.stdinHex,
          stdoutHex: s.stdoutHex,
          exitCode: s.exitCode ?? kernelMatch?.exitCode ?? null,
        };
      });

      const stdoutText = Buffer.from(jobReport.stdoutHex || '', 'hex').toString('utf8');
      const legacyMatch = /IG5_ELECTRON_(?:UI_)?RESULT=(\{[^\r\n]+\})/.exec(stdoutText);
      const legacyParsed = legacyMatch ? JSON.parse(legacyMatch[1]) : null;

      if (effectiveMode === 'discover') {
        return {
          ok: logParsed.integrity === 'verified' && Boolean(discoveryEvent) && jobReport.cleanupVerified,
          action: 'electron_scenario',
          scenarioMode: 'discover',
          fixtureOnlyProtocol: false,
          runId,
          target: path.resolve(target),
          runtimeSelection: launch.runtimeSelection,
          environmentModifications,
          observerLogIntegrity: logParsed.integrity,
          discoveredWindow: discoveryEvent?.domSchema || null,
          registeredIpcChannels: discoveryEvent?.ipcChannels || hookEvents.filter((e) => e.kind === 'ipc-channel-registered').map((e) => e.channel),
          systemObservedProcesses: jobProcs,
          cleanup: {
            cleanupVerified: jobReport.cleanupVerified,
            cleanupDisposition: jobReport.cleanupDisposition,
            lingeringOwnedProcessesCount: jobReport.lingeringPidsAfterCleanup?.length ?? null,
          },
        };
      }

      // Extract observed output strictly from real observed channels (DOM / IPC / file / child pipe),
      // isolating target stdout claims under `applicationReported`.
      let outputHex = null;
      let outputChannelUsed = null;
      const prefKind = outputChannel?.kind || null;

      if ((!prefKind || prefKind === 'dom') && uiWitnessEvent?.uiWitness?.readOutputText) {
        outputHex = normalizeExtractedHex(uiWitnessEvent.uiWitness.readOutputText);
        if (outputHex) outputChannelUsed = 'dom-text';
      }
      if (!outputHex && (!prefKind || prefKind === 'ipc-return')) {
        const ipcCandidate = ipcInvokeEvent?.ipcWitness?.returnValue ?? ipcEvents.at(-1)?.result;
        outputHex = normalizeExtractedHex(ipcCandidate);
        if (outputHex) outputChannelUsed = 'ipc-return';
      }
      if (!outputHex && (!prefKind || prefKind === 'file') && jobReport.observedFileWrites?.length > 0) {
        const targetWrite = outputChannel?.path
          ? jobReport.observedFileWrites.find((w) => path.resolve(w.path).toLowerCase() === path.resolve(appDir, outputChannel.path).toLowerCase())
          : jobReport.observedFileWrites.find((w) => !w.relativePath.includes('cache') && !w.relativePath.includes('history'));
        if (targetWrite?.bytesHex) {
          const textCandidate = Buffer.from(targetWrite.bytesHex, 'hex').toString('utf8').trim();
          outputHex = (/^[0-9a-fA-F]+$/.test(textCandidate) && textCandidate.length % 2 === 0)
            ? textCandidate.toLowerCase()
            : targetWrite.bytesHex;
          outputChannelUsed = `file-write:${targetWrite.relativePath}`;
        }
      }
      if (!outputHex && (!prefKind || prefKind === 'child-stdout') && handoffEdges.length > 0) {
        const lastEdge = handoffEdges.at(-1);
        if (lastEdge?.stdoutHex) {
          const childTxt = Buffer.from(lastEdge.stdoutHex, 'hex').toString('utf8').trim();
          outputHex = normalizeExtractedHex(childTxt) || lastEdge.stdoutHex;
          outputChannelUsed = 'child-stdout';
        }
      }
      if (!outputHex && effectiveMode === 'legacy-cooperative-fixture' && legacyParsed) {
        outputHex = normalizeExtractedHex(legacyParsed);
        if (outputHex) outputChannelUsed = 'legacy-fixture-stdout';
      }

      // System-observed diagnosis (never trusting target `cached: true` claim alone!)
      const uiOrIpcTriggered = Boolean(
        (triggerMode === 'ui-click' && uiWitnessEvent?.uiWitness?.ok)
        || (triggerMode === 'ipc-invoke' && ipcInvokeEvent?.ipcWitness?.ok)
        || ipcEvents.length > 0
        || effectiveMode === 'legacy-cooperative-fixture',
      );
      let observationDiagnosis = 'OK';
      if (jobReport.cancelled) observationDiagnosis = 'CANCELLED_ABORTED';
      else if (jobReport.timedOut) observationDiagnosis = 'WINDOW_TIMEOUT';
      else if (logParsed.integrity !== 'verified') observationDiagnosis = `OBSERVER_LOG_${logParsed.integrity.toUpperCase()}`;
      else if (triggerMode === 'ui-click' && effectiveMode !== 'legacy-cooperative-fixture' && !uiWitnessEvent?.uiWitness?.ok) {
        observationDiagnosis = `UI_TRIGGER_FAILED:${uiWitnessEvent?.uiWitness?.error || 'no-window-witness'}`;
      } else if (handoffEdges.length === 0 && outputHex && (fsReads.length > 0 || ipcEvents.length > 0)) {
        observationDiagnosis = 'CACHE_SHORT_CIRCUIT';
      } else if (handoffEdges.length === 0) {
        observationDiagnosis = 'HELPER_NOT_SPAWNED';
      } else if (handoffEdges.every((e) => e.exitCode !== 0)) {
        observationDiagnosis = 'HELPER_REJECTED_HANDOFF';
      }

      return {
        ok: logParsed.integrity === 'verified'
          && !jobReport.timedOut
          && !jobReport.cancelled
          && uiOrIpcTriggered
          && Boolean(outputHex)
          && jobReport.cleanupVerified,
        action: 'electron_scenario',
        scenarioMode: effectiveMode,
        fixtureOnlyProtocol: effectiveMode === 'legacy-cooperative-fixture',
        runId,
        target: path.resolve(target),
        triggerMode,
        runtimeSelection: launch.runtimeSelection,
        environmentModifications,
        observerLogIntegrity: logParsed.integrity,
        observerLogReason: logParsed.reason,
        parentProcess: {
          pid: jobReport.rootPid,
          creationIdentity: jobReport.rootCreationIdentity,
          executable: launch.executable,
        },
        observedInputHex,
        outputHex,
        outputChannelUsed,
        observationDiagnosis,
        uiClickWitness: uiWitnessEvent?.uiWitness || null,
        ipcInvokeWitness: ipcInvokeEvent?.ipcWitness || null,
        ipcEvents,
        fsReads,
        fsWrites,
        handoffEdges,
        verifiedProcessLineage: jobProcs,
        observedFileWrites: jobReport.observedFileWrites || [],
        applicationReported: {
          trustLevel: 'untrusted-target-claim',
          rawStdoutPreview: stdoutText.slice(0, 1024),
          legacyFixtureJson: legacyParsed,
        },
        cleanup: {
          cleanupVerified: jobReport.cleanupVerified,
          cleanupDisposition: jobReport.cleanupDisposition,
          cleanupEnumerationStatus: jobReport.cleanupEnumerationStatus,
          lingeringOwnedProcessesCount: jobReport.lingeringPidsAfterCleanup?.length ?? null,
        },
      };
    } finally {
      try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  }

  /**
   * Generic Evidence-Driven Multi-Process Chain Observer:
   * - Accepts arbitrary `args`, `cwd`, `stdinHex`, `inputFiles`, `envDiff`, and `outputChannel`.
   * - Builds `verifiedProcessLineage` strictly from Win32 Job Object kernel telemetry (`worker/win32_job_supervisor.py`).
   * - Isolates target stdout / self-reported PIDs under `applicationReported` (`untrusted-target-claim`).
   */
  async runProcessChainScenario({
    target,
    args = null,
    cwd = null,
    stdinHex = null,
    inputFiles = null,
    envDiff = null,
    outputChannel = null, // { kind: 'stdout-hex' | 'stdout-regex' | 'file-bytes' | 'file-hex', path?, regex? }
    declaredInputChannel = null,
    payloadHex = null,
    corrId = null,
    restartWorker1 = false,
    legacyFixtureProtocol = false,
    timeoutMs = 20_000,
    signal = null,
  }) {
    if (signal?.aborted) {
      fail('IG5_CANCELLED_BEFORE_DISPATCH', 'Process-chain scenario aborted before launch');
    }
    const entryExe = path.resolve(target);
    if (!fs.existsSync(entryExe)) fail('ENOENT', `Process chain entry binary does not exist: ${entryExe}`);
    const baseDir = cwd ? path.resolve(cwd) : path.dirname(entryExe);
    const entrySha256 = sha256(fs.readFileSync(entryExe));
    const runId = `chain-run-${randomUUID()}`;
    const canonFileKey = (p) => {
      const r = path.resolve(p);
      try { return (fs.realpathSync.native || fs.realpathSync)(r).toLowerCase(); } catch { return r.toLowerCase(); }
    };

    // Determine whether legacy fixture CLI shaping was explicitly requested or generic args were supplied
    let effectiveArgs = Array.isArray(args) ? args.map(String) : null;
    let isFixtureOnly = Boolean(legacyFixtureProtocol);
    const effectiveCorrId = corrId || `corr-${randomUUID().slice(0, 8)}`;

    if (!effectiveArgs) {
      if (payloadHex && legacyFixtureProtocol) {
        const cleanHex = String(payloadHex).trim().toLowerCase();
        effectiveArgs = [`--req=${effectiveCorrId}`, `--payload=${cleanHex}`, ...(restartWorker1 ? ['--restart-worker1'] : [])];
        isFixtureOnly = true;
      } else {
        effectiveArgs = [];
      }
    }

    // Write any explicit scenario input files inside baseDir prior to launch
    const writtenInputFiles = [];
    if (Array.isArray(inputFiles)) {
      for (const inf of inputFiles) {
        if (!inf?.path || typeof inf.hex !== 'string') fail('INVALID_ARGUMENT', 'inputFiles entry requires path and hex');
        const resolvedInf = path.resolve(baseDir, inf.path);
        if (!resolvedInf.toLowerCase().startsWith(baseDir.toLowerCase())) {
          fail('PATH_ESCAPE_FORBIDDEN', `inputFiles path must stay inside scenario cwd: ${inf.path}`);
        }
        fs.mkdirSync(path.dirname(resolvedInf), { recursive: true });
        const buf = Buffer.from(inf.hex.trim(), 'hex');
        fs.writeFileSync(resolvedInf, buf);
        writtenInputFiles.push({ path: resolvedInf, bytes: buf.length, sha256: sha256(buf), hex: buf.toString('hex') });
      }
    }

    // Bind observed input STRICTLY to the declared/unambiguous business channel (NEVER guess `writtenInputFiles[0]` on multi-file calls!).
    let observedInputHex = null;
    let observedInputSha256 = null;
    let inputChannelUsed = null;
    let channelBindingConflict = null;
    let boundChannelMeta = null;

    const hasStdin = typeof stdinHex === 'string' && stdinHex.trim().length > 0;
    if (declaredInputChannel && typeof declaredInputChannel === 'object') {
      if (declaredInputChannel.kind === 'stdin') {
        if (!hasStdin) {
          channelBindingConflict = 'declared-stdin-channel-missing-stdinHex';
        } else {
          observedInputHex = stdinHex.trim().toLowerCase();
          observedInputSha256 = sha256(Buffer.from(observedInputHex, 'hex'));
          inputChannelUsed = 'stdin';
          boundChannelMeta = { kind: 'stdin' };
        }
      } else if (declaredInputChannel.kind === 'file') {
        if (hasStdin) {
          channelBindingConflict = 'stdinHex-supplied-for-declared-file-channel';
        } else {
          const expectedFile = path.resolve(baseDir, declaredInputChannel.filePath);
          const expectedKey = canonFileKey(expectedFile);
          let argvBound = false;
          if (Number.isSafeInteger(declaredInputChannel.argIndex)) {
            const idx = declaredInputChannel.argIndex;
            const pfx = declaredInputChannel.prefix || '';
            const sfx = declaredInputChannel.suffix || '';
            if (idx >= 0 && idx < effectiveArgs.length) {
              const rawArg = String(effectiveArgs[idx] || '');
              if (rawArg.startsWith(pfx) && (!sfx || rawArg.endsWith(sfx)) && rawArg.length >= pfx.length + sfx.length) {
                const argPath = rawArg.slice(pfx.length, sfx ? rawArg.length - sfx.length : rawArg.length);
                argvBound = canonFileKey(path.resolve(baseDir, argPath)) === expectedKey;
              }
            }
          } else if (declaredInputChannel.fixedFilename) {
            argvBound = canonFileKey(path.resolve(baseDir, declaredInputChannel.fixedFilename)) === expectedKey;
          }
          if (!argvBound) {
            channelBindingConflict = 'argv-or-cwd-does-not-point-to-declared-input-file';
          } else if (!fs.existsSync(expectedFile) || !fs.statSync(expectedFile).isFile()) {
            channelBindingConflict = 'declared-input-file-missing-at-launch';
          } else {
            const fileBuf = fs.readFileSync(expectedFile);
            if (!fileBuf.length || fileBuf.length > 4096) {
              channelBindingConflict = 'declared-input-file-empty-or-oversized';
            } else {
              observedInputHex = fileBuf.toString('hex').toLowerCase();
              observedInputSha256 = sha256(fileBuf);
              inputChannelUsed = `file:${path.relative(baseDir, expectedFile).replaceAll('\\', '/')}`;
              boundChannelMeta = {
                kind: 'file',
                filePath: expectedFile,
                ...(Number.isSafeInteger(declaredInputChannel.argIndex) ? {
                  argIndex: declaredInputChannel.argIndex,
                  prefix: declaredInputChannel.prefix || '',
                  suffix: declaredInputChannel.suffix || '',
                } : { fixedFilename: declaredInputChannel.fixedFilename }),
              };
            }
          }
        }
      } else if (declaredInputChannel.kind === 'cli-arg') {
        const idx = declaredInputChannel.argIndex ?? 0;
        const pfx = declaredInputChannel.prefix || '';
        const sfx = declaredInputChannel.suffix || '';
        const enc = declaredInputChannel.encoding || 'utf8';
        if (idx >= 0 && idx < effectiveArgs.length) {
          const rawArg = String(effectiveArgs[idx] || '');
          if (rawArg.startsWith(pfx) && (!sfx || rawArg.endsWith(sfx))) {
            const inner = rawArg.slice(pfx.length, sfx ? rawArg.length - sfx.length : rawArg.length);
            const buf = enc === 'hex' ? Buffer.from(inner, 'hex') : Buffer.from(inner, enc === 'ascii' ? 'ascii' : 'utf8');
            observedInputHex = buf.toString('hex').toLowerCase();
            observedInputSha256 = sha256(buf);
            inputChannelUsed = 'cli-arg';
            boundChannelMeta = { kind: 'cli-arg', argIndex: idx, prefix: pfx, suffix: sfx, encoding: enc };
          } else {
            channelBindingConflict = 'cli-arg-affix-mismatch-at-launch';
          }
        } else {
          channelBindingConflict = 'cli-arg-index-out-of-bounds-at-launch';
        }
      } else if (declaredInputChannel.kind === 'ipc' && typeof payloadHex === 'string' && payloadHex.trim()) {
        observedInputHex = payloadHex.trim().toLowerCase();
        observedInputSha256 = sha256(Buffer.from(observedInputHex, 'hex'));
        inputChannelUsed = isFixtureOnly ? 'legacy-cli-payload' : 'ipc';
        boundChannelMeta = { kind: 'ipc' };
      }
    } else if (hasStdin) {
      observedInputHex = stdinHex.trim().toLowerCase();
      observedInputSha256 = sha256(Buffer.from(observedInputHex, 'hex'));
      inputChannelUsed = 'stdin';
      boundChannelMeta = { kind: 'stdin' };
    } else if (writtenInputFiles.length === 1) {
      observedInputHex = writtenInputFiles[0].hex.toLowerCase();
      observedInputSha256 = writtenInputFiles[0].sha256;
      inputChannelUsed = `file:${path.relative(baseDir, writtenInputFiles[0].path).replaceAll('\\', '/')}`;
      boundChannelMeta = { kind: 'file', filePath: writtenInputFiles[0].path };
    } else if (writtenInputFiles.length > 1) {
      // Refuse to guess `writtenInputFiles[0]` when multiple files are staged without an explicit channel binding!
      observedInputHex = null;
      inputChannelUsed = 'ambiguous-multiple-input-files';
      channelBindingConflict = 'multiple-input-files-require-declared-scenario-channel';
    } else if (typeof payloadHex === 'string' && payloadHex.trim()) {
      observedInputHex = payloadHex.trim().toLowerCase();
      observedInputSha256 = sha256(Buffer.from(observedInputHex, 'hex'));
      inputChannelUsed = isFixtureOnly ? 'legacy-cli-payload' : 'cli-arg';
      boundChannelMeta = { kind: 'cli-arg' };
    }

    // Snapshot explicit outputChannel file before launch if outside/inside baseDir so post-launch diff is exact
    const explicitOutPath = outputChannel?.path ? path.resolve(baseDir, outputChannel.path) : null;
    let preOutSnapshot = null;
    if (explicitOutPath && fs.existsSync(explicitOutPath) && fs.statSync(explicitOutPath).isFile()) {
      const st = fs.statSync(explicitOutPath);
      preOutSnapshot = { mtimeMs: st.mtimeMs, sha256: sha256(fs.readFileSync(explicitOutPath)) };
    }

    const jobReport = await runInWin32JobContainer({
      executable: entryExe,
      args: effectiveArgs,
      cwd: baseDir,
      env: envDiff || null,
      stdinHex: stdinHex !== null && stdinHex !== undefined ? String(stdinHex).trim() : null,
      timeoutMs,
      signal,
      watchDir: baseDir,
      cfg: this.cfg,
    });

    const stdoutBuf = Buffer.from(jobReport.stdoutHex || '', 'hex');
    const stdoutText = stdoutBuf.toString('utf8').trim();

    // Parse untrusted self-reported stdout JSON ONLY into `applicationReported`!
    let selfReportedJson = null;
    const legacyTag = /IG5_CHAIN_RESULT=(\{[^\r\n]+\})/.exec(stdoutText);
    if (legacyTag) {
      try { selfReportedJson = JSON.parse(legacyTag[1]); } catch { selfReportedJson = null; }
    } else if (stdoutText.startsWith('{') && stdoutText.endsWith('}')) {
      try { selfReportedJson = JSON.parse(stdoutText); } catch { selfReportedJson = null; }
    }

    // Extract observed output from configured channel (file write, raw stdout hex/bytes, regex, or explicit legacy JSON)
    let outputHex = null;
    let outputChannelUsed = null;
    let outputExtractionDiagnosis = null;
    const outKind = outputChannel?.kind || null;

    if (outKind === 'file' || outKind === 'file-bytes' || outKind === 'file-hex' || (!outKind && jobReport.observedFileWrites?.length > 0 && !stdoutText)) {
      let targetOutFile = explicitOutPath
        ? jobReport.observedFileWrites?.find((w) => canonFileKey(w.path) === canonFileKey(explicitOutPath))
        : jobReport.observedFileWrites?.find((w) => !writtenInputFiles.some((inf) => canonFileKey(inf.path) === canonFileKey(w.path)));
      if (!targetOutFile && explicitOutPath && fs.existsSync(explicitOutPath) && fs.statSync(explicitOutPath).isFile()) {
        const postSt = fs.statSync(explicitOutPath);
        const postBuf = fs.readFileSync(explicitOutPath);
        const postSha = sha256(postBuf);
        if (!preOutSnapshot || postSt.mtimeMs > preOutSnapshot.mtimeMs || postSha !== preOutSnapshot.sha256) {
          targetOutFile = {
            path: explicitOutPath,
            relativePath: path.relative(baseDir, explicitOutPath).replaceAll('\\', '/'),
            bytesHex: postBuf.subarray(0, 8192).toString('hex'),
          };
        }
      }
      if (targetOutFile?.bytesHex) {
        if (outKind === 'file-hex') {
          const rawBuf = Buffer.from(targetOutFile.bytesHex, 'hex');
          const isCleanAsciiHexText = rawBuf.length >= 2
            && rawBuf.every((b) => b === 9 || b === 10 || b === 13 || b === 32 || (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66) || b === 0x78 || b === 0x58);
          if (isCleanAsciiHexText) {
            const txt = rawBuf.toString('ascii').trim();
            outputHex = normalizeExtractedHex(txt);
            if (outputHex) outputChannelUsed = `file-ascii-hex:${targetOutFile.relativePath}`;
          }
          // If the emitted file contains raw binary bytes rather than ASCII hex digits, return its exact bytes as hex!
          if (!outputHex) {
            outputHex = targetOutFile.bytesHex.toLowerCase();
            outputChannelUsed = `file-bytes:${targetOutFile.relativePath}`;
          }
        } else {
          outputHex = targetOutFile.bytesHex.toLowerCase();
          if (outputHex) outputChannelUsed = `file:${targetOutFile.relativePath}`;
        }
      } else if (outKind === 'file' || outKind === 'file-bytes' || outKind === 'file-hex') {
        outputExtractionDiagnosis = explicitOutPath
          ? `Requested output file "${explicitOutPath}" was not created or modified during execution`
          : 'No non-input output file write was observed during execution';
      }
    }

    if (!outputHex && (outKind === 'stdout-bytes' || outKind === 'child-stdout') && stdoutBuf.length > 0) {
      outputHex = stdoutBuf.toString('hex').toLowerCase();
      outputChannelUsed = 'stdout-bytes';
    }

    if (!outputHex && outKind === 'stdout-regex' && outputChannel?.pattern) {
      const re = new RegExp(outputChannel.pattern, 'i');
      const m = re.exec(stdoutText);
      const candidateMatch = m ? (m[1] !== undefined ? m[1] : m[0]) : null;
      if (candidateMatch && candidateMatch.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(candidateMatch)) {
        outputHex = candidateMatch.toLowerCase();
        outputChannelUsed = 'stdout-regex';
      } else {
        outputExtractionDiagnosis = m
          ? 'stdout-regex matched text is not even-length hexadecimal; use capture group around hex digits or stdout-bytes for non-hex stdout'
          : `stdout-regex pattern "${outputChannel.pattern}" did not match stdout`;
      }
    }

    if (!outputHex && (!outKind || outKind === 'stdout-hex')) {
      // Check clean hex line on stdout (common in CLI/pipeline tools)
      const lines = stdoutText.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      for (let i = lines.length - 1; i >= 0; i -= 1) {
        if (/^[0-9a-fA-F]{2,512}$/.test(lines[i]) && lines[i].length % 2 === 0) {
          outputHex = lines[i].toLowerCase();
          outputChannelUsed = 'stdout-hex-line';
          break;
        }
        const kvMatch = /^(?:OUTPUT|RESULT|FRAME|DIGEST|HEX)\s*[:=]\s*([0-9a-fA-F]{2,512})$/i.exec(lines[i]);
        if (kvMatch && kvMatch[1].length % 2 === 0) {
          outputHex = kvMatch[1].toLowerCase();
          outputChannelUsed = 'stdout-kv-hex';
          break;
        }
      }
      if (!outputHex && !outKind && jobReport.observedFileWrites?.length > 0) {
        const autoOutFile = jobReport.observedFileWrites.find((w) => !writtenInputFiles.some((inf) => canonFileKey(inf.path) === canonFileKey(w.path)));
        if (autoOutFile?.bytesHex) {
          outputHex = autoOutFile.bytesHex.toLowerCase();
          outputChannelUsed = `file:${autoOutFile.relativePath}`;
        }
      }
      if (!outputHex && outKind === 'stdout-hex') {
        outputExtractionDiagnosis = 'No hexadecimal line found on stdout';
      }
    }

    if (!outputHex && isFixtureOnly && selfReportedJson?.finalOutHex) {
      outputHex = String(selfReportedJson.finalOutHex).toLowerCase();
      outputChannelUsed = 'legacy-fixture-json';
    }

    // Build `verifiedProcessLineage` EXCLUSIVELY from kernel Job Object observed processes!
    // Never populate from disk directory scans or `selfReportedJson` PIDs!
    const verifiedProcessLineage = (jobReport.systemObservedProcesses || []).map((proc) => ({
      seq: proc.seq,
      pid: proc.pid,
      parentPid: proc.parentPid,
      creationIdentity: proc.creationIdentity,
      imagePath: proc.imagePath,
      sha256: proc.imageSha256,
      commandLine: proc.commandLine,
      exitCode: proc.exitCode,
      relationOrigin: 'win32-job-kernel-observed',
      status: (proc.exitCode !== null && proc.exitCode !== 0) ? 'exited-nonzero' : 'completed',
    }));

    const explicitOutputChannelFailed = Boolean(outKind && !outputHex);
    return {
      ok: !jobReport.timedOut
        && !jobReport.cancelled
        && jobReport.rootExitCode === 0
        && !explicitOutputChannelFailed
        && (Boolean(outputHex) || !outKind)
        && !channelBindingConflict
        && jobReport.cleanupVerified,
      action: 'process_chain_scenario',
      fixtureOnlyProtocol: isFixtureOnly,
      runId,
      corrId: effectiveCorrId,
      target: entryExe,
      targetSha256: entrySha256,
      inputChannelUsed,
      observedInputHex,
      observedInputSha256,
      inputChannelWitness: {
        boundChannel: boundChannelMeta,
        channelBindingConflict,
        observedInputSha256,
        byteLength: observedInputHex ? observedInputHex.length / 2 : 0,
        consumptionProof: observedInputHex ? 'channel-delivered-prelaunch-verified-not-syscall-traced' : 'unverified',
        stagedInputFiles: writtenInputFiles.map((f) => ({
          path: f.path,
          relativePath: path.relative(baseDir, f.path).replaceAll('\\', '/'),
          bytes: f.bytes,
          sha256: f.sha256,
        })),
      },
      outputChannelUsed,
      outputHex,
      ...(outputExtractionDiagnosis ? { outputExtractionDiagnosis } : {}),
      launchScenario: { argv: effectiveArgs, cwd: baseDir, stdinProvided: stdinHex !== null && stdinHex !== undefined },
      verifiedProcessLineage,
      observedFileWrites: jobReport.observedFileWrites || [],
      applicationReported: {
        trustLevel: 'untrusted-target-claim',
        rawStdoutPreview: stdoutText.slice(0, 1024),
        parsedJson: selfReportedJson,
      },
      cleanup: {
        cleanupVerified: jobReport.cleanupVerified,
        cleanupDisposition: jobReport.cleanupDisposition,
        cleanupEnumerationStatus: jobReport.cleanupEnumerationStatus,
        lingeringOwnedProcessesCount: jobReport.lingeringPidsAfterCleanup?.length ?? null,
      },
    };
  }

  /** Start a long-lived owned process-chain session inside a Win32 Job Object container. */
  async startHeldChainSession({ target, args = null, payloadHex = '41424344', holdMs = 30_000 }) {
    const entryExe = path.resolve(target);
    const key = entryExe.toLowerCase();
    if (this.activeSessions.has(key)) {
      fail('SESSION_ALREADY_ACTIVE', `Active app observer session already exists for ${entryExe}`);
    }
    const runId = `chain-live-${randomUUID()}`;
    const effectiveArgs = Array.isArray(args) && args.length > 0
      ? args.map(String)
      : [`--req=${runId}`, `--payload=${payloadHex}`, `--hold-ms=${holdMs}`];

    const held = await startHeldWin32JobContainer({
      executable: entryExe,
      args: effectiveArgs,
      cwd: path.dirname(entryExe),
      holdMs,
      cfg: this.cfg,
    });

    this.activeSessions.set(key, {
      runId,
      target: entryExe,
      container: held,
      rootPid: held.rootPid,
      creationIdentity: held.rootCreationIdentity,
      rootImageSha256: held.rootImageSha256,
    });

    return {
      ok: true,
      action: 'start',
      runId,
      containerId: held.containerId,
      state: 'running',
      target: entryExe,
      rootPid: held.rootPid,
      creationIdentity: held.rootCreationIdentity,
      targetSha256: held.rootImageSha256,
      ownedPids: held.initialObservedProcesses.map((p) => Number(p.pid)),
      verifiedProcessLineage: held.initialObservedProcesses,
    };
  }

  async stopHeldChainSession({ target, disposition = 'STOP' }) {
    const entryExe = path.resolve(target);
    const key = entryExe.toLowerCase();
    const sess = this.activeSessions.get(key);
    if (!sess) {
      return {
        ok: true,
        action: 'stop',
        state: 'no-task',
        stateName: 'no-task',
        cleanupDisposition: 'no-active-session',
        runId: null,
        killedPids: [],
      };
    }
    const stopReport = await sess.container.stop(disposition);
    this.activeSessions.delete(key);
    return {
      ok: Boolean(stopReport.cleanupVerified),
      action: 'stop',
      runId: sess.runId,
      state: stopReport.cleanupVerified ? 'no-task' : 'cleanup-unknown',
      stateName: stopReport.cleanupVerified ? 'no-task' : 'cleanup-unknown',
      cleanupDisposition: stopReport.cleanupDisposition,
      cleanupEnumerationStatus: stopReport.cleanupEnumerationStatus,
      killedPids: stopReport.killedPids || [],
      lingeringOwnedProcessesCount: stopReport.lingeringPidsAfterCleanup?.length ?? null,
      verifiedProcessLineage: stopReport.systemObservedProcesses || [],
    };
  }

  status() {
    return {
      ok: true,
      action: 'status',
      activeProcessSessions: [...this.activeSessions.values()].map((s) => ({
        runId: s.runId,
        target: s.target,
        rootPid: s.rootPid,
        creationIdentity: s.creationIdentity,
        targetSha256: s.rootImageSha256,
      })),
    };
  }

  async dispose() {
    for (const sess of [...this.activeSessions.values()]) {
      try {
        await this.stopHeldChainSession({ target: sess.target, disposition: 'ABORT' });
      } catch { /* best effort */ }
    }
  }
}
