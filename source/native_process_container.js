// Controlled Windows Job Object process container & fail-closed process ownership verifier.
// Layer: engines (must NOT import from research layer).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function fail(code, message, extra = {}) {
  throw Object.assign(new Error(message), { code, retryable: false, ...extra });
}

export function normalizeExecutableIdentityPath(p) {
  if (typeof p !== 'string' || !p.trim()) return null;
  const resolved = path.resolve(p.trim());
  const realNative = fs.realpathSync.native || fs.realpathSync;
  try {
    return process.platform === 'win32' ? realNative(resolved).toLowerCase() : realNative(resolved);
  } catch {
    return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
  }
}

/**
 * Controlled Python discovery without hardcoded developer Desktop paths.
 */
export function resolveControlledPythonBinary(cfg = {}) {
  const pluginRoot = cfg?.pluginRoot || path.resolve(__dirname, '..');
  const runtimeRoot = cfg?.runtimeRoot || process.env.IG5_RUNTIME_ROOT || path.join(pluginRoot, 'runtimes');
  const candidates = [
    cfg?.pythonBinary,
    process.env.IG5_PYTHON,
    runtimeRoot ? path.join(runtimeRoot, 'ghidra', 'python', process.platform === 'win32' ? 'python.exe' : 'bin/python3') : null,
    runtimeRoot ? path.join(runtimeRoot, 'python', process.platform === 'win32' ? 'python.exe' : 'bin/python3') : null,
  ].filter(Boolean);

  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) {
      return path.resolve(c);
    }
  }
  // Controlled PATH fallback check
  const cmd = process.platform === 'win32' ? 'python' : 'python3';
  try {
    const out = execFileSync(cmd, ['-c', 'import sys; print(sys.executable)'], {
      encoding: 'utf8',
      timeout: 5_000,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
    if (out && fs.existsSync(out)) return path.resolve(out);
  } catch { /* missing */ }

  fail('PYTHON_RUNTIME_UNAVAILABLE', 'Controlled Python 3 runtime is not configured; set IG5_PYTHON or IG5_RUNTIME_ROOT', {
    missingAtom: 'runtime:python3',
  });
}

/**
 * Strict OS process enumeration that NEVER conflates enumeration failure with zero processes.
 * Returns `{ status: 'ok', processes: [...] }` or `{ status: 'enumeration-failed', error, processes: null }`.
 */
export function queryWin32ProcessLineageStrict({ timeoutMs = 10_000 } = {}) {
  if (process.platform !== 'win32') {
    return { status: 'enumeration-failed', error: 'UNSUPPORTED_PLATFORM', processes: null };
  }
  try {
    const ps = execFileSync('powershell.exe', [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      '$ErrorActionPreference="Stop"; @(Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{ ProcessId=[int]$_.ProcessId; ParentProcessId=[int]$_.ParentProcessId; Name=[string]$_.Name; ExecutablePath=$_.ExecutablePath; CommandLine=$_.CommandLine; CreationId=$(if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().Ticks.ToString() } else { $null }) } }) | ConvertTo-Json -Compress',
    ], { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024, windowsHide: true });
    const trimmed = ps.trim();
    if (!trimmed) {
      return { status: 'enumeration-failed', error: 'EMPTY_CIM_OUTPUT', processes: null };
    }
    const parsed = JSON.parse(trimmed);
    const list = Array.isArray(parsed) ? parsed : [parsed];
    return { status: 'ok', error: null, processes: list };
  } catch (err) {
    return {
      status: 'enumeration-failed',
      error: err.code || err.message || 'CIM_QUERY_ERROR',
      processes: null,
    };
  }
}

/**
 * Fail-closed descendant collector:
 * - Requires non-empty `rootCreationIdentity` and `enumResult.status === 'ok'`.
 * - Any candidate row missing `CreationId` or with `CreationId < rootCreationIdentity` is NEVER added to `owned`;
 *   instead it is recorded in `ambiguousOrMissingIdentity` and taints `status` to `'unknown'`.
 */
export function collectVerifiedOwnedProcessTree(enumResult, rootPid, rootCreationIdentity, expectedRootExecutablePath = null) {
  if (!enumResult || enumResult.status !== 'ok' || !Array.isArray(enumResult.processes)) {
    return {
      status: 'unknown',
      reason: enumResult?.error || 'process-enumeration-unavailable',
      owned: [],
      ambiguousOrMissingIdentity: [],
    };
  }
  const numericRootPid = Number(rootPid);
  if (!Number.isSafeInteger(numericRootPid) || numericRootPid <= 0 || !rootCreationIdentity || !/^\d+$/.test(String(rootCreationIdentity))) {
    return {
      status: 'unknown',
      reason: 'missing-root-pid-or-creation-identity',
      owned: [],
      ambiguousOrMissingIdentity: [{ pid: numericRootPid || null, reason: 'missing-root-creation-identity' }],
    };
  }

  const allProcs = enumResult.processes;
  const owned = new Map();
  const ambiguous = [];
  const rootTicks = BigInt(String(rootCreationIdentity));

  const rootCandidate = allProcs.find((p) => Number(p.ProcessId) === numericRootPid);
  if (rootCandidate) {
    if (!rootCandidate.CreationId || !/^\d+$/.test(String(rootCandidate.CreationId))) {
      return {
        status: 'unknown',
        reason: 'live-root-missing-creation-identity',
        owned: [],
        ambiguousOrMissingIdentity: [{ pid: numericRootPid, reason: 'missing-creation-identity' }],
      };
    }
    if (String(rootCandidate.CreationId) !== String(rootCreationIdentity)) {
      // Root PID exited and OS recycled the PID to a newer unrelated process: root itself is gone (not owned!)
      return {
        status: 'ok',
        reason: 'root-pid-recycled-after-exit',
        owned: [],
        ambiguousOrMissingIdentity: [],
      };
    }
    if (expectedRootExecutablePath && rootCandidate.ExecutablePath) {
      if (normalizeExecutableIdentityPath(rootCandidate.ExecutablePath) !== normalizeExecutableIdentityPath(expectedRootExecutablePath)) {
        return {
          status: 'unknown',
          reason: 'root-executable-path-conflict',
          owned: [],
          ambiguousOrMissingIdentity: [{ pid: numericRootPid, reason: 'executable-path-conflict' }],
        };
      }
    }
    owned.set(numericRootPid, rootCandidate);
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const p of allProcs) {
      const pid = Number(p.ProcessId);
      const ppid = Number(p.ParentProcessId);
      if (owned.has(pid)) continue;
      const parentIsOwned = (owned.has(numericRootPid) && ppid === numericRootPid) || owned.has(ppid);
      if (!parentIsOwned) continue;
      if (!p.CreationId || !/^\d+$/.test(String(p.CreationId))) {
        ambiguous.push({ pid, parentPid: ppid, name: p.Name || null, reason: 'missing-child-creation-identity' });
        continue;
      }
      if (BigInt(String(p.CreationId)) < rootTicks) {
        // Parent PID reuse artifact: child predates root creation, so it is a bystander, not our descendant.
        continue;
      }
      owned.set(pid, p);
      changed = true;
    }
  }

  return {
    status: ambiguous.length > 0 ? 'unknown' : 'ok',
    reason: ambiguous.length > 0 ? 'child-creation-identity-missing' : null,
    owned: [...owned.values()],
    ambiguousOrMissingIdentity: ambiguous,
  };
}

/**
 * Fail-closed process terminator:
 * - NEVER kills any record lacking `creationIdentity`.
 * - NEVER kills if process enumeration fails (`status: 'unknown'`).
 * - NEVER kills if `CreationId` or `ExecutablePath` conflicts with the recorded identity.
 */
export function terminateVerifiedOwnedProcessesStrict(ownedRecords, {
  queryImpl = queryWin32ProcessLineageStrict,
  killImpl = (pid) => process.kill(pid, 'SIGKILL'),
} = {}) {
  if (!Array.isArray(ownedRecords) || ownedRecords.length === 0) {
    return {
      status: 'ok',
      killedPids: [],
      alreadyExitedPids: [],
      skippedRecycledPids: [],
      refusedUnknownPids: [],
    };
  }

  const refusedUnknownPids = [];
  const validRecords = [];
  for (const rec of ownedRecords) {
    const pid = Number(rec?.ProcessId ?? rec?.pid);
    const expectedTicks = rec?.CreationId ?? rec?.creationIdentity ?? null;
    if (!Number.isSafeInteger(pid) || pid <= 0 || !expectedTicks || !/^\d+$/.test(String(expectedTicks))) {
      refusedUnknownPids.push({ pid: Number.isFinite(pid) ? pid : null, reason: 'missing-creation-identity' });
    } else {
      validRecords.push({
        pid,
        expectedTicks: String(expectedTicks),
        expectedPath: rec?.ExecutablePath ?? rec?.imagePath ?? rec?.executablePath ?? null,
      });
    }
  }

  // If ANY supplied record lacks creation identity, fail-closed on those records and mark overall status 'unknown'!
  const enumRes = queryImpl();
  if (!enumRes || enumRes.status !== 'ok' || !Array.isArray(enumRes.processes)) {
    return {
      status: 'unknown',
      reason: enumRes?.error || 'enumeration-failed',
      killedPids: [],
      alreadyExitedPids: [],
      skippedRecycledPids: [],
      refusedUnknownPids: [
        ...refusedUnknownPids,
        ...validRecords.map((r) => ({ pid: r.pid, reason: 'enumeration-failed-cannot-verify-identity' })),
      ],
    };
  }

  const curByPid = new Map(enumRes.processes.map((p) => [Number(p.ProcessId), p]));
  const killedPids = [];
  const alreadyExitedPids = [];
  const skippedRecycledPids = [];

  for (const rec of [...validRecords].reverse()) {
    const live = curByPid.get(rec.pid);
    if (!live) {
      alreadyExitedPids.push(rec.pid);
      continue;
    }
    if (!live.CreationId || !/^\d+$/.test(String(live.CreationId))) {
      refusedUnknownPids.push({ pid: rec.pid, reason: 'live-process-missing-creation-identity' });
      continue;
    }
    if (String(live.CreationId) !== rec.expectedTicks) {
      skippedRecycledPids.push(rec.pid);
      continue;
    }
    if (rec.expectedPath) {
      if (!live.ExecutablePath || normalizeExecutableIdentityPath(live.ExecutablePath) !== normalizeExecutableIdentityPath(rec.expectedPath)) {
        refusedUnknownPids.push({ pid: rec.pid, reason: 'executable-path-mismatch-or-missing' });
        continue;
      }
    }
    try {
      killImpl(rec.pid);
      killedPids.push(rec.pid);
    } catch (err) {
      if (err && err.code === 'ESRCH') {
        alreadyExitedPids.push(rec.pid);
      } else {
        refusedUnknownPids.push({ pid: rec.pid, reason: `kill-error:${err?.code || err?.message || 'UNKNOWN'}` });
      }
    }
  }

  return {
    status: refusedUnknownPids.length > 0 ? 'unknown' : 'ok',
    killedPids,
    alreadyExitedPids,
    skippedRecycledPids,
    refusedUnknownPids,
  };
}

function snapshotDirectoryFiles(dirPath, maxDepth = 2) {
  const snap = new Map();
  if (!dirPath || !fs.existsSync(dirPath)) return snap;
  const walk = (cur, depth) => {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { return; }
    for (const ent of entries) {
      if (ent.name === 'node_modules' || ent.name === '.git') continue;
      const full = path.join(cur, ent.name);
      if (ent.isDirectory()) walk(full, depth + 1);
      else if (ent.isFile()) {
        try {
          const st = fs.statSync(full);
          if (st.size <= 4 * 1024 * 1024) {
            snap.set(full, { size: st.size, mtimeMs: st.mtimeMs, sha256: sha256(fs.readFileSync(full)) });
          }
        } catch { /* ignore transient lock */ }
      }
    }
  };
  walk(dirPath, 0);
  return snap;
}

function diffDirectoryWrites(beforeMap, dirPath, maxDepth = 2) {
  const afterMap = snapshotDirectoryFiles(dirPath, maxDepth);
  const writes = [];
  for (const [filePath, meta] of afterMap.entries()) {
    const prev = beforeMap.get(filePath);
    if (!prev || prev.sha256 !== meta.sha256) {
      let previewHex = null;
      try {
        const b = fs.readFileSync(filePath);
        if (b.length <= 65536) previewHex = b.toString('hex');
      } catch { /* ignore */ }
      writes.push({
        path: filePath,
        relativePath: path.relative(dirPath, filePath).replaceAll('\\', '/'),
        bytes: meta.size,
        sha256: meta.sha256,
        changeKind: prev ? 'modified' : 'created',
        bytesHex: previewHex,
      });
    }
  }
  return writes;
}

/**
 * Execute a target binary inside a kernel Win32 Job Object container (`worker/win32_job_supervisor.py`),
 * capturing verified process creation lineage, stdin/stdout/file channels, cancellation propagation,
 * and post-exit zero-residual proof.
 */
export async function runInWin32JobContainer({
  executable,
  args = [],
  cwd = null,
  env = null,
  stdinHex = null,
  timeoutMs = 20_000,
  signal = null,
  watchDir = null,
  cfg = {},
}) {
  if (signal?.aborted) {
    fail('IG5_CANCELLED_BEFORE_DISPATCH', 'Operation aborted before Win32 Job container launch');
  }
  const pythonExe = resolveControlledPythonBinary(cfg);
  const supervisorPy = path.resolve(__dirname, '..', 'worker', 'win32_job_supervisor.py');
  const resolvedExe = path.resolve(executable);
  if (!fs.existsSync(resolvedExe)) {
    fail('ENOENT', `Target executable not found: ${resolvedExe}`);
  }
  const effectiveCwd = cwd ? path.resolve(cwd) : path.dirname(resolvedExe);
  const trackedDir = watchDir ? path.resolve(watchDir) : effectiveCwd;
  const beforeFiles = snapshotDirectoryFiles(trackedDir, 2);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-job-cfg-'));
  const cfgPath = path.join(tmpDir, 'job-config.json');
  fs.writeFileSync(cfgPath, JSON.stringify({
    mode: 'run',
    executable: resolvedExe,
    args,
    cwd: effectiveCwd,
    env,
    stdinHex,
    timeoutMs,
  }), 'utf8');

  try {
    const sup = spawn(pythonExe, [supervisorPy, cfgPath], {
      cwd: effectiveCwd,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const outLines = [];
    const errChunks = [];
    sup.stdout.on('data', (c) => outLines.push(c.toString('utf8')));
    sup.stderr.on('data', (c) => errChunks.push(c.toString('utf8')));

    const onAbort = () => {
      try { sup.stdin.write('ABORT\n'); } catch { /* ignore */ }
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    try {
      await new Promise((resolve, reject) => {
        const hardTimer = setTimeout(() => {
          try { sup.kill('SIGKILL'); } catch { /* ignore */ }
          reject(Object.assign(new Error('Job supervisor hard timeout'), { code: 'SUPERVISOR_TIMEOUT' }));
        }, timeoutMs + 8_000);
        sup.on('close', () => {
          clearTimeout(hardTimer);
          resolve();
        });
        sup.on('error', (e) => {
          clearTimeout(hardTimer);
          reject(e);
        });
      });
    } finally {
      if (signal) signal.removeEventListener('abort', onAbort);
    }

    const lines = outLines.join('').trim().split(/\r?\n/).filter(Boolean);
    const lastLine = lines.at(-1);
    if (!lastLine) {
      fail('SUPERVISOR_EMPTY_OUTPUT', `Win32 Job supervisor returned no report: ${errChunks.join('').slice(0, 512)}`);
    }
    const report = JSON.parse(lastLine);
    if (report.ok === false && report.errorCode) {
      fail(report.errorCode, report.message || `Win32 Job supervisor error: ${report.errorCode}`, report);
    }
    const observedFileWrites = diffDirectoryWrites(beforeFiles, trackedDir, 2);
    return {
      ...report,
      observedFileWrites,
    };
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

/**
 * Start a long-lived held Win32 Job Object container for cross-turn resource ownership,
 * cancellation, and explicit owner `stop` verification.
 */
export async function startHeldWin32JobContainer({
  executable,
  args = [],
  cwd = null,
  env = null,
  holdMs = 30_000,
  cfg = {},
}) {
  const pythonExe = resolveControlledPythonBinary(cfg);
  const supervisorPy = path.resolve(__dirname, '..', 'worker', 'win32_job_supervisor.py');
  const resolvedExe = path.resolve(executable);
  if (!fs.existsSync(resolvedExe)) fail('ENOENT', `Target executable not found: ${resolvedExe}`);
  const effectiveCwd = cwd ? path.resolve(cwd) : path.dirname(resolvedExe);
  const containerId = `job-${randomUUID()}`;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-job-hold-'));
  const cfgPath = path.join(tmpDir, 'job-config.json');
  fs.writeFileSync(cfgPath, JSON.stringify({
    mode: 'hold',
    executable: resolvedExe,
    args,
    cwd: effectiveCwd,
    env,
    timeoutMs: holdMs,
  }), 'utf8');

  const sup = spawn(pythonExe, [supervisorPy, cfgPath], {
    cwd: effectiveCwd,
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let buffer = '';
  const allLines = [];
  let resolveStarted;
  let rejectStarted;
  const startedPromise = new Promise((res, rej) => { resolveStarted = res; rejectStarted = rej; });

  let resolveCompleted;
  const completedPromise = new Promise((res) => { resolveCompleted = res; });

  sup.stdout.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    let idx;
    while ((idx = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (!line) continue;
      allLines.push(line);
      try {
        const msg = JSON.parse(line);
        if (msg.event === 'started') resolveStarted(msg);
        if (msg.event === 'completed') resolveCompleted(msg);
      } catch { /* ignore non-json */ }
    }
  });
  sup.on('close', () => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
    resolveCompleted(null);
    rejectStarted(Object.assign(new Error('Supervisor closed before started event'), { code: 'SUPERVISOR_CLOSED_EARLY' }));
  });

  const startedInfo = await Promise.race([
    startedPromise,
    new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error('Timeout waiting for held Job container start'), { code: 'JOB_START_TIMEOUT' })), 8_000)),
  ]);

  return {
    containerId,
    target: resolvedExe,
    rootPid: startedInfo.rootPid,
    rootCreationIdentity: startedInfo.rootCreationIdentity,
    rootImagePath: startedInfo.rootImagePath,
    rootImageSha256: startedInfo.rootImageSha256,
    initialObservedProcesses: startedInfo.observedProcesses || [],
    async stop(dispositionCommand = 'STOP') {
      try {
        sup.stdin.write(`${dispositionCommand}\n`);
      } catch { /* already closed */ }
      const completed = await Promise.race([
        completedPromise,
        new Promise((res) => setTimeout(() => res(null), 5_000)),
      ]);
      if (!completed) {
        try { sup.kill('SIGKILL'); } catch { /* ignore */ }
        return {
          ok: false,
          cleanupDisposition: 'unknown-supervisor-unresponsive',
          cleanupEnumerationStatus: 'enumeration-failed',
          cleanupVerified: false,
          killedPids: [],
          lingeringPidsAfterCleanup: null,
          systemObservedProcesses: startedInfo.observedProcesses || [],
        };
      }
      return completed;
    },
  };
}
