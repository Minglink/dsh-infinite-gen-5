import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import { randomUUID } from 'node:crypto';

const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const pid = value => Number.isSafeInteger(value) && value > 0;
const identity = value => value === null || typeof value === 'string' && /^\d+$/.test(value);

/** OS process creation identity. Failure is unknown, never permission to release a lease. */
export function processCreationIdentity(processId) {
  if (!pid(processId)) return null;
  try {
    if (process.platform === 'win32') {
      const value = execFileSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
        `(Get-Process -Id ${processId} -ErrorAction Stop).StartTime.ToUniversalTime().Ticks.ToString()`],
      { encoding: 'utf8', windowsHide: true, timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      return /^\d+$/.test(value) ? value : null;
    }
    if (process.platform === 'linux') {
      const stat = fs.readFileSync(`/proc/${processId}/stat`, 'utf8');
      const value = stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19];
      return /^\d+$/.test(value || '') ? value : null;
    }
  } catch {}
  return null;
}

export function validAttachmentLease(value) {
  return !!value && value.schema === 1 && uuid(value.nonce) && typeof value.platform === 'string' && typeof value.hostName === 'string'
    && ['host', 'worker'].every(key => value[key] && pid(value[key].pid) && identity(value[key].creationIdentity));
}

export function captureAttachmentLease(workerPid, hostCreationIdentity) {
  if (!pid(workerPid) || workerPid === process.pid) throw Object.assign(new Error('A distinct worker PID is required for an attachment lease'), { code: 'INVALID_ATTACHMENT_OWNER' });
  return { schema: 1, nonce: randomUUID(), platform: process.platform, hostName: os.hostname(),
    host: { pid: process.pid, creationIdentity: hostCreationIdentity ?? processCreationIdentity(process.pid) },
    worker: { pid: workerPid, creationIdentity: processCreationIdentity(workerPid) } };
}

/** Both original process identities must be demonstrably gone; PID existence alone is insufficient. */
export function probeAttachmentLease(value) {
  if (!validAttachmentLease(value)) return { releasable: false, reason: 'legacy-or-invalid-owner' };
  if (value.platform !== process.platform || value.hostName !== os.hostname()) return { releasable: false, reason: 'foreign-host' };
  const inspect = owner => {
    if (!owner.creationIdentity) return { state: 'unknown', reason: 'missing-creation-identity' };
    try { process.kill(owner.pid, 0); }
    catch (error) { return error.code === 'ESRCH' ? { state: 'dead', reason: 'pid-gone' } : { state: 'unknown', reason: 'process-probe-failed' }; }
    const current = processCreationIdentity(owner.pid);
    if (!current) return { state: 'unknown', reason: 'creation-identity-unavailable' };
    return current === owner.creationIdentity ? { state: 'alive', reason: 'same-process' } : { state: 'dead', reason: 'pid-reused' };
  };
  const host = inspect(value.host), worker = inspect(value.worker);
  return { releasable: host.state === 'dead' && worker.state === 'dead', reason: host.state !== 'dead' ? 'host-' + host.state : worker.state !== 'dead' ? 'worker-' + worker.state : 'both-owners-dead', host, worker };
}
