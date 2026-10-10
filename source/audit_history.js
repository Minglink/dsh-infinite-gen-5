import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const CHUNK = 64 * 1024;
const MAX_LINE = 2 * 1024 * 1024;
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
export function targetIdentity(value, platform = process.platform) {
  if (typeof value !== 'string' || !value) return '';
  const resolved = (platform === 'win32' ? path.win32 : path).resolve(value);
  return platform === 'win32' ? resolved.toLowerCase() : resolved;
}
function identity(stat) { return `${stat.dev}:${stat.ino}`; }
async function openJournal(filename) {
  let before;
  try { before = await fs.promises.lstat(filename, { bigint: true }); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  if (!before.isFile() || before.isSymbolicLink()) fail('AUDIT_CHANGED', 'Audit history must be a regular non-linked file');
  const handle = await fs.promises.open(filename, 'r');
  const opened = await handle.stat({ bigint: true });
  if (identity(before) !== identity(opened)) { await handle.close(); fail('AUDIT_CHANGED', 'Audit history was replaced while opening'); }
  if (opened.size > BigInt(Number.MAX_SAFE_INTEGER)) { await handle.close(); fail('AUDIT_LIMIT', 'Audit history size is not safely addressable'); }
  return { handle, before: opened, size: Number(opened.size) };
}
async function verifyJournal(filename, opened) {
  const after = await fs.promises.lstat(filename, { bigint: true });
  if (!after.isFile() || after.isSymbolicLink() || identity(after) !== identity(opened.before)
      || after.size < opened.before.size || (after.size === opened.before.size && after.mtimeNs !== opened.before.mtimeNs)) {
    fail('AUDIT_CHANGED', 'Audit history was replaced, truncated or rewritten during reading');
  }
}

/** Read newest rows first. A cursor pins file identity and a snapshot byte boundary. */
export async function readAuditPage(filename, { predicate = () => true, scope = '', cursor,
  offset = 0, limit = 20, maxScanBytes = 4 * 1024 * 1024 } = {}) {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 200
      || !Number.isSafeInteger(maxScanBytes) || maxScanBytes < 1 || maxScanBytes > 64 * 1024 * 1024)
    fail('INVALID_INPUT', 'Invalid audit pagination');
  if (cursor !== undefined && (typeof cursor !== 'string' || cursor.length > 2048)) fail('INVALID_INPUT', 'Invalid audit cursor');
  const opened = await openJournal(filename);
  if (!opened) return { rows: [], total: 0, totalExact: true, offset, limit, hasMore: false, scannedBytes: 0 };
  const scopeHash = createHash('sha256').update(scope).digest('hex');
  let end = opened.size, cursorTotal, seenMatches = 0, remainingSkip = 0, matched = 0, scannedBytes = 0, reachedStart = false, stopped = false;
  const matches = [], issues = [];
  try {
    if (cursor) {
      let value; try { value = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')); } catch { fail('INVALID_INPUT', 'Invalid audit cursor'); }
      if (!value || typeof value !== 'object' || Array.isArray(value)) fail('INVALID_INPUT', 'Invalid audit cursor');
      if (value.v !== 2 || value.identity !== identity(opened.before) || value.scope !== scopeHash
          || !Number.isSafeInteger(value.snapshotSize) || value.snapshotSize < value.end || value.snapshotSize > opened.size
          || typeof value.generation !== 'string' || opened.size === value.snapshotSize && value.generation !== String(opened.before.mtimeNs)
          || value.total !== undefined && (!Number.isSafeInteger(value.total) || value.total < 0)
          || value.seenMatches !== undefined && (!Number.isSafeInteger(value.seenMatches) || value.seenMatches < 0)
          || value.remainingSkip !== undefined && (!Number.isSafeInteger(value.remainingSkip) || value.remainingSkip < 0)
          || !Number.isSafeInteger(value.end) || value.end < 0 || value.end > opened.size) fail('STALE_CURSOR', 'Audit cursor belongs to another history or selection');
      end = value.end; cursorTotal = value.total; seenMatches = value.seenMatches || 0; remainingSkip = value.remainingSkip || 0;
    }
    const skip = cursor ? remainingSkip : offset;
    reachedStart = end === 0;
    const scanEntireSmallFile = end <= 256 * 1024;
    let carry = Buffer.alloc(0), position = end;
    const consume = (line, start) => {
      if (!line.length) return;
      if (line.length > MAX_LINE) fail('AUDIT_LINE_LIMIT', 'Audit row exceeds its 2 MiB budget');
      let row; try { row = JSON.parse(line.toString('utf8')); } catch { issues.push('invalid-json-row'); return; }
      if (!predicate(row)) return;
      matched++;
      if (matched > skip && matches.length < limit + 1) matches.push({ row, start });
      if (!scanEntireSmallFile && matches.length > limit) stopped = true;
    };
    while (position > 0 && !stopped && scannedBytes < maxScanBytes) {
      const count = Math.min(CHUNK, position, maxScanBytes - scannedBytes), start = position - count;
      const chunk = Buffer.alloc(count); let read = 0;
      while (read < count) { const value = await opened.handle.read(chunk, read, count - read, start + read); if (!value.bytesRead) fail('AUDIT_CHANGED', 'Audit history became shorter'); read += value.bytesRead; }
      scannedBytes += count; position = start;
      const combined = Buffer.concat([chunk, carry]);
      let last = combined.length;
      for (let index = combined.length - 1; index >= 0 && !stopped; index--) if (combined[index] === 10) {
        consume(combined.subarray(index + 1, last), start + index + 1); last = index;
      }
      if (stopped) break;
      carry = combined.subarray(0, last);
      if (carry.length > MAX_LINE) fail('AUDIT_LINE_LIMIT', 'Audit row exceeds its 2 MiB budget');
      if (position === 0) { consume(carry, 0); reachedStart = true; }
    }
    await verifyJournal(filename, opened);
    const selected = matches.slice(0, limit), partial = !reachedStart && !stopped;
    const hasMore = matches.length > limit || !reachedStart;
    const nextEnd = selected.length ? selected.at(-1).start : Math.max(0, position + carry.length);
    if (partial && hasMore && nextEnd >= end) fail('AUDIT_SCAN_LIMIT', 'Scan budget cannot complete one audit row; increase maxScanBytes');
    const total = cursorTotal ?? (reachedStart && !cursor ? matched : null);
    const nextCursor = hasMore ? Buffer.from(JSON.stringify({ v: 2, identity: identity(opened.before), scope: scopeHash,
      snapshotSize: opened.size, generation: String(opened.before.mtimeNs),
      seenMatches: seenMatches + (selected.length ? skip + selected.length : matched), remainingSkip: Math.max(0, skip - matched),
      end: nextEnd, ...(total !== null ? { total } : {}) })).toString('base64url') : undefined;
    return { rows: selected.map(value => value.row), total, totalExact: total !== null, totalLowerBound: seenMatches + matched,
      offset, limit, hasMore, nextCursor, scannedBytes, partial, issues: [...new Set(issues)],
      ...(partial ? { note: 'Scan budget reached; continue with nextCursor to inspect older records' } : {}) };
  } finally { await opened.handle.close(); }
}

/** Forward streaming is used for export; no historical patch is silently omitted. */
export async function* auditRecords(filename) {
  const opened = await openJournal(filename);
  if (!opened) return;
  let carry = Buffer.alloc(0), position = 0;
  try {
    while (position < opened.size) {
      const chunk = Buffer.alloc(Math.min(CHUNK, opened.size - position));
      const { bytesRead } = await opened.handle.read(chunk, 0, chunk.length, position);
      if (!bytesRead) fail('AUDIT_CHANGED', 'Audit history became shorter');
      position += bytesRead; const bytes = Buffer.concat([carry, chunk.subarray(0, bytesRead)]);
      let start = 0;
      for (let index = 0; index < bytes.length; index++) if (bytes[index] === 10) {
        if (index - start > MAX_LINE) fail('AUDIT_LINE_LIMIT', 'Audit row exceeds its 2 MiB budget');
        const line = bytes.subarray(start, index).toString('utf8'); start = index + 1;
        if (!line.trim()) continue;
        let value; try { value = JSON.parse(line); } catch { fail('AUDIT_CORRUPT', 'Audit history contains a corrupt row; recover it before export'); }
        if (!value || typeof value !== 'object' || Array.isArray(value)) fail('AUDIT_CORRUPT', 'Audit history contains a non-record row; recover it before export');
        yield value;
      }
      carry = Buffer.from(bytes.subarray(start));
      if (carry.length > MAX_LINE) fail('AUDIT_LINE_LIMIT', 'Audit row exceeds its 2 MiB budget');
    }
    // A writer may have crashed in the middle of the final line. Never export it.
    if (carry.length && carry.toString('utf8').trim()) fail('AUDIT_INCOMPLETE', 'Audit history ends in an uncommitted row; recover it before export');
    await verifyJournal(filename, opened);
  } finally { await opened.handle.close(); }
}
