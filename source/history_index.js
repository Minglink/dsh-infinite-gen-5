import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { targetIdentity } from './audit_history.js';

const ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const hash = value => createHash('sha256').update(value).digest('hex');
const stamp = value => `${value.dev}:${value.ino}:${value.mtimeNs}`;
const equalFile = (a, b) => ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key]);
function compact(row, digest) {
  return { id: row.id, createdAt: row.createdAt, target: targetIdentity(row.association?.target),
    engine: row.association?.engine, digest };
}
const order = (a, b) => b.createdAt.localeCompare(a.createdAt) || b.id.localeCompare(a.id);

/** Build compact metadata indexes asynchronously, once per directory generation. */
export class HistoryIndex {
  constructor(store, part = 'metadata') {
    this.store = store; this.part = part; this.cache = null; this.scan = null; this.inflight = null;
    const probe = fs.opendirSync(store.directory(part));
    try { if (!probe.readSync()) this.cache = { stamp: stamp(fs.lstatSync(store.directory(part), { bigint: true })), rows: [], complete: true }; }
    finally { probe.closeSync(); }
  }
  invalidate() { this.cache = null; if (this.scan) { this.scan.invalidated = true; } }
  saved(row, data) {
    if (!this.cache?.complete || this.scan) { this.invalidate(); return; }
    const entry = compact(row, hash(data)), rows = this.cache.rows;
    let left = 0, right = rows.length;
    while (left < right) { const middle = (left + right) >>> 1; if (order(rows[middle], entry) < 0) left = middle + 1; else right = middle; }
    rows.splice(left, 0, entry);
    this.cache.stamp = stamp(fs.lstatSync(this.store.directory(this.part), { bigint: true }));
    if (rows.length > 100000) this.invalidate();
  }
  async refresh() {
    if (this.inflight) return this.inflight;
    this.inflight = this.build().catch(async error => {
      if (this.scan) { await this.scan.directory.close().catch(() => {}); this.scan = null; }
      this.cache = null; throw error;
    }).finally(() => { this.inflight = null; });
    return this.inflight;
  }
  async build() {
    const directory = this.store.directory(this.part), currentStamp = stamp(await fs.promises.lstat(directory, { bigint: true }));
    if (this.cache?.complete && this.cache.stamp === currentStamp) return { cacheHit: true, indexBytesRead: 0 };
    if (this.scan && (this.scan.invalidated || this.scan.stamp !== currentStamp)) { await this.scan.directory.close(); this.scan = null; }
    if (!this.scan) this.scan = { directory: await fs.promises.opendir(directory), rows: [], stamp: currentStamp, invalidated: false };
    const scan = this.scan; let count = 0, bytes = 0, complete = false;
    while (count < 10000 && bytes + 8192 <= 16 * 1024 * 1024 && scan.rows.length < 100000) {
      const entry = await scan.directory.read();
      if (!entry) { complete = true; break; }
      count++;
      if (!entry.name.endsWith('.json') || !ID.test(entry.name.slice(0, -5))) continue;
      const filename = path.join(directory, entry.name), before = await fs.promises.lstat(filename, { bigint: true });
      if (!before.isFile() || before.isSymbolicLink() || before.size > 8192n) fail('ARTIFACT_CHANGED', 'Invalid history metadata file');
      const handle = await fs.promises.open(filename, 'r'); let data;
      try {
        if (!equalFile(before, await handle.stat({ bigint: true }))) fail('ARTIFACT_CHANGED', 'History metadata was replaced');
        data = Buffer.alloc(Number(before.size));
        for (let position = 0; position < data.length;) { const value = await handle.read(data, position, data.length - position, position); if (!value.bytesRead) fail('ARTIFACT_CHANGED', 'History metadata became shorter'); position += value.bytesRead; }
        if (!equalFile(before, await handle.stat({ bigint: true })) || !equalFile(before, await fs.promises.lstat(filename, { bigint: true }))) fail('ARTIFACT_CHANGED', 'History metadata changed while indexing');
      } finally { await handle.close(); }
      const row = JSON.parse(data.toString('utf8'));
      if (row.id !== entry.name.slice(0, -5) || row.schemaVersion !== 1 || typeof row.createdAt !== 'string' || !/^[a-f0-9]{64}$/.test(row.recordSha256)) fail('ARTIFACT_CHANGED', 'History metadata identity mismatch');
      scan.rows.push(compact(row, hash(data))); bytes += data.length;
    }
    if (scan.invalidated || stamp(await fs.promises.lstat(directory, { bigint: true })) !== scan.stamp) {
      await scan.directory.close(); this.scan = null; this.cache = null;
      return { cacheHit: false, indexBytesRead: bytes, changed: true };
    }
    scan.rows.sort(order); this.cache = { stamp: scan.stamp, rows: scan.rows, complete };
    if (complete) { await scan.directory.close(); this.scan = null; }
    return { cacheHit: false, indexBytesRead: bytes };
  }
  async list({ target, engine, offset = 0, limit = 20 } = {}) {
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) fail('INVALID_INPUT', 'Invalid result pagination');
    const indexed = await this.refresh();
    if (indexed.changed) return { items: [], total: null, offset, limit, partial: true, indexing: true, note: 'History changed while indexing; refresh to continue', metadataBytesRead: 0 };
    const normalized = targetIdentity(target), rows = this.cache.rows.filter(row => (!normalized || row.target === normalized) && (!engine || !row.engine || row.engine === engine));
    let metadataBytesRead = 0;
    const items = rows.slice(offset, offset + limit).map(entry => {
      const { result: row, bytes, digest } = this.store.metadata(entry.id, this.part);
      if (digest !== entry.digest) { this.invalidate(); fail('ARTIFACT_CHANGED', 'Indexed metadata was rewritten; refresh the history'); }
      metadataBytesRead += bytes; const { recordSha256, ...visible } = row; return visible;
    });
    return { total: this.cache.complete ? rows.length : null, totalLowerBound: rows.length, offset, limit, items,
      metadataBytesRead, ...indexed, partial: !this.cache.complete, indexing: !this.cache.complete,
      hasMore: offset + items.length < rows.length || !this.cache.complete,
      ...(!this.cache.complete ? { note: 'History index is partial; refresh to continue indexing or archive older reports' } : {}) };
  }
  async dispose() {
    await this.inflight?.catch(() => {});
    if (this.scan) { await this.scan.directory.close(); this.scan = null; }
    this.cache = null;
  }
}
