import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { HistoryIndex } from './history_index.js';

export const hashBytes = bytes => createHash('sha256').update(bytes).digest('hex');
function fail(code, message) { throw Object.assign(new Error(message), { code }); }
function actual(pathname, directory = false) {
  const stat = fs.lstatSync(pathname, { bigint: true });
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) fail('INVALID_INPUT', 'Expected a regular, non-linked analysis file or directory');
  return stat;
}
function same(a, b) { return ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key]); }

/** Bounded regular-file read; reject replacement, mutation and special files. */
export function readStableFile(filename, maximum) {
  if (typeof filename !== 'string' || !filename || filename.includes('\0')) fail('INVALID_INPUT', 'input.path must be an explicit file path');
  const resolved = path.resolve(filename), before = actual(resolved);
  if (before.size > BigInt(maximum)) fail('INPUT_LIMIT', `Input exceeds ${maximum} bytes`);
  const fd = fs.openSync(resolved, 'r');
  try {
    if (!same(before, fs.fstatSync(fd, { bigint: true }))) fail('INPUT_CHANGED', 'Input file changed before reading');
    const data = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < data.length) {
      const count = fs.readSync(fd, data, offset, data.length - offset, null);
      if (!count) fail('INPUT_CHANGED', 'Input file became shorter while reading');
      offset += count;
    }
    if (!same(before, fs.fstatSync(fd, { bigint: true })) || !same(before, actual(resolved))) fail('INPUT_CHANGED', 'Input file changed while reading');
    return { data, origin: { kind: 'file', path: resolved } };
  } finally { fs.closeSync(fd); }
}

export function decodeInline(input, maximum) {
  if (!input || typeof input.data !== 'string' || !['hex', 'base64'].includes(input.encoding)) fail('INVALID_INPUT', 'Inline input requires encoding=hex|base64 and data');
  let data;
  if (input.encoding === 'hex') {
    if (input.data.length > maximum * 2) fail('INPUT_LIMIT', 'Hex input exceeds the byte budget');
    if (input.data.length % 2 || !/^[0-9a-f]*$/i.test(input.data)) fail('INVALID_INPUT', 'Hex must contain complete bytes without separators');
    data = Buffer.from(input.data, 'hex');
  } else {
    if (input.data.length > Math.ceil(maximum / 3) * 4) fail('INPUT_LIMIT', 'Base64 input exceeds the byte budget');
    if (input.data.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(input.data)) fail('INVALID_INPUT', 'Base64 must be canonical and padded');
    data = Buffer.from(input.data, 'base64');
    if (data.toString('base64') !== input.data) fail('INVALID_INPUT', 'Non-canonical base64');
  }
  if (data.length > maximum) fail('INPUT_LIMIT', 'Input exceeds the byte budget');
  return { data, origin: { kind: 'inline', encoding: input.encoding } };
}

/** Analysis data are separate from native engine databases. No user-chosen output paths. */
export class AnalysisArtifacts {
  constructor(root) {
    this.root = path.resolve(root);
    fs.mkdirSync(this.root, { recursive: true }); actual(this.root, true);
    for (const part of ['blobs', 'records', 'metadata', 'archived-metadata']) { fs.mkdirSync(path.join(this.root, part), { recursive: true }); actual(path.join(this.root, part), true); }
    this.directoryIdentity = Object.fromEntries(['', 'blobs', 'records', 'metadata', 'archived-metadata'].map(part => [part, actual(path.join(this.root, part), true)]));
    this.historyIndex = new HistoryIndex(this);
    this.archivedIndex = new HistoryIndex(this, 'archived-metadata');
  }
  directory(part) {
    for (const name of ['', part]) {
      const current = actual(path.join(this.root, name), true), expected = this.directoryIdentity[name];
      if (current.dev !== expected.dev || current.ino !== expected.ino) fail('ARTIFACT_CHANGED', 'Analysis artifact directory was replaced');
    }
    return path.join(this.root, part);
  }
  put(bytes) {
    const data = Buffer.from(bytes), sha256 = hashBytes(data), ref = `sha256:${sha256}`;
    const filename = path.join(this.directory('blobs'), `${sha256}.bin`);
    try { fs.writeFileSync(filename, data, { flag: 'wx', mode: 0o600 }); }
    catch (error) { if (error.code !== 'EEXIST') throw error; this.read(ref, data.length); }
    return { ref, sha256, bytes: data.length };
  }
  read(ref, maximum = 8 * 1024 * 1024) {
    if (typeof ref !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(ref)) fail('INVALID_REF', 'Expected a SHA-256 analysis blob reference');
    const { data } = readStableFile(path.join(this.directory('blobs'), `${ref.slice(7)}.bin`), maximum);
    if (hashBytes(data) !== ref.slice(7)) fail('ARTIFACT_CHANGED', 'Analysis blob hash does not match its reference');
    return { data, origin: { kind: 'analysis-ref', ref } };
  }
  save(record) {
    const id = randomUUID(), createdAt = new Date().toISOString();
    const value = { ...record, schemaVersion: 1, id, createdAt };
    const data = Buffer.from(JSON.stringify(value));
    if (data.length > 8 * 1024 * 1024) fail('RESULT_LIMIT', 'Analysis result exceeds 8 MiB');
    const { result, ...metadata } = value;
    metadata.summary = result?.summary || result?.action || result?.op || value.action;
    metadata.recordSha256 = hashBytes(data);
    const metaData = Buffer.from(JSON.stringify(metadata));
    if (metaData.length > 8192) fail('RESULT_LIMIT', 'Analysis metadata exceeds 8 KiB');
    const filename = path.join(this.directory('records'), `${id}.json`);
    const stage = filename + '.partial';
    fs.writeFileSync(stage, data, { flag: 'wx', mode: 0o600 });
    try { fs.renameSync(stage, filename); } catch (error) { fs.unlinkSync(stage); throw error; }
    // Reports and metadata are two files. A missing metadata commit is explicitly
    // unreadable, and listing never parses the much larger result payloads.
    const metaFile = path.join(this.directory('metadata'), `${id}.json`), metaStage = metaFile + '.partial';
    fs.writeFileSync(metaStage, metaData, { flag: 'wx', mode: 0o600 });
    try { fs.renameSync(metaStage, metaFile); } catch (error) { fs.unlinkSync(metaStage); throw error; }
    this.historyIndex.saved(metadata, metaData);
    return value;
  }
  metadata(id, part) {
    if (typeof id !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(id)) fail('INVALID_REF', 'Expected an analysis result UUID');
    const active = path.join(this.directory('metadata'), `${id}.json`);
    const filename = part ? path.join(this.directory(part), `${id}.json`) : fs.existsSync(active) ? active : path.join(this.directory('archived-metadata'), `${id}.json`);
    const { data } = readStableFile(filename, 8192);
    const result = JSON.parse(data.toString('utf8'));
    if (result.id !== id || result.schemaVersion !== 1 || !/^[a-f0-9]{64}$/.test(result.recordSha256)) fail('ARTIFACT_CHANGED', 'Analysis metadata identity mismatch');
    return { result, bytes: data.length, digest: hashBytes(data), archived: filename !== active };
  }
  get(id) {
    const { result: meta } = this.metadata(id);
    const { data } = readStableFile(path.join(this.directory('records'), `${id}.json`), 8 * 1024 * 1024);
    if (hashBytes(data) !== meta.recordSha256) fail('ARTIFACT_CHANGED', 'Analysis report hash does not match committed metadata');
    const result = JSON.parse(data.toString('utf8'));
    if (result.id !== id || result.schemaVersion !== 1) fail('ARTIFACT_CHANGED', 'Analysis result identity mismatch');
    return result;
  }
  list(options = {}) { return (options.archived ? this.archivedIndex : this.historyIndex).list(options); }
  archive(ids, restore = false) {
    if (!Array.isArray(ids) || !ids.length || ids.length > 1000 || new Set(ids).size !== ids.length) fail('INVALID_INPUT', 'Choose 1..1000 distinct report IDs');
    const from = restore ? 'archived-metadata' : 'metadata', to = restore ? 'metadata' : 'archived-metadata';
    const moved = [];
    try {
      for (const id of ids) {
        const { archived } = this.metadata(id);
        if (archived !== restore) continue;
        const source = path.join(this.directory(from), `${id}.json`), destination = path.join(this.directory(to), `${id}.json`);
        if (fs.existsSync(destination)) fail('ARTIFACT_CHANGED', 'Archive destination already exists');
        fs.renameSync(source, destination); moved.push(id);
      }
      return { ok: true, action: restore ? 'restore' : 'archive', ids: moved, retainedRecordsAndBlobs: true };
    } catch (error) { return { ok: false, action: restore ? 'restore' : 'archive', ids: moved, remaining: ids.filter(id => !moved.includes(id)), error: error.message, atomic: false }; }
    finally { this.historyIndex.invalidate(); this.archivedIndex.invalidate(); }
  }
  dispose() { return Promise.all([this.historyIndex.dispose(), this.archivedIndex.dispose()]); }
}
