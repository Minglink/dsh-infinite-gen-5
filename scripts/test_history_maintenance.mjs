import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { AnalysisArtifacts, hashBytes } from '../source/analysis_artifacts.js';
import { analyzeProtocol } from '../source/protocol_analysis.js';

const temporary = fs.realpathSync(os.tmpdir());
function fixture(t) {
  const root = fs.mkdtempSync(path.join(temporary, 'ig5-history-maintenance-'));
  const store = new AnalysisArtifacts(root);
  t.after(async () => {
    await store.dispose();
    const resolved = path.resolve(root);
    assert(resolved.startsWith(temporary + path.sep)); fs.rmSync(resolved, { recursive: true, force: true });
  });
  return { root, store };
}
const association = { target: 'C:\\fixtures\\generated sample.bin', engine: 'reverse', artifactId: 'artifact_' + 'a'.repeat(64), dbRevision: 1 };
function save(store, label, assoc = association) {
  return store.save({ kind: 'protocol', action: 'decode', association: assoc,
    input: { sha256: hashBytes(Buffer.from(label)) }, result: { action: 'decode', summary: label } });
}
const rejectsCode = (run, code) => assert.rejects(run, error => error.code === code);

test('active/archive pages retain IDs, reports and reusable blob bytes after a store restart', async t => {
  const { root, store } = fixture(t), payload = Buffer.from('00060148454c4c4f', 'hex'), blob = store.put(payload);
  const record = store.save({ kind: 'protocol', action: 'inspect', association, input: blob,
    result: { action: 'inspect', output: { dataRef: { ...blob, producer: { resultId: 'fixture-producer' } } } } });
  const second = save(store, 'second');
  const foreign = save(store, 'foreign', { ...association, target: 'C:\\fixtures\\other.bin', engine: 'ghidra' });
  const active = await store.list({ target: association.target.toUpperCase(), engine: 'reverse', limit: 100 });
  assert.equal(active.partial, false); assert.equal(active.total, 2); assert.deepEqual(new Set(active.items.map(item => item.id)), new Set([record.id, second.id]));
  assert(active.items.every(item => !Object.hasOwn(item, 'recordSha256')));
  const archived = store.archive([record.id, second.id]); assert.equal(archived.ok, true); assert.equal(archived.retainedRecordsAndBlobs, true);
  assert.equal((await store.list()).total, 1); assert.equal((await store.list({ archived: true })).total, 2);
  assert.deepEqual(store.get(record.id), record); assert.deepEqual(store.read(blob.ref).data, payload);
  assert.deepEqual(store.archive([record.id]).ids, [], 'archiving an archived report is idempotent');
  const reopened = new AnalysisArtifacts(root); t.after(() => reopened.dispose());
  const page = await reopened.list({ archived: true, target: association.target, engine: 'reverse' }); assert.equal(page.total, 2);
  const recoveredRef = reopened.get(record.id).result.output.dataRef.ref;
  const decoded = analyzeProtocol({ action: 'decode', data: reopened.read(recoveredRef).data.toString('hex'), encoding: 'hex',
    framing: { type: 'length-prefix', size: 2, endian: 'big', headerLength: 2 },
    schema: { fields: [{ name: 'message', offset: 3, type: 'utf8', length: 5 }] } });
  assert.equal(decoded.frames[0].fields[0].value, 'HELLO');
  assert.equal(reopened.archive([record.id], true).ok, true);
  assert.equal((await reopened.list()).total, 2); assert.equal((await reopened.list({ archived: true })).total, 1);
  assert.deepEqual(reopened.get(record.id), record); assert.deepEqual(reopened.read(recoveredRef).data, payload);
  assert.equal(reopened.get(foreign.id).id, foreign.id);
});

test('cached selected metadata rewrites, report corruption and blob corruption fail closed', async t => {
  const { root, store } = fixture(t), first = save(store, 'committed');
  const baseline = await store.list(); assert.equal(baseline.items[0].id, first.id);
  const metaFile = path.join(root, 'metadata', first.id + '.json'), metadata = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
  fs.writeFileSync(metaFile, JSON.stringify({ ...metadata, summary: 'rewritten metadata' }));
  await rejectsCode(() => store.list(), 'ARTIFACT_CHANGED');
  fs.writeFileSync(metaFile, JSON.stringify(metadata)); store.historyIndex.invalidate(); await store.list();
  const reportFile = path.join(root, 'records', first.id + '.json'), report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
  fs.writeFileSync(reportFile, JSON.stringify({ ...report, result: { action: 'forged' } }));
  assert.throws(() => store.get(first.id), { code: 'ARTIFACT_CHANGED' });
  const blob = store.put(Buffer.from('bounded payload')); fs.writeFileSync(path.join(root, 'blobs', blob.sha256 + '.bin'), Buffer.from('tampered payload'));
  assert.throws(() => store.read(blob.ref), { code: 'ARTIFACT_CHANGED' });
  const archivedRecord = save(store, 'archived metadata'); store.archive([archivedRecord.id]); await store.list({ archived: true });
  const archivedFile = path.join(root, 'archived-metadata', archivedRecord.id + '.json'), archiveMetadata = JSON.parse(fs.readFileSync(archivedFile, 'utf8'));
  fs.writeFileSync(archivedFile, JSON.stringify({ ...archiveMetadata, id: randomUUID() }));
  await rejectsCode(() => store.list({ archived: true }), 'ARTIFACT_CHANGED');
});

test('replacing either metadata directory or the blob directory cannot redirect a live store', async t => {
  for (const part of ['metadata', 'archived-metadata', 'blobs']) {
    const { root, store } = fixture(t), record = save(store, 'directory identity'), blob = store.put(Buffer.from('same bytes'));
    if (part === 'archived-metadata') store.archive([record.id]);
    await store.list({ archived: part === 'archived-metadata' });
    const source = path.resolve(root, part), moved = path.resolve(root, part + '-original');
    assert(source.startsWith(root + path.sep) && moved.startsWith(root + path.sep));
    fs.renameSync(source, moved); fs.mkdirSync(source);
    if (part === 'blobs') {
      fs.writeFileSync(path.join(source, blob.sha256 + '.bin'), Buffer.from('same bytes'));
      assert.throws(() => store.read(blob.ref), { code: 'ARTIFACT_CHANGED' });
    } else {
      for (const file of fs.readdirSync(moved)) fs.copyFileSync(path.join(moved, file), path.join(source, file));
      await rejectsCode(() => store.list({ archived: part === 'archived-metadata' }), 'ARTIFACT_CHANGED');
      assert.throws(() => store.get(record.id), { code: 'ARTIFACT_CHANGED' });
    }
  }
});

function metadataRow(index, bytes = 8000) {
  const id = randomUUID(), row = { schemaVersion: 1, id, createdAt: new Date(Date.UTC(2025, 0, 1) + index).toISOString(),
    association, summary: 'generated bounded history ' + index, recordSha256: 'b'.repeat(64), padding: '' };
  row.padding = 'x'.repeat(bytes - Buffer.byteLength(JSON.stringify(row)));
  const data = Buffer.from(JSON.stringify(row)); assert.equal(data.length, bytes); return { id, data };
}

test('more than 16 MiB of metadata advances across bounded async batches and caches complete pages', async t => {
  const { root, store } = fixture(t), count = 2300, expected = [];
  for (let index = 0; index < count; index++) {
    const row = metadataRow(index); expected.push(row.id); fs.writeFileSync(path.join(root, 'metadata', row.id + '.json'), row.data);
  }
  store.historyIndex.invalidate(); let eventLoopYielded = false; setImmediate(() => { eventLoopYielded = true; });
  const first = await store.list({ limit: 2 });
  assert(eventLoopYielded, 'index building must yield while reading metadata');
  assert.equal(first.partial, true); assert.equal(first.total, null); assert(first.totalLowerBound > 0 && first.totalLowerBound < count);
  assert(first.indexBytesRead <= 16 * 1024 * 1024); assert(first.metadataBytesRead <= 2 * 8192); assert.equal(first.cacheHit, false);
  const second = await store.list({ limit: 2 });
  assert.equal(second.partial, false); assert.equal(second.total, count); assert(second.indexBytesRead > 0 && second.indexBytesRead <= 16 * 1024 * 1024);
  assert.deepEqual(second.items.map(item => item.id), expected.slice(-2).reverse());
  const page = await store.list({ offset: 100, limit: 3 });
  assert.equal(page.cacheHit, true); assert.equal(page.indexBytesRead, 0); assert.equal(page.total, count); assert.equal(page.metadataBytesRead, 3 * 8000);
  assert.deepEqual(page.items.map(item => item.id), expected.slice(count - 103, count - 100).reverse());
  const empty = await store.list({ offset: count + 10, limit: 2 }); assert.equal(empty.items.length, 0); assert.equal(empty.cacheHit, true); assert.equal(empty.metadataBytesRead, 0);
});

test('directory-entry budget counts unrelated files, and archived indexing uses the same bounded contract', async t => {
  const { root, store } = fixture(t);
  for (let index = 0; index < 10005; index++) fs.writeFileSync(path.join(root, 'archived-metadata', 'unrelated-' + index + '.tmp'), '');
  store.archivedIndex.invalidate(); const first = await store.list({ archived: true });
  assert.equal(first.partial, true); assert.equal(first.indexing, true); assert.equal(first.total, null); assert.equal(first.indexBytesRead, 0);
  const second = await store.list({ archived: true }); assert.equal(second.partial, false); assert.equal(second.total, 0);
  assert.equal((await store.list({ archived: true })).cacheHit, true);
});

test('invalid pagination and archive IDs fail without moving committed records', async t => {
  const { root, store } = fixture(t), record = save(store, 'safe pagination');
  for (const archived of [false, true]) {
    for (const offset of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '0', 0n]) await rejectsCode(() => store.list({ offset, archived }), 'INVALID_INPUT');
    for (const limit of [0, 101, -1, 1.5, '20']) await rejectsCode(() => store.list({ limit, archived }), 'INVALID_INPUT');
  }
  for (const ids of [[], [record.id, record.id], new Array(1001).fill(record.id), 'id']) assert.throws(() => store.archive(ids), { code: 'INVALID_INPUT' });
  assert(fs.existsSync(path.join(root, 'metadata', record.id + '.json'))); assert.deepEqual(store.get(record.id), record);
  const result = store.archive([record.id, 'not-a-uuid']); assert.equal(result.ok, false); assert.equal(result.atomic, false); assert.deepEqual(result.ids, [record.id]);
  assert.deepEqual(result.remaining, ['not-a-uuid']); assert.deepEqual(store.get(record.id), record);
});
