// Pure file fixtures and a mock database; never starts or executes a sample.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { exportPatchDiff } from '../source/patch_export.js';

const tempRoot = fs.realpathSync(os.tmpdir());
const scratch = fs.mkdtempSync(path.join(tempRoot, 'ig5-patch-scope-'));
const hash = value => createHash('sha256').update(value).digest('hex');
let passed = 0, serial = 0;
async function test(name, callback) {
  await callback(); passed++; console.log(`PASS ${name}`);
}
function fixture(image = Buffer.from(Array.from({ length: 64 }, (_, index) => index))) {
  const directory = path.join(scratch, String(++serial)); fs.mkdirSync(directory);
  const target = path.join(directory, 'sample.bin'), artifactDir = path.join(directory, 'artifacts');
  fs.mkdirSync(artifactDir); fs.writeFileSync(target, image);
  const session = { artifactId: 'artifact-current', sha256: hash(image), attachmentId: 'attachment-current',
    engine: 'reverse', projectId: 'project-current' };
  const attachments = new Map([[session.attachmentId, { artifactId: session.artifactId, engine: session.engine, databaseId: 'database-current' }]]);
  const db = Buffer.from(image), calls = [], registrations = [];
  const evidence = () => ({ artifactId: session.artifactId, sha256: session.sha256,
    attachmentId: session.attachmentId, engine: session.engine });
  const patch = (overrides = {}) => ({ applied: true, ea: '0x1010', fileOffset: 16, size: 2,
    before: '1011', after: 'aabb', ...overrides });
  const row = (overrides = {}) => ({ tool: 'ig5_patch_bytes', args: { target, engine: session.engine },
    isError: false, detail: { ...patch(), _ig5: evidence() }, ...overrides });
  const writeRows = rows => fs.writeFileSync(path.join(artifactDir, 'approvals.jsonl'), rows.map(value => JSON.stringify(value)).join('\n') + '\n');
  const mgr = {
    get: () => session, alive: value => value === session,
    projects: {
      getAttachment(id) { if (!attachments.has(id)) throw new Error('Unknown attachment'); return attachments.get(id); },
      open(filename, options) { registrations.push({ filename, options }); return { projectId: session.projectId, artifactId: 'artifact-derived' }; },
    },
    async rpc(value, method, params) {
      assert.equal(value, session); calls.push({ method, params });
      const fileOffset = Number(BigInt(params.ea) - 0x1000n);
      if (method === 'fileoffset') return { contiguous: true, size: params.size, fileOffset };
      if (method === 'bytes') return { hex: db.subarray(fileOffset, fileOffset + params.size).toString('hex') };
      throw new Error('Unexpected RPC');
    },
  };
  return { target, artifactDir, image, session, attachments, db, calls, registrations, evidence, patch, row, writeRows, mgr,
    cfg: { artifactDir, host: { platform: 'win32' } }, export: () => exportPatchDiff({ target, mgr, cfg: { artifactDir, host: { platform: 'win32' } } }) };
}
const reject = (promise, code) => assert.rejects(promise, error => error.code === code);
const unchanged = value => assert.deepEqual(fs.readFileSync(value.target), value.image, 'Original input must remain unchanged');
const noPublication = value => {
  const directory = path.join(value.artifactDir, 'exports');
  const files = fs.existsSync(directory) ? fs.readdirSync(directory, { recursive: true }).filter(name => /\.ig5-patched$|\.partial$|\.changes\.md$/.test(name)) : [];
  assert.deepEqual(files, [], 'Failed export must not publish or leave a staged binary');
};

try {
  await test('same path with a different artifact/hash cannot replay old patches', async () => {
    const f = fixture(); const old = f.row(); old.detail._ig5.artifactId = 'artifact-old'; old.detail._ig5.sha256 = '1'.repeat(64);
    f.writeRows([old]); const result = await f.export();
    assert.equal(result.patches, 0); assert.equal(result.excludedHistory.foreignArtifact, 1); assert.equal(result.patchedBinary, undefined);
    assert.deepEqual(f.calls, []); unchanged(f);
  });
  await test('same artifact id but a different SHA-256 is excluded', async () => {
    const f = fixture(); const old = f.row(); old.detail._ig5.sha256 = '1'.repeat(64); f.writeRows([old]);
    const result = await f.export(); assert.equal(result.patches, 0); assert.equal(result.excludedHistory.foreignArtifact, 1); unchanged(f);
  });
  await test('Windows path case and separators share one identity', async () => {
    const f = fixture(); const record = f.row(); record.args.target = f.target.toUpperCase().replaceAll('\\', '/'); f.db[16] = 0xaa; f.db[17] = 0xbb;
    f.writeRows([record]); const result = await f.export();
    assert.equal(result.patches, 1); assert.equal(fs.readFileSync(result.patchedBinary)[16], 0xaa); unchanged(f);
  });
  await test('foreign targets and foreign engines cannot contribute evidence', async () => {
    const f = fixture(); const other = f.row({ args: { target: path.join(path.dirname(f.target), 'other.bin') } });
    const engine = f.row(); engine.detail._ig5.engine = 'ghidra'; f.writeRows([other, engine]);
    const result = await f.export(); assert.equal(result.patches, 0); assert.deepEqual(f.calls, []); unchanged(f);
  });
  await test('another database for the same sample is excluded', async () => {
    const f = fixture(); f.attachments.set('attachment-other', { artifactId: f.session.artifactId, engine: 'reverse', databaseId: 'database-other' });
    const record = f.row(); record.detail._ig5.attachmentId = 'attachment-other'; f.writeRows([record]);
    const result = await f.export(); assert.equal(result.patches, 0); assert.equal(result.excludedHistory.foreignDatabase, 1); unchanged(f);
  });
  await test('historical attachment of the same physical database remains bound', async () => {
    const f = fixture(); f.attachments.set('attachment-previous', { artifactId: f.session.artifactId, engine: 'reverse', databaseId: 'database-current' });
    const record = f.row(); record.detail._ig5.attachmentId = 'attachment-previous'; f.db[16] = 0xff; f.writeRows([record]);
    const result = await f.export(); assert.equal(result.patches, 1); assert.equal(fs.readFileSync(result.patchedBinary)[16], 0xff); unchanged(f);
  });
  await test('unknown attachments fail their database binding', async () => {
    const f = fixture(); const record = f.row(); record.detail._ig5.attachmentId = 'attachment-missing'; f.writeRows([record]);
    const result = await f.export(); assert.equal(result.patches, 0); assert.equal(result.excludedHistory.foreignDatabase, 1); unchanged(f);
  });
  await test('applied unbound legacy patches fail closed even beside valid evidence', async () => {
    const f = fixture(); const legacy = f.row(); delete legacy.detail._ig5; f.writeRows([f.row(), legacy]);
    await reject(f.export(), 'UNBOUND_PATCH_HISTORY'); assert.deepEqual(f.calls, []); unchanged(f); noPublication(f);
  });
  await test('failed/unapplied historical operations are not patch evidence', async () => {
    const f = fixture(); const failed = f.row({ isError: true }); delete failed.detail._ig5;
    const preview = f.row(); preview.detail.applied = false; delete preview.detail._ig5; f.writeRows([failed, preview]);
    const result = await f.export(); assert.equal(result.patches, 0); assert.equal(result.excludedHistory.unbound, 0); unchanged(f);
  });
  await test('sync evidence belongs to its destination database and engine', async () => {
    const f = fixture(); f.db[16] = 0x99;
    f.writeRows([{ tool: 'ig5_sync', args: { target: f.target, engine: 'ghidra' }, detail: {
      destination: f.evidence(), applied: [{ kind: 'rename', result: { applied: true } }, { kind: 'patch', result: f.patch() }] } }]);
    const result = await f.export(); assert.equal(result.patches, 1); assert.equal(fs.readFileSync(result.patchedBinary)[16], 0x99); unchanged(f);
  });
  await test('current database bytes override historical after bytes', async () => {
    const f = fixture(); f.db[16] = 0xcc; f.db[17] = 0xdd; f.writeRows([f.row()]);
    const result = await f.export(); const output = fs.readFileSync(result.patchedBinary);
    assert.equal(output.subarray(16, 18).toString('hex'), 'ccdd'); assert.match(fs.readFileSync(result.report, 'utf8'), /\| 1011 \| ccdd \|/);
    assert.equal(result.auditedRegions, 1); assert.equal(result.sampleSha256, f.session.sha256);
    assert.equal(f.registrations[0].options.derivedFrom, f.session.artifactId); unchanged(f);
  });
  await test('Undo exports original current bytes and no changed ranges', async () => {
    const f = fixture(); f.writeRows([f.row()]); const result = await f.export();
    assert.equal(result.patches, 0); assert.equal(result.auditedRegions, 1); assert.deepEqual(fs.readFileSync(result.patchedBinary), f.image);
    assert.equal(f.registrations[0].options.derivedFrom, undefined); assert.doesNotMatch(fs.readFileSync(result.report, 'utf8'), /\| 1011 \| aabb \|/); unchanged(f);
  });
  await test('pre-existing report hardlinks cannot overwrite the original input', async () => {
    const f = fixture(); f.db[16] = 0x99; f.writeRows([f.row()]);
    const directory = path.join(f.artifactDir, 'exports', f.session.artifactId, f.session.engine); fs.mkdirSync(directory, { recursive: true });
    const report = path.join(directory, path.basename(f.target) + '.changes.md'); fs.linkSync(f.target, report);
    const result = await f.export(); assert.equal(result.patches, 1); unchanged(f);
    assert.match(fs.readFileSync(result.report, 'utf8'), /# IG5/); assert.notEqual(fs.statSync(report, { bigint: true }).ino, fs.statSync(f.target, { bigint: true }).ino);
  });
  await test('duplicate historical ranges are read once in current database', async () => {
    const f = fixture(); f.db[16] = 0x99; f.writeRows([f.row(), f.row()]); const result = await f.export();
    assert.equal(result.auditedRegions, 1); assert.equal(f.calls.filter(value => value.method === 'bytes').length, 1); unchanged(f);
  });
  await test('noncontiguous mappings reject instead of projecting a partial range', async () => {
    const f = fixture(); f.writeRows([f.row()]); f.mgr.rpc = async () => ({ contiguous: false, size: 2, fileOffset: 16 });
    await reject(f.export(), 'PATCH_MAPPING_CHANGED'); unchanged(f); noPublication(f);
  });
  await test('changed mapping size or file offset rejects', async () => {
    for (const mapping of [{ contiguous: true, size: 1, fileOffset: 16 }, { contiguous: true, size: 2, fileOffset: 17 }]) {
      const f = fixture(); f.writeRows([f.row()]); f.mgr.rpc = async () => mapping;
      await reject(f.export(), 'PATCH_MAPPING_CHANGED'); unchanged(f); noPublication(f);
    }
  });
  await test('out-of-file audited ranges reject before database reads', async () => {
    const f = fixture(); f.writeRows([f.row({ detail: { ...f.patch({ fileOffset: 63, ea: '0x103f' }), _ig5: f.evidence() } })]);
    await reject(f.export(), 'INVALID_PATCH_EVIDENCE'); assert.deepEqual(f.calls, []); unchanged(f); noPublication(f);
  });
  await test('invalid size, address, file offset and after evidence reject', async () => {
    for (const bad of [{ size: 0 }, { size: 4097 }, { fileOffset: -1 }, { fileOffset: 1.5 }, { ea: '0x10000000000000000' }, { after: 'aa' }, { after: 'zzzz' }]) {
      const f = fixture(); f.writeRows([f.row({ detail: { ...f.patch(bad), _ig5: f.evidence() } })]);
      await reject(f.export(), 'INVALID_PATCH_EVIDENCE'); unchanged(f); noPublication(f);
    }
  });
  await test('incomplete current database bytes reject', async () => {
    const f = fixture(); f.writeRows([f.row()]); const originalRpc = f.mgr.rpc;
    f.mgr.rpc = (session, method, args) => method === 'bytes' ? { hex: 'aa' } : originalRpc(session, method, args);
    await reject(f.export(), 'INVALID_PATCH_EVIDENCE'); unchanged(f); noPublication(f);
  });
  await test('a changed source hash requires reopening before export', async () => {
    const f = fixture(); f.writeRows([f.row()]); const changed = Buffer.from(f.image); changed[0] ^= 1; fs.writeFileSync(f.target, changed);
    await reject(f.export(), 'INPUT_CHANGED'); assert.deepEqual(f.calls, []); assert.deepEqual(fs.readFileSync(f.target), changed); noPublication(f);
  });
  await test('source mutation during current-byte collection aborts publication', async () => {
    const f = fixture(); f.writeRows([f.row()]); const originalRpc = f.mgr.rpc; let changed;
    f.mgr.rpc = async (session, method, args) => {
      if (method === 'bytes') { changed = Buffer.from(f.image); changed[0] ^= 1; fs.writeFileSync(f.target, changed); }
      return originalRpc(session, method, args);
    };
    await reject(f.export(), 'INPUT_CHANGED'); assert.deepEqual(fs.readFileSync(f.target), changed); noPublication(f);
  });
  await test('large sources are streamed with bounded reads and remain unchanged', async () => {
    const image = Buffer.alloc(3 * 1024 * 1024 + 19, 0x5a), f = fixture(image); f.db[16] = 0xff; f.writeRows([f.row()]);
    const sizes = [], originalOpen = fs.promises.open;
    fs.promises.open = async (...args) => {
      const handle = await originalOpen(...args);
      if (args[0] === f.target) { const read = handle.read.bind(handle); handle.read = (...values) => { sizes.push(values[2]); return read(...values); }; }
      return handle;
    };
    let result; try { result = await f.export(); } finally { fs.promises.open = originalOpen; }
    assert.ok(sizes.length >= 8); assert.ok(sizes.every(size => size <= 1024 * 1024));
    const output = fs.readFileSync(result.patchedBinary), expected = Buffer.from(image); expected[16] = 0xff;
    assert.deepEqual(output, expected); unchanged(f);
  });
  await test('short file reads and partial output writes are completed', async () => {
    const f = fixture(); f.db[16] = 0xee; f.writeRows([f.row()]); const originalOpen = fs.promises.open;
    fs.promises.open = async (...args) => {
      const handle = await originalOpen(...args);
      if (args[0] === f.target) { const read = handle.read.bind(handle); handle.read = (buffer, offset, length, position) => read(buffer, offset, Math.min(length, 1), position); }
      if (args[1] === 'wx+') { const write = handle.write.bind(handle); handle.write = (buffer, offset, length, position) => write(buffer, offset, Math.min(length, 1), position); }
      return handle;
    };
    let result; try { result = await f.export(); } finally { fs.promises.open = originalOpen; }
    const expected = Buffer.from(f.image); expected[16] = 0xee;
    assert.deepEqual(fs.readFileSync(result.patchedBinary), expected); unchanged(f);
  });
  await test('distinct audited region limits reject before native reads or publication', async () => {
    const f = fixture(); f.writeRows(Array.from({ length: 16385 }, (_, index) => f.row({ detail: {
      ...f.patch({ ea: '0x' + (0x1000 + index).toString(16), fileOffset: index, size: 1, after: 'aa' }), _ig5: f.evidence(),
    } })));
    await reject(f.export(), 'EXPORT_LIMIT'); assert.deepEqual(f.calls, []); unchanged(f); noPublication(f);
  });
  await test('total audited byte budget rejects excessive evidence before database reads', async () => {
    const f = fixture(Buffer.alloc(4096, 0x55)), after = 'aa'.repeat(4096);
    // Distinct virtual ranges can alias the same file range; they still consume evidence memory.
    f.writeRows(Array.from({ length: 2049 }, (_, index) => f.row({ detail: {
      ...f.patch({ ea: '0x' + (0x1000 + index * 4096).toString(16), fileOffset: 0, size: 4096, after }), _ig5: f.evidence(),
    } })));
    await reject(f.export(), 'EXPORT_LIMIT'); assert.deepEqual(f.calls, []); unchanged(f); noPublication(f);
  });
  await test('oversized reports reject before publication and clean stages', async () => {
    const count = 260, f = fixture(Buffer.alloc(count * 4096, 0x55)), after = 'aa'.repeat(4096); f.db.fill(0x66);
    f.writeRows(Array.from({ length: count }, (_, index) => f.row({ detail: {
      ...f.patch({ ea: '0x' + (0x1000 + index * 4096).toString(16), fileOffset: index * 4096, size: 4096, after }), _ig5: f.evidence(),
    } })));
    await reject(f.export(), 'EXPORT_LIMIT'); assert.equal(f.calls.filter(value => value.method === 'bytes').length, count);
    unchanged(f); noPublication(f);
  });
  await test('report commit failure explicitly identifies a partial delivery', async () => {
    const f = fixture(); f.db[16] = 0x99; f.writeRows([f.row()]);
    const originalRename = fs.promises.rename;
    fs.promises.rename = async (from, to) => {
      if (String(to).endsWith('.changes.md')) throw Object.assign(new Error('Synthetic commit failure'), { code: 'EACCES' });
      return originalRename(from, to);
    };
    try { await assert.rejects(f.export(), error => error.code === 'EXPORT_PARTIAL' && /Binary exported at/.test(error.message)); }
    finally { fs.promises.rename = originalRename; }
    const directory = path.join(f.artifactDir, 'exports', f.session.artifactId, f.session.engine), files = fs.readdirSync(directory);
    assert.equal(files.filter(name => name.endsWith('.ig5-patched')).length, 1);
    assert.equal(files.some(name => name.endsWith('.partial') || name.endsWith('.changes.md')), false);
    assert.equal(fs.readFileSync(path.join(directory, files[0]))[16], 0x99); assert.deepEqual(f.registrations, []); unchanged(f);
  });
  await test('corrupt and incomplete history cannot silently omit patch evidence', async () => {
    for (const [suffix, code] of [['{bad-json}\n', 'AUDIT_CORRUPT'], ['{"tool":"ig5_patch_bytes"', 'AUDIT_INCOMPLETE']]) {
      const f = fixture(); f.writeRows([f.row()]); fs.appendFileSync(path.join(f.artifactDir, 'approvals.jsonl'), suffix);
      await reject(f.export(), code); unchanged(f); noPublication(f);
    }
  });
  await test('unopened or unbound sessions refuse export', async () => {
    for (const key of ['artifactId', 'sha256', 'attachmentId']) { const f = fixture(); delete f.session[key]; await reject(f.export(), 'NOT_OPEN'); noPublication(f); }
  });
  console.log(`Patch export scope: ${passed} tests passed.`);
} finally {
  const resolved = fs.realpathSync(scratch), relative = path.relative(tempRoot, resolved);
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
  assert.equal(fs.lstatSync(scratch).isSymbolicLink(), false);
  await fs.promises.rm(resolved, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
}
