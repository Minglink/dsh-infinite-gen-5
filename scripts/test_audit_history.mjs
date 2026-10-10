// Disposable JSONL fixtures; does not access the user's audit journal.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { auditRecords, readAuditPage, targetIdentity } from '../source/audit_history.js';

const tempRoot = fs.realpathSync(os.tmpdir());
const scratch = fs.mkdtempSync(path.join(tempRoot, 'ig5-audit-history-'));
let passed = 0, serial = 0;
async function test(name, callback) { await callback(); passed++; console.log(`PASS ${name}`); }
function fixture(rows = []) {
  const filename = path.join(scratch, `${++serial}.jsonl`);
  fs.writeFileSync(filename, rows.map(value => JSON.stringify(value)).join('\n') + (rows.length ? '\n' : ''));
  return filename;
}
const rows = (count, padding = 0) => Array.from({ length: count }, (_, id) => ({ id, ...(padding ? { padding: 'x'.repeat(padding) } : {}) }));
const collect = async filename => { const result = []; for await (const value of auditRecords(filename)) result.push(value); return result; };
const reject = (promise, code) => assert.rejects(promise, error => error.code === code);
const decodeCursor = value => JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
const encodeCursor = value => Buffer.from(JSON.stringify(value)).toString('base64url');
async function allPages(filename, options = {}) {
  const output = [], pages = []; let cursor;
  for (let iteration = 0; iteration < 200; iteration++) {
    const page = await readAuditPage(filename, { ...options, cursor }); pages.push(page); output.push(...page.rows);
    if (!page.hasMore) return { rows: output, pages };
    assert.ok(page.nextCursor); assert.notEqual(page.nextCursor, cursor, 'Cursor must make progress'); cursor = page.nextCursor;
  }
  assert.fail('Audit pagination did not terminate');
}

try {
  await test('Windows identity canonicalizes case and separators without changing POSIX case', async () => {
    assert.equal(targetIdentity('C:\\Samples\\TEST.exe', 'win32'), targetIdentity('c:/samples/test.exe', 'win32'));
    assert.notEqual(targetIdentity('/tmp/TEST.exe', 'linux'), targetIdentity('/tmp/test.exe', 'linux'));
    assert.equal(targetIdentity(undefined, 'win32'), ''); assert.equal(targetIdentity('', 'win32'), '');
  });
  await test('missing and empty journals return an exact empty page', async () => {
    for (const filename of [path.join(scratch, 'missing.jsonl'), fixture()]) {
      const page = await readAuditPage(filename);
      assert.deepEqual(page.rows, []); assert.equal(page.total, 0); assert.equal(page.totalExact, true); assert.equal(page.hasMore, false);
      assert.deepEqual(await collect(filename), []);
    }
  });
  await test('tail read is asynchronous and rows are newest first', async () => {
    const filename = fixture(rows(6)), pending = readAuditPage(filename, { limit: 2 }); assert.equal(typeof pending.then, 'function');
    const page = await pending; assert.deepEqual(page.rows.map(value => value.id), [5, 4]);
    assert.equal(page.total, 6); assert.equal(page.totalExact, true); assert.equal(page.hasMore, true);
    assert.ok(page.scannedBytes <= fs.statSync(filename).size);
  });
  await test('offset and predicate count only selected scope', async () => {
    const input = rows(15).map(value => ({ ...value, target: value.id % 2 ? 'A' : 'B', engine: value.id % 3 ? 'reverse' : 'ghidra' }));
    const predicate = value => value.target === 'A' && value.engine === 'reverse';
    const eligible = input.filter(predicate).reverse(), page = await readAuditPage(fixture(input), { predicate, scope: 'A:reverse', offset: 1, limit: 2 });
    assert.deepEqual(page.rows, eligible.slice(1, 3)); assert.equal(page.total, eligible.length);
  });
  await test('cursor retains an exact small-file total through all pages', async () => {
    const filename = fixture(rows(13)), result = await allPages(filename, { limit: 3, scope: 'scope-A' });
    assert.deepEqual(result.rows.map(value => value.id), rows(13).map(value => value.id).reverse());
    assert.ok(result.pages.every(page => page.total === 13 && page.totalExact)); assert.equal(result.pages.at(-1).hasMore, false);
  });
  await test('append after first page does not enter its pinned snapshot', async () => {
    const filename = fixture(rows(9)), first = await readAuditPage(filename, { limit: 2, scope: 'scope-A' });
    fs.appendFileSync(filename, JSON.stringify({ id: 100 }) + '\n');
    const output = [...first.rows]; let cursor = first.nextCursor;
    for (let iteration = 0; cursor && iteration < 20; iteration++) {
      const page = await readAuditPage(filename, { limit: 2, cursor, scope: 'scope-A' }); output.push(...page.rows); cursor = page.nextCursor;
    }
    assert.equal(cursor, undefined); assert.deepEqual(output.map(value => value.id), rows(9).map(value => value.id).reverse());
    assert.equal((await readAuditPage(filename, { limit: 1 })).rows[0].id, 100);
  });
  await test('append during a tail scan keeps its opened snapshot', async () => {
    const filename = fixture(rows(4)); let appended = false;
    const page = await readAuditPage(filename, { limit: 4, predicate: value => {
      if (!appended) { appended = true; fs.appendFileSync(filename, JSON.stringify({ id: 99 }) + '\n'); } return true;
    } });
    assert.deepEqual(page.rows.map(value => value.id), [3, 2, 1, 0]); assert.equal(page.total, 4);
  });
  await test('cursors cannot cross scopes or journals', async () => {
    const filename = fixture(rows(4)), other = fixture(rows(4)); const page = await readAuditPage(filename, { limit: 1, scope: 'A' });
    await reject(readAuditPage(filename, { limit: 1, scope: 'B', cursor: page.nextCursor }), 'STALE_CURSOR');
    await reject(readAuditPage(other, { limit: 1, scope: 'A', cursor: page.nextCursor }), 'STALE_CURSOR');
  });
  await test('malformed cursors and forged numeric bounds fail safely', async () => {
    const filename = fixture(rows(4)), page = await readAuditPage(filename, { limit: 1, scope: 'A' }), base = decodeCursor(page.nextCursor);
    for (const cursor of ['not-json', encodeCursor(null), encodeCursor([]), encodeCursor(42)]) {
      await assert.rejects(readAuditPage(filename, { scope: 'A', cursor }), error => ['INVALID_INPUT', 'STALE_CURSOR'].includes(error.code));
    }
    for (const mutation of [{ end: -1 }, { end: 1.5 }, { end: Number.MAX_SAFE_INTEGER }, { snapshotSize: -1 }, { total: -1 }, { total: 1.5 }, { total: '4' }]) {
      await reject(readAuditPage(filename, { scope: 'A', cursor: encodeCursor({ ...base, ...mutation }) }), 'STALE_CURSOR');
    }
  });
  await test('invalid offset, limit and scan budgets are rejected', async () => {
    const filename = fixture(rows(1));
    for (const options of [{ offset: -1 }, { offset: 0.5 }, { limit: 0 }, { limit: 201 }, { limit: NaN },
      { maxScanBytes: 0 }, { maxScanBytes: -1 }, { maxScanBytes: 1.5 }, { maxScanBytes: NaN }, { maxScanBytes: Infinity }, { maxScanBytes: 64 * 1024 * 1024 + 1 }]) {
      await reject(readAuditPage(filename, options), 'INVALID_INPUT');
    }
  });
  await test('same-size rewrite and truncation invalidate previous cursors', async () => {
    for (const truncate of [false, true]) {
      const filename = fixture(rows(8)), page = await readAuditPage(filename, { limit: 2 });
      if (truncate) fs.truncateSync(filename, 5);
      else { const text = fs.readFileSync(filename, 'utf8').replace('"id":0', '"id":9'); fs.writeFileSync(filename, text); fs.utimesSync(filename, new Date(), new Date(Date.now() + 2000)); }
      await reject(readAuditPage(filename, { cursor: page.nextCursor }), 'STALE_CURSOR');
    }
  });
  await test('rewrite or truncation during a tail read is detected', async () => {
    for (const truncate of [false, true]) {
      const filename = fixture(rows(8)); let changed = false;
      await reject(readAuditPage(filename, { predicate: () => {
        if (!changed) { changed = true;
          if (truncate) fs.truncateSync(filename, 5);
          else { fs.writeFileSync(filename, rows(8).reverse().map(value => JSON.stringify(value)).join('\n') + '\n'); fs.utimesSync(filename, new Date(), new Date(Date.now() + 2000)); }
        } return true;
      } }), 'AUDIT_CHANGED');
    }
  });
  await test('large-file cursor pages neither duplicate nor omit records', async () => {
    const filename = fixture(rows(40, 20 * 1024)), result = await allPages(filename, { limit: 5 });
    assert.deepEqual(result.rows.map(value => value.id), rows(40).map(value => value.id).reverse());
    for (const page of result.pages) {
      assert.ok(page.scannedBytes <= 4 * 1024 * 1024);
      if (page.totalExact) assert.equal(page.total, 40, 'An exact total must describe the whole query, not only its final page');
    }
  });
  await test('partial scan pages preserve rows across arbitrary byte boundaries', async () => {
    const filename = fixture(rows(27, 180)), result = await allPages(filename, { limit: 3, maxScanBytes: 700 });
    assert.deepEqual(result.rows.map(value => value.id), rows(27).map(value => value.id).reverse());
    assert.ok(result.pages.some(page => page.partial)); assert.ok(result.pages.every(page => page.scannedBytes <= 700));
  });
  await test('a scan too small for one row returns an explicit limit rather than a looping cursor', async () => {
    const filename = fixture([{ id: 1, padding: 'x'.repeat(200) }]); let cursor, limited = false;
    for (let iteration = 0; iteration < 4; iteration++) {
      try {
        const page = await readAuditPage(filename, { limit: 1, maxScanBytes: 64, cursor });
        assert.deepEqual(page.rows, []); assert.equal(page.partial, true); assert.ok(page.nextCursor);
        assert.notEqual(page.nextCursor, cursor); cursor = page.nextCursor;
      } catch (error) { assert.equal(error.code, 'AUDIT_SCAN_LIMIT'); limited = true; break; }
    }
    assert.equal(limited, true); const recovered = await readAuditPage(filename, { maxScanBytes: 1024, cursor });
    assert.deepEqual(recovered.rows.map(value => value.id), [1]);
  });
  await test('invalid JSON is visible in page issues and excluded from returned records', async () => {
    const filename = fixture(rows(3)); fs.appendFileSync(filename, '{broken-json}\n');
    const page = await readAuditPage(filename); assert.deepEqual(page.rows.map(value => value.id), [2, 1, 0]);
    assert.ok(page.issues.includes('invalid-json-row')); assert.equal(page.total, 3);
  });
  await test('forward export iterator rejects corrupt rows and non-record JSON', async () => {
    for (const line of ['{broken-json}', 'null', '42', '[]']) {
      const filename = fixture(rows(1)); fs.appendFileSync(filename, line + '\n');
      await reject(collect(filename), 'AUDIT_CORRUPT');
    }
  });
  await test('forward iterator rejects a final uncommitted record but ignores whitespace', async () => {
    const incomplete = fixture(rows(1)); fs.appendFileSync(incomplete, '{"id":99}'); await reject(collect(incomplete), 'AUDIT_INCOMPLETE');
    const whitespace = fixture(rows(2)); fs.appendFileSync(whitespace, '\r\n   \n\t');
    assert.deepEqual((await collect(whitespace)).map(value => value.id), [0, 1]);
  });
  await test('forward iterator pins a snapshot while a writer appends', async () => {
    const filename = fixture(rows(7)), iterator = auditRecords(filename), first = await iterator.next();
    assert.equal(first.value.id, 0); fs.appendFileSync(filename, JSON.stringify({ id: 99 }) + '\n');
    const output = [first.value]; for await (const row of iterator) output.push(row);
    assert.deepEqual(output.map(value => value.id), rows(7).map(value => value.id));
    assert.equal((await collect(filename)).at(-1).id, 99);
  });
  await test('forward iterator detects rewrite or truncation while yielding', async () => {
    for (const truncate of [false, true]) {
      const filename = fixture(rows(8)), iterator = auditRecords(filename); await iterator.next();
      if (truncate) fs.truncateSync(filename, 1);
      else { fs.writeFileSync(filename, rows(8).reverse().map(value => JSON.stringify(value)).join('\n') + '\n'); fs.utimesSync(filename, new Date(), new Date(Date.now() + 2000)); }
      await reject((async () => { for await (const row of iterator) void row; })(), 'AUDIT_CHANGED');
    }
  });
  await test('short reads are assembled without record loss in both directions', async () => {
    const filename = fixture(rows(9)), originalOpen = fs.promises.open;
    fs.promises.open = async (...args) => { const handle = await originalOpen(...args); if (args[0] === filename) {
      const read = handle.read.bind(handle); handle.read = (buffer, offset, length, position) => read(buffer, offset, Math.min(length, 7), position);
    } return handle; };
    try {
      assert.deepEqual((await readAuditPage(filename)).rows.map(value => value.id), rows(9).map(value => value.id).reverse());
      assert.deepEqual((await collect(filename)).map(value => value.id), rows(9).map(value => value.id));
    } finally { fs.promises.open = originalOpen; }
  });
  await test('stream reads and individual record sizes are bounded', async () => {
    const filename = fixture(rows(120, 4096)), sizes = [], originalOpen = fs.promises.open;
    fs.promises.open = async (...args) => { const handle = await originalOpen(...args); if (args[0] === filename) {
      const read = handle.read.bind(handle); handle.read = (...values) => { sizes.push(values[2]); return read(...values); };
    } return handle; };
    try { assert.equal((await collect(filename)).length, 120); assert.ok(sizes.length > 1); assert.ok(sizes.every(size => size <= 64 * 1024)); }
    finally { fs.promises.open = originalOpen; }
    const huge = fixture([{ id: 1, padding: 'x'.repeat(2 * 1024 * 1024 + 1) }]);
    await reject(readAuditPage(huge), 'AUDIT_LINE_LIMIT'); await reject(collect(huge), 'AUDIT_LINE_LIMIT');
  });
  await test('partial scans do not claim unknown matching rows in the lower bound', async () => {
    const filename = fixture(rows(100, 200)), page = await readAuditPage(filename, { predicate: () => false, maxScanBytes: 1024 });
    assert.equal(page.partial, true); assert.equal(page.hasMore, true); assert.equal(page.totalLowerBound, 0);
  });
  await test('a requested offset survives multiple budget-limited cursor pages', async () => {
    const filename = fixture(rows(100, 200)), result = await allPages(filename, { offset: 20, limit: 5, maxScanBytes: 1024 });
    assert.deepEqual(result.rows.map(row => row.id), Array.from({ length: 80 }, (_, index) => 79 - index));
    assert(result.pages.every(page => page.totalLowerBound <= 100));
  });
  console.log(`Audit history: ${passed} tests passed.`);
} finally {
  const resolved = fs.realpathSync(scratch), relative = path.relative(tempRoot, resolved);
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
  assert.equal(fs.lstatSync(scratch).isSymbolicLink(), false);
  await fs.promises.rm(resolved, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
}
