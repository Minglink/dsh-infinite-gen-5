import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { ProjectStore } from '../source/project_store.js';
import { convertAddress } from '../source/address_ref.js';

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-project-test-'));
  t.after(() => {
    const resolved = path.resolve(directory);
    assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
    assert.ok(path.basename(resolved).startsWith('ig5-project-test-'));
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const target = path.join(directory, '测试 sample.bin');
  fs.writeFileSync(target, Buffer.from([0, 1, 2, 3, 255]));
  const root = path.join(directory, 'store');
  const store = new ProjectStore({ root });
  return { directory, target, root, store };
}
const fails = (fn, code) => assert.throws(fn, error => error.code === code);
const attach = (store, identity, sessionId, extra = {}) => store.attachEngine({ projectId: identity.projectId, artifactId: identity.artifactId, engine: 'reverse', sessionId, ...extra });
const storeModule = new URL('../source/project_store.js', import.meta.url).href;
function crashWithLock(root) {
  const child = spawnSync(process.execPath, ['--input-type=module', '-e',
    `import { ProjectStore } from ${JSON.stringify(storeModule)}; const store = new ProjectStore({ root: ${JSON.stringify(root)} }); store._write(() => process.exit(17));`],
  { encoding: 'utf8', windowsHide: true, timeout: 15000 });
  assert.equal(child.status, 17, child.stderr);
}
function childWriter(root, body) {
  const child = spawn(process.execPath, ['--input-type=module', '-e',
    `import fs from 'node:fs'; import { ProjectStore } from ${JSON.stringify(storeModule)}; const store = new ProjectStore({ root: ${JSON.stringify(root)} }); ${body}`],
  { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '', errors = '';
  child.stdout.on('data', bytes => { output += bytes; });
  child.stderr.on('data', bytes => { errors += bytes; });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject); child.once('exit', code => resolve({ code, output, errors }));
  });
  const ready = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { child.kill(); reject(new Error('Child lock fixture did not become ready')); }, 15000);
    const check = () => { if (output.includes('READY')) { clearTimeout(timeout); child.stdout.off('data', check); resolve(); } };
    child.stdout.on('data', check);
    child.once('exit', code => { clearTimeout(timeout); if (!output.includes('READY')) reject(new Error(`Child exited ${code}: ${errors}`)); });
  });
  return { child, done, ready };
}

test('same bytes at a moved path restore identity; replaced bytes do not', t => {
  const { directory, target, store } = fixture(t);
  const first = store.open(target);
  assert.equal(first.sha256, createHash('sha256').update(fs.readFileSync(target)).digest('hex'));
  const moved = path.join(directory, 'moved.bin');
  fs.renameSync(target, moved);
  const restored = store.register(moved);
  assert.equal(restored.projectId, first.projectId);
  assert.equal(restored.artifactId, first.artifactId);
  assert.equal(store.getArtifact(first.artifactId).paths.length, 2);
  fs.writeFileSync(moved, 'different bytes');
  const replacement = store.open(moved);
  assert.notEqual(replacement.artifactId, first.artifactId);
  assert.notEqual(replacement.projectId, first.projectId);
  assert.equal(store.resolveTarget(moved).artifactId, replacement.artifactId);
  assert.equal(store.getArtifact(first.artifactId).sha256, first.sha256);
});

test('derived files preserve the original hash and explicit lineage', t => {
  const { directory, target, store } = fixture(t);
  const original = store.open(target);
  const patched = path.join(directory, 'patched.bin');
  fs.writeFileSync(patched, 'patch');
  const derived = store.open(patched, { derivedFrom: original.artifactId });
  assert.equal(derived.projectId, original.projectId);
  assert.equal(derived.project.originalHash, original.sha256);
  assert.deepEqual(derived.artifact.derivedFrom, [original.artifactId]);
  fails(() => store.open(target, { derivedFrom: original.artifactId }), 'INVALID_DERIVATION');
});

test('identical files share artifact identity but never default engine attachments', t => {
  const { directory, target, store } = fixture(t);
  const copy = path.join(directory, 'copy.bin'); fs.copyFileSync(target, copy);
  const a = store.open(target), b = store.open(copy);
  const one = attach(store, a, 'session-A'), two = attach(store, b, 'session-B');
  assert.equal(a.artifactId, b.artifactId);
  assert.notEqual(one.attachmentId, two.attachmentId);
  assert.notEqual(one.databasePath, two.databasePath);
  store.bumpRevision(one.attachmentId, { expectedRevision: 0, reason: 'comment' });
  assert.equal(store.getAttachment(one.attachmentId).dbRevision, 1);
  assert.equal(store.getAttachment(two.attachmentId).dbRevision, 0);
});

test('stable database paths retain revisions across explicit close and reopen', t => {
  const { target, root, store } = fixture(t);
  const identity = store.open(target), databasePath = path.join(root, 'stable.db');
  const one = attach(store, identity, 'session-A', { databasePath });
  const reuse = attach(store, identity, 'session-A', { reuseAttachmentId: one.attachmentId });
  assert.equal(reuse.attachmentId, one.attachmentId);
  fails(() => attach(store, identity, 'session-B', { databasePath }), 'DATABASE_IN_USE');
  fails(() => attach(store, identity, 'session-B', { reuseAttachmentId: one.attachmentId }), 'ATTACHMENT_IDENTITY_MISMATCH');
  store.bumpRevision(one.attachmentId, { expectedRevision: 0 });
  store.closeAttachment(one.attachmentId);
  const reopened = attach(new ProjectStore({ root }), identity, 'session-B', { databasePath });
  assert.notEqual(reopened.attachmentId, one.attachmentId);
  assert.equal(reopened.databaseId, one.databaseId);
  assert.equal(reopened.dbRevision, 1);
  fails(() => store.bumpRevision(one.attachmentId), 'ATTACHMENT_CLOSED');
  fails(() => store.bumpRevision(reopened.attachmentId, { expectedRevision: 0 }), 'STALE_DATABASE_REVISION');
  assert.equal(store.getAttachment(reopened.attachmentId).dbRevision, 1);
});

test('a database path cannot silently be rebound to another artifact or engine', t => {
  const { target, root, store } = fixture(t);
  const a = store.open(target), databasePath = path.join(root, 'stable.db');
  const one = attach(store, a, 'session-A', { databasePath }); store.closeAttachment(one.attachmentId);
  fs.writeFileSync(target, 'replacement'); const b = store.open(target);
  fails(() => attach(store, b, 'session-B', { databasePath }), 'DATABASE_IDENTITY_MISMATCH');
  fails(() => store.attachEngine({ ...a, engine: 'ghidra', sessionId: 'session-B', databasePath }), 'DATABASE_IDENTITY_MISMATCH');
});

test('independent store instances preserve committed changes and return detached snapshots', t => {
  const { directory, target, root, store } = fixture(t);
  const another = new ProjectStore({ root }), first = store.open(target);
  const secondPath = path.join(directory, 'second.bin'); fs.writeFileSync(secondPath, 'another');
  another.open(secondPath);
  const attachment = attach(store, first, 'session-A');
  assert.equal(another.listProjects().length, 2);
  const snapshot = store.getProject(first.projectId); snapshot.artifactIds.length = 0;
  assert.equal(store.getProject(first.projectId).artifactIds.length, 1);
  assert.equal(another.getAttachment(attachment.attachmentId).dbRevision, 0);
});

test('failed atomic replacement preserves old metadata and releases the lock', t => {
  const { target, root, store } = fixture(t);
  const identity = store.open(target), before = fs.readFileSync(store.file, 'utf8');
  const rename = fs.renameSync;
  fs.renameSync = (source, destination) => { if (destination === store.file) throw new Error('simulated atomic replace failure'); return rename(source, destination); };
  try { assert.throws(() => attach(store, identity, 'session-A'), /simulated atomic/); }
  finally { fs.renameSync = rename; }
  assert.equal(fs.readFileSync(store.file, 'utf8'), before);
  assert.equal(fs.existsSync(store.lockFile), false);
  assert.equal(fs.readdirSync(root).some(name => name.endsWith('.tmp')), false);
  assert.equal(attach(store, identity, 'session-A').dbRevision, 0);
});

test('busy or corrupt stores fail closed without overwriting metadata', t => {
  const { target, root, store } = fixture(t);
  store.open(target); const before = fs.readFileSync(store.file, 'utf8');
  fs.writeFileSync(store.lockFile, 'another writer');
  fails(() => store.open(target), 'STORE_BUSY');
  assert.equal(fs.readFileSync(store.file, 'utf8'), before); fs.unlinkSync(store.lockFile);
  fs.writeFileSync(store.file, '{broken');
  fails(() => new ProjectStore({ root }), 'STORE_CORRUPT');
  assert.equal(fs.readFileSync(store.file, 'utf8'), '{broken');
});

test('runtime snapshots invalidate on resume, new pause, module reload, and stop', t => {
  const { target, store } = fixture(t); const identity = store.open(target);
  const run = store.createRuntime({ ...identity, engine: 'x64dbg', sessionId: 'session-A' });
  assert.equal(run.state, 'created'); assert.equal(run.stopSeq, 0);
  fails(() => store.recordRuntimeEvent(run.runId, { type: 'paused' }), 'INVALID_RUNTIME_TRANSITION');
  store.recordRuntimeEvent(run.runId, { type: 'started' });
  store.recordRuntimeEvent(run.runId, { type: 'module-loaded', moduleId: 'sample', artifactId: identity.artifactId, base: '0x7fff12340000', size: '0x6000' });
  const paused = store.recordRuntimeEvent(run.runId, { type: 'paused' });
  const context = { runId: run.runId, epoch: paused.epoch, stopSeq: paused.stopSeq, moduleId: 'sample', moduleLoadEpoch: paused.modules.sample.moduleLoadEpoch };
  const module = store.assertRuntimeContext(context);
  const address = convertAddress({ artifactId: identity.artifactId, space: 'static', kind: 'rva', value: '0x1234' }, { space: 'runtime', kind: 'va' }, { module });
  assert.equal(address.value, '0x7fff12341234');
  store.recordRuntimeEvent(run.runId, { type: 'resumed' });
  fails(() => store.assertRuntimeContext(context), 'RUNTIME_NOT_PAUSED');
  store.recordRuntimeEvent(run.runId, { type: 'paused' });
  fails(() => store.assertRuntimeContext(context), 'STALE_RUNTIME_CONTEXT');
  store.recordRuntimeEvent(run.runId, { type: 'module-unloaded', moduleId: 'sample' });
  store.recordRuntimeEvent(run.runId, { type: 'module-loaded', moduleId: 'sample', artifactId: identity.artifactId, base: '0x7fff56780000', size: '0x6000' });
  fails(() => store.assertRuntimeContext({ runId: run.runId, moduleId: 'sample', moduleLoadEpoch: module.moduleLoadEpoch }), 'STALE_RUNTIME_CONTEXT');
  const current = store.assertRuntimeContext({ runId: run.runId, moduleId: 'sample' });
  fails(() => convertAddress(address, 'rva', { module: current }), 'STALE_RUNTIME_CONTEXT');
  store.recordRuntimeEvent(run.runId, { type: 'stopped' });
  fails(() => store.assertRuntimeContext({ runId: run.runId }), 'RUNTIME_NOT_PAUSED');
  fails(() => store.recordRuntimeEvent(run.runId, { type: 'started' }), 'RUNTIME_STOPPED');
});

test('internal database paths survive moving the store directory', t => {
  const { directory, target, root, store } = fixture(t); const identity = store.open(target);
  const one = attach(store, identity, 'session-A'); store.bumpRevision(one.attachmentId); store.closeAttachment(one.attachmentId);
  const movedRoot = path.join(directory, 'moved-store'); fs.renameSync(root, movedRoot);
  const movedStore = new ProjectStore({ root: movedRoot });
  const newPath = path.join(movedRoot, path.relative(root, one.databasePath));
  const reopened = attach(movedStore, identity, 'session-B', { databasePath: newPath });
  assert.equal(reopened.databaseId, one.databaseId); assert.equal(reopened.dbRevision, 1);
});

test('a crashed writer is recovered by owner identity while an orphan claim is ignored', t => {
  const { target, root, store } = fixture(t); store.open(target);
  const orphan = path.join(root, '.projects-lock-orphan.claim'); fs.mkdirSync(orphan);
  crashWithLock(root);
  assert.equal(fs.lstatSync(store.lockFile).isDirectory(), true);
  const owner = JSON.parse(fs.readFileSync(path.join(store.lockFile, 'owner.json'), 'utf8'));
  assert.equal(Number.isSafeInteger(owner.pid), true); assert.ok(owner.nonce);
  const recovered = new ProjectStore({ root }); recovered.open(target);
  assert.equal(fs.existsSync(store.lockFile), false);
  assert.equal(fs.existsSync(path.join(root, `.projects-stale-lock-${owner.nonce}`, 'owner.json')), true);
  assert.equal(fs.existsSync(orphan), true, 'Unpublished claims are harmless and are not guessed to be active locks');
});

test('a live writer keeps its lock and a contender cannot alter its owner', async t => {
  const { target, root, store } = fixture(t); store.open(target);
  const writer = childWriter(root, `store._write(() => { process.stdout.write('READY\\n'); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30000); });`);
  try {
    await writer.ready;
    const owner = fs.readFileSync(path.join(store.lockFile, 'owner.json'), 'utf8');
    fails(() => store.open(target), 'STORE_BUSY');
    assert.equal(fs.readFileSync(path.join(store.lockFile, 'owner.json'), 'utf8'), owner);
  } finally { writer.child.kill(); await writer.done; }
  store.open(target);
  assert.equal(fs.existsSync(store.lockFile), false);
});

test('process creation identity distinguishes a reused PID from a live owner', t => {
  const { target, store, root } = fixture(t); store.open(target);
  const owner = store._acquireLock(); store._releaseLock(owner);
  if (!owner.creationIdentity) return t.skip('OS process creation identity is unavailable; live PID remains fail-closed');
  owner.nonce = randomUUID();
  fs.mkdirSync(store.lockFile);
  fs.writeFileSync(path.join(store.lockFile, 'owner.json'), JSON.stringify({ ...owner, creationIdentity: owner.creationIdentity + '-old' }));
  store.open(target);
  assert.equal(fs.existsSync(store.lockFile), false);
  assert.equal(fs.existsSync(path.join(root, `.projects-stale-lock-${owner.nonce}`)), true);
});

test('competing processes recover one dead owner without removing a new live lock', async t => {
  const { target, root, store } = fixture(t); store.open(target); crashWithLock(root);
  const deadOwner = JSON.parse(fs.readFileSync(path.join(store.lockFile, 'owner.json'), 'utf8'));
  const marker = path.join(root, 'inside-writer');
  const body = `process.stdout.write('READY\\n'); process.stdin.once('data', () => {
    try { store._write(data => {
      let fd; try { fd = fs.openSync(${JSON.stringify(marker)}, 'wx'); } catch { process.stdout.write('OVERLAP\\n'); process.exit(3); }
      data.raceCommits = (data.raceCommits || 0) + 1;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
      fs.closeSync(fd); fs.unlinkSync(${JSON.stringify(marker)});
    }); process.stdout.write('COMMIT\\n'); }
    catch (error) { process.stdout.write(error.code + '\\n'); if (error.code !== 'STORE_BUSY') { process.stderr.write(error.stack + '\\n'); process.exitCode = 2; } }
  });`;
  const writers = Array.from({ length: 4 }, () => childWriter(root, body));
  let outcomes;
  try {
    await Promise.all(writers.map(writer => writer.ready));
    writers.forEach(writer => writer.child.stdin.end('go'));
    outcomes = await Promise.all(writers.map(writer => writer.done));
  } finally {
    for (const writer of writers) if (writer.child.exitCode === null) writer.child.kill();
    await Promise.all(writers.map(writer => writer.done));
  }
  assert.ok(outcomes.every(outcome => outcome.code === 0 && !outcome.output.includes('OVERLAP')), JSON.stringify(outcomes));
  const committed = outcomes.filter(outcome => outcome.output.includes('COMMIT')).length;
  assert.ok(committed >= 1);
  assert.equal(JSON.parse(fs.readFileSync(store.file, 'utf8')).raceCommits, committed);
  assert.equal(fs.existsSync(path.join(root, `.projects-stale-lock-${deadOwner.nonce}`, 'owner.json')), true);
  store.open(target);
});

test('a delayed stale-lock recovery cannot rename a replacement live lock', t => {
  const { target, root, store } = fixture(t); store.open(target); crashWithLock(root);
  const deadOwner = JSON.parse(fs.readFileSync(path.join(store.lockFile, 'owner.json'), 'utf8'));
  const tombstone = path.join(root, `.projects-stale-lock-${deadOwner.nonce}`);
  const rename = fs.renameSync; let replacement;
  fs.renameSync = (from, to) => {
    if (from === store.lockFile && to === tombstone && !replacement) {
      rename(from, to);
      replacement = store._acquireLock();
    }
    return rename(from, to);
  };
  try { assert.equal(store._recoverLock(), false); }
  finally { fs.renameSync = rename; }
  assert.ok(replacement);
  assert.equal(JSON.parse(fs.readFileSync(path.join(store.lockFile, 'owner.json'), 'utf8')).nonce, replacement.nonce);
  store._releaseLock(replacement);
  store.open(target);
});

test('normal release prevents delayed dead-owner recovery from moving a new live lock', t => {
  const { target, root, store } = fixture(t); store.open(target); crashWithLock(root);
  const releasedOwner = JSON.parse(fs.readFileSync(path.join(store.lockFile, 'owner.json'), 'utf8'));
  const tombstone = path.join(root, `.projects-stale-lock-${releasedOwner.nonce}`);
  const rename = fs.renameSync; let replacement;
  fs.renameSync = (from, to) => {
    if (from === store.lockFile && to === tombstone && !replacement) {
      // The owner was read before its normal release; its process has exited
      // before the delayed recoverer gets to rename. Simulate that release.
      store._releaseLock(releasedOwner);
      replacement = store._acquireLock();
    }
    return rename(from, to);
  };
  // Avoid re-entering this fixture hook when the simulated owner releases.
  const release = store._releaseLock.bind(store);
  store._releaseLock = owner => {
    fs.renameSync = rename;
    try { return release(owner); }
    finally { fs.renameSync = intercepted; }
  };
  const intercepted = fs.renameSync;
  try { assert.equal(store._recoverLock(), false); }
  finally { fs.renameSync = rename; store._releaseLock = release; }
  assert.ok(replacement);
  assert.equal(JSON.parse(fs.readFileSync(path.join(store.lockFile, 'owner.json'), 'utf8')).nonce, replacement.nonce);
  assert.equal(fs.existsSync(path.join(tombstone, 'owner.json')), true);
  store._releaseLock(replacement);
  store.open(target);
});

test('hard-link database aliases share exclusivity and persistent revisions', t => {
  const { target, root, store } = fixture(t), identity = store.open(target);
  const firstPath = path.join(root, 'database.bin'), alias = path.join(root, 'hard-link.bin');
  fs.writeFileSync(firstPath, 'database'); fs.linkSync(firstPath, alias);
  const first = attach(store, identity, 'A', { databasePath: firstPath }); store.bumpRevision(first.attachmentId);
  fails(() => attach(store, identity, 'B', { databasePath: alias }), 'DATABASE_IN_USE');
  store.closeAttachment(first.attachmentId);
  const second = attach(store, identity, 'B', { databasePath: alias });
  assert.equal(second.databaseId, first.databaseId); assert.equal(second.dbRevision, 1);
  store.bumpRevision(second.attachmentId); store.closeAttachment(second.attachmentId);
  assert.equal(attach(store, identity, 'C', { databasePath: firstPath }).dbRevision, 2);
});

test('a database registered before creation gains physical alias protection', t => {
  const { target, root, store } = fixture(t), identity = store.open(target);
  const firstPath = path.join(root, 'future.bin'), alias = path.join(root, 'future-alias.bin');
  const first = attach(store, identity, 'A', { databasePath: firstPath });
  assert.equal(fs.existsSync(firstPath), false);
  fs.writeFileSync(firstPath, 'database'); fs.linkSync(firstPath, alias);
  fails(() => attach(store, identity, 'B', { databasePath: alias }), 'DATABASE_IN_USE');
  store.bumpRevision(first.attachmentId); store.closeAttachment(first.attachmentId);
  assert.equal(attach(store, identity, 'B', { databasePath: alias }).dbRevision, 1);
});

test('an active physical database keeps its lease if its original path disappears', t => {
  const { target, root, store } = fixture(t), identity = store.open(target);
  const firstPath = path.join(root, 'original.bin'), alias = path.join(root, 'remaining-link.bin');
  fs.writeFileSync(firstPath, 'database'); fs.linkSync(firstPath, alias);
  const first = attach(store, identity, 'A', { databasePath: firstPath });
  store.bumpRevision(first.attachmentId);
  fs.unlinkSync(firstPath);
  fails(() => attach(store, identity, 'B', { databasePath: alias }), 'DATABASE_IN_USE');
  store.closeAttachment(first.attachmentId);
  const second = attach(store, identity, 'B', { databasePath: alias });
  assert.equal(second.databaseId, first.databaseId); assert.equal(second.dbRevision, 1);
});

test('not-yet-created database paths through a directory alias cannot obtain two leases', t => {
  const { target, root, store } = fixture(t), identity = store.open(target);
  const physical = path.join(root, 'physical'), alias = path.join(root, 'directory-alias'); fs.mkdirSync(physical);
  try { fs.symlinkSync(physical, alias, process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (['EPERM', 'ENOTSUP'].includes(error.code)) return t.skip('Directory links are unavailable'); throw error; }
  const first = attach(store, identity, 'A', { databasePath: path.join(physical, 'future.db') });
  fails(() => attach(store, identity, 'B', { databasePath: path.join(alias, 'future.db') }), 'DATABASE_IN_USE');
  store.bumpRevision(first.attachmentId); store.closeAttachment(first.attachmentId);
  assert.equal(attach(store, identity, 'B', { databasePath: path.join(alias, 'future.db') }).dbRevision, 1);
});
