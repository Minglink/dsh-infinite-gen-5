import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { ProjectStore } from '../source/project_store.js';
import { captureAttachmentLease, probeAttachmentLease, processCreationIdentity } from '../source/attachment_lease.js';

const storeModule = new URL('../source/project_store.js', import.meta.url).href;
const fails = (run, code) => assert.throws(run, error => error.code === code);
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
function alive(pid) { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw error; } }
async function gone(pid) { for (let at = 0; at < 100; at++) { if (!alive(pid)) return; await delay(50); } throw new Error('Owned process did not exit'); }
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-lease-test-'));
  const target = path.join(directory, 'generated sample.bin'); fs.writeFileSync(target, Buffer.from('01020304', 'hex'));
  const root = path.join(directory, 'store'), store = new ProjectStore({ root });
  t.after(() => { const resolved = path.resolve(directory); assert.equal(path.dirname(resolved), fs.realpathSync(os.tmpdir())); assert(path.basename(resolved).startsWith('ig5-lease-test-')); fs.rmSync(resolved, { recursive: true, force: true }); });
  return { root, target, store, identity: store.open(target) };
}
function idle(t) {
  const child = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { windowsHide: true, stdio: 'ignore' });
  t.after(async () => { if (child.exitCode === null && !child.signalCode) child.kill(); if (alive(child.pid)) await gone(child.pid); });
  return child;
}
async function crashedOwner(t, root, target) {
  const code = `import {spawn} from 'node:child_process';import {ProjectStore} from ${JSON.stringify(storeModule)};
    const worker=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,windowsHide:true,stdio:'ignore'});worker.unref();
    console.log(JSON.stringify({workerPid:worker.pid}));
    const store=new ProjectStore({root:${JSON.stringify(root)}}), identity=store.open(${JSON.stringify(target)});
    const attachment=store.attachEngine({projectId:identity.projectId,artifactId:identity.artifactId,engine:'reverse',sessionId:String(process.pid)+'-'+worker.pid+'-fixture',databasePath:${JSON.stringify(path.join(root, 'shared.db'))},workerPid:worker.pid});
    console.log(JSON.stringify({attachment}));process.exit(0);`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '', errors = '', workerPid;
  child.stdout.on('data', chunk => { output += chunk; try { workerPid = JSON.parse(output.split('\n')[0]).workerPid; } catch {} }); child.stderr.on('data', chunk => { errors += chunk; });
  t.after(async () => { if (child.exitCode === null && !child.signalCode) child.kill(); if (workerPid && alive(workerPid)) { process.kill(workerPid, 'SIGKILL'); await gone(workerPid); } });
  const result = await new Promise((resolve, reject) => { const timer = setTimeout(() => { child.kill(); reject(new Error('Lease owner fixture timeout')); }, 20000); child.once('error', error => { clearTimeout(timer); reject(error); }); child.once('exit', status => { clearTimeout(timer); resolve(status); }); });
  assert.equal(result, 0, errors); const record = output.split('\n').filter(Boolean).map(line => JSON.parse(line)).find(record => record.attachment); assert(record);
  return record.attachment;
}

test('attachment records contain host/worker creation identities and an immutable nonce', async t => {
  const { store, identity } = fixture(t), worker = idle(t);
  const attachment = store.attachEngine({ ...identity, engine: 'reverse', sessionId: 'owned', workerPid: worker.pid });
  assert.equal(attachment.lease.host.pid, process.pid); assert.equal(attachment.lease.worker.pid, worker.pid);
  assert(attachment.lease.host.creationIdentity); assert(attachment.lease.worker.creationIdentity); assert.match(attachment.lease.nonce, /^[a-f0-9-]{36}$/);
  const reused = store.attachEngine({ ...identity, engine: 'reverse', sessionId: 'owned', reuseAttachmentId: attachment.attachmentId, workerPid: worker.pid });
  assert.equal(reused.lease.nonce, attachment.lease.nonce); assert.equal(store.recoverAttachments().retained[0].reason, 'host-alive');
  worker.kill(); await gone(worker.pid); assert.equal(store.recoverAttachments().retained[0].reason, 'host-alive'); assert.equal(store.getAttachment(attachment.attachmentId).state, 'active');
  store.closeAttachment(attachment.attachmentId);
});

test('dead host with a real surviving worker retains the database until both owners exit', async t => {
  const { store, root, target, identity } = fixture(t), orphan = await crashedOwner(t, root, target);
  assert.equal(probeAttachmentLease(orphan.lease).host.state, 'dead'); assert.equal(probeAttachmentLease(orphan.lease).worker.state, 'alive');
  const before = fs.readFileSync(store.file, 'utf8'), retained = store.recoverAttachments();
  assert.equal(retained.recovered.length, 0); assert.equal(retained.retained[0].reason, 'worker-alive'); assert.equal(fs.readFileSync(store.file, 'utf8'), before);
  fails(() => store.attachEngine({ ...identity, engine: 'reverse', sessionId: 'contender', databasePath: path.join(root, 'shared.db') }), 'DATABASE_IN_USE');
  process.kill(orphan.lease.worker.pid, 'SIGKILL'); await gone(orphan.lease.worker.pid);
  const recovered = store.recoverAttachment(orphan.attachmentId, orphan.lease.nonce); assert.equal(recovered.recovered, true);
  const revision = JSON.parse(fs.readFileSync(store.file, 'utf8')).revision;
  assert.equal(store.recoverAttachment(orphan.attachmentId, orphan.lease.nonce).alreadyClosed, true); assert.equal(JSON.parse(fs.readFileSync(store.file, 'utf8')).revision, revision);
  const worker = idle(t), replacement = store.attachEngine({ ...identity, engine: 'reverse', sessionId: 'replacement', databasePath: path.join(root, 'shared.db'), workerPid: worker.pid });
  assert.notEqual(replacement.lease.nonce, orphan.lease.nonce);
  store.recoverAttachment(orphan.attachmentId, orphan.lease.nonce); assert.equal(store.getAttachment(replacement.attachmentId).state, 'active');
});

test('legacy, missing creation identity and foreign-host leases remain fail-closed', async t => {
  const { store, root, target, identity } = fixture(t);
  const legacy = store.attachEngine({ ...identity, engine: 'ghidra', sessionId: '999999-999998-legacy' });
  assert.equal(store.recoverAttachments().retained[0].reason, 'legacy-or-invalid-owner'); assert.equal(store.getAttachment(legacy.attachmentId).state, 'active');
  const orphan = await crashedOwner(t, root, target); process.kill(orphan.lease.worker.pid, 'SIGKILL'); await gone(orphan.lease.worker.pid);
  store._write(data => { data.attachments[orphan.attachmentId].lease.worker.creationIdentity = null; });
  assert(store.recoverAttachments().retained.some(row => row.attachmentId === orphan.attachmentId && row.reason === 'worker-unknown'));
  store._write(data => { data.attachments[orphan.attachmentId].lease = { ...orphan.lease, hostName: 'another-host-' + randomUUID() }; });
  assert(store.recoverAttachments().retained.some(row => row.attachmentId === orphan.attachmentId && row.reason === 'foreign-host'));
});

test('a delayed recovery cannot close an owner replaced while it waits for the metadata lock', async t => {
  const { store, root, target } = fixture(t), orphan = await crashedOwner(t, root, target);
  process.kill(orphan.lease.worker.pid, 'SIGKILL'); await gone(orphan.lease.worker.pid);
  const worker = idle(t), replacement = captureAttachmentLease(worker.pid, processCreationIdentity(process.pid));
  const nativeWrite = store._write.bind(store); let injected = false;
  store._write = run => { if (!injected) { injected = true; nativeWrite(data => { data.attachments[orphan.attachmentId].lease = replacement; }); } return nativeWrite(run); };
  fails(() => store.recoverAttachment(orphan.attachmentId, orphan.lease.nonce), 'ATTACHMENT_OWNER_CHANGED');
  store._write = nativeWrite;
  assert.equal(store.getAttachment(orphan.attachmentId).lease.nonce, replacement.nonce); assert.equal(store.getAttachment(orphan.attachmentId).state, 'active');
});

test('recovery batches are bounded and invalid worker/recovery inputs preserve metadata', t => {
  const { store, identity } = fixture(t);
  for (let index = 0; index < 3; index++) store.attachEngine({ ...identity, engine: 'reverse', sessionId: 'legacy-' + index });
  const before = fs.readFileSync(store.file, 'utf8'); const result = store.recoverAttachments({ limit: 1 }); assert.equal(result.examined, 1); assert.equal(result.truncated, true); assert.equal(result.retained.length, 1);
  for (const workerPid of [null, -1, 1.5, process.pid, Number.MAX_SAFE_INTEGER + 1]) fails(() => store.attachEngine({ ...identity, engine: 'reverse', sessionId: 'invalid', workerPid }), 'INVALID_ATTACHMENT_OWNER');
  fails(() => store.recoverAttachments({ limit: 0 }), 'INVALID_ARGUMENT'); assert.equal(fs.readFileSync(store.file, 'utf8'), before);
});
