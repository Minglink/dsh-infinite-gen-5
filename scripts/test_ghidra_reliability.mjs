import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, chmod, access } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
import { runtimeConfiguration } from '../engine_runtime.js';

// Real native failures are injected only in an isolated generated project.
const source = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = runtimeConfiguration().ghidra;
assert(manifest.available, manifest.reason);
const resolveRuntime = value => value;
const temp = await mkdtemp(path.join(os.tmpdir(), 'ig5-ghidra-reliability-'));
const projectRoot = path.join(temp, 'projects');
const target = path.join(temp, '隔离可靠性样本.exe');
const fixture = buildPE64Fixture();
await writeFile(target, fixture.image);
let active, journalPath, statePath;

async function start() {
  const child = spawn(resolveRuntime(manifest.pythonExe), ['-I', '-B', path.join(source, 'adapters', 'ghidra', 'worker.py')], {
    env: { ...process.env, IG5_GHIDRA_HOME: resolveRuntime(manifest.ghidraHome),
      IG5_JAVA_HOME: resolveRuntime(manifest.javaHome), IG5_GHIDRA_PROJECT_ROOT: projectRoot },
    windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
  });
  let sequence = 0, stderr = '', readyResolve, readyReject;
  const pending = new Map();
  const greeting = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const readyTimer = setTimeout(() => readyReject(new Error('ready timed out\n' + stderr)), 120000);
  const exited = new Promise(resolve => child.once('exit', (code, signal) => {
    clearTimeout(readyTimer);
    const error = new Error(`worker exited ${code}/${signal}\n${stderr}`);
    readyReject(error);
    for (const slot of pending.values()) { clearTimeout(slot.timer); slot.reject(error); }
    pending.clear(); resolve();
  }));
  child.once('error', error => { clearTimeout(readyTimer); readyReject(error); });
  child.stderr.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-50000); });
  readline.createInterface({ input: child.stdout }).on('line', line => {
    let value;
    try { value = JSON.parse(line); }
    catch { readyReject(new Error('non-JSON stdout: ' + line)); return; }
    if (value.ig5 === 'ready') { clearTimeout(readyTimer); readyResolve(value); return; }
    if (value.ig5 === 'progress') return;
    const slot = pending.get(value.id);
    if (!slot) throw new Error('unknown response: ' + line);
    clearTimeout(slot.timer); pending.delete(value.id);
    if (value.error) slot.reject(Object.assign(new Error(value.error.message), value.error));
    else slot.resolve(value.result);
  });
  const session = {
    child, exited,
    rpc(method, params = {}, timeout = 120000) {
      const id = ++sequence;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out\n${stderr}`)); }, timeout);
        pending.set(id, { resolve, reject, timer });
        child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
      });
    },
    stderr: () => stderr,
  };
  active = session;
  await greeting;
  return session;
}

async function stop(session, hard = false) {
  if (!session || session.child.exitCode !== null || session.child.signalCode !== null) return;
  if (!hard) {
    await session.rpc('close');
    session.child.stdin.end();
    const completed = await Promise.race([session.exited.then(() => true), new Promise(resolve => setTimeout(() => resolve(false), 5000))]);
    if (completed) return;
  }
  if (process.platform === 'win32') {
    await new Promise((resolve, reject) => {
      const killer = spawn('taskkill', ['/PID', String(session.child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
      killer.once('error', reject); killer.once('exit', resolve);
    });
  } else session.child.kill('SIGKILL');
  await session.exited;
}

async function open(session) { return session.rpc('open', { path: target, auto: false, database_key: 'reliability-fixture' }); }
async function failure(promise, saved) {
  let failure;
  await assert.rejects(promise, error => {
    assert.equal(error.code, 'partial_commit'); assert.equal(error.committed, true);
    assert.equal(error.saved, saved); assert.equal(error.recoveryRequired, true);
    assert(error.journalId); assert(error.revision > 0); failure = error; return true;
  });
  return failure;
}
const pass = (label, details = '') => console.log('PASS', label, JSON.stringify(details));

try {
  let session = await start();
  const imported = await open(session);
  assert.equal(imported.analysisComplete, false); assert.equal(imported.analysisProfile, 'unknown');
  const local = await session.rpc('analyze', { action: 'reanalyze', ea: fixture.addresses.add, size: 5, analysis_profile: 'full' });
  assert.equal(local.analysisScope, 'range'); assert.equal(local.scopeComplete, true);
  assert.equal(local.requestedAnalysisProfile, 'full'); assert.equal(local.analysisProfile, 'unknown');
  assert.equal(local.analysisComplete, false); assert.equal(local.partial, true); assert.equal(local.scopePartial, false); assert.equal(local.saved, false);
  let stats = await session.rpc('stats');
  assert.equal(stats.analysisComplete, false); assert.equal(stats.partial, true); assert.equal(stats.analysisProfile, 'unknown');
  pass('a successful range pass cannot certify an unanalysed program', local);
  const full = await session.rpc('analyze', { action: 'reanalyze', analysis_profile: 'interactive' });
  assert.equal(full.analysisScope, 'program'); assert.equal(full.analysisComplete, true);
  const rangeFull = await session.rpc('analyze', { action: 'reanalyze', ea: fixture.addresses.add, size: 5, analysis_profile: 'full' });
  assert.equal(rangeFull.analysisProfile, 'interactive'); assert.equal(rangeFull.analysisComplete, true);
  assert.equal((await session.rpc('stats')).analysisProfile, 'interactive');
  pass('range profile requests preserve the whole-program profile');

  const seeded = await session.rpc('comment', { ea: fixture.addresses.add, text: 'create journal' });
  assert.equal(seeded.saved, true);
  journalPath = path.join(projectRoot, imported.project + '-journal.jsonl');
  statePath = path.join(projectRoot, imported.project + '-state.json');
  const intentPath = path.join(projectRoot, imported.project + '-intent.json');
  await chmod(journalPath, 0o444);
  const journalFailure = await failure(session.rpc('rename', { ea: fixture.addresses.add, new_name: 'SAVED_DESPITE_ERROR' }), true);
  assert.equal((await session.rpc('inspect', { ea: fixture.addresses.add })).name, 'SAVED_DESPITE_ERROR');
  assert.equal((await session.rpc('stats')).recoveryRequired, true); await access(intentPath);
  assert(!(await readFile(journalPath, 'utf8')).includes('SAVED_DESPITE_ERROR'));
  await failure(session.rpc('comment', { ea: fixture.addresses.add, text: 'must not execute while blocked' }), true);
  assert.equal((await session.rpc('inspect', { ea: fixture.addresses.add })).comment, 'create journal');
  await chmod(journalPath, 0o666);
  await stop(session, true);
  session = await start();
  const journalRecovered = await open(session);
  assert.equal(journalRecovered.recovery.status, 'reconciled'); assert.equal(journalRecovered.recoveryRequired, false);
  assert.equal(journalRecovered.revision, journalFailure.revision); assert.equal(journalRecovered.durableRevision, journalFailure.revision);
  assert.equal((await session.rpc('inspect', { ea: fixture.addresses.add })).name, 'SAVED_DESPITE_ERROR');
  let audit = (await readFile(journalPath, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(audit.filter(row => row.id === journalFailure.journalId).length, 1);
  pass('readonly journal returns saved partial_commit; hard restart reconciles the native marker', journalRecovered.recovery);

  await chmod(statePath, 0o444);
  const stateFailure = await failure(session.rpc('comment', { ea: fixture.addresses.add, text: 'sidecar recovery' }), true);
  assert.equal((await session.rpc('inspect', { ea: fixture.addresses.add })).comment, 'sidecar recovery');
  await chmod(statePath, 0o666);
  await stop(session, true);
  session = await start();
  const stateRecovered = await open(session);
  assert.equal(stateRecovered.recovery.status, 'reconciled'); assert.equal(stateRecovered.revision, stateFailure.revision);
  assert.equal(JSON.parse(await readFile(statePath, 'utf8')).durableRevision, stateFailure.revision);
  audit = (await readFile(journalPath, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(audit.filter(row => row.id === stateFailure.journalId).length, 1);
  pass('readonly sidecar reconciles without duplicating the already-written audit record');

  const original = (await session.rpc('decompile', { ea: fixture.addresses.add })).code;
  const nativeWrite = await session.rpc('set_type', { ea: fixture.addresses.add, decl: 'int SAVED_DESPITE_ERROR(int durable_x, int durable_y);' });
  assert.equal(nativeWrite.saved, false); assert.equal(nativeWrite.persistence, 'session-only');
  assert.notEqual((await session.rpc('decompile', { ea: fixture.addresses.add })).code, original);
  await stop(session, true);
  session = await start();
  const lost = await open(session);
  assert.equal(lost.recovery.status, 'session_changes_lost'); assert(lost.durableRevision < lost.revision);
  assert.equal((await session.rpc('decompile', { ea: fixture.addresses.add })).code, original);
  pass('hard termination of native-undo writes reports the unsaved revision boundary', lost.recovery);
  const checkpointed = await session.rpc('set_type', { ea: fixture.addresses.add, decl: 'int SAVED_DESPITE_ERROR(int saved_x, int saved_y);' });
  await stop(session);
  session = await start();
  const durable = await open(session);
  assert.equal(durable.durableRevision, checkpointed.revision); assert.equal(durable.recoveryRequired, false);
  assert((await session.rpc('decompile', { ea: fixture.addresses.add })).code.includes('saved_x'));
  pass('graceful close checkpoints advanced native-undo writes');
  assert.deepEqual(await readFile(target), fixture.image);
  await stop(session); active = null;
  console.log('Ghidra reliability passed; artifacts:', temp);
} catch (error) {
  console.error(error.stack, '\nWORKER STDERR:\n', active?.stderr(), '\nArtifacts:', temp);
  process.exitCode = 1;
} finally {
  if (journalPath) await chmod(journalPath, 0o666).catch(() => {});
  if (statePath) await chmod(statePath, 0o666).catch(() => {});
  if (active) {
    try { await stop(active); }
    catch { await stop(active, true); }
  }
}
