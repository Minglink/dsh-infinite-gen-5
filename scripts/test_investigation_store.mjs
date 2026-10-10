import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { InvestigationStore } from '../source/investigation_store.js';
import { ProjectStore } from '../source/project_store.js';

const storeModule = new URL('../source/investigation_store.js', import.meta.url).href;
const digest = text => createHash('sha256').update(text).digest('hex');
const failure = (call, code) => assert.throws(call, error => error.code === code);
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-investigation-test-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('ig5-investigation-test-'));
    fs.rmSync(root, { recursive: true, force: true });
  });
  const sha256 = digest('sample');
  const context = { projectId: `project_${randomUUID()}`, artifactId: `artifact_${sha256}`, sha256, engine: 'reverse', provider: 'ghidra', attachmentId: `attachment_${randomUUID()}`, dbRevision: 0 };
  return { root, context, store: new InvestigationStore({ root }) };
}
function snapshot(key = 'snapshot') {
  return { digest: digest(key), report_id: randomUUID(), report_sha256: digest(`report:${key}`), function: { ea: '0x140001000', name: 'decode' }, sections: ['decompile', 'cfg', 'callers', 'callees', 'stack'] };
}

test('tasks recover without engine startup and keep caller statements distinct from system evidence', t => {
  const { root, context, store } = fixture(t);
  const task = store.create(context, { goal: '解释输入处理函数', hypothesis: '可能是解码器', next_step: '读取调用关系' }, 'agent-a');
  assert.equal(task.taskRevision, 0); assert.equal(task.status, 'active');
  assert.equal(task.progressIsCallerDeclared, true); assert.equal(task.statementOrigin, 'caller-statement');
  assert.deepEqual(task.systemEvidence, []);
  const updated = store.update(context, task.taskId, { expected_task_revision: 0, status: 'completed', conclusion: '模型声明完成，尚无独立验证' }, 'agent-a');
  assert.equal(updated.status, 'completed'); assert.equal(updated.taskRevision, 1);
  assert.equal(updated.progressIsCallerDeclared, true); assert.equal(updated.verified, undefined);
  assert.equal(new InvestigationStore({ root }).get(context, task.taskId).conclusion, updated.conclusion);
  const list = new InvestigationStore({ root }).list(context);
  assert.equal(list.tasks.length, 1); assert.equal(list.limit, 128); assert.equal(list.progressIsCallerDeclared, true);
  assert.equal(fs.existsSync(path.join(root, 'projects.json')), false, 'global engine project metadata stays untouched');
});

test('artifact/project/provider/engine identities are never inferred or merged', t => {
  const { context, store } = fixture(t), task = store.create(context, { goal: '定位函数' }, 'agent-a');
  const otherHash = digest('other');
  for (const changed of [
    { ...context, sha256: otherHash, artifactId: `artifact_${otherHash}` },
    { ...context, projectId: `project_${randomUUID()}` },
    { ...context, provider: 'commercial' },
    { ...context, engine: 'ghidra' },
  ]) {
    failure(() => store.get(changed, task.taskId), 'INVESTIGATION_IDENTITY_MISMATCH');
    failure(() => store.update(changed, task.taskId, { expected_task_revision: 0, status: 'paused' }, 'agent-b'), 'INVESTIGATION_IDENTITY_MISMATCH');
    assert.deepEqual(store.list(changed).tasks, []);
  }
  failure(() => store.get({ ...context, artifactId: `artifact_${otherHash}` }, task.taskId), 'INVESTIGATION_IDENTITY_MISMATCH');
});

test('system snapshots bind actual capture revision; reopening or mutations preserve and mark historical evidence', t => {
  const { context, store } = fixture(t), task = store.create(context, { goal: '解释分支' }, 'agent-a'), ref = snapshot();
  const recorded = store.recordSnapshot(context, task.taskId, ref, 'agent-a');
  assert.equal(recorded.taskRevision, 1); assert.equal(recorded.snapshotDeduplicated, false);
  const entry = recorded.systemEvidence[0];
  assert.equal(entry.provenance, 'system-tool-snapshot'); assert.equal(entry.stale, false);
  assert.equal(entry.context.dbRevision, 0); assert.equal(entry.context.attachmentId, context.attachmentId);
  assert.equal(entry.report_id, ref.report_id); assert.equal(entry.function.ea, '0x140001000');
  assert.match(entry.snapshot_id, /^[a-f0-9-]{36}$/);
  const changedRevision = store.get({ ...context, dbRevision: 2 }, task.taskId).systemEvidence[0];
  assert.equal(changedRevision.stale, true); assert.deepEqual(changedRevision.staleReasons, ['database-revision-changed']);
  const reopened = store.get({ ...context, attachmentId: `attachment_${randomUUID()}` }, task.taskId).systemEvidence[0];
  assert.deepEqual(reopened.staleReasons, ['attachment-changed']);
  assert.equal(reopened.context.attachmentId, context.attachmentId, 'historical capture is not promoted to current attachment');
  const both = store.get({ ...context, attachmentId: `attachment_${randomUUID()}`, dbRevision: 1 }, task.taskId).systemEvidence[0];
  assert.deepEqual(both.staleReasons, ['attachment-changed', 'database-revision-changed']);
});

test('dedup retains original report and revision instead of certifying a second supplied record', t => {
  const { context, store } = fixture(t), task = store.create(context, { goal: '读取函数' }, 'agent-a'), ref = snapshot();
  const first = store.recordSnapshot(context, task.taskId, ref, 'agent-a');
  const again = store.recordSnapshot(context, task.taskId, { ...ref, report_id: randomUUID() }, 'agent-b');
  assert.equal(again.snapshotDeduplicated, true); assert.equal(again.taskRevision, first.taskRevision);
  assert.equal(again.systemEvidence.length, 1); assert.equal(again.systemEvidence[0].report_id, ref.report_id);
  failure(() => store.update(context, task.taskId, { expected_task_revision: 0, status: 'completed' }, 'agent-b'), 'STALE_TASK_REVISION');
  const detached = store.get(context, task.taskId); detached.systemEvidence[0].report_id = randomUUID();
  assert.equal(store.get(context, task.taskId).systemEvidence[0].report_id, ref.report_id);
});

test('long C++ symbol metadata declares truncation while reports remain separately referenced', t => {
  const { context, store } = fixture(t), task = store.create(context, { goal: '还原长C++符号' }, 'agent-a');
  const longName = `namespace::${'TemplateArgument'.repeat(40)}`;
  assert(longName.length > 256);
  const value = { ...snapshot('long-symbol'), function: { ea: '0x140001000', name: longName.slice(0, 256), nameTruncated: true } };
  const captured = store.recordSnapshot(context, task.taskId, value, 'agent-a');
  assert.equal(captured.systemEvidence[0].function.name.length, 256);
  assert.equal(captured.systemEvidence[0].function.nameTruncated, true);
  assert.equal(store.get(context, task.taskId).systemEvidence[0].function.nameTruncated, true);
  for (const func of [
    { ea: '0x140001000', name: longName },
    { ea: '0x140001000', name: 'short', nameTruncated: true },
    { ea: '0x140001000', nameTruncated: true },
    { ea: '0x140001000', name: longName.slice(0, 256), nameTruncated: 'true' },
  ]) failure(() => store.recordSnapshot(context, task.taskId, { ...snapshot(randomUUID()), function: func }, 'agent-a'), 'INVALID_INVESTIGATION');
  failure(() => store.create(context, { goal: 'x', function: value.function }, 'agent-a'), 'INVALID_INVESTIGATION');
});

test('caller inputs cannot submit verification, system evidence, paths or unsupported fields', t => {
  const { context, store } = fixture(t), task = store.create(context, { goal: '核对分支' }, 'agent-a');
  for (const extra of [{ verified: true }, { evidence: [] }, { systemEvidence: [] }, { path: 'C:\\outside.json' }, { output_path: '../task.json' }, { report_id: randomUUID() }]) {
    failure(() => store.create(context, { goal: 'x', ...extra }, 'agent-a'), 'INVALID_INVESTIGATION');
    failure(() => store.update(context, task.taskId, { expected_task_revision: 0, status: 'completed', ...extra }, 'agent-a'), 'INVALID_INVESTIGATION');
    if (!Object.hasOwn(extra, 'report_id')) failure(() => store.recordSnapshot(context, task.taskId, { ...snapshot(), ...extra }, 'agent-a'), 'INVALID_INVESTIGATION');
  }
  const accessor = { goal: 'x' }; Object.defineProperty(accessor, 'hypothesis', { enumerable: true, get() { throw new Error('must not run'); } });
  failure(() => store.create(context, accessor, 'agent-a'), 'INVALID_INVESTIGATION');
  failure(() => store.update(context, task.taskId, { expected_task_revision: 0, status: 'verified' }, 'agent-a'), 'INVALID_INVESTIGATION');
  failure(() => store.update(context, task.taskId, { status: 'completed' }, 'agent-a'), 'INVALID_INVESTIGATION');
  failure(() => store.create(context, { goal: 'x'.repeat(4097) }, 'agent-a'), 'INVALID_INVESTIGATION');
  failure(() => store.create(context, { goal: ' ' }, 'agent-a'), 'INVALID_INVESTIGATION');
  failure(() => store.create(context, { goal: 'x' }, ''), 'INVALID_INVESTIGATION');
  failure(() => store.get(context, '../outside'), 'INVALID_INVESTIGATION');
  failure(() => store.recordSnapshot(context, task.taskId, { ...snapshot(), report_id: `${randomUUID()}.json` }, 'agent-a'), 'INVALID_INVESTIGATION');
  failure(() => store.recordSnapshot(context, task.taskId, { ...snapshot(), function: { ea: 9007199254740992 } }, 'agent-a'), 'INVALID_ADDRESS');
  failure(() => store.recordSnapshot(context, task.taskId, { ...snapshot(), sections: ['idapython'] }, 'agent-a'), 'INVALID_INVESTIGATION');
  assert.equal(store.get(context, task.taskId).taskRevision, 0);
});

test('bounded retention rejects overflow without replacing older tasks or evidence', t => {
  const { context, store } = fixture(t), task = store.create(context, { goal: '证据预算' }, 'agent-a');
  for (let index = 0; index < 64; index++) store.recordSnapshot(context, task.taskId, snapshot(`snapshot-${index}`), 'agent-a');
  failure(() => store.recordSnapshot(context, task.taskId, snapshot('overflow'), 'agent-a'), 'INVESTIGATION_EVIDENCE_LIMIT');
  assert.equal(store.get(context, task.taskId).systemEvidence.length, 64);
  // Create the remaining tasks under the normal atomic transaction; no synthetic oversized metadata.
  for (let index = 1; index < 128; index++) store.create(context, { goal: `task-${index}` }, 'agent-a');
  failure(() => store.create(context, { goal: 'overflow' }, 'agent-a'), 'INVESTIGATION_LIMIT');
  assert.equal(store.list(context).tasks.length, 128);
});

test('failed atomic metadata replacement preserves old task and releases the owner lock', t => {
  const { root, context, store } = fixture(t), task = store.create(context, { goal: '旧任务' }, 'agent-a');
  const before = fs.readFileSync(store.metadata.file), rename = fs.renameSync;
  fs.renameSync = (from, to) => { if (to === store.metadata.file) throw new Error('simulated metadata replacement failure'); return rename(from, to); };
  try { assert.throws(() => store.update(context, task.taskId, { expected_task_revision: 0, goal: '不得出现' }, 'agent-a'), /simulated/); }
  finally { fs.renameSync = rename; }
  assert.deepEqual(fs.readFileSync(store.metadata.file), before); assert.equal(fs.existsSync(store.metadata.lockFile), false);
  assert.equal(new InvestigationStore({ root }).get(context, task.taskId).goal, '旧任务');
  assert.equal(fs.readdirSync(store.metadata.root).some(file => file.endsWith('.tmp')), false);
});

test('schema 1 project metadata without investigation records remains compatible', t => {
  const { root, store } = fixture(t), target = path.join(root, 'sample.bin'); fs.writeFileSync(target, 'fixture');
  const original = new ProjectStore({ root: path.join(root, 'legacy-projects') }); original.open(target);
  assert.deepEqual(new ProjectStore({ root: original.root }).readInvestigationRecords(), {});
  assert.equal(new ProjectStore({ root: original.root }).listProjects().length, 1);
  assert.deepEqual(store.metadata.readInvestigationRecords(), {});
});

test('malformed stored provenance fails closed rather than yielding a verified-looking record', t => {
  const { context, store } = fixture(t), task = store.create(context, { goal: '记录完整性' }, 'agent-a');
  store.recordSnapshot(context, task.taskId, snapshot(), 'agent-a');
  const data = JSON.parse(fs.readFileSync(store.metadata.file, 'utf8'));
  data.investigations[task.taskId].systemEvidence[0].provenance = 'verified-by-user';
  fs.writeFileSync(store.metadata.file, JSON.stringify(data));
  const before = fs.readFileSync(store.metadata.file);
  failure(() => store.get(context, task.taskId), 'INVESTIGATION_STORE_CORRUPT');
  failure(() => store.list(context), 'INVESTIGATION_STORE_CORRUPT');
  failure(() => store.update(context, task.taskId, { expected_task_revision: 1, status: 'completed' }, 'agent-a'), 'INVESTIGATION_STORE_CORRUPT');
  assert.deepEqual(fs.readFileSync(store.metadata.file), before);
});

test('two real host processes compare-and-swap one task revision without a lost update', { timeout: 45000 }, async t => {
  const { root, context, store } = fixture(t), task = store.create(context, { goal: '竞争更新' }, 'agent-a');
  function child(name) {
    const code = `import { InvestigationStore } from ${JSON.stringify(storeModule)};
      const store = new InvestigationStore({root:${JSON.stringify(root)}});
      process.stdout.write('READY\\n'); await new Promise(resolve => process.stdin.once('data', resolve));
      for (let attempt=0; attempt<200; attempt++) {
        try { const value=store.update(${JSON.stringify(context)},${JSON.stringify(task.taskId)}, {expected_task_revision:0,goal:${JSON.stringify(name)}}, ${JSON.stringify(name)}); process.stdout.write(JSON.stringify({ok:true,revision:value.taskRevision})+'\\n'); break; }
        catch(error) { if(error.code==='STORE_BUSY') { await new Promise(resolve=>setTimeout(resolve,10)); continue; } process.stdout.write(JSON.stringify({ok:false,code:error.code})+'\\n'); break; }
      }`;
    const proc = spawn(process.execPath, ['--input-type=module', '-e', code], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    t.after(() => { if (proc.exitCode === null && proc.signalCode === null) proc.kill(); });
    let out = '', stderr = '';
    const ready = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`child ${name} startup timed out: ${stderr}`)), 20000);
      proc.stdout.on('data', bytes => { out += bytes; if (out.includes('READY\n')) { clearTimeout(timer); resolve(); } });
      proc.once('error', error => { clearTimeout(timer); reject(error); });
    });
    proc.stderr.on('data', bytes => { stderr += bytes; });
    const done = new Promise((resolve, reject) => { proc.once('error', reject); proc.once('exit', code => code === 0 ? resolve(out) : reject(new Error(`child ${name} exited ${code}: ${stderr}`))); });
    return { proc, ready, done };
  }
  const children = [child('writer-a'), child('writer-b')];
  await Promise.all(children.map(value => value.ready));
  for (const value of children) value.proc.stdin.end('GO');
  const results = (await Promise.all(children.map(value => value.done))).map(out => JSON.parse(out.split('\n').find(line => line.startsWith('{'))));
  assert.equal(results.filter(value => value.ok).length, 1);
  assert.equal(results.filter(value => value.code === 'STALE_TASK_REVISION').length, 1);
  const persisted = new InvestigationStore({ root }).get(context, task.taskId);
  assert.equal(persisted.taskRevision, 1); assert.ok(['writer-a', 'writer-b'].includes(persisted.goal));
});
