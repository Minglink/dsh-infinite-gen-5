import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { apply } from './evals/m2_suite_guard.mjs';

function harness(t, config = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-m2-guard-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const hooks = new Map();
  const logPath = path.join(dir, 'guard.jsonl');
  apply({ on: (event, hook) => hooks.set(event, hook) }, {
    allowedRoots: [dir], workspaceRoot: dir, logPath,
    maxTotalToolCalls: 5, terminalControlReserve: 2, ...config,
  });
  return {
    dir,
    call: (name, args = {}, next = async () => ({ kind: 'continued' })) => hooks.get('tools/pre-execute')({ name, arguments: args }, next),
    logs: () => fs.readFileSync(logPath, 'utf8').trim().split('\n').map(JSON.parse),
  };
}

test('M2 reserves finite terminal controls within the original total cap', async t => {
  const h = harness(t);
  for (let i = 0; i < 3; i++) assert.equal((await h.call('ig5_status')).kind, 'continued');
  for (let i = 0; i < 4; i++) assert.equal((await h.call('ig5_decompile')).kind, 'deny');
  assert.equal((await h.call('get_goal')).kind, 'continued');
  assert.equal((await h.call('get_goal')).kind, 'deny', 'repeat status must preserve the final commit slot');
  assert.equal((await h.call('update_goal', { action: 'complete' })).kind, 'continued');
  assert.equal((await h.call('get_goal')).kind, 'deny');
  assert.equal((await h.call('update_goal', { action: 'complete' })).kind, 'deny');
  const admitted = h.logs().filter(e => e.event === 'allowed' && !e.isCleanupCall);
  assert.equal(admitted.length, 5);
  assert.equal(admitted.filter(e => e.usesTerminalReserve).length, 2);
});

test('reserved completion still reaches and obeys the downstream completion gate', async t => {
  const h = harness(t, { maxTotalToolCalls: 2 });
  let checked = 0;
  const result = await h.call('update_goal', { action: 'complete' }, async () => {
    checked++;
    return { kind: 'deny', reason: 'IG5 root is partial or cleanup is unconfirmed' };
  });
  assert.equal(checked, 1);
  assert.equal(result.kind, 'deny');
  assert.match(result.reason, /partial/);
  assert.equal((await h.call('update_goal', { action: 'blocked' })).kind, 'continued');
  assert.equal((await h.call('update_goal', { action: 'pause' })).kind, 'deny');
});

test('business, resume, edit, invalid paused, and budget reset cannot use terminal reserve', async t => {
  const h = harness(t, { maxTotalToolCalls: 2 });
  for (const [name, args] of [
    ['create_goal', {}],
    ['update_goal', { action: 'resume' }],
    ['update_goal', { action: 'edit' }],
    ['update_goal', { action: 'paused' }],
    ['ig5_profile', { collaboration: { action: 'start', max_calls: 999 } }],
    ['ig5_workspace', { workspace: { action: 'root-update' } }],
    ['ig5_dbg', { op: 'start' }],
  ]) assert.equal((await h.call(name, args)).kind, 'deny');
  assert.equal((await h.call('get_goal')).kind, 'continued');
  assert.equal((await h.call('update_goal', { action: 'pause' })).kind, 'continued');
});

test('cleanup stays available after both budgets, without bypassing owner checks', async t => {
  const h = harness(t, { maxTotalToolCalls: 2 });
  await h.call('get_goal');
  await h.call('update_goal', { action: 'blocked' });
  for (const [name, args] of [['ig5_dbg', { op: 'stop' }], ['ig5_capture_control', { action: 'stop' }], ['ig5_close', {}]]) {
    const result = await h.call(name, args, async () => ({ kind: 'deny', reason: 'owner gate retained' }));
    assert.equal(result.reason, 'owner gate retained');
  }
  assert.equal((await h.call('ig5_status')).kind, 'deny');
});

test('reserved terminal calls still undergo path checks', async t => {
  const h = harness(t, { maxTotalToolCalls: 2 });
  let dispatched = false;
  const result = await h.call('update_goal', { action: 'complete', path: path.dirname(h.dir) }, async () => { dispatched = true; });
  assert.equal(result.kind, 'deny');
  assert.equal(dispatched, false);
  assert.equal(h.logs().filter(e => e.event === 'denied-path-escape').length, 1);
});

test('zero reserve preserves the legacy budget cutoff; invalid reserves fail', async t => {
  const h = harness(t, { maxTotalToolCalls: 1, terminalControlReserve: 0 });
  assert.equal((await h.call('ig5_status')).kind, 'continued');
  assert.equal((await h.call('get_goal')).kind, 'deny');
  for (const terminalControlReserve of [-1, 6, 1.5]) assert.throws(() => harness(t, { terminalControlReserve }), /Invalid M2/);
});

test('closed tool allowlist blocks unconstrained code, patch, subagent, and external archive channels', async t => {
  const h = harness(t, { maxTotalToolCalls: 30, terminalControlReserve: 2 });
  for (const [name, args] of [
    ['ig5_run_idapython', { target: path.join(h.dir, 'sample.exe'), code: 'open("C:/secret").read()' }],
    ['apply_patch', { input: '*** Begin Patch\n*** Update File: ../secret.txt\n*** End Patch' }],
    ['read_image', { file_path: path.join(h.dir, 'img.png') }],
    ['subagent', { prompt: 'read outside' }],
    ['ig5_package', { path: path.join(h.dir, 'a.apk') }],
    ['ig5_capture', {}],
    ['ig5_capture_control', { action: 'start' }],
    ['ig5_recovery', {}],
    ['ig5_patch_bytes', { target: path.join(h.dir, 'sample.exe') }],
    ['ig5_sync', { target: path.join(h.dir, 'sample.exe') }],
    ['ig5_bindiff', {}],
    ['ig5_profile', { guest_debug: {} }],
    ['ig5_profile', { knowledge: { action: 'publish' } }],
  ]) {
    const res = await h.call(name, args);
    assert.equal(res.kind, 'deny', `${name} must be denied`);
  }
  assert.equal(h.logs().filter(e => e.event === 'denied-unallowlisted-tool').length, 13);
});

test('read/write/plugin-internal separation and CLI-arg path containment', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-m2-sep-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const workspace = path.join(root, 'workspace');
  const skills = path.join(root, 'skills');
  const ig5Home = path.join(root, 'ig5-home');
  const scriptsBlocked = path.join(root, 'scripts');
  const vault = path.join(root, 'vault');
  for (const d of [workspace, skills, ig5Home, scriptsBlocked, vault]) fs.mkdirSync(d, { recursive: true });

  const hooks = new Map();
  const logPath = path.join(root, 'guard.jsonl');
  apply({ on: (ev, fn) => hooks.set(ev, fn) }, {
    workspaceRoot: workspace,
    readOnlyRoots: [skills],
    searchAllowedRoots: [workspace, skills],
    pluginInternalRoots: [ig5Home],
    blockedPluginSubdirs: [scriptsBlocked],
    logPath,
    maxTotalToolCalls: 40,
    terminalControlReserve: 2,
  });
  const agent = { id: 'agent-sep' };
  const call = async (name, args = {}) => {
    const pre = await hooks.get('tools/pre-execute')({ name, arguments: args, agent }, async () => ({ kind: 'continued' }));
    if (pre.kind === 'continued' && hooks.has('tools/post-execute')) {
      await hooks.get('tools/post-execute')({ name, arguments: args, agent }, { isError: false, value: {} }, async () => {});
    }
    return pre;
  };

  // Read allowed in workspace & read-only skills, denied in ig5-home, scripts, and vault
  assert.equal((await call('read', { file_path: path.join(workspace, 'a.txt') })).kind, 'continued');
  assert.equal((await call('read', { file_path: path.join(skills, 'SKILL.md') })).kind, 'continued');
  assert.equal((await call('read', { file_path: path.join(ig5Home, 'projects.json') })).kind, 'deny');
  assert.equal((await call('read', { file_path: path.join(scriptsBlocked, 'run.py') })).kind, 'deny');
  assert.equal((await call('read', { file_path: path.join(vault, 'sentinel.txt') })).kind, 'deny');
  assert.equal((await call('read', { file_path: path.join(workspace, 'a.txt'), sandbox_permissions: 'danger-full-access', justification: 'x' })).kind, 'deny');

  // Write/edit strictly confined to workspace (denied even in read-only skills!)
  assert.equal((await call('write', { file_path: path.join(workspace, 'trigger_spec.json'), content: '{}' })).kind, 'continued');
  assert.equal((await call('write', { file_path: path.join(skills, 'SKILL.md'), content: 'x' })).kind, 'deny');
  assert.equal((await call('edit', { file_path: path.join(skills, 'SKILL.md'), old_string: 'a', new_string: 'b' })).kind, 'deny');
  assert.equal((await call('write', { file_path: path.join(vault, 'pwn.txt'), content: 'x' })).kind, 'deny');

  // Search pattern traversal & cd confinement
  assert.equal((await call('glob', { pattern: '**/*' })).kind, 'continued');
  assert.equal((await call('glob', { pattern: '../vault/*' })).kind, 'deny');
  assert.equal((await call('grep', { pattern: 'SENTINEL', glob: '../*' })).kind, 'deny');
  assert.equal((await call('grep', { pattern: 'SENTINEL', path: vault })).kind, 'deny');
  assert.equal((await call('working_directory', { cd: '../vault' })).kind, 'deny');
  const subDir = path.join(workspace, 'stage_run');
  fs.mkdirSync(subDir, { recursive: true });
  assert.equal((await call('working_directory', { cd: 'stage_run' })).kind, 'continued');
  assert.equal((await call('read', { file_path: '../../vault/sentinel.txt' })).kind, 'deny');

  // IG5 CLI args & scenario inputSpec file channel escapes denied
  assert.equal((await call('ig5_dbg', { op: 'start', target: path.join(workspace, 't.exe'), args: ['--mode=run', 'X=ABCD'] })).kind, 'continued');
  assert.equal((await call('ig5_dbg', { op: 'start', target: path.join(workspace, 't.exe'), args: [`--in=${path.join(vault, 'sentinel.txt')}`] })).kind, 'deny');
  assert.equal((await call('ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: 'r1',
      root: { scenario: { scenarioId: 's1', componentId: 'c1', args: ['--in=..\\..\\vault\\sentinel.txt'] } },
    },
  })).kind, 'deny');
  assert.equal((await call('ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: 'r1',
      root: { scenario: { scenarioId: 's1', componentId: 'c1', args: ['--in=in.bin'], inputSpec: { kind: 'file', filePath: path.join(vault, 'sentinel.txt') } } },
    },
  })).kind, 'deny');
  assert.equal((await call('ig5_workspace', {
    workspace: {
      action: 'root-update',
      id: 'r1',
      root: { prepareInputs: [{ path: path.join(vault, 'escape.bin'), hex: '4142' }] },
    },
  })).kind, 'deny');
});

test('host 3-round blocked check preserves ordinary and terminal reserve slots while cleanup never consumes ordinary budget', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-m2-rounds-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const hooks = new Map();
  const logPath = path.join(dir, 'guard.jsonl');
  const liveGoal = { id: 'goal-r', revision: 1, phase: 'active', roundsStarted: 1 };
  const mockCtx = {
    on: (ev, fn) => hooks.set(ev, fn),
    get: (svc) => (svc === 'goals' ? { get: () => liveGoal } : undefined),
  };
  apply(mockCtx, {
    allowedRoots: [dir],
    workspaceRoot: dir,
    logPath,
    maxTotalToolCalls: 4, // 2 ordinary + 2 terminal reserve
    terminalControlReserve: 2,
  });
  const agent = { id: 'agent-r', ctx: mockCtx };
  const call = (name, args = {}) => hooks.get('tools/pre-execute')({ name, arguments: args, agent }, async () => ({ kind: 'continued' }));

  // Cleanup calls BEFORE ordinary cap do NOT consume the 2 ordinary call slots!
  assert.equal((await call('ig5_dbg', { op: 'stop' })).kind, 'continued');
  assert.equal((await call('ig5_close', {})).kind, 'continued');

  // Both ordinary slots are still available:
  assert.equal((await call('ig5_status', {})).kind, 'continued');
  assert.equal((await call('ig5_status', {})).kind, 'continued');
  // 3rd ordinary call denied by budget:
  assert.equal((await call('ig5_status', {})).kind, 'deny');

  // Premature update_goal(action="blocked") in Round 1 and Round 2 is denied WITHOUT burning terminal reserve!
  const r1 = await call('update_goal', { goal_id: 'goal-r', revision: 1, action: 'blocked', blocked_reason: 'falsified' });
  assert.equal(r1.kind, 'deny');
  assert.match(r1.reason, /current round is 1\/3/);

  liveGoal.roundsStarted = 2;
  const r2 = await call('update_goal', { goal_id: 'goal-r', revision: 1, action: 'blocked', blocked_reason: 'falsified' });
  assert.equal(r2.kind, 'deny');
  assert.match(r2.reason, /current round is 2\/3/);

  // Advance to Round 3: BOTH terminal reserve slots (get_goal + update_goal blocked) remain intact!
  liveGoal.roundsStarted = 3;
  assert.equal((await call('get_goal', {})).kind, 'continued');
  assert.equal((await call('update_goal', { goal_id: 'goal-r', revision: 1, action: 'blocked', blocked_reason: 'falsified' })).kind, 'continued');
  assert.equal((await call('update_goal', { goal_id: 'goal-r', revision: 1, action: 'blocked', blocked_reason: 'again' })).kind, 'deny');

  const logs = fs.readFileSync(logPath, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(logs.filter((e) => e.event === 'denied-host-round-threshold-not-met').length, 2);
  assert.equal(logs.filter((e) => e.event === 'allowed' && e.isCleanupCall).length, 2);
  assert.equal(logs.filter((e) => e.event === 'allowed' && !e.isCleanupCall).length, 4);
});
