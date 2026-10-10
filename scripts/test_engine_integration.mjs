// End-to-end public tool routing, database evidence and explicit cross-engine plans.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { apply } from '../index.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const temporary = fs.realpathSync(os.tmpdir());
const scratch = fs.mkdtempSync(path.join(temporary, 'ig5-engines-'));
const fixture = buildPE64Fixture(1), target = path.join(scratch, '样本.exe');
fs.writeFileSync(target, fixture.image);
const tools = new Map(), effects = [], events = new Map(), routes = new Map();
const webServer = { register(spec) { routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } };
const ctx = {
  tools: { register(definition) { tools.set(definition.name, definition); return () => tools.delete(definition.name); } },
  get: (name) => name === 'webServer' ? webServer : undefined,
  on(name, handler) { events.set(name, handler); },
  inject(names, callback) { if (names.includes('webServer')) callback({ webServer }); return { dispose() {} }; },
  effect(body) { const remove = body(); if (typeof remove === 'function') effects.push(remove); },
};
const call = (name, args = {}, agent = 'test-agent') => tools.get(name).execute({ target, ...args }, { agent: { id: agent } });
const read = (type, engine, extra = {}) => new Promise((resolve, reject) => {
  routes.get('/ig5-data')({ method: 'GET', url: '/ig5-data?' + new URLSearchParams({ target, type, engine, ...extra }) }, {
    writeHead(code) { assert.equal(code, 200); }, end(body) { const data = JSON.parse(body); data.error ? reject(new Error(data.error)) : resolve(data); },
  });
});
try {
  // Proves Ghidra can bootstrap with the commercial runtime deliberately disabled.
  apply(ctx, { reverse: false, defaultEngine: 'ghidra', toolset: 'full', artifactDir: path.join(scratch, 'artifacts'), requestTimeoutMs: 120000 });
  assert.equal(tools.size, 38);
  const profile = await call('ig5_profile');
  const builtin = profile.engines.find((item) => item.id === 'reverse');
  assert.equal(builtin.available, true); assert.equal(builtin.provider, 'ghidra'); assert.equal(builtin.distribution, 'bundled');
  assert.equal((await call('ig5_doctor')).engine, 'ghidra');
  await assert.rejects(call('ig5_open', { path: target, background: false, analysis_profile: 'invalid' }), /analysis_profile/);
  const first = await call('ig5_open', { path: target, background: false });
  assert.equal(first.engine, 'ghidra'); assert.ok(first.n_funcs >= 16); assert.equal(first.dbRevision, 0);
  assert.equal(first.analysisProfile, 'interactive'); assert.equal(first.partial, false);
  assert.equal(first.analysisComplete, true); assert.deepEqual(first.skippedAnalyzers, ['Decompiler Parameter ID']);
  const ea = fixture.addresses.add;
  const before = await call('ig5_decompile', { ea });
  assert.ok(before.code.length > 10); assert.equal(before._ig5.engine, 'ghidra');
  assert.equal((await read('funcs', 'ghidra')).engine, 'ghidra');
  const intermediate = await call('ig5_microcode', { ea, maturity: 'generated' });
  assert.equal(intermediate.ok, true); assert.equal(intermediate.graph_built, true);
  assert.equal(intermediate.representation, 'Ghidra p-code'); assert.equal(intermediate.hexRaysEquivalent, false);
  assert.equal(intermediate.idb_modified, false); assert.equal(intermediate.actualStage, 'firstpass');
  assert.ok(intermediate.returned_instructions > 0); assert.ok(intermediate.blocks.some(block => block.instructions.length));
  assert.equal(intermediate._ig5.engine, 'ghidra');
  assert.ok((await call('ig5_ir', { engine: 'ghidra', ea, level: 'high' })).instructions.length > 0);
  await call('ig5_rename', { ea, new_name: 'IG5Renamed', expected_revision: 0 });
  const after = await call('ig5_decompile', { ea });
  assert.equal(after.name, 'IG5Renamed'); assert.equal(after._ig5.dbRevision, 1);
  await assert.rejects(call('ig5_comment', { ea, text: 'stale', expected_revision: 0 }), /revision changed/);
  const concurrent = await Promise.allSettled([
    call('ig5_comment', { ea, text: 'reviewed', expected_revision: 1 }),
    call('ig5_comment', { ea, text: 'outdated', expected_revision: 1 }),
  ]);
  assert.equal(concurrent.filter((result) => result.status === 'fulfilled').length, 1, 'revision guard must run when the serialized write begins');
  await call('ig5_close');
  const reopened = await call('ig5_open', { path: target, background: false });
  assert.equal(reopened.dbRevision, 2); assert.equal((await call('ig5_decompile', { ea })).name, 'IG5Renamed');
  console.log('[Ghidra-only] native routing, UI read route, IR, persisted rename, cache invalidation, concurrent stale guard and revision reuse passed');
  for (const dispose of effects.splice(0).reverse()) await dispose();
  tools.clear();

  apply(ctx, { toolset: 'full', artifactDir: path.join(scratch, 'cross'), requestTimeoutMs: 120000 });
  const reverse = await call('ig5_open', { path: target, engine: 'reverse', background: false });
  const ghidra = await call('ig5_open', { path: target, engine: 'ghidra', background: false });
  assert.equal(reverse.artifactId, ghidra.artifactId); assert.equal(reverse.projectId, ghidra.projectId);
  assert.equal(reverse.engine, 'reverse'); assert.equal(reverse.provider, 'ghidra');
  assert.ok(reverse.databasePath); assert.ok(ghidra.databasePath); assert.notEqual(reverse.databasePath, ghidra.databasePath);
  assert.equal((await call('ig5_ir', { ea, level: 'raw' }))._ig5.engine, 'ghidra', 'IR retains Ghidra evidence when the primary engine is Reverse');
  await call('ig5_rename', { engine: 'reverse', ea, new_name: 'UnifiedAdd' });
  await call('ig5_comment', { engine: 'reverse', ea, text: 'Cross-engine evidence' });
  assert.notEqual((await call('ig5_decompile', { engine: 'ghidra', ea })).name, 'UnifiedAdd', 'the destination database must remain unchanged before the explicit sync');
  const params = { target, source_engine: 'reverse', destination_engine: 'ghidra',
    selections: [{ kind: 'rename', rva: '0x1000' }, { kind: 'comment', rva: '0x1000' }] };
  const plan = await call('ig5_sync', { action: 'preview', ...params });
  assert.equal(plan.rows.length, 2);
  let approvalDispatch = false;
  const unapproved = await events.get('tools/pre-execute')({ name: 'ig5_sync', arguments: { ...params, action: 'apply', plan_id: plan.plan_id } }, () => { approvalDispatch = true; return { kind: 'allow' }; });
  assert.equal(unapproved.kind, 'deny', 'Missing agent/approval service must deny cross-engine writes');
  assert.equal(approvalDispatch, false);
  await assert.rejects(call('ig5_sync', { action: 'apply', plan_id: plan.plan_id, plan_digest: 'wrong' }), /digest/);
  const applyArgs = { action: 'apply', plan_id: plan.plan_id, plan_digest: plan.plan_digest };
  const contenders = await Promise.allSettled([call('ig5_sync', applyArgs), call('ig5_sync', applyArgs)]);
  assert.equal(contenders.filter((item) => item.status === 'fulfilled').length, 1, 'concurrent calls cannot consume the same plan twice');
  assert.match(contenders.find((item) => item.status === 'rejected').reason.message, /already been attempted/);
  const applied = contenders.find((item) => item.status === 'fulfilled').value;
  assert.equal(applied.ok, true); assert.equal(applied.applied.length, 2);
  assert.equal(applied._ig5.engine, 'ghidra', 'changeset evidence belongs to the destination engine');
  assert.equal((await call('ig5_decompile', { engine: 'ghidra', ea })).name, 'UnifiedAdd');
  await assert.rejects(call('ig5_sync', { action: 'apply', plan_id: plan.plan_id, plan_digest: plan.plan_digest }), /already been attempted/);
  await call('ig5_comment', { engine: 'reverse', ea, text: 'Next version' });
  const stale = await call('ig5_sync', { action: 'preview', ...params });
  await call('ig5_comment', { engine: 'ghidra', ea, text: 'independent change' });
  await assert.rejects(call('ig5_sync', { action: 'apply', plan_id: stale.plan_id, plan_digest: stale.plan_digest }), /stale/);
  await call('ig5_patch_bytes', { engine: 'reverse', ea, hex: '90', expected: '48' });
  const bytesPlan = await call('ig5_sync', { action: 'preview', ...params, selections: [{ kind: 'patch', rva: '0x1000', size: 1 }] });
  const bytesApplied = await call('ig5_sync', { action: 'apply', plan_id: bytesPlan.plan_id, plan_digest: bytesPlan.plan_digest });
  assert.equal(bytesApplied.ok, true);
  await events.get('tools/post-execute')({ name: 'ig5_sync', arguments: { target, action: 'apply', plan_id: bytesPlan.plan_id } }, { isError: false, value: bytesApplied }, async () => ({}));
  const exported = await call('ig5_export_diff', { engine: 'ghidra' });
  assert.equal(exported.patches, 1); assert.equal(fs.readFileSync(exported.patchedBinary)[0x400], 0x90);
  assert.ok(exported.derivedArtifactId); assert.notEqual(exported.derivedArtifactId, ghidra.artifactId);
  await call('ig5_undo', { engine: 'ghidra' });
  assert.equal((await call('ig5_export_diff', { engine: 'ghidra' })).patches, 0);
  assert.equal((await call('ig5_status')).sessions.filter((session) => session.target === target).length, 2);
  console.log('[cross-engine] shared artifact, separate databases, concrete changeset preview/digest/gate, apply, replay and stale rejection passed');
} finally {
  for (const dispose of effects.reverse()) await dispose();
  assert.equal(path.dirname(path.resolve(scratch)), temporary);
  assert.ok(path.basename(scratch).startsWith('ig5-engines-'));
  await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 30, retryDelay: 100 });
}
