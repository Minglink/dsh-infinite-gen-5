// Byte guards, undo-aware export, approval gate and paged audit records on a disposable fixture.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempRoot = fs.realpathSync(os.tmpdir());
const scratch = fs.mkdtempSync(path.join(tempRoot, 'ig5-patch-runtime-'));
const target = path.join(scratch, 'sample.exe');
const artifactDir = path.join(scratch, 'artifacts');
const fixture = buildPE64Fixture(1);
const tools = new Map(), routes = new Map(), listeners = new Map(), effects = [];
const service = { register(spec) { routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } };
const ctx = {
  tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
  get(name) { return name === 'webServer' ? service : undefined; },
  on(name, handler) { listeners.set(name, handler); },
  inject(names, callback) { const dispose = names.every(name => ctx.get(name)) ? callback({ get: ctx.get, webServer: service }) : null; return { dispose() { dispose?.(); } }; },
  effect(fn) { const remove = fn(); if (typeof remove === 'function') effects.push(remove); },
};
const call = async (name, args = {}) => tools.get(name).execute({ target, ...args });
function readAudit(query = '') {
  return new Promise(resolve => {
    let status;
    routes.get('/ig5-data')({ method: 'GET', url: '/ig5-data?type=approvals&target=' + encodeURIComponent(target) + query }, {
      writeHead(value) { status = value; }, end(body) { resolve({ status, body: JSON.parse(body) }); },
    });
  });
}
try {
  fs.writeFileSync(target, fixture.image);
  const plugin = await import(pathToFileURL(path.join(root, 'index.js')).href);
  plugin.apply(ctx, { toolset: 'full', artifactDir });
  await call('ig5_open', { path: target, background: false });
  const address = fixture.addresses.add;
  const original = await call('ig5_bytes', { ea: address, size: 1 });
  assert.equal(original.hex, '48');
  await assert.rejects(call('ig5_patch_bytes', { ea: address, hex: '90', expected: 'ff' }), /no longer match/);
  assert.equal((await call('ig5_bytes', { ea: address, size: 1 })).hex, '48');
  await assert.rejects(call('ig5_patch_bytes', { ea: '0x55550000', hex: '90' }), /fully readable/);
  const args = { target, ea: address, hex: '90', expected: '48' };
  const patch = await call('ig5_patch_bytes', args);
  assert.equal(patch.ok, true); assert.equal(patch.applied, true);
  await listeners.get('tools/post-execute')({ name: 'ig5_patch_bytes', arguments: args }, { isError: false, value: patch }, async () => ({ kind: 'accept' }));
  const exported = await call('ig5_export_diff');
  assert.equal(exported.patches, 1);
  assert.equal(fs.readFileSync(exported.patchedBinary)[patch.fileOffset], 0x90);
  assert.match(fs.readFileSync(exported.report, 'utf8'), /\| 48 \| 90 \|/);
  assert.equal((await call('ig5_undo')).kind, 'bytes');
  const undone = await call('ig5_export_diff');
  assert.equal(undone.patches, 0, 'export must exclude an undone historical patch');
  assert.deepEqual(fs.readFileSync(undone.patchedBinary), fixture.image);
  const auditPath = path.join(artifactDir, 'approvals.jsonl');
  const records = Array.from({ length: 45 }, (_, index) => ({ ts: '2026-10-09T00:00:00.000Z',
    tool: 'ig5_comment', args: { target }, isError: false, detail: { ok: true, index } }));
  records.push({ tool: 'ig5_patch_bytes', args: { target: path.join(scratch, 'other.exe') }, detail: { secret: 'other target' } });
  fs.appendFileSync(auditPath, records.map(value => JSON.stringify(value)).join('\n') + '\n');
  const page = await readAudit('&offset=20&limit=20');
  assert.equal(page.status, 200); assert.equal(page.body.data.total, 46);
  assert.equal(page.body.data.rows.length, 20); assert.equal(page.body.data.rows[0].detail.index, 24);
  assert.ok(page.body.data.rows.every(value => value.args.target === target));
  const gate = listeners.get('tools/pre-execute');
  for (const name of ['ig5_patch_bytes', 'ig5_switch_repair', 'ig5_emulate', 'ig5_dbg', 'ig5_struct']) {
    let dispatched = false;
    const decision = await gate({ name, arguments: { target } }, async () => { dispatched = true; return { kind: 'allow' }; });
    assert.equal(decision.kind, 'deny', 'Missing agent/approval service must deny ' + name);
    assert.equal(dispatched, false);
  }
  for (const name of ['ig5_stack', 'ig5_switches', 'ig5_vtables', 'ig5_microcode', 'ig5_bindiff']) {
    assert.equal((await gate({ name, arguments: { target } }, async () => ({ kind: 'allow' }))).kind, 'allow');
  }
  console.log('Patch runtime: original-byte guards, unmapped rejection, undo-aware export, target pagination and new approval tools passed.');
} finally {
  if (tools.has('ig5_close')) await call('ig5_close').catch(() => {});
  for (const remove of effects.reverse()) await remove();
  const relative = path.relative(tempRoot, path.resolve(scratch));
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
  await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
