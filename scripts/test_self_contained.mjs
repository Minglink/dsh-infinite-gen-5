// Real public API acceptance from any relocated installation. Only generated code runs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';
import { runtimeConfiguration } from '../engine_runtime.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-contained-中文 '));
const saved = { ...process.env };
for (const key of Object.keys(process.env)) {
  if (/^IG5_|^JAVA_HOME$|^JDK_HOME$|^PYTHON|^GHIDRA/i.test(key)) delete process.env[key];
}
process.env.IG5_HOME = path.join(scratch, 'empty-home');
process.env.PATH = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32');
const tools = new Map(), effects = [];
const ctx = {
  tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
  get() {}, on() {}, inject() { return { dispose() {} }; },
  effect(body) { const dispose = body(); if (typeof dispose === 'function') effects.push(dispose); },
};
const fixture = buildPE64Fixture(1), target = path.join(scratch, 'generated.exe');
fs.writeFileSync(target, fixture.image);
const call = (name, args = {}) => tools.get(name).execute({ target, ...args }, { agent: { id: 'self-contained-acceptance' } });
const digest = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const runtimeManifest = JSON.parse(fs.readFileSync(path.join(root, 'runtimes/manifest.json'), 'utf8').replace(/^\uFEFF/, ''));
function verifyRuntime() {
  for (const item of runtimeManifest.files) {
    const full = path.resolve(root, 'runtimes', item.path);
    assert.ok(full.startsWith(path.join(root, 'runtimes') + path.sep));
    assert.equal(fs.statSync(full).size, item.bytes, item.path);
    assert.equal(digest(full), item.sha256, item.path);
  }
}
try {
  const runtime = runtimeConfiguration();
  for (const id of ['ghidra', 'x64dbg']) {
    assert.equal(runtime[id].available, true, runtime[id].reason);
    assert.equal(runtime[id].source, 'bundled');
    assert.ok(runtime[id].manifest.startsWith(path.join(root, 'runtimes') + path.sep));
  }
  verifyRuntime();
  apply(ctx, { reverse: false, toolset: 'full', requestTimeoutMs: 120000 });
  const profile = await call('ig5_profile');
  assert.equal(profile.engine, 'ghidra');
  assert.equal(profile.engineConfigured, true); assert.equal(profile.pythonConfigured, true);
  assert.equal(profile.engines.find(e => e.id === 'reverse').available, false);
  for (const engine of ['ghidra', 'x64dbg']) assert.equal((await call('ig5_doctor', { engine })).ok, true);
  const opened = await call('ig5_open', { path: target, background: false });
  assert.equal(opened.engine, 'ghidra'); assert.ok(opened.n_funcs >= 16);
  const ea = fixture.addresses.add;
  assert.ok((await call('ig5_decompile', { ea })).code.length > 10);
  assert.ok((await call('ig5_ir', { ea, level: 'high' })).instructions.length);
  await call('ig5_rename', { ea, new_name: 'OfflineBundledAdd', expected_revision: 0 });
  await call('ig5_close');
  await call('ig5_open', { path: target, background: false });
  assert.equal((await call('ig5_decompile', { ea })).name, 'OfflineBundledAdd');
  const dbg = (op, args = {}) => call('ig5_dbg', { engine: 'ghidra', backend: 'x64dbg', op, timeout: 15, ...args });
  const started = await dbg('start'); assert.equal(started.ok, true);
  assert.equal(started.mode, 'headless'); assert.equal(started.state, 'suspended');
  await dbg('bpt', { rva: '0x1000' });
  const entry = '0x' + (BigInt(started.context.mainModuleBase) + 0x1000n).toString(16);
  let regs = await dbg('regs');
  for (let i = 0; regs.regs.rip !== entry && i < 4; i++) { await dbg('cont'); regs = await dbg('regs'); }
  assert.equal(regs.regs.rip, entry);
  assert.equal((await dbg('readmem', { rva: '0x1000', size: 5 })).hex, '488d0411c3');
  assert.equal((await dbg('step')).ok, true);
  assert.notEqual((await dbg('regs')).regs.rip, entry);
  assert.equal((await dbg('stop')).state, 'no-task');
  const state = path.join(process.env.IG5_HOME, 'state/x64dbg/sessions');
  assert.ok(fs.readdirSync(state).length, 'debugger state belongs in the user home');
  assert.ok(fs.existsSync(path.join(process.env.IG5_HOME, 'projects')));
  assert.ok(!fs.existsSync(path.join(root, 'runtimes/x64dbg/sessions')));
  assert.deepEqual(fs.readFileSync(target), fixture.image);
  for (const dispose of effects.splice(0).reverse()) await dispose();
  verifyRuntime();
  console.log(JSON.stringify({ ok: true, pluginRoot: root, runtimes: 'bundled', reverse: false,
    runtimeFilesUnchanged: runtimeManifest.files.length, cleanEnvironment: true,
    ghidra: 'doctor/open/decompile/IR/persisted rename', x64dbg: 'headless start/breakpoint/registers/memory/step/stop' }));
} finally {
  for (const dispose of effects.reverse()) await dispose();
  for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
  Object.assign(process.env, saved);
  assert.equal(path.dirname(scratch), path.resolve(os.tmpdir()));
  assert.ok(path.basename(scratch).startsWith('ig5-contained-'));
  await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 30, retryDelay: 100 });
}
