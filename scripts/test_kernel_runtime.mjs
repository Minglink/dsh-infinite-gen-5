// Real public tool -> isolated IG5 native core; no opened engine database.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-native-kernel-'));
const fixture = buildPE64Fixture(), target = path.join(scratch, '独立内核.exe');
fs.writeFileSync(target, fixture.image);
const hash = () => createHash('sha256').update(fs.readFileSync(target)).digest('hex');
const original = hash(), tools = new Map(), effects = [];
const ctx = {
  tools: { register(definition) { tools.set(definition.name, definition); return () => tools.delete(definition.name); } },
  get() {}, on() {}, inject() { return { dispose() {} }; },
  effect(body) { const remove = body(); if (typeof remove === 'function') effects.push(remove); },
};
const call = args => tools.get('ig5_ir').execute({ target, level: 'kernel', ...args }, { agent: { id: 'kernel-test' } });
try {
  apply(ctx, { reverse: false, toolset: 'full', defaultEngine: 'ghidra', artifactDir: path.join(scratch, 'artifacts') });
  assert.equal(tools.size, 38);
  const info = await call({ action: 'info' });
  assert.equal(info.engine, 'IG5 Kernel'); assert.equal(info.commercialEngineUsed, false); assert.equal(info.jvmStarted, false);
  assert.equal(info.image.bits, 64); assert.equal(info.image.sha256, original);
  const inspected = await call({ ea: fixture.addresses.add, max_code_bytes: 5 });
  assert.deepEqual(inspected.instructions.map(row => row.mnemonic), ['LEA', 'RET']);
  assert.equal(inspected.cfg.blocks.length, 2); assert.equal(inspected.source.jvmStarted, false);
  assert.equal(inspected.source.commercialEngineUsed, false); assert.equal(inspected.idb_modified, false);
  assert.equal(inspected._ig5, undefined, 'stateless core must not fabricate a database attachment');
  const folded = await call({ ea: fixture.addresses.xor_self, max_code_bytes: 3, optimize: true });
  assert(folded.optimizations.some(row => row.rule === 'xor-self'));
  assert(folded.optimizations.every(row => row.after.opcode === 'COPY'));
  const branch = await call({ ea: fixture.addresses.branch, max_code_bytes: 15 });
  assert(branch.cfg.edges.some(row => row.kind === 'branch'));
  assert(branch.cfg.edges.some(row => row.kind === 'fallthrough'));
  const table = await call({ action: 'vtables', ea: fixture.vtable, abi: 'msvc', offset: 8 });
  assert.equal(table.total, 1); assert.equal(table.tables[0].selected_slot.target, fixture.addresses.buffer);
  const constant = await call({ action: 'decompile', ea: fixture.addresses.constant, max_code_bytes: 6 });
  assert.equal(constant.ok, true, JSON.stringify(constant)); assert.equal(constant.complete, true); assert.equal(constant.kind, 'native-c');
  assert.match(constant.code, /return (0x11|17);/); assert.equal(constant.source.jvmStarted, false);
  const cBranch = await call({ action: 'decompile', ea: fixture.addresses.branch, max_code_bytes: 16 });
  assert.equal(cBranch.ok, true, JSON.stringify(cBranch)); assert.equal(cBranch.complete, true); assert(cBranch.blocks >= 3);
  assert.match(cBranch.code, /if\s*\(/); assert.match(cBranch.code, /param_1/);
  const parameters = await call({ action: 'decompile', ea: fixture.addresses.add, max_code_bytes: 5 });
  assert.equal(parameters.ok, true); assert.match(parameters.code, /param_1 \+ param_2/);
  const incomplete = await call({ action: 'decompile', ea: fixture.addresses.constant, max_code_bytes: 4 });
  assert.equal(incomplete.ok, false); assert.equal(incomplete.complete, false); assert.equal(incomplete.partial, true);
  await assert.rejects(call({ ea: fixture.data }), /executable/);
  await assert.rejects(call({ ea: fixture.addresses.add, max_instructions: 1025 }), /max_instructions/);
  const bad = path.join(scratch, 'bad.bin'); fs.writeFileSync(bad, 'not a binary');
  await assert.rejects(call({ target: bad, action: 'info' }), /PE|ELF|format|unsupported/i);
  assert.equal(hash(), original);
  const status = await tools.get('ig5_status').execute({}, { agent: { id: 'kernel-test' } });
  assert.equal(status.count, 0, 'kernel request must not start a static database');
  console.log(JSON.stringify({ ok: true, tests: 15, publicTool: 'ig5_ir', level: 'kernel',
    decoder: 'Ghidra SLEIGH C ABI', kernelAnalysis: 'IG5-owned', commercialEngineUsed: false,
    jvmStarted: false, targetExecuted: false, targetUnchanged: true,
    nativeCDecompilerVerified: true, cScope: 'bounded explicit functions; constant/branch/parameters and incomplete bounds' }));
} finally {
  for (const dispose of effects.reverse()) await dispose();
  fs.rmSync(scratch, { recursive: true, force: true });
}
