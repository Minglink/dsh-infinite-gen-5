// Integration smoke test against an isolated copy; never writes the source fixture.
// Usage: node scripts/test_new_tools.mjs [targetBinary]
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixture = process.argv[2] || process.env.IG5_TEST_TARGET
  || path.join(pluginRoot, '..', '_research', 'fixtures', 'notepad.exe');
const tempRoot = fs.realpathSync(os.tmpdir());
const scratch = fs.mkdtempSync(path.join(tempRoot, 'ig5-new-tools-'));
const target = path.join(scratch, path.basename(fixture));
const tools = new Map();
const effects = [];

try {
  fs.copyFileSync(fixture, target);
  const mod = await import(pathToFileURL(path.join(pluginRoot, 'index.js')).href);
  const ctx = {
    tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
    on() {},
    get() { return undefined; },
    inject() { return { dispose() {} }; },
    effect(fn) { const dispose = fn(); if (typeof dispose === 'function') effects.push(dispose); },
  };
  mod.apply(ctx, {
    ...(process.env.IG5_IDA_DIR ? { idaDir: process.env.IG5_IDA_DIR } : {}),
    ...(process.env.IG5_PYTHON ? { pythonExe: process.env.IG5_PYTHON } : {}),
    artifactDir: path.join(scratch, 'artifacts'),
    toolset: 'full',
  });
  assert.equal(tools.size, 36, 'all 36 tools must be registered in full mode');

  const call = (name, args = {}) => tools.get(name).execute({ target, ...args });
  const core = await call('ig5_profile', { toolset: 'core' });
  assert.equal(core.activeTools.length, 8);
  assert.equal(tools.size, 8);
  assert.equal(tools.has('ig5_patch_bytes'), false);
  const full = await call('ig5_profile', { toolset: 'full' });
  assert.equal(full.activeTools.length, 36);
  assert.equal(tools.size, 36);
  const info = await call('ig5_open', { path: target, background: false });
  assert.ok(info.n_funcs > 0, 'fixture must contain analyzed functions');
  const funcs = await call('ig5_funcs', { limit: 30 });
  assert.ok(funcs.funcs.length > 0);
  const ea = [...funcs.funcs].sort((a, b) => b.size - a.size)[0].ea;

  const fp = await call('ig5_fingerprint');
  assert.equal(typeof fp.abi, 'string');
  assert.equal(fp.total_functions, funcs.total);
  assert.equal(fp.library_functions_count + fp.user_functions_count, fp.total_functions);
  const userFuncs = await call('ig5_funcs', { user_only: true, limit: 200 });
  assert.equal(userFuncs.total, fp.user_functions_count);
  assert.ok(userFuncs.funcs.every((fn) => fn.is_lib === false));
  console.log(`[fingerprint/filter] ${fp.total_functions} functions; ${userFuncs.total} user functions`);

  const defined = await call('ig5_struct', {
    action: 'define',
    decl: 'struct IG5TestHeader { int magic; int version; char tag[8]; };',
  });
  assert.equal(defined.status, 'ok');
  assert.equal(defined.action, 'define');
  assert.equal(defined.name, 'IG5TestHeader');
  assert.equal(defined.details?.size, 16);
  const header = await call('ig5_struct', { action: 'get', name: 'IG5TestHeader' });
  assert.equal(header.is_struct, true);
  assert.equal(header.size, 16);
  assert.deepEqual(header.fields.map(({ name, offset, size }) => ({ name, offset, size })), [
    { name: 'magic', offset: 0, size: 4 },
    { name: 'version', offset: 4, size: 4 },
    { name: 'tag', offset: 8, size: 8 },
  ]);
  const types = await call('ig5_struct', { action: 'list', filter: 'IG5TestHeader' });
  assert.ok(types.total_types > 0);
  assert.ok(types.items.some((item) => item.name === 'IG5TestHeader' && item.size === 16));
  console.log('[struct] define/get/list verified, including member offsets');

  const cfg = await call('ig5_cfg', { ea });
  assert.ok(cfg.total_blocks > 0);
  assert.ok(cfg.total_edges > 0, 'fixture function must exercise CFG edges');
  assert.equal(cfg.total_blocks, cfg.blocks.length);
  assert.equal(cfg.total_edges, cfg.edges.length);
  assert.match(cfg.mermaid, /flowchart TD/);
  const blocks = new Map(cfg.blocks.map((block) => [block.id, block]));
  for (const edge of cfg.edges) {
    assert.ok(blocks.get(edge.from)?.succs.includes(edge.to));
    assert.ok(blocks.get(edge.to)?.preds.includes(edge.from));
  }
  console.log(`[cfg] ${cfg.total_blocks} blocks, ${cfg.total_edges} edges`);

  const slice = await call('ig5_slice', { ea });
  assert.ok(slice.total_variables > 0, 'fixture function must have variables');
  assert.equal(slice.total_variables, slice.variables.length);
  assert.equal(slice.slice_lines, null, 'unfocused query returns the symbol table');
  const variable = slice.variables[0].name;
  const focused = await call('ig5_slice', { ea, var: variable });
  assert.equal(focused.slice_variable, variable);
  assert.ok(focused.slice_lines.length > 0);
  assert.ok(focused.slice_lines.every((line) => line.line_no > 0 && line.code.includes(variable)));
  console.log(`[slice] ${slice.total_variables} variables; ${focused.slice_lines.length} lines for ${variable}`);

  const data = info.segments.find((segment) => segment.name === '.data' && segment.size >= 16);
  assert.ok(data, 'fixture must contain writable data for type application');
  const applied = await call('ig5_struct', { action: 'apply', name: 'IG5TestHeader', ea: data.start });
  assert.equal(applied.status, 'ok');
  assert.equal(applied.applied, true);
  console.log('[struct] apply verified on isolated database');

  await call('ig5_close');
} finally {
  for (const dispose of effects.reverse()) await dispose();
  // Verify the absolute cleanup target remains inside the system temp directory.
  const relative = path.relative(tempRoot, path.resolve(scratch));
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
  await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
console.log('=== ALL NEW TOOL ASSERTIONS PASSED ===');
