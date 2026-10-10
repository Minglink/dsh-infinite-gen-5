// Real Reverse/Unicorn integration on generated, disposable PE64 copies only.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempRoot = fs.realpathSync(os.tmpdir());
const scratch = fs.mkdtempSync(path.join(tempRoot, 'ig5-advanced-runtime-'));
const fixtures = [buildPE64Fixture(1), buildPE64Fixture(2)];
const targets = fixtures.map((fixture) => path.join(scratch, 'version-' + fixture.version + '.exe'));
const tools = new Map();
const routes = new Map();
const effects = [];
const services = {
  webServer: { register(spec) { routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } },
};
const ctx = {
  tools: { register(definition) { assert.ok(!tools.has(definition.name)); tools.set(definition.name, definition); return () => tools.delete(definition.name); } },
  on() {},
  get(name) { return services[name]; },
  inject(names, callback) {
    let remove;
    if (names.every((name) => services[name])) remove = callback({ get: ctx.get, ...services });
    return { async dispose() { if (typeof remove === 'function') { const once = remove; remove = undefined; await once(); } } };
  },
  effect(body) { const remove = body(); if (typeof remove === 'function') effects.push(remove); },
};
async function call(name, args = {}, target = targets[0]) {
  const definition = tools.get(name);
  assert.ok(definition, name + ' must be registered in full mode');
  return definition.execute({ target, ...args }, {});
}
async function readData(query) {
  return new Promise((resolve, reject) => {
    try {
      routes.get('/ig5-data')({ method: 'GET', url: '/ig5-data?' + new URLSearchParams({ target: targets[0], ...query }) }, {
        writeHead(status) { assert.equal(status, 200); },
        end(body) { const value = JSON.parse(body); if (value.error) reject(new Error(value.error)); else resolve(value.data); },
      });
    } catch (error) { reject(error); }
  });
}
try {
  targets.forEach((target, index) => fs.writeFileSync(target, fixtures[index].image));
  const plugin = await import(pathToFileURL(path.join(root, 'index.js')).href);
  plugin.apply(ctx, {
    reverseProvider: 'commercial', defaultEngine: 'reverse',
    ...(process.env.IG5_IDA_DIR ? { idaDir: process.env.IG5_IDA_DIR } : {}),
    ...(process.env.IG5_PYTHON ? { pythonExe: process.env.IG5_PYTHON } : {}),
    toolset: 'full', artifactDir: path.join(scratch, 'artifacts'), requestTimeoutMs: 120_000,
  });
  for (const target of targets) {
    const opened = await call('ig5_open', { path: target, background: false }, target);
    assert.equal(opened.bits, 64);
    assert.ok(opened.n_funcs >= 16, 'all exported fixture functions must be analyzed');
  }
  const addresses = fixtures[0].addresses;
  const added = await call('ig5_emulate', { ea: addresses.add, args: ['19', '23'] });
  assert.equal(added.ok, true); assert.equal(added.reason, 'returned'); assert.equal(added.return_value, '0x2a');
  assert.ok(added.instructions >= 2);
  const buffer = await call('ig5_emulate', {
    ea: addresses.buffer, args: ['0x60000000'], memory: [{ ea: '0x60000000', hex: '11223344' }],
    capture: [{ ea: '0x60000000', size: 4 }],
  });
  assert.equal(buffer.ok, true); assert.equal(buffer.return_value, '0x60000000');
  assert.equal(buffer.memory[0].hex, '5a223344');
  const spin = await call('ig5_emulate', { ea: addresses.spin, max_instructions: 25, timeout_ms: 100 });
  assert.equal(spin.ok, false); assert.equal(spin.reason, 'instruction-limit'); assert.equal(spin.instructions, 25);
  const fault = await call('ig5_emulate', { ea: addresses.fault, args: ['0x55550000'] });
  assert.equal(fault.ok, false); assert.equal(fault.reason, 'unmapped-memory'); assert.equal(fault.fault.ea, '0x55550000');
  console.log('[emulate] integer return, copied memory capture, instruction budget, and unmapped access verified');

  const disasm = await readData({ type: 'disasm', ea: addresses.add, limit: '2', size: '5' });
  assert.equal(disasm.rows.length, 2);
  assert.equal(disasm.rows[0].bytes, '488d0411'); assert.match(disasm.rows[0].text, /lea/i);
  assert.equal(disasm.rows[1].bytes, 'c3'); assert.match(disasm.rows[1].text, /ret/i);
  const diff = await call('ig5_bindiff', { left: targets[0], right: targets[1], threshold: 0.4, limit: 100 });
  const constant = diff.matches.find((item) => item.old.name === 'ig5_fixture_constant');
  assert.ok(constant && constant.new.name === 'ig5_fixture_constant' && constant.changed);
  assert.ok(constant.evidence.constantsRemoved.includes('0x11'));
  assert.ok(constant.evidence.constantsAdded.includes('0x29'));
  assert.ok(constant.changedBlocks.old.length && constant.changedBlocks.new.length);
  const branch = diff.matches.find((item) => item.old.name === 'ig5_fixture_branch');
  assert.ok(branch && branch.new.name === 'ig5_fixture_branch' && branch.changed);
  assert.ok(branch.changedBlocks.new.length > 0, 'the new comparison arm adds basic blocks; preserved old blocks need not be reported as removed');
  const memoff = diff.matches.find((item) => item.old.name === 'ig5_fixture_memoff');
  assert.ok(memoff && memoff.new.name === 'ig5_fixture_memoff' && memoff.changed, 'changing a memory displacement must change function semantics');
  assert.ok(memoff.changedBlocks.old.length > 0 && memoff.changedBlocks.new.length > 0, 'changed memory operands must appear in block evidence');
  const same = diff.matches.find((item) => item.old.name === 'ig5_fixture_add');
  assert.ok(same && same.changed === false);
  assert.equal(diff.summary.incomplete, false);
  // Anonymous call targets used to normalize to the same literal "mapped".
  // Build a caller outside the export table and retarget it from return-17 to return-0.
  for (let index = 0; index < targets.length; index++) {
    const callee = index === 0 ? 0x1100 : 0x12c0;
    const call = Buffer.alloc(6); call[0] = 0xe8; call.writeInt32LE(callee - 0x1385, 1); call[5] = 0xc3;
    await tools.get('ig5_run_idapython').execute({ target: targets[index], code: [
      'import ida_bytes, ida_funcs, ida_name, ida_ua',
      `ida_bytes.patch_bytes(0x140001380, bytes.fromhex('${call.toString('hex')}'))`,
      'ida_bytes.del_items(0x140001380, 0, 6)',
      'ida_ua.create_insn(0x140001380)',
      'ida_ua.create_insn(0x140001385)',
      'ida_funcs.add_func(0x140001380, 0x140001386)',
      "ida_name.set_name(0x140001380, 'IG5AnonymousCaller', ida_name.SN_NOWARN)",
      "ida_name.set_name(0x140001100, '', ida_name.SN_NOWARN)",
      "ida_name.set_name(0x1400012c0, '', ida_name.SN_NOWARN)",
    ].join('\n') }, {});
  }
  const anonymous = await call('ig5_bindiff', { left: targets[0], right: targets[1], threshold: 0.4, limit: 100 });
  const retargeted = anonymous.matches.find((item) => item.old.name === 'IG5AnonymousCaller');
  assert.ok(retargeted?.changed, 'anonymous call retargeting must not be reported as unchanged');
  assert.ok(retargeted.changedBlocks.old.length && retargeted.changedBlocks.new.length);
  await assert.rejects(call('ig5_bindiff', { left: targets[0], right: targets[0] }), /different target/);
  console.log('[disasm/bindiff] exact instruction rows; unchanged function and constant/CFG changes across two paths verified');

  const stack = await call('ig5_stack', { ea: addresses.frame });
  assert.equal(stack.ok, true); assert.equal(stack.has_frame, true);
  assert.ok(stack.total_members > 0 && stack.frame_size >= 32);
  assert.ok(stack.members.some((member) => member.kind === 'locals' && member.size === 8));
  const microcode = await call('ig5_microcode', { ea: addresses.add, maturity: 'generated' });
  assert.equal(microcode.ok, true); assert.equal(microcode.graph_built, true);
  assert.ok(microcode.total_blocks > 0 && microcode.returned_instructions > 0);
  assert.ok(microcode.blocks.some((block) => block.instructions.some((instruction) => instruction.text.length > 0)));
  const optimized = await call('ig5_microcode', { ea: addresses.add, maturity: 'generated', action: 'optimize' });
  assert.equal(optimized.ok, true); assert.equal(optimized.optimization.idb_modified, false);
  assert.ok(Array.isArray(optimized.optimization.before) && optimized.optimization.before.length > 0);
  assert.ok(Array.isArray(optimized.optimization.after) && optimized.optimization.after.length > 0);
  assert.equal(typeof optimized.optimization.changes, 'number');
  for (const [functionName, rule] of [['xor_self', 'xor-self'], ['sub_self', 'sub-self'], ['xor_copy', 'xor-self'], ['sub_copy', 'sub-self']]) {
    const size = functionName.endsWith('_copy') ? 5 : 3;
    const originalBytes = await call('ig5_bytes', { ea: addresses[functionName], size });
    const filtered = await call('ig5_microcode', {
      ea: addresses[functionName], action: 'optimize', maturity: 'generated', rules: [rule],
    });
    assert.equal(filtered.ok, true);
    const optimization = filtered.optimization;
    assert.equal(optimization.ok, true);
    assert.deepEqual(optimization.custom_rules, [rule]);
    assert.equal(optimization.filter_installed, true); assert.equal(optimization.filter_removed, true);
    assert.equal(optimization.idb_modified, false);
    assert.deepEqual(optimization.callback_errors, []);
    assert.equal(typeof optimization.callback_invocations, 'number');
    assert.equal(typeof optimization.callback_calls_total, 'number');
    assert.ok(optimization.callback_calls_total >= optimization.callback_invocations);
    assert.ok(Array.isArray(optimization.rule_hits));
    assert.ok(Array.isArray(optimization.before) && optimization.before.length > 0);
    assert.ok(Array.isArray(optimization.after) && optimization.after.length > 0);
    assert.ok(optimization.rule_hits.every((hit) => hit.rule === rule && hit.before !== hit.after));
    assert.equal((await call('ig5_bytes', { ea: addresses[functionName], size })).hex, originalBytes.hex);
    console.log('[microcode-rule-probe] ' + JSON.stringify({ functionName, rule, callbackCallsTotal: optimization.callback_calls_total, callbackInvocations: optimization.callback_invocations, hits: optimization.rule_hits, generated: optimization.before }));
  }
  // Native generation may already fold self-xor/sub before custom callbacks run.
  // Exercise the rule handler on a constructed instruction in a real temporary
  // MBA as separate evidence; this is not a claim of a natural fixture rule hit.
  for (const [functionName, rule, opcode] of [['xor_self', 'xor-self', 'm_xor'], ['sub_self', 'sub-self', 'm_sub']]) {
    const originalBytes = await call('ig5_bytes', { ea: addresses[functionName], size: 3 });
    const constructed = await call('ig5_run_idapython', { code: `
import json, ida_bytes, ida_funcs, ida_hexrays as hx, advanced_analysis
ea = ${addresses[functionName]}
original_bytes = ida_bytes.get_bytes(ea, 3)
assert hx.init_hexrays_plugin()
failure = hx.hexrays_failure_t()
mba = hx.gen_microcode(hx.mba_ranges_t(ida_funcs.get_func(ea)), failure, None, 0, hx.MMAT_GENERATED)
assert mba is not None, "native MBA generation failed"
chosen = None
for index in range(mba.qty):
    block = mba.get_mblock(index)
    instruction = block.head
    while instruction is not None:
        if instruction.opcode == hx.m_mov and instruction.d.t == hx.mop_r and instruction.d.size == 4:
            chosen = (block, instruction)
            break
        instruction = instruction.next
    if chosen is not None:
        break
assert chosen is not None, "fixture must have a real register assignment"
block, instruction = chosen
destination = hx.mop_t()
destination.assign(instruction.d)
instruction.l.assign(destination)
instruction.r.assign(destination)
instruction.opcode = hx.${opcode}
block.mark_lists_dirty()
before = str(instruction.dstr())
optimizer = advanced_analysis._make_rule_filter(hx, mba, ["${rule}"], 8)
optimizer.install()
removed = False
try:
    assert optimizer.func(block, instruction, 0) == 1, optimizer.errors
    assert len(optimizer.hits) == 1, optimizer.hits
    assert instruction.opcode == hx.m_mov
    assert instruction.l.t == hx.mop_n and instruction.l.is_equal_to(0)
    assert instruction.r.empty()
    assert instruction.d.equal_mops(destination, 0)
    assert optimizer.errors == [], optimizer.errors
    after = str(instruction.dstr())
    native_changes = int(mba.optimize_local(0))
    mba.verify(True)
finally:
    removed = bool(optimizer.remove())
    if not removed:
        advanced_analysis._retained_optimizer_filters.append(optimizer)
assert removed, "native callback must be removed"
assert ida_bytes.get_bytes(ea, 3) == original_bytes
print(json.dumps({"constructed_ir": True, "rule": "${rule}", "hits": optimizer.hits,
                  "before": before, "after": after, "native_changes": native_changes,
                  "filter_installed": True, "filter_removed": removed, "verified": True,
                  "idb_modified": False, "bytes_unchanged": True}))
` });
    assert.equal(constructed.ok, true, constructed.error);
    const evidence = JSON.parse(constructed.output.trim());
    assert.equal(evidence.constructed_ir, true); assert.equal(evidence.rule, rule);
    assert.equal(evidence.hits.length, 1); assert.equal(evidence.hits[0].width, 4);
    assert.notEqual(evidence.before, evidence.after);
    assert.equal(evidence.filter_installed, true); assert.equal(evidence.filter_removed, true);
    assert.equal(evidence.verified, true); assert.equal(evidence.idb_modified, false);
    assert.equal(evidence.bytes_unchanged, true);
    assert.equal((await call('ig5_bytes', { ea: addresses[functionName], size: 3 })).hex, originalBytes.hex);
    console.log('[microcode-constructed-ir] ' + JSON.stringify(evidence));
  }
  const vtables = await call('ig5_vtables', { ea: fixtures[0].vtable, abi: 'msvc', offset: 8 });
  assert.equal(vtables.ok, true); assert.equal(vtables.total, 1);
  const table = vtables.tables[0];
  assert.equal(table.slots.length, 2);
  assert.equal(table.selected_slot.target, addresses.buffer);
  assert.equal(table.rtti.type.raw_name, '.?AVIG5Derived@@');
  assert.equal(table.rtti.bases[1].type.raw_name, '.?AVIG5Base@@');
  assert.equal(table.rtti.inheritance_edges.length, 1);
  for (const [key, kind, baseCount] of [['class', 'class', 0], ['si', 'si-class', 1], ['vmi', 'vmi-class', 2]]) {
    const itanium = await call('ig5_vtables', { ea: fixtures[0].itaniumTables[key], abi: 'itanium', offset: 8 });
    assert.equal(itanium.ok, true); assert.equal(itanium.total, 1);
    const recovered = itanium.tables[0];
    assert.equal(recovered.slots.length, 2);
    assert.equal(recovered.rtti.type.kind, kind);
    assert.equal(recovered.rtti.bases.length, baseCount);
    assert.equal(recovered.rtti.offset_to_top, 0);
    if (key === 'si') {
      assert.equal(recovered.rtti.bases[0].type.raw_name, '7IG5Base');
      assert.equal(recovered.rtti.bases[0].public, true);
      assert.equal(recovered.selected_slot.target, addresses.add);
    }
    if (key === 'vmi') {
      assert.deepEqual(recovered.rtti.bases.map((base) => base.offset), [0, 16]);
      assert.ok(recovered.rtti.bases.every((base) => base.public === true && base.virtual === false));
      assert.equal(recovered.rtti.bases[1].type.kind, 'si-class');
    }
  }
  console.log('[stack/microcode/vtables] real frame locals, nonempty intermediate instructions, and two RTTI-backed slots verified');
  console.log('[itanium-layout] class/SI/VMI RTTI, base offsets, public flags, and virtual slots verified on generated PE bytes');

  // Metadata is created only in the generated tmp database through the explicit
  // write-tool integration seam. It must round-trip through the read-only tool.
  const switchDefinition = {
    ea: fixtures[0].switchJump, action: 'define', apply: true,
    table: fixtures[0].switchTable, ncases: 3, element_size: 8, lowcase: 0,
    default: fixtures[0].switchDefault,
  };
  const beforeSwitch = await call('ig5_switches', { ea: fixtures[0].switchJump, exact: true });
  const preview = await call('ig5_switch_repair', { ...switchDefinition, apply: false });
  assert.equal(preview.ok, true); assert.equal(preview.applied, false);
  assert.deepEqual(await call('ig5_switches', { ea: fixtures[0].switchJump, exact: true }), beforeSwitch, 'switch preview must leave metadata unchanged');
  const repaired = await call('ig5_switch_repair', switchDefinition);
  assert.equal(repaired.ok, true);
  const switches = await call('ig5_switches', { ea: fixtures[0].switchJump, exact: true });
  assert.equal(switches.ok, true); assert.equal(switches.total, 1);
  assert.equal(switches.switches[0].ncases, 3);
  assert.deepEqual(switches.switches[0].cases.flatMap((item) => item.values).sort(), [0, 1, 2]);
  assert.deepEqual(switches.switches[0].cases.map((item) => item.target).sort(), [addresses.case0, addresses.case1, addresses.case2].sort());
  console.log('[switches] explicit generated jump table and three concrete case targets verified');
} finally {
  for (const target of targets) if (tools.has('ig5_close')) await call('ig5_close', {}, target).catch(() => {});
  for (const remove of effects.reverse()) await remove();
  const relative = path.relative(tempRoot, path.resolve(scratch));
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
  await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
console.log('IG5 advanced runtime assertions passed on generated temporary PE64 fixtures.');
