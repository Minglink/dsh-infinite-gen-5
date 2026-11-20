// Opt-in offline research corpus. Never execute samples or download during tests.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { apply } from '../index.js';

const corpus = JSON.parse(fs.readFileSync(new URL('./fixtures/vmp_samples.json', import.meta.url), 'utf8'));
const sampleRoot = path.resolve(process.env.IG5_VMP_SAMPLE_ROOT || path.join(os.homedir(), '.dsh/ig5/artifacts/vmp-research-20261014/samples'));
const output = path.join(os.homedir(), '.dsh/ig5/artifacts/vmp-research-20261014', `${process.env.IG5_VMP_RUN_LABEL || 'native'}-${randomUUID()}`);
fs.mkdirSync(output, { recursive: true });
const hash = data => createHash('sha256').update(data).digest('hex');
const root = fileURLToPath(new URL('..', import.meta.url));
const sourceFiles = ['advanced_tools.js', 'integration_tools.js', 'adapters/ghidra/microcode_analysis.py', 'adapters/ghidra/deobfuscation_analysis.py', 'adapters/ghidra/deobfuscation_symbolic.py', 'scripts/test_vmp_research.mjs', 'scripts/fixtures/vmp_samples.json'];
const receipt = { kind: 'external-learning-corpus-static-acceptance', startedUtc: new Date().toISOString(), sourceRoot: root,
  sourceHashes: Object.fromEntries(sourceFiles.filter(f => fs.existsSync(path.join(root, f))).map(f => [f, hash(fs.readFileSync(path.join(root, f)))])),
  targetExecuted: false, databaseModified: false, corpus: [],
  limits: ['Successful loading is not devirtualization. Local expression identities do not reconstruct the protected function.', 'Author source describes ground truth; it is not fed into the analysis.', 'No third-party sample binaries are distributed with IG5.'] };
const definitions = new Map(), effects = [], events = new Map();
const ctx = {
  tools: { register(def) { definitions.set(def.name, def); return () => definitions.delete(def.name); } },
  on(name, fn) { events.set(name, fn); return () => events.delete(name); }, get() {},
  inject(names, fn) { if (names.includes('webServer')) fn({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(fn) { const dispose = fn(); if (typeof dispose === 'function') effects.push(dispose); },
};
const call = (name, args) => definitions.get(name).execute(args, { agent: { id: 'vmp-static-corpus-test' }, signal: new AbortController().signal });
function save() { fs.writeFileSync(path.join(output, 'receipt.json'), JSON.stringify(receipt, null, 2)); }
try {
  // Reject missing or changed input before starting any worker.
  for (const item of corpus.samples) {
    const file = path.join(sampleRoot, item.file), bytes = fs.readFileSync(file);
    assert.equal(bytes.length, item.bytes, `${item.id} size`); assert.equal(hash(bytes), item.sha256, `${item.id} SHA-256`);
  }
  apply(ctx, { toolset: 'full', reverseProvider: 'bundled', defaultEngine: 'reverse', reverse: false,
    artifactDir: path.join(output, 'analysis'), projectRoot: path.join(output, 'projects'), requestTimeoutMs: 120000, openTimeoutMs: 180000 });
  assert.equal(definitions.size, 44);
  for (const item of corpus.samples) {
    const target = path.join(sampleRoot, item.file);
    const row = { id: item.id, source: item.url, sha256: item.sha256, protection: item.protection, results: [], functionRecovered: false };
    receipt.corpus.push(row); save();
    console.log('ANALYZE', item.id);
    const opened = await call('ig5_open', { path: target, background: false, analysis_timeout: 45, analysis_profile: 'interactive' });
    assert.equal(opened.provider, 'ghidra');
    row.opened = { engine: opened.engine, provider: opened.provider, functions: opened.n_funcs, analysis: opened.analysis, partial: opened.partial };
    const list = await call('ig5_funcs', { target, filter: item.functionFilter || '', limit: item.functionFilter ? 8 : 2 });
    fs.writeFileSync(path.join(output, `${item.id}-functions.json`), JSON.stringify(list, null, 2));
    const funcs = list.funcs || list.functions || list.items || [];
    assert(funcs.length > 0, `${item.id} function discovery`);
    const pending = funcs.slice(0, item.functionFilter ? 2 : 1), visited = new Set();
    for (const func of pending) {
      const ea = func.ea || func.address || func.start;
      if (visited.has(ea)) continue;
      visited.add(ea);
      let result;
      try { result = await call('ig5_microcode', { target, ea, action: 'deobfuscate', max_steps: 250000, timeout: 45 }); }
      catch (error) {
        if (!func.followedCall) throw error;
        row.results.push({ ea, followedCall: true, unsupported: true, error: error.message });
        continue;
      }
      fs.writeFileSync(path.join(output, `${item.id}-${ea}.json`), JSON.stringify(result, null, 2));
      assert.equal(result.idb_modified, false); assert.equal(result.deobfuscation.executed, false);
      assert.equal(result.source.artifactSHA256, item.sha256);
      const d = result.deobfuscation;
      row.results.push({ ea, name: func.name, followedCall: !!func.followedCall, blocks: result.total_blocks, returnedInstructions: result.returned_instructions,
        partial: d.partial, controlFlowIncomplete: d.controlFlowIncomplete, branchProofs: d.branchDecisions.length,
        localExpressionProofs: d.expressionSimplifications?.length || 0, indirectTransfers: d.indirectTransfers?.length || 0,
        unresolved: d.unresolved.length, exhausted: d.budget.exhausted, evidenceTruncated: d.evidenceTruncated });
      if (d.controlFlowIncomplete) { assert.deepEqual(d.branchDecisions, []); assert.deepEqual(d.unreachableBlocks, []); }
      if (item.id === 'sample2.vmp.bin' && ea === '0x8538d8') {
        await assert.rejects(call('ig5_ir', { target, ea, level: 'raw', action: 'analyze', max_instructions: 256 }), /level=kernel: action.*max_instructions.*supported/);
        const raw = await call('ig5_ir', { target, ea, level: 'raw', max_instructions: 256 });
        fs.writeFileSync(path.join(output, 'sample2-vmp-raw-ir.json'), JSON.stringify(raw, null, 2));
        const byte = await call('ig5_bytes', { target, ea: '0x8538db', size: 1 });
        assert.equal(byte.hex, 'f5');
        const cmc = raw.instructions.filter(op => op.ea === '0x8538db');
        assert(cmc.some(op => op.opcode === 'INT_EQUAL' && op.output?.register === 'CF' && op.inputs[0]?.register === 'CF' && op.inputs[1]?.value === '0x0'));
        row.rawIrVerified = { ea: '0x8538db', byte: 'f5', mnemonic: 'CMC', meaning: 'CF = !CF', count: cmc.length, rejectedParameter: 'action', maxInstructionsSupported: true };
      }
      // Virtualized wrappers can be tiny. Inspect up to two actual native
      // direct callees as well; wrappers alone do not measure the VM body.
      if (item.protection.startsWith('VMProtect') && !func.followedCall) {
        for (const op of result.blocks.flatMap(b => b.instructions)) {
          const node = op.inputs?.[0];
          if (op.mnemonic === 'CALL' && node?.kind === 'memory' && node.space === 'ram' && pending.length < 3 && !visited.has(node.offset)) {
            pending.push({ ea: node.offset, name: 'observed-direct-callee', followedCall: true });
          }
        }
      }
    }
    const status = await call('ig5_status', { target });
    assert(status.sessions.every(s => s.dbRevision === 0));
    assert.equal(hash(fs.readFileSync(target)), item.sha256);
    await call('ig5_close', { target }); row.staticChecksPassed = true; save();
    console.log('RESULT', JSON.stringify(row.results));
  }
  receipt.ok = true;
} catch (error) { receipt.ok = false; receipt.error = { name: error.name, message: error.message }; throw error; }
finally { for (const dispose of effects.reverse()) await dispose(); receipt.finishedUtc = new Date().toISOString(); save(); console.log('RECEIPT', path.join(output, 'receipt.json')); }
