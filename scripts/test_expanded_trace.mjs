// Pinned author recordings, real public tool wrapper, no external target execution.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';

const root = path.resolve(import.meta.dirname, '..');
const output = process.env.IG5_CORPUS_EVIDENCE || path.join(os.homedir(), '.dsh/ig5/artifacts/corpus-expansion-20261014');
const corpus = process.env.IG5_PROTECTION_CORPUS || path.join(output, 'corpus');
const pins = JSON.parse(fs.readFileSync(path.join(root, 'scripts/fixtures/protection_corpus.json'), 'utf8')).files;
function pinned(relative) {
  const pin = pins.find(row => row.file === (relative.startsWith('derived/') ? relative : 'salwan-vmp/' + relative));
  assert(pin, 'Missing pin: ' + relative);
  const full = path.join(corpus, pin.file);
  assert.equal(fs.statSync(full).size, pin.bytes);
  assert.equal(createHash('sha256').update(fs.readFileSync(full)).digest('hex'), pin.sha256);
  return { path: full, sha256: pin.sha256 };
}
// Validate every selected binary and recording BEFORE starting any worker.
const requests = [1, 5, 6].map(index => ({ index,
  target: pinned(`vmp_binaries/binaries/sample${index}.vmp.bin`).path,
  level: 'trace', traces: (index === 1 ? [''] : ['.1', '.2']).map(suffix => pinned(index === 5 && suffix === '.2' ? 'derived/sample5.vmp.trace.2' : `vmp_traces/sample${index}.vmp.trace${suffix}`)),
  trace_entry: '0x4011c0', trace_exit: index === 1 ? '0x4011f1' : '0x40120f',
  trace_inputs: ['edi', 'esi'], trace_output: 'eax', initial_flags: '0x202', max_instructions: 50000,
}));
const definitions = new Map(), effects = [];
const ctx = { tools: { register(d) { definitions.set(d.name, d); return () => definitions.delete(d.name); } },
  on() { return () => {}; }, get() {},
  inject(names, callback) { if (names.includes('webServer')) callback({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(callback) { const remove = callback(); if (typeof remove === 'function') effects.push(remove); },
};
apply(ctx, { toolset: 'full', reverse: false, artifactDir: output, projectRoot: path.join(output, 'projects') });
assert.equal(definitions.size, 44);
function evaluate(e, x, y) {
  const trim = value => BigInt.asUintN(e.bits, value);
  if (e.op === 'input') return trim(e.name === 'x' ? x : y);
  if (e.op === 'constant') return trim(BigInt(e.value));
  if (e.op === 'select') return evaluate(predicate(e.conditionExpression, x, y) ? e.then : e.else, x, y);
  const a = e.args.map(item => evaluate(item, x, y));
  return trim(({ add: () => a[0] + a[1], sub: () => a[0] - a[1], mul: () => a[0] * a[1],
    xor: () => a[0] ^ a[1], and: () => a[0] & a[1], or: () => a[0] | a[1], not: () => ~a[0] })[e.op]());
}
function predicate(e, x, y) {
  assert(e, 'Structured guard required for arithmetic predicates');
  if (e.op === 'true') return true;
  if (e.op === 'false') return false;
  if (e.op === 'not') return !predicate(e.args[0], x, y);
  if (e.op === 'all') return e.args.every(item => predicate(item, x, y));
  if (e.op === 'any') return e.args.some(item => predicate(item, x, y));
  const a = e.args.map(item => evaluate(item, x, y));
  const signed = v => BigInt.asIntN(e.args[0].bits, v);
  return ({ eq: () => a[0] === a[1], ne: () => a[0] !== a[1], ult: () => a[0] < a[1], uge: () => a[0] >= a[1],
    slt: () => signed(a[0]) < signed(a[1]), sge: () => signed(a[0]) >= signed(a[1]) })[e.op]();
}
function validate(index, expression) {
  const pairs = [], edges = [0n, 1n, 2n, 1000n, 1001n, 1233n, 1234n, 0xffffffffn, 0x80000000n, 0x7fffffffn];
  for (const x of edges) for (const y of edges) pairs.push([x, y]);
  for (const x of edges) for (const boundary of [1000n, 1001n, 1002n, 1233n, 1234n, 1235n]) pairs.push([x, BigInt.asUintN(32, boundary - x)]);
  let seed = 0x153661n;
  for (let i = 0; i < 1024; i++) {
    seed = BigInt.asUintN(32, 1664525n * seed + 1013904223n); const x = seed;
    seed = BigInt.asUintN(32, 1664525n * seed + 1013904223n); pairs.push([x, seed]);
  }
  // Independent author-source machine-width semantics; never passed to recovery.
  // Signed C overflow is undefined: these checks model the recorded 32-bit instructions.
  for (const [x, y] of pairs) {
    const sum = BigInt.asUintN(32, x + y);
    const expected = index === 1 ? sum : ((index === 5 ? sum === 1001n : sum < 1234n) ? x + 1n : y - 1n);
    assert.equal(evaluate(expression, x, y), BigInt.asUintN(32, expected));
  }
  return { method: 'independent-source-derived-32bit-semantics', cases: pairs.length, includesOverflowAndBranchBoundaries: true };
}
const rows = [];
try {
  for (const { index, ...args } of requests) {
    const start = performance.now();
    try {
      const result = await definitions.get('ig5_ir').execute(args, { agent: { id: 'expanded-vmp-learning-test' }, signal: new AbortController().signal });
      assert.equal(result.nativeTargetExecuted, false); assert.equal(result.databaseModified, false); assert.equal(result.wholeBinaryVerified, false);
      assert(result.paths.every(p => p.outputProof.status === 'unsat' && p.binaryBinding.allInstructionBytesMatch));
      const validation = result.recoveredExpression ? validate(index, result.recoveredExpression) : null;
      rows.push({ sample: index, args, status: validation ? 'trace-model-recovered' : 'partial-paths', result, validation, elapsedMs: Math.round(performance.now() - start) });
    } catch (error) { rows.push({ sample: index, args, status: 'failed', error: error.message, elapsedMs: Math.round(performance.now() - start) }); }
    const row = rows.at(-1);
    console.log(JSON.stringify({ sample: index, status: row.status, expression: row.result?.recoveredExpression, guards: row.result?.paths.map(p => p.guard), unresolved: row.result?.paths.map(p => p.unresolvedGuardCount), error: row.error, elapsedMs: row.elapsedMs }));
  }
  const baseline = process.env.IG5_CORPUS_BASELINE === '1';
  fs.writeFileSync(path.join(output, baseline ? 'trace-baseline.json' : 'trace-acceptance.json'), JSON.stringify({ pluginRoot: root, nativeTargetExecuted: false, rows }, null, 2));
  if (!baseline) assert(rows.every(row => row.status === 'trace-model-recovered'), 'Expanded trace cases must all be recovered and independently validated');
} finally { for (const dispose of effects.reverse()) await dispose(); }
