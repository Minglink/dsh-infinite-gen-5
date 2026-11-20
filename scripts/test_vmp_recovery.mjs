// Real offline instruction semantics with pinned external author traces.
// Binaries/traces remain in artifacts, never launched or bundled as fixtures.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';

const root = path.resolve(import.meta.dirname, '..');
const artifacts = process.env.IG5_RECOVERY_EVIDENCE || path.join(os.homedir(), '.dsh/ig5/artifacts/vmp-recovery-20261014');
const samples = process.env.IG5_VMP_SAMPLES || path.join(os.homedir(), '.dsh/ig5/artifacts/vmp-research-20261014/samples');
const samplePins = JSON.parse(fs.readFileSync(path.join(root, 'scripts/fixtures/vmp_samples.json'), 'utf8')).samples;
const expected = {
  'sample2.vmp.trace': '735c076fdaf56cbdd6b80e0a66d88c76479f258faaf8bdaff1bec7662a63f443',
  'sample3.vmp.trace': '8dbd08069f095f64966dfe960e350a872e8a0eef6cd0177ecd6db60a1346d846',
  'sample4.vmp.trace.1': 'e54a4323f23bf3ad481aebf71385d6a2d8b80682674b2d8a138434624a77ff02',
  'sample4.vmp.trace.2': '2d1aae4d2fddf1fc3f28c10266fc3a68e08b44477dec67f379414215cde22d06',
};
const cfg = { host: { id: 'win32-x64' }, projectRoot: path.join(artifacts, 'projects'), artifactDir: artifacts,
  ghidra: { available: true, pythonExe: path.join(root, 'runtimes/ghidra/python/python.exe'), manifest: path.join(root, 'runtimes/ghidra/runtime.json') } };
function request(index) {
  const names = index === 4 ? ['sample4.vmp.trace.1', 'sample4.vmp.trace.2'] : [`sample${index}.vmp.trace`];
  return { target: path.join(samples, `sample${index}.vmp.bin`), level: 'trace',
    traces: names.map(name => ({ path: path.join(artifacts, name), sha256: expected[name] })),
    trace_entry: index === 3 ? '0x4011c9' : '0x4011c0', trace_exit: index === 2 ? '0x4011ef' : index === 3 ? '0x4012e4' : '0x401202',
    trace_inputs: index === 3 ? ['dil', 'sil'] : ['edi', 'esi'], trace_output: index === 3 ? 'al' : 'eax',
    initial_flags: '0x202', max_instructions: 50000 };
}
const definitions = new Map(), effects = [];
const ctx = {
  tools: { register(definition) { definitions.set(definition.name, definition); return () => definitions.delete(definition.name); } },
  on() { return () => {}; }, get() {},
  inject(names, callback) { if (names.includes('webServer')) callback({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(callback) { const remove = callback(); if (typeof remove === 'function') effects.push(remove); },
};
apply(ctx, { toolset: 'full', reverse: false, reverseProvider: 'bundled', defaultEngine: 'reverse', artifactDir: artifacts, projectRoot: cfg.projectRoot });
assert.equal(definitions.size, 44);
const jobs = {
  run: args => definitions.get('ig5_ir').execute(args, { agent: { id: 'offline-vmp-recovery-test' }, signal: new AbortController().signal }),
  dispose: async () => { for (const remove of effects.reverse()) await remove(); },
};
const rows = [];
function evaluate(expression, x, y) {
  const width = expression.bits, trim = value => BigInt.asUintN(width, value);
  if (expression.op === 'input') return trim(expression.name === 'x' ? x : y);
  if (expression.op === 'constant') return trim(BigInt(expression.value));
  if (expression.op === 'select') {
    assert.equal(expression.condition, 'signed(x) < signed(y)');
    return evaluate(BigInt.asIntN(width, x) < BigInt.asIntN(width, y) ? expression.then : expression.else, x, y);
  }
  const args = expression.args.map(arg => evaluate(arg, x, y));
  // Independent BigInt bit-vector oracle for the documented expression IR.
  // Recovery may retain a proved wider expression instead of a compact XOR.
  // Author reference formulas and exhaustive input checks below are unchanged.
  if (expression.op === 'extract') return trim(args[0] >> BigInt(expression.low));
  if (expression.op === 'zx') return trim(args[0]);
  if (expression.op === 'sx') return trim(BigInt.asIntN(expression.args[0].bits, args[0]));
  if (expression.op === 'concat') return trim(args.reduce((value, child, index) => (value << BigInt(expression.args[index].bits)) | child, 0n));
  if (expression.op === 'not') return trim(~args[0]);
  if (['shl','lshr','ashr'].includes(expression.op)) {
    const count=args[1];
    if (count >= BigInt(width)) return expression.op==='ashr' && BigInt.asIntN(width,args[0])<0n ? trim(-1n) : 0n;
    return trim(expression.op==='shl' ? args[0] << count : expression.op==='ashr' ? BigInt.asIntN(width,args[0]) >> count : args[0] >> count);
  }
  if (['rol','ror'].includes(expression.op)) {
    const count=args[1]%BigInt(width), inverse=BigInt(width)-count;
    return trim(expression.op==='rol' ? (args[0]<<count)|(args[0]>>inverse) : (args[0]>>count)|(args[0]<<inverse));
  }
  if (expression.op==='urem') return args[1]===0n ? args[0] : args[0]%args[1];
  const functions={add:(a,b)=>a+b,sub:(a,b)=>a-b,mul:(a,b)=>a*b,xor:(a,b)=>a^b,and:(a,b)=>a&b,or:(a,b)=>a|b};
  if (functions[expression.op]) return trim(args.reduce(functions[expression.op]));
  throw new Error('Unexpected recovered operation');
}
// Independent author C semantics, used only AFTER recovery; never fed to the solver.
function sample3Reference(x, y) {
  x = BigInt.asIntN(8, x); y = BigInt.asIntN(8, y);
  const a = 229n * x + 247n;
  const b = 237n * a + 214n + ((38n * a + 85n) & 254n);
  const c = (b + ((-(2n * b) + 255n) & 254n)) * 3n + 77n;
  const d = ((86n * c + 36n) & 70n) * 75n + 231n * c + 118n;
  const e = ((58n * d + 175n) & 244n) + 99n * d + 46n;
  const f = e & 148n;
  const g = (f - (e & 255n) + f) * 103n + 13n;
  return BigInt.asUintN(8, (237n * (45n * g + (174n * g | 34n) * 229n + 194n - 247n) & 255n) + y);
}
function validateReference(index, result) {
  assert(result.recoveredExpression, 'The recovered business expression must be present');
  let count = 0;
  const check = (x, y) => {
    const expectedValue = index === 2 ? BigInt.asUintN(32, x ^ y) : index === 3 ? sample3Reference(x, y)
      : BigInt.asUintN(32, BigInt.asIntN(32, x) >= BigInt.asIntN(32, y) ? x : y);
    assert.equal(evaluate(result.recoveredExpression, x, y), expectedValue); count++;
  };
  if (index === 3) for (let x = 0n; x < 256n; x++) for (let y = 0n; y < 256n; y++) check(x, y);
  else {
    const boundaries = [0n, 1n, 2n, 0xffffffffn, 0x80000000n, 0x7fffffffn, 0x80000001n, 0x7ffffffen];
    for (const x of boundaries) for (const y of boundaries) check(x, y);
    let seed = 0x51a74n;
    for (let i = 0; i < 1024; i++) {
      seed = BigInt.asUintN(32, 1664525n * seed + 1013904223n); const x = seed;
      seed = BigInt.asUintN(32, 1664525n * seed + 1013904223n); check(x, seed);
    }
  }
  return { method: 'independent-reference-C-semantics', cases: count, exhaustive8bitPairs: index === 3, binaryExecuted: false };
}
try {
  for (const index of [2, 3, 4]) {
    const args = request(index);
    const before = createHash('sha256').update(fs.readFileSync(args.target)).digest('hex');
    assert.equal(before, samplePins.find(pin => pin.file === `sample${index}.vmp.bin`).sha256, 'Sample must match its fixed author corpus hash');
    const result = await jobs.run(args);
    assert.equal(result.nativeTargetExecuted, false); assert.equal(result.databaseModified, false);
    assert.equal(result.wholeBinaryVerified, false);
    assert(result.paths.every(row => row.outputProof.status === 'unsat' && !row.outputDependsOnUndefinedFlags));
    assert.equal(before, createHash('sha256').update(fs.readFileSync(args.target)).digest('hex'));
    assert(result.paths.every(row => row.binaryBinding.allInstructionBytesMatch));
    assert.equal(result.coverage, 'trace-model-input-domain');
    if (index === 4) {
      assert.equal(result.coverageProof.disjoint.status, 'unsat'); assert.equal(result.coverageProof.exhaustive.status, 'unsat');
    }
    const validation = validateReference(index, result);
    rows.push({ sample: `sample${index}`, args, result, validation });
    console.log(JSON.stringify({ sample: index, expression: result.recoveredExpression, guards: result.paths.map(row => row.guard), counts: result.paths.map(row => row.instructionCount), binding: result.paths.map(row => row.binaryBinding) }));
  }
  fs.writeFileSync(path.join(artifacts, 'recovery-native.json'), JSON.stringify({ ok: true, pluginRoot: root, rows }, null, 2));
} finally { await jobs.dispose(); }
