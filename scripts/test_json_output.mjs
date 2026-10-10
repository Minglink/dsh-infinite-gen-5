import assert from 'node:assert/strict';
import { jsonToolOutput } from '../source/json_output.js';

const engine = { id: 'ghidra', available: true, reason: undefined };
const input = { config: { engines: [engine] }, runtime: undefined, ea: '0xffffffffffffffff',
  nested: { nullable: null, count: 0, enabled: false }, empty: [], text: '中文' };
const actual = jsonToolOutput(input);
assert.deepEqual(actual, JSON.parse(JSON.stringify(input)));
assert.equal(actual.ea, '0xffffffffffffffff');
assert.ok(Object.hasOwn(engine, 'reason'), 'response preparation must not mutate session/config data');
assert.ok(!Object.hasOwn(actual.config.engines[0], 'reason'));

const hostileKey = JSON.parse('{"__proto__":{"polluted":true},"constructor":"data"}');
assert.deepEqual(jsonToolOutput(hostileKey), hostileKey);
assert.equal({}.polluted, undefined);
const shared = { count: 2 };
assert.deepEqual(jsonToolOutput({ first: shared, second: shared }), { first: { count: 2 }, second: { count: 2 } });

const cyclic = {}; cyclic.self = cyclic;
for (const invalid of [undefined, [undefined], [,], { ea: 2n ** 64n }, { score: NaN }, { score: Infinity }, { score: -0 },
  { callback() {} }, new Date(), Buffer.from('hidden bytes'), cyclic]) {
  assert.throws(() => jsonToolOutput(invalid), error => error.code === 'INVALID_IG5_OUTPUT');
}
const accessor = {};
Object.defineProperty(accessor, 'value', { enumerable: true, get() { throw Error('must not invoke'); } });
assert.throws(() => jsonToolOutput(accessor), /accessor field/);
const decorated = []; decorated[Symbol('hidden')] = 1;
assert.throws(() => jsonToolOutput(decorated), /decorated array/);
console.log('PASS: optional output fields, precise addresses, non-mutation, prototype safety and invalid data rejection');
