import assert from 'node:assert/strict';
import { compareSemantics } from '../semantic_diff.js';
const fn = (ea, name, hash, constant = '0x10') => ({ ea, name, semantic_hash: hash,
  bytes_hash: hash + ea, instructions: 5, size: 16, mnemonics: { mov: 2, cmp: 1, jne: 1, ret: 1 },
  topology: ['shape-a', 'shape-b'], constants: [constant], strings: [], calls: [], call_degree: 0,
  blocks: [{ start: ea, end: ea + '+16', insns: 5, hash }] });
const original = fn('0x1000', 'check_size', 'old');
const patched = fn('0x3000', 'check_size', 'new', '0x20');
const helper = fn('0x1100', 'helper', 'same');
const moved = fn('0x3100', 'helper', 'same');
const result = compareSemantics({ functions: [original, helper] }, { functions: [patched, moved] });
assert.equal(result.summary.matched, 2);
assert.equal(result.summary.changed, 1);
assert.equal(result.changes[0].old.name, 'check_size');
assert.deepEqual(result.changes[0].evidence.constantsAdded, ['0x20']);
assert.deepEqual(result.changes[0].evidence.constantsRemoved, ['0x10']);
assert.equal(result.changes[0].changedBlocks.old.length, 1);
assert.equal(result.changes[0].changedBlocks.new.length, 1);
assert.equal(result.matches.find((item) => item.old.name === 'helper').changed, false);
const duplicate = compareSemantics({ functions: [helper] }, { functions: [moved, { ...moved, ea: '0x3200' }] });
assert.equal(duplicate.matches[0].ambiguous, true, 'identical helpers must report ambiguous matching');
assert.equal(duplicate.summary.unmatchedRight, 1);
assert.equal(compareSemantics({ functions: [], truncated: true }, { functions: [] }).summary.incomplete, true);
assert.throws(() => compareSemantics({}, {}, { threshold: NaN }));
console.log('Semantic diff: changed constants/blocks, relocation, ambiguity, truncation and validation passed.');
