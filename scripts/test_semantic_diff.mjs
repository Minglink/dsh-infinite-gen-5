import assert from 'node:assert/strict';
import { compareSemantics } from '../semantic_diff.js';
import { compareSemanticsAsync } from '../semantic_diff_async.js';
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
const repeated = (base, hash = 'same') => Array.from({ length: 4 }, (_, i) => fn('0x' + (base + i * 16).toString(16), 'sub_' + (base + i * 16).toString(16), hash));
const four = compareSemantics({ functions: repeated(0x1000) }, { functions: repeated(0x3000) });
assert.equal(four.summary.matched, 4, 'the former three-candidate cap lost the fourth identical helper');
assert.equal(four.summary.incomplete, false);
assert.ok(four.matches.every((match) => match.ambiguous));
const crowded = compareSemantics({ functions: Array.from({ length: 40 }, (_, i) => fn('L' + i, 'sub_' + i, 'left-' + i)) },
  { functions: Array.from({ length: 40 }, (_, i) => fn('R' + i, 'sub_' + i, 'right-' + i)) });
assert.equal(crowded.summary.matched, 40, 'consumed early candidates must be backfilled');
assert.ok(crowded.summary.candidatePruned > 0);
assert.equal(crowded.summary.incomplete, true, 'bounded search must disclose candidate pruning');
// Distinct hashes force the expensive all-pairs path, rather than the exact-match shortcut.
const large = (prefix) => ({ functions: Array.from({ length: 2000 }, (_, i) => fn(prefix + i, 'sub_' + i, prefix + '-' + i)) });
let completed = false, ticksWhileWorking = 0;
const timer = setInterval(() => { if (!completed) ticksWhileWorking++; }, 10);
const largeResult = await compareSemanticsAsync(large('L'), large('R'));
completed = true; clearInterval(timer);
assert.equal(largeResult.summary.matched, 2000);
assert.ok(ticksWhileWorking > 1, 'matching must leave the host event loop responsive');
const abort = new AbortController();
const cancelled = compareSemanticsAsync(large('L'), large('R'), {}, abort.signal);
abort.abort();
await assert.rejects(cancelled, { code: 'ABORT_ERR' });
assert.deepEqual(await compareSemanticsAsync({ functions: [original] }, { functions: [patched] }), compareSemantics({ functions: [original] }, { functions: [patched] }));
console.log('Semantic diff: constants/blocks, relocation, four-way ambiguity, bounded-search disclosure, 2000-function event-loop responsiveness and cancellation passed.');
