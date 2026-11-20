// 对账：测试侧的工具分类必须与产品审批闸门的名单完全一致。纯静态，不启动任何 worker。
import assert from 'node:assert/strict';
import test from 'node:test';
import { IG5_WRITE_TOOLS } from '../source/approval_gate.js';
import { ALL_TOOLS, APPROVAL_GATED, NOT_GATED, NOT_GATED_RATIONALE } from './fixtures/tool_classification.mjs';

test('the approval gate list equals the reviewed approval-gated list, in both directions', () => {
  assert.deepEqual([...IG5_WRITE_TOOLS].sort(), [...APPROVAL_GATED].sort());
});

test('every tool is classified exactly once', () => {
  assert.equal(new Set(ALL_TOOLS).size, ALL_TOOLS.length, 'a tool appears in both lists or twice');
  assert.equal(ALL_TOOLS.length, 44, 'Full 44 contract (P2 + M3/M4 ig5_app_observe): changing the tool count needs a separate review');
  assert.equal(APPROVAL_GATED.length, 14, '14 approval gates contract');
  assert(ALL_TOOLS.every(name => /^ig5_[a-z_]+$/.test(name)));
});

test('rationales exist only for tools that are deliberately not gated', () => {
  for (const name of Object.keys(NOT_GATED_RATIONALE)) assert(NOT_GATED.includes(name), `${name} has a rationale but is not in NOT_GATED`);
  for (const name of ['ig5_open', 'ig5_export_diff']) assert(NOT_GATED_RATIONALE[name], `${name} must document why it is not gated`);
});
