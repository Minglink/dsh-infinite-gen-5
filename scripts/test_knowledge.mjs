import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runKnowledge, validateKnowledgeCard, KNOWLEDGE_LIMITS } from '../source/knowledge_catalog.js';
import { knowledgeSeeds } from '../source/knowledge_seeds.js';
import { installReadOnlyDataRoute } from '../source/read_only_data_route.js';

test('bilingual lookup ranks expected methods without evidence or execution promotion', () => {
  const expectedQueries = [
    ['混合布尔算术', 'mba-synthesis'],
    ['MBA', 'mba-synthesis'],
    ['控制流平坦化', 'cff-investigation'],
    ['去虚拟化', 'vm-role-experiments'],
    ['ReCopilot', 'homology-review'],
    ['加密', 'crypto-evaluation'],
    ['S-box 常量指纹', 'crypto-constant-triage'],
    ['PBKDF2 密钥派生', 'crypto-key-provenance'],
    ['whitebox 白盒', 'whitebox-table-inspection'],
    ['协议 分帧 CRC', 'protocol-frame-correlation'],
    ['UPX 节熵 查壳', 'packer-entropy-triage'],
    ['OEP IAT修复 脱壳', 'unpacking-reconstruction-levels'],
    ['PUSHFQ 上下文槽', 'vm-handler-projection-bounds'],
    ['不透明谓词 花指令', 'opaque-predicate-verification'],
    ['vtable 虚表 RTTI', 'indirect-call-vtable-dispatch'],
    ['stack-strings 栈字符串', 'encoded-string-materialization'],
    ['pclntab Go逆向 Rust逆向', 'language-abi-recovery'],
    ['BinDiff 补丁对比', 'patch-bindiff-triage'],
    ['CWE-121 栈溢出 漏洞审计', 'decompiled-vuln-audit'],
    ['结构体恢复 字段偏移', 'struct-stack-reconstruction'],
    ['RegisterNatives JNI APK', 'android-apk-jni-workflow'],
    ['Electron ASAR IPC 进程链', 'electron-process-chain-workflow'],
    ['firmware 固件分析 向量表', 'firmware-address-alignment'],
    ['常量展开 位域混淆', 'bitfield-constant-folding'],
  ];
  for (const [query, id] of expectedQueries) {
    const value = runKnowledge({}, { action: 'search', query });
    assert.equal(value.items[0].ref.id, id, `expected top match ${id} for query: ${query}`);
    assert.equal(value.semanticVerified, false); assert.equal(value.executionAuthorized, false); assert.equal(value.automaticInjection, false);
    assert(Buffer.byteLength(JSON.stringify(value)) <= KNOWLEDGE_LIMITS.responseBytes);
  }
  assert.equal(runKnowledge({}, { action: 'search', query: 'not-a-real-technique-012345' }).total, 0);
  assert.equal(runKnowledge({}, { action: 'search', query: 'MBA', category: 'vm' }).total, 0);
});

test('catalog pages are stable and bound to the queried generation', () => {
  assert.equal(knowledgeSeeds.length, 24);
  const seen = new Set();
  let offset = 0;
  let generation;
  let pages = 0;
  while (offset !== null) {
    const page = runKnowledge({}, { action: 'methods', limit: 5, offset, ...(generation ? { generation } : {}) });
    generation ??= page.generation;
    assert.equal(page.generation, generation);
    for (const item of page.items) seen.add(item.ref.id);
    offset = page.nextOffset;
    pages++;
    assert(pages <= 20);
  }
  assert.equal(seen.size, knowledgeSeeds.length);
  assert.throws(() => runKnowledge({}, { action: 'methods', generation: '0'.repeat(64) }), { code: 'STALE_KNOWLEDGE_GENERATION' });
});

test('strict actions reject extra fields, execution inputs, invalid paging and disabled lookup', () => {
  for (const input of [{ action: 'crawl', url: 'https://example.com' }, { action: 'status', path: 'C:/' }, { action: 'search', query: '' },
    { action: 'methods', limit: 11 }, { action: 'methods', offset: -1 }, { action: 'methods', offset: -0 }, { action: 'methods', category: 'unknown' }, { action: 'read', ref: { sha256: '0'.repeat(64) } }, { action: 'read', ref: { id: '../../x', sha256: '0'.repeat(64) } }]) assert.throws(() => runKnowledge({}, input));
  assert.equal(runKnowledge({ knowledge: false }, { action: 'status' }).enabled, false);
  assert.throws(() => runKnowledge({ knowledge: false }, { action: 'methods' }), { code: 'KNOWLEDGE_DISABLED' });
  const ref = runKnowledge({}, { action: 'methods' }).items[0].ref;
  assert.throws(() => runKnowledge({}, { action: 'read', ref: { ...ref, sha256: '0'.repeat(64) } }), { code: 'KNOWLEDGE_REF_MISMATCH' });
});

test('local original method notes retain pinned sources, full Unicode paging and change detection', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-knowledge-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const cfg = { projectRoot: root }, dir = path.join(root, 'knowledge-v1'), file = path.join(dir, 'catalog.json');
  fs.mkdirSync(dir);
  const card = { ...structuredClone(knowledgeSeeds[0]), id: 'local-unicode', body: '甲'.repeat(2047) + '😀' + '乙'.repeat(2300), rightsStatus: 'authorized-local' };
  fs.writeFileSync(file, JSON.stringify({ schema: 'ig5-knowledge-catalog-v1', cards: [card] }));
  const ref = runKnowledge(cfg, { action: 'search', query: 'MBA', limit: 10 }).items.find(x => x.ref.id === card.id).ref;
  let cursor, offset = 0, full = '';
  do {
    const value = runKnowledge(cfg, { action: 'read', ref, ...(cursor ? { cursor } : {}) });
    assert.equal(value.offset, offset); assert(value.body.length <= 2048); assert(!/[\uD800-\uDBFF]$/.test(value.body));
    full += value.body; cursor = value.nextCursor; offset = value.nextOffset;
    if (cursor) assert.throws(() => runKnowledge(cfg, { action: 'read', ref: runKnowledge({}, { action: 'methods' }).items[0].ref, cursor }), { code: 'INVALID_KNOWLEDGE_CURSOR' });
  } while (cursor);
  assert.equal(full, card.body);
  const generation = runKnowledge(cfg, { action: 'status' }).generation;
  card.body += '修订'; fs.writeFileSync(file, JSON.stringify({ schema: 'ig5-knowledge-catalog-v1', cards: [card] }));
  assert.throws(() => runKnowledge(cfg, { action: 'read', ref }), { code: 'KNOWLEDGE_REF_MISMATCH' });
  assert.throws(() => runKnowledge(cfg, { action: 'methods', generation }), { code: 'STALE_KNOWLEDGE_GENERATION' });
});

test('local data cannot override bundled methods or smuggle proof status and unsafe sources', t => {
  for (const change of [{ reviewStatus: 'verified' }, { executionAuthorized: true }, { body: 'x'.repeat(16385) },
    { sources: [{ ...knowledgeSeeds[0].sources[0], url: 'javascript:alert(1)' }] },
    { sources: [{ ...knowledgeSeeds[0].sources[0], url: 'https://github.com/x/y/blob/main/README.md' }] }]) assert.throws(() => validateKnowledgeCard({ ...knowledgeSeeds[0], ...change }));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-knowledge-bad-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'knowledge-v1'));
  const file = path.join(root, 'knowledge-v1', 'catalog.json');
  fs.writeFileSync(file, JSON.stringify({ schema: 'ig5-knowledge-catalog-v1', cards: [knowledgeSeeds[0]] }));
  assert.throws(() => runKnowledge({ projectRoot: root }, { action: 'status' }), { code: 'KNOWLEDGE_ID_CONFLICT' });
  fs.writeFileSync(file, Buffer.from([0xff,0xfe]));
  assert.throws(() => runKnowledge({ projectRoot: root }, { action: 'status' }), { code: 'INVALID_KNOWLEDGE_FILE' });
});

test('read-only HTTP works without a target and rejects mutation, duplicates and scope inputs', () => {
  let handler;
  const mgr = new Proxy({}, { get() { throw new Error('Knowledge route must not access engines or sessions'); } });
  installReadOnlyDataRoute({ inject(_deps, fn) { fn({ webServer: { register(spec) { handler = spec.handler; return () => {}; } } }); } }, mgr, {}, { diagAppend() {}, publicEngineError: e => e.message });
  const request = (query, method = 'GET') => {
    let result; handler({ method, url: '/ig5-data?type=knowledge&' + query }, { writeHead(status) { result = { status }; }, end(body) { result.body = JSON.parse(body); } }); return result;
  };
  const list = request('action=search&query=MBA'); assert.equal(list.body.data.items[0].ref.id, 'mba-synthesis');
  const ref = list.body.data.items[0].ref;
  assert.equal(request(`action=read&id=${ref.id}&sha256=${ref.sha256}`).body.data.metadata.id, ref.id);
  for (const query of ['action=install', 'action=status&target=x', 'action=status&action=read', 'action=methods&limit=NaN', 'action=status&path=secret']) assert(request(query).body.error);
  assert.equal(request('action=status', 'POST').status, 405);
});
