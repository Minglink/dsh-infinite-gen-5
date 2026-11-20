import path from 'node:path';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { knowledgeSeeds } from './knowledge_seeds.js';
import { readKnowledgeBytes, decodeKnowledgeText } from './knowledge_io.js';
import { DOCUMENT_LIMITS, validateKnowledgeDocument } from './knowledge_documents.js';
import { loadPublicResearchV2 } from './knowledge_v2.js';
import { readLegacyKnowledge } from './knowledge_v2_compat.js';

export const KNOWLEDGE_LIMITS = Object.freeze({ fileBytes: 1024 * 1024, cards: 128, bodyBytes: 16384, pageChars: 2048, results: 10, responseBytes: 32768 });
const hash = value => createHash('sha256').update(value).digest('hex');
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
  && Object.values(Object.getOwnPropertyDescriptors(value)).every(d => 'value' in d);
const fields = ['schema','id','revision','title','category','tags','prerequisites','limitations','steps','verification','integration','relatedTools','sources','authorship','reviewStatus','rightsStatus','body'];
const text = (value, max) => typeof value === 'string' && value.trim().length > 0 && value.length <= max && !value.includes('\0');
const strings = (value, max = 16) => Array.isArray(value) && value.length > 0 && value.length <= max && value.every(x => text(x, 512));
export function validateKnowledgeCard(card) {
  if (!plain(card) || Object.keys(card).some(k => !fields.includes(k)) || fields.some(k => !(k in card))
    || card.schema !== 'ig5-method-card-v1' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(card.id)
    || !Number.isSafeInteger(card.revision) || card.revision < 1 || !text(card.title, 160)
    || !['mba','control-flow','vm','workflow','homology','crypto'].includes(card.category)
    || !strings(card.tags) || !strings(card.prerequisites) || !strings(card.limitations) || !strings(card.steps)
    || !strings(card.relatedTools) || card.relatedTools.some(x => !/^ig5_[a-z_]+$/.test(x))
    || !text(card.verification, 1024) || !text(card.authorship, 256)
    || !['reference-only','candidate'].includes(card.reviewStatus)
    || !['original-notes-with-links','authorized-local'].includes(card.rightsStatus)
    || !['research-only','existing-read-only-tools','available-reference'].includes(card.integration)
    || !text(card.body, KNOWLEDGE_LIMITS.bodyBytes) || Buffer.byteLength(card.body) > KNOWLEDGE_LIMITS.bodyBytes
    || !Array.isArray(card.sources) || card.sources.length < 1 || card.sources.length > 8)
    fail('INVALID_KNOWLEDGE_CARD', 'Invalid bounded method card');
  for (const ref of card.sources) {
    if (!plain(ref) || Object.keys(ref).some(k => !['url','repo','commit','license'].includes(k))
      || !text(ref.url, 1024) || !text(ref.repo, 160) || !text(ref.license, 160)
      || typeof ref.commit !== 'string' || !/^[a-f0-9]{40}$/.test(ref.commit)) fail('INVALID_KNOWLEDGE_SOURCE', 'Source requires an immutable commit and attribution');
    let url; try { url = new URL(ref.url); } catch { fail('INVALID_KNOWLEDGE_SOURCE', 'Invalid source URL'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search
      || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(ref.repo)
      || url.hostname !== 'github.com' || !url.pathname.startsWith(`/${ref.repo}/blob/${ref.commit}/`))
      fail('INVALID_KNOWLEDGE_SOURCE', 'Use an HTTPS GitHub source bound to its exact commit');
  }
  // Copy so callers cannot mutate a cached card or the bundled seeds.
  return JSON.parse(JSON.stringify(card));
}

export function assertKnowledgeInput(input, maxOffset = 128) {
  if (!plain(input)) fail('INVALID_ARGUMENT', 'knowledge must be an object');
  const allowed = { status: ['action'], search: ['action','query','category','limit','offset','generation'], documents: ['action','query','limit','offset','generation'],
    methods: ['action','category','limit','offset','generation'], read: ['action','ref','cursor'] };
  if (!allowed[input.action] || Object.keys(input).some(k => !allowed[input.action].includes(k))) fail('INVALID_ARGUMENT', 'Unsupported knowledge action or parameters');
  if (input.action === 'search' && !text(input.query, 256)) fail('INVALID_ARGUMENT', 'Search query must be 1..256 characters');
  if (input.action === 'documents' && input.query !== undefined && !text(input.query, 256)) fail('INVALID_ARGUMENT', 'Document query must be 1..256 characters');
  if (input.category !== undefined && !['mba','control-flow','vm','workflow','homology','crypto'].includes(input.category)) fail('INVALID_ARGUMENT', 'Unknown method category');
  for (const [key, max] of [['limit',10],['offset',maxOffset]]) if (input[key] !== undefined && (!Number.isSafeInteger(input[key]) || Object.is(input[key], -0) || input[key] < (key === 'limit' ? 1 : 0) || input[key] > max)) fail('INVALID_ARGUMENT', `Invalid knowledge ${key}`);
  if (input.generation !== undefined && !/^[a-f0-9]{64}$/.test(input.generation)) fail('INVALID_ARGUMENT', 'Invalid generation');
  if (input.action === 'read' && (!plain(input.ref) || Object.keys(input.ref).some(k => !['id','sha256'].includes(k)) || typeof input.ref.id !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(input.ref.id) || !/^[a-f0-9]{64}$/.test(input.ref.sha256))) fail('INVALID_ARGUMENT', 'Read requires an exact id/sha256 reference');
  if (input.cursor !== undefined && !text(input.cursor, 1024)) fail('INVALID_ARGUMENT', 'Invalid cursor');
  return input;
}

const aliases = [
  ['mba','混合布尔算术','程序合成','msynth','bitvector','位向量'],
  ['cff','控制流平坦化','flattening','dispatcher','ollvm'],
  ['vm','虚拟化','去虚拟化','vmprotect','vmp','vip','vsp','handler'],
  ['知识库','knowledge','rag','方法检索'],
  ['同源','homology','recopilot','符号恢复','类型恢复'],
  ['加密','crypto','crebench','算法识别'],
  ['查壳','加壳','脱壳','packer','unpack','upx','oep'],
  ['白盒','whitebox','tbox','查表加密'],
  ['密钥','key','pbkdf2','hkdf','kdf'],
  ['协议','protocol','分帧','pcap','报文'],
  ['apk','android','安卓','dex','jni','registernatives'],
  ['electron','asar','ipc','进程链'],
  ['固件','firmware','基址','地址空间','rva'],
  ['补丁','bindiff','diff','变体'],
  ['漏洞','cwe','栈溢出','uaf','安全审计'],
  ['虚表','vtable','rtti','跳转表','switch'],
  ['花指令','opaque','不透明谓词','死分支'],
  ['字符串解密','栈字符串','异或解码','strings'],
];
const normalize = s => s.normalize('NFKC').toLowerCase();
function queryTerms(query) {
  const original = [...new Set((normalize(query).match(/[a-z0-9_]+|[\p{Script=Han}]+/gu) || []).filter(t => t.length > 1 || /\p{Script=Han}/u.test(t)))];
  const expanded = new Set(original);
  for (const group of aliases) if (original.some(t => group.some(a => t === a || /\p{Script=Han}/u.test(a) && t.includes(a)))) group.forEach(a => expanded.add(a));
  return [...expanded];
}

// Optional local catalog only. No network, writes, engine RPC, or background capture.
export function validateKnowledgeCatalog(data) {
  if (!plain(data) || Object.keys(data).some(k => !['schema','cards','documents'].includes(k)) || data.schema !== 'ig5-knowledge-catalog-v1'
    || !Array.isArray(data.cards) || data.cards.length > KNOWLEDGE_LIMITS.cards - knowledgeSeeds.length
    || data.documents !== undefined && (!Array.isArray(data.documents) || data.documents.length > DOCUMENT_LIMITS.documents)) fail('INVALID_KNOWLEDGE_FILE', 'Invalid knowledge catalog envelope');
  const cards = data.cards.map(validateKnowledgeCard), documents = (data.documents || []).map(validateKnowledgeDocument);
  const ids = [...knowledgeSeeds.map(c => c.id), ...cards.map(c => c.id), ...documents.map(d => d.id)];
  if (new Set(ids).size !== ids.length) fail('KNOWLEDGE_ID_CONFLICT', 'Duplicate research id; bundled records cannot be overridden');
  const methods = new Set([...knowledgeSeeds, ...cards].map(c => c.id));
  if (documents.some(d => d.methodIds.some(id => !methods.has(id)))) fail('INVALID_KNOWLEDGE_DOCUMENT', 'Document refers to an unknown method');
  return { schema: data.schema, cards, documents };
}
function loadLocal(cfg) {
  if (!cfg.projectRoot) return { cards: [], documents: [] };
  const legacy = readLegacyKnowledge(cfg.projectRoot), bytes = legacy.bytes;
  if (!bytes) return { cards: [], documents: [] };
  return { ...validateKnowledgeCatalog(legacy.data), fenced: legacy.fenced };
}

export function runKnowledge(cfg = {}, input) {
  assertKnowledgeInput(input, 512);
  const enabled = cfg.knowledge !== false;
  if (!enabled) {
    if (input.action === 'status') return { schema: 'ig5-knowledge-response-v1', enabled: false, mode: 'off', automaticInjection: false };
    fail('KNOWLEDGE_DISABLED', 'Research references are disabled by configuration');
  }
  const local = loadLocal(cfg), cards = [...knowledgeSeeds.map(validateKnowledgeCard), ...local.cards];
  // Absent v2 is the normal v1 path. Probe only the optional pointer; actual reads
  // still use the strict linked-path/digest/scope checks in ResearchV2Store.
  const v2 = cfg.projectRoot && (local.fenced || fs.existsSync(path.join(path.resolve(cfg.projectRoot), 'knowledge-v2', 'CURRENT.json'))) ? loadPublicResearchV2(cfg) : null;
  const fenced = local.fenced === true;
  if (v2 && !fenced) fail('RESEARCH_COMPAT_FENCE_REQUIRED', 'Public v2 generation requires its v1 compatibility fence');
  if (!v2 && input.offset > 128) fail('INVALID_ARGUMENT', 'v1 knowledge offset is at most 128');
  if (new Set(cards.map(c => c.id)).size !== cards.length) fail('KNOWLEDGE_ID_CONFLICT', 'Duplicate knowledge id; bundled cards cannot be overridden');
  const entries = cards.map(card => ({ card, ref: { id: card.id, sha256: hash(JSON.stringify(card)) } }));
  const documents = local.documents.map(card => ({ card, ref: { id: card.id, sha256: hash(JSON.stringify(card)) } }));
  if (v2) {
    const oldIds = new Set([...entries,...documents].map(e => e.ref.id));
    if (v2.entries.some(e => oldIds.has(e.ref.id))) fail('KNOWLEDGE_ID_CONFLICT', 'v2 cannot shadow a bundled or v1 identity');
    entries.push(...v2.entries.filter(e => e.state === 'active' && e.card.schema === 'ig5-method-card-v2'));
    documents.push(...v2.entries.filter(e => e.state === 'active' && e.card.schema === 'ig5-source-document-v2'));
  }
  const generation = v2 ? hash(JSON.stringify({ v1: [...entries,...documents].filter(e=>!e.v2).map(e=>e.ref), v2: v2.generation })) : hash(JSON.stringify([...entries, ...documents].map(e => e.ref)));
  const base = { schema: 'ig5-knowledge-response-v1', enabled: true, mode: 'explicit-read', generation,
    automaticInjection: false, executionAuthorized: false, semanticVerified: false, scope: 'local research references; not current-target evidence' };
  if (input.generation && input.generation !== generation) fail('STALE_KNOWLEDGE_GENERATION', 'Research catalog changed; start a new query');
  let result;
  if (input.action === 'status') result = { ...base, count: entries.length, documentCount: documents.length, bundledCount: knowledgeSeeds.length, localCount: entries.length - knowledgeSeeds.length, limits: { ...KNOWLEDGE_LIMITS, ...DOCUMENT_LIMITS }, ...(fenced ? { compatibility: v2 ? 'v2-fenced' : 'v2-prepared-no-generation' } : {}), ...(v2 ? { v2Generation: v2.generation, v2Limits: v2.limits, historicalV2Records: v2.entries.filter(e=>e.state!=='active').length } : {}) };
  else if (input.action === 'read') {
    let entry = [...entries, ...documents, ...(v2?.entries || [])].find(e => e.ref.id === input.ref.id && e.ref.sha256 === input.ref.sha256);
    if (!entry || entry.ref.sha256 !== input.ref.sha256) fail('KNOWLEDGE_REF_MISMATCH', 'Research reference is absent or changed');
    const v2Read = entry.v2 ? v2.read(entry.ref) : null;
    if (v2Read) entry = { ...entry, card: v2Read.card };
    let offset = 0;
    if (input.cursor) {
      let cursor; try { cursor = JSON.parse(Buffer.from(input.cursor, 'base64url').toString('utf8')); } catch { fail('INVALID_KNOWLEDGE_CURSOR', 'Invalid research cursor'); }
      if (!plain(cursor) || Object.keys(cursor).sort().join(',') !== 'generation,id,offset,sha256' || cursor.generation !== generation || cursor.id !== entry.ref.id || cursor.sha256 !== entry.ref.sha256 || !Number.isSafeInteger(cursor.offset) || cursor.offset < 0 || cursor.offset > entry.card.body.length) fail('INVALID_KNOWLEDGE_CURSOR', 'Research cursor does not match this catalog and reference');
      offset = cursor.offset;
    }
    const body = entry.card.body;
    if (offset > 0 && /[\uDC00-\uDFFF]/.test(body[offset]) && /[\uD800-\uDBFF]/.test(body[offset - 1])) fail('INVALID_KNOWLEDGE_CURSOR', 'Cursor splits a Unicode pair');
    let end = Math.min(body.length, offset + KNOWLEDGE_LIMITS.pageChars);
    if (end < body.length && /[\uD800-\uDBFF]/.test(body[end - 1])) end--;
    const { body: _body, ...metadata } = entry.card;
    const isDocument = ['ig5-source-document-v1','ig5-source-document-v2'].includes(entry.card.schema);
    const related = isDocument ? entries.filter(e => entry.card.methodIds.includes(e.card.id)).map(e => ({ ref: e.ref, title: e.card.title }))
      : documents.filter(e => e.card.methodIds.includes(entry.card.id)).map(e => ({ ref: e.ref, title: e.card.title }));
    result = { ...base, ref: entry.ref, metadata, relatedReferences: related, body: body.slice(offset, end), bodySha256: hash(body), offset, nextOffset: end < body.length ? end : null,
      nextCursor: end < body.length ? Buffer.from(JSON.stringify({ generation, ...entry.ref, offset: end })).toString('base64url') : null };
    if (v2Read) {
      const paragraphs = v2Read.paragraphs.filter(p=>p.start<end && p.end>offset);
      Object.assign(result, { format: 'v2', recordState: v2Read.state, stateReason: v2Read.reason, replacementRef: v2Read.replacementRef,
        paragraphRefs: paragraphs.slice(0,8), omittedParagraphRefs: Math.max(0,paragraphs.length-8) });
    }
  } else {
    const terms = input.query ? queryTerms(input.query) : [];
    const ranked = (input.action === 'documents' ? documents : entries).filter(e => !input.category || e.card.category === input.category).map(e => {
      const title = normalize(e.card.title), tags = (e.card.tags || []).map(normalize), body = normalize(e.v2 ? e.searchText : e.card.body);
      const matches = terms.filter(t => title.includes(t) || tags.some(a => a === t) || body.includes(t));
      const score = matches.reduce((s, t) => s + (title.includes(t) ? 8 : 0) + (tags.includes(t) ? 6 : 0) + (body.includes(t) ? 1 : 0), 0);
      return { ...e, matches, score };
    }).filter(e => !input.query || e.score > 0).sort((a, b) => b.score - a.score);
    const offset = input.offset ?? 0, limit = input.limit ?? 5;
    result = { ...base, total: ranked.length, offset, limit, nextOffset: offset + limit < ranked.length ? offset + limit : null,
      items: ranked.slice(offset, offset + limit).map(e => ['ig5-source-document-v1','ig5-source-document-v2'].includes(e.card.schema)
        ? { ref: e.ref, title: e.card.title, kind: 'document', author: e.card.author, sourceUrl: e.card.sourceUrl, methodIds: e.card.methodIds, matchedTerms: e.matches, score: e.score, scoreMeaning: 'ranking-only', preview: (e.v2 ? e.searchText : e.card.body).slice(0, 160), ...(e.v2 ? { format: 'v2', contentKind: e.card.contentKind, searchScope: 'reviewed-metadata-and-explicit-search-summary' } : {}) }
        : { ref: e.ref, title: e.card.title, category: e.card.category, tags: e.card.tags, reviewStatus: e.card.reviewStatus,
          integration: e.card.integration, matchedTerms: e.matches, score: e.score, scoreMeaning: 'ranking-only', preview: e.card.verification.slice(0, 160), ...(e.v2 ? { format: 'v2', searchScope: 'reviewed-metadata-and-explicit-search-summary' } : {}) }) };
    if (input.action === 'search' && input.query && ranked.length === 0 && documents.length > 0) {
      const docHits = documents.filter(e => { const b = normalize(e.v2 ? e.searchText : e.card.body), t = normalize(e.card.title); return terms.some(x => t.includes(x) || b.includes(x)); }).length;
      if (docHits > 0) result.hint = { code: 'TRY_DOCUMENTS', message: 'No method cards matched, but imported source documents did. Use action=documents with the same query, then read by returned ref.', documentMatches: docHits };
    }
  }
  if (Buffer.byteLength(JSON.stringify(result)) > KNOWLEDGE_LIMITS.responseBytes) fail('KNOWLEDGE_RESPONSE_BUDGET', 'Research response exceeds its byte budget; narrow the query');
  return result;
}

export const knowledgeSchema = { type: 'object',
  properties: { action: { type: 'string', enum: ['status','search','methods','documents','read'] }, query: { type: 'string', minLength: 1, maxLength: 256 },
    category: { type: 'string', enum: ['mba','control-flow','vm','workflow','homology','crypto'] }, limit: { type: 'integer', minimum: 1, maximum: 10 }, offset: { type: 'integer', minimum: 0, maximum: 512 },
    generation: { type: 'string', pattern: '^[a-f0-9]{64}$' }, cursor: { type: 'string', maxLength: 1024 },
    ref: { type: 'object', properties: { id: { type: 'string', maxLength: 64 }, sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' } }, required: ['id','sha256'], additionalProperties: false } }, required: ['action'], additionalProperties: false };
