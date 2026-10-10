import path from 'node:path';
import { AnalysisArtifacts, decodeInline, readStableFile, hashBytes } from './source/analysis_artifacts.js';
import { AnalysisJobs } from './source/analysis_jobs.js';
import { normalizeHex } from './source/address_ref.js';

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const INPUT_LIMIT = { crypto: 1024 * 1024, protocol: 8 * 1024 * 1024 };
const bytesProperty = { type: 'object', properties: { encoding: { type: 'string', enum: ['hex', 'base64'] }, data: { type: 'string' } }, required: ['encoding', 'data'], additionalProperties: false };
const inputProperty = { type: 'object', properties: {
  encoding: { type: 'string', enum: ['hex', 'base64'] }, data: { type: 'string' },
  ref: { type: 'string', description: 'sha256: analysis blob reference; avoids resending large buffers. Producer-marked sensitive keys are only accepted as controlled recovery.key_source or recipe.key_ref. Unbound refs retain explicit raw data reads.' },
  result_id: { type: 'string', description: 'For ref input, explicit producer report ID to preserve provenance; never inferred from a shared hash' },
  path: { type: 'string', description: 'Explicit local regular input file; read only with a byte budget' },
  source: { type: 'object', properties: { target: { type: 'string' }, engine: { type: 'string', enum: ['reverse', 'ghidra'] }, ea: { type: 'string' }, size: { type: 'number' }, expected_revision: { type: 'number' } }, required: ['target', 'ea', 'size'], additionalProperties: false },
}, required: [], additionalProperties: false };
const keyRefProperty = { type: 'object', properties: { ref: { type: 'string' }, result_id: { type: 'string' } }, required: ['ref', 'result_id'], additionalProperties: false };
const aesProperty = { type: 'object', properties: { kind: { type: 'string', enum: ['aes-cbc', 'aes-ctr', 'aes-gcm'] }, iv: bytesProperty, tag: bytesProperty, aad: bytesProperty, padding: { type: 'string', enum: ['none', 'pkcs7'] } }, required: ['kind', 'iv'], additionalProperties: false };
const recoveryProperty = { type: 'object', properties: {
  method: { type: 'string', enum: ['auto', 'xor-single', 'xor-repeat', 'aes-candidates'] },
  max_key_bytes: { type: 'integer', minimum: 1, maximum: 32 }, max_candidates: { type: 'integer', minimum: 1, maximum: 8 }, max_trials: { type: 'integer', minimum: 1, maximum: 4096 },
  sample_bytes: { type: 'integer', minimum: 256, maximum: 65536 }, max_work_bytes: { type: 'integer', minimum: 1, maximum: 67108864 },
  material_stride: { type: 'integer', minimum: 1, maximum: 32 }, key_lengths: { type: 'array', maxItems: 32, items: { type: 'integer', minimum: 1, maximum: 32 } },
  key_candidates: { type: 'array', maxItems: 256, items: bytesProperty }, key_material: bytesProperty,
  key_source: { ...inputProperty, description: 'Explicit bounded key-material input, up to 64 KiB. Bound producer/static inputs must match the ciphertext target, engine and sample identity. Material bytes are not saved in reports.' },
  known_plaintext: { type: 'array', maxItems: 16, items: { type: 'object', properties: { offset: { type: 'integer', minimum: 0 }, encoding: { type: 'string', enum: ['hex', 'base64'] }, data: { type: 'string' } }, required: ['offset', 'encoding', 'data'], additionalProperties: false } },
  aes: aesProperty,
}, required: [], additionalProperties: false };
const inferenceProperty = { type: 'object', properties: {
  format: { type: 'string', enum: ['auto', 'stream', 'messages', 'capture'] }, boundary: { type: 'string', enum: ['unknown', 'message-start'] },
  samples: { type: 'array', maxItems: 64, items: bytesProperty, description: 'When present, these are the training messages; the primary input is retained as provenance rather than added to training.' },
  holdout_samples: { type: 'array', maxItems: 64, items: bytesProperty, description: 'Independent validation messages; train and holdout combined are limited to 64 samples and 1 MiB.' },
  min_frames: { type: 'integer', minimum: 3, maximum: 64 }, max_candidates: { type: 'integer', minimum: 1, maximum: 8 }, max_scan_bytes: { type: 'integer', minimum: 1, maximum: 262144 }, max_work: { type: 'integer', minimum: 1, maximum: 2000000 },
}, required: [], additionalProperties: false };

/** Preserve complete reports on disk; return bounded, explicitly truncated model views. */
export function compactAnalysis(value) {
  let budget = 20000, truncated = false;
  function visit(node, depth = 0) {
    if (budget <= 0 || depth > 12) { truncated = true; return '[response budget reached]'; }
    if (typeof node === 'string') {
      let low = 0, high = Math.min(2048, node.length);
      while (low < high) { const middle = Math.ceil((low + high) / 2); if (JSON.stringify(node.slice(0, middle)).length <= budget) low = middle; else high = middle - 1; }
      const text = node.slice(0, low); budget -= JSON.stringify(text).length;
      if (low < node.length) truncated = true;
      return text;
    }
    if (node === null || typeof node !== 'object') { budget -= (JSON.stringify(node) || 'null').length; return node; }
    if (Array.isArray(node)) {
      budget -= 2; const out = [];
      if (node.length > 8) truncated = true;
      for (const item of node.slice(0, 8)) { if (budget < 4) { truncated = true; break; } budget -= out.length ? 1 : 0; out.push(visit(item, depth + 1)); }
      return out;
    }
    budget -= 2;
    const out = Object.create(null);
    for (const [key, child] of Object.entries(node)) { const cost = JSON.stringify(key).length + 2; if (budget < cost + 4) { truncated = true; break; } budget -= cost; out[key] = visit(child, depth + 1); }
    return out;
  }
  let excerpt = visit(value);
  if ((JSON.stringify(excerpt) || 'null').length > 20000) { truncated = true; excerpt = { note: 'Result excerpt exceeded the response budget; select a narrower result path.' }; }
  return { value: excerpt, responseTruncated: truncated, responseBudgetChars: 20000 };
}

function selectResult(record, select) {
  let result = record.result;
  if (select !== undefined) {
    if (typeof select !== 'string' || !select || select.length > 256) fail('INVALID_INPUT', 'select must be a short dot-separated result path');
    const keys = select.split('.');
    if (keys.length > 10 || keys.some(key => !/^[A-Za-z0-9_-]+$/.test(key) || ['__proto__', 'constructor', 'prototype'].includes(key))) fail('INVALID_INPUT', 'Invalid result selection');
    for (const key of keys) { if (!result || !Object.hasOwn(result, key)) fail('NOT_FOUND', 'Result selection does not exist'); result = result[key]; }
  }
  return result;
}
function containsRef(node, ref) {
  if (!node || typeof node !== 'object') return false;
  if (node.ref === ref) return true;
  return Object.values(node).some(child => containsRef(child, ref));
}
function containsSensitiveRef(node, ref) {
  if (!node || typeof node !== 'object') return false;
  if (node.ref === ref && node.sensitive === true) return true;
  return Object.values(node).some(child => containsSensitiveRef(child, ref));
}
function bindRefs(node, id) {
  if (!node || typeof node !== 'object') return node;
  if (Array.isArray(node)) return node.map(item => bindRefs(item, id));
  const copy = { ...node };
  if (typeof copy.ref === 'string' && /^sha256:[a-f0-9]{64}$/.test(copy.ref)) copy.result_id = id;
  for (const [key, value] of Object.entries(copy)) if (value && typeof value === 'object') copy[key] = bindRefs(value, id);
  return copy;
}

export function createAnalysisService(mgr, cfg) {
  const artifacts = new AnalysisArtifacts(path.join(cfg.artifactDir, 'analysis-data'));
  const jobs = new AnalysisJobs();
  async function input(args, kind, value = args.input, maximum = INPUT_LIMIT[kind], allowSensitive = false) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail('INVALID_INPUT', 'input is required');
    const fields = ['data', 'ref', 'path', 'source'].filter(key => Object.hasOwn(value, key));
    if (fields.length !== 1 || fields[0] !== 'data' && Object.hasOwn(value, 'encoding')) fail('INVALID_INPUT', 'Choose exactly one inline data, ref, path or static source');
    if (Object.hasOwn(value, 'result_id') && fields[0] !== 'ref') fail('INVALID_INPUT', 'input.result_id is only used with ref input');
    if (fields[0] === 'data') return decodeInline(value, maximum);
    if (fields[0] === 'path') return readStableFile(value.path, maximum);
    if (fields[0] === 'ref') {
      let parent;
      if (value.result_id !== undefined) {
        parent = artifacts.get(value.result_id);
        if (!containsRef(parent.input, value.ref) && !containsRef(parent.output, value.ref) && !containsRef(parent.result, value.ref)) fail('INVALID_REF', 'Buffer reference does not belong to the selected producer result');
        if (!allowSensitive && [parent.input, parent.output, parent.result].some(node => containsSensitiveRef(node, value.ref))) fail('KEY_REF_AS_DATA', 'A producer-marked sensitive key reference is not ordinary analysis data; use recipe.key_ref or recovery.key_source');
      }
      const captured = artifacts.read(value.ref, maximum);
      if (parent) {
        captured.association = parent.association;
        captured.origin.derivedFrom = { resultId: parent.id, kind: parent.kind, association: parent.association };
      } else captured.origin.provenance = 'unbound: no producer result_id was selected';
      return captured;
    }
    const source = value.source;
    if (!source || typeof source !== 'object' || typeof source.target !== 'string' || !Number.isSafeInteger(source.size) || source.size < 1 || source.size > Math.min(maximum, 1024 * 1024)) fail('INVALID_INPUT', 'Static source requires a target and a 1..1 MiB range');
    const ea = BigInt(normalizeHex(source.ea)), engine = source.engine || args.engine || cfg.defaultEngine;
    if (ea < 0n || ea + BigInt(source.size) > 1n << 64n) fail('INVALID_INPUT', 'Static source address range exceeds 64 bits');
    const session = mgr.get(source.target, engine);
    if (!mgr.alive(session) || session.engine === 'x64dbg') fail('NOT_OPEN', 'Static source target is not open in the selected engine');
    return mgr.withSessions([session], async () => {
      if (source.expected_revision !== undefined && session.dbRevision !== source.expected_revision) fail('STALE_REVISION', 'Static source revision changed');
      const evidence = mgr.evidence(session), buffers = [];
      for (let offset = 0; offset < source.size; offset += 4096) {
        mgr.checkCancelled();
        const size = Math.min(4096, source.size - offset);
        const value = await mgr.rpc(session, 'bytes', { ea: '0x' + (ea + BigInt(offset)).toString(16), size });
        const chunk = decodeInline({ encoding: 'hex', data: value.hex }, size).data;
        if (chunk.length !== size) fail('PARTIAL_INPUT', 'Static source range is not completely readable');
        buffers.push(chunk);
      }
      if (mgr.evidence(session).dbRevision !== evidence.dbRevision) fail('STALE_REVISION', 'Static source changed during capture');
      return { data: Buffer.concat(buffers), origin: { kind: 'static-memory', target: session.target, ea: normalizeHex(source.ea), size: source.size, ...evidence }, association: { target: session.target, ...evidence } };
    });
  }
  function externalize(node, total = { bytes: 0, keyBytes: 0 }, sensitive = false) {
    if (Array.isArray(node)) return node.map(child => externalize(child, total, sensitive));
    if (!node || typeof node !== 'object') return node;
    const priority = node.framing && node.schema && node.validation ? ['id', 'framing', 'decodeInput', 'validation', 'score', 'confidence', 'schema']
      : Array.isArray(node.candidates) ? ['status', 'format', 'method', 'budget', 'truncated', 'search_truncated', 'truncation_reasons', 'ambiguity', 'strong_hypotheses', 'limits', 'candidate_count', 'returned_candidates', 'candidates'] : [];
    // Keep acceptance evidence ahead of large field/evidence lists in bounded AI views.
    const result = Object.fromEntries([...priority.filter(key => Object.hasOwn(node, key)).map(key => [key, node[key]]), ...Object.entries(node).filter(([key]) => !priority.includes(key))]);
    if (typeof result.dataHex === 'string') {
      const data = decodeInline({ encoding: 'hex', data: result.dataHex }, sensitive ? 32 : 8 * 1024 * 1024).data;
      if (sensitive) {
        total.keyBytes += data.length;
        if (total.keyBytes > 256) fail('RESULT_LIMIT', 'Recovered key buffers exceed the 256-byte artifact budget');
      } else {
        total.bytes += data.length;
        if (total.bytes > 8 * 1024 * 1024) fail('RESULT_LIMIT', 'Analysis payload buffers exceed the 8 MiB artifact budget');
      }
      result.dataRef = { ...artifacts.put(data), ...(sensitive ? { sensitive: true } : {}) }; delete result.dataHex;
      if (!sensitive) result.previewHex ??= data.subarray(0, 256).toString('hex');
    }
    // Recovered keys are executable references, never an automatically expanded preview.
    // Drop unexpected future preview fields too, so pure-layer additions cannot leak keys.
    if (sensitive) for (const key of Object.keys(result)) if (!['dataRef', 'keyComplete', 'known_mask', 'unknown_mask', 'keyBytes'].includes(key)) delete result[key];
    for (const [key, child] of Object.entries(result)) if (child && typeof child === 'object') result[key] = key === 'dataRef' ? child : externalize(child, total, sensitive || key === 'keyMaterial');
    return result;
  }
  const equalTarget = (a, b) => typeof a === 'string' && typeof b === 'string' && (process.platform === 'win32' ? path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase() : path.resolve(a) === path.resolve(b));
  function associationFor(captured, args) {
    if (captured.association && (args.target && !equalTarget(args.target, captured.association.target) || args.engine && captured.association.engine && args.engine !== captured.association.engine)) fail('ASSOCIATION_CONFLICT', 'Explicit target or engine conflicts with the captured input provenance');
    return captured.association || (args.target ? { target: path.resolve(args.target), ...(args.engine ? { engine: args.engine } : {}) } : undefined);
  }
  function checkKeyAssociation(source, association) {
    if (!source) return;
    if (!association || !equalTarget(source.target, association.target) || source.engine && source.engine !== association.engine) fail('ASSOCIATION_CONFLICT', 'Key source must belong to the selected ciphertext target and engine');
    for (const field of ['sha256', 'artifactId', 'attachmentId', 'dbRevision']) if (source[field] !== undefined && association[field] !== undefined && source[field] !== association[field]) fail('ASSOCIATION_CONFLICT', 'Key source sample identity or revision differs from the ciphertext');
  }
  function completeRecoveredKey(record, value) {
    if (record.kind !== 'crypto' || record.action !== 'recover') fail('INVALID_KEY_REF', 'Key reference requires a crypto recover producer report');
    const rows = record.result?.recovery?.candidates;
    const found = Array.isArray(rows) && rows.find(row => row.keyComplete === true && row.keyMaterial?.keyComplete === true && row.keyMaterial.dataRef?.ref === value.ref);
    const material = found?.keyMaterial;
    if (!material || material.dataRef.sensitive !== true || typeof material.unknown_mask !== 'string' || !/^(?:00)+$/.test(material.unknown_mask) || material.unknown_mask.length !== material.dataRef.bytes * 2 || typeof material.known_mask !== 'string' || !/^(?:01)+$/.test(material.known_mask) || material.known_mask.length !== material.dataRef.bytes * 2) fail('INVALID_KEY_REF', 'Only a complete recovered key reference can be used for decryption');
    return material;
  }
  return {
    artifacts, jobs,
    list: options => artifacts.list(options),
    history: async ({ action = 'stats', ids } = {}) => {
      if (action === 'archive' || action === 'restore') return artifacts.archive(ids, action === 'restore');
      if (action !== 'stats') fail('INVALID_INPUT', 'History action must be stats, archive or restore');
      const active = await artifacts.list({ limit: 1 }), archived = await artifacts.list({ archived: true, limit: 1 });
      return { active: active.total, activeLowerBound: active.totalLowerBound, archived: archived.total,
        archivedLowerBound: archived.totalLowerBound, partial: active.partial || archived.partial,
        retainedRecordsAndBlobs: true, note: 'Archive removes reports from active pages; result IDs and data refs remain usable. Restore returns them to active pages.' };
    },
    result(id, select) { const record = artifacts.get(id); return { id: record.id, createdAt: record.createdAt, kind: record.kind, action: record.action, association: record.association, input: bindRefs(record.input, id), output: bindRefs(record.output, id), ...(record.keySource ? { keySource: record.keySource } : {}), ...compactAnalysis(bindRefs(selectResult(record, select), id)) }; },
    async execute(kind, args) {
      mgr.checkCancelled();
      if (args.action === 'result') {
        if (args.recovery !== undefined || args.inference !== undefined) fail('INVALID_INPUT', 'Recovery and inference options are not used when reading a report');
        if (kind === 'protocol' && (args.offset !== undefined || args.length !== undefined)) fail('INVALID_INPUT', 'Byte ranges are not used when reading a report');
        const record = artifacts.get(args.result_id);
        if (record.kind !== kind) fail('INVALID_REF', 'Result belongs to a different analysis lane');
        return this.result(args.result_id, args.select);
      }
      if (args.recovery !== undefined && (kind !== 'crypto' || args.action !== 'recover') || args.inference !== undefined && (kind !== 'protocol' || args.action !== 'infer')) fail('INVALID_INPUT', 'Recovery or inference options do not apply to this action');
      if (kind === 'crypto' && args.recipe !== undefined && args.action !== 'transform' || kind === 'protocol' && (args.schema !== undefined || args.framing !== undefined) && !['capture', 'decode'].includes(args.action)) fail('INVALID_INPUT', 'Recipe, schema or framing options do not apply to this action');
      const captured = await input(args, kind);
      mgr.checkCancelled();
      if (kind === 'protocol') {
        // The complete source is read under its existing limit before slicing. A range cannot
        // be used to bypass the stable-file, blob or native capture input budget.
        const sourceBytes = captured.data.length, offset = args.offset ?? 0, length = args.length ?? sourceBytes - offset;
        if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset > sourceBytes || length > sourceBytes - offset) fail('INVALID_INPUT', 'Protocol byte range must fit entirely within the captured input');
        captured.origin = { ...captured.origin, range: { offset, length, sourceBytes, sourceSha256: hashBytes(captured.data) } };
        captured.data = captured.data.subarray(offset, offset + length);
      }
      const association = associationFor(captured, args);
      let recovery = args.recovery, recipe = args.recipe, keySource;
      if (kind === 'crypto' && args.action === 'recover' && recovery?.key_source !== undefined) {
        if (recovery.key_material !== undefined) fail('INVALID_INPUT', 'Choose key_source or key_material, not both');
        const material = await input(args, kind, recovery.key_source, 64 * 1024, true);
        checkKeyAssociation(material.association, association);
        const { key_source, ...options } = recovery;
        recovery = { ...options, key_material: { encoding: 'hex', data: material.data.toString('hex') } };
        keySource = { origin: material.origin, sha256: hashBytes(material.data), bytes: material.data.length, sensitive: true, ...(material.association ? { association: material.association } : {}) };
      }
      if (kind === 'crypto' && args.action === 'recover' && recovery?.key_material !== undefined && !keySource) {
        const material = decodeInline(recovery.key_material, 64 * 1024);
        keySource = { origin: { kind: 'inline-key-material', encoding: recovery.key_material.encoding }, sha256: hashBytes(material.data), bytes: material.data.length, sensitive: true };
      }
      if (kind === 'crypto' && args.action === 'transform' && recipe?.key_ref !== undefined) {
        if (recipe.key !== undefined || !recipe.key_ref || typeof recipe.key_ref !== 'object' || Array.isArray(recipe.key_ref) || Object.keys(recipe.key_ref).some(key => !['ref', 'result_id'].includes(key)) || typeof recipe.key_ref.result_id !== 'string') fail('INVALID_KEY_REF', 'Provide one key_ref with ref and producer result_id, without an inline key');
        const parent = artifacts.get(recipe.key_ref.result_id);
        const material = completeRecoveredKey(parent, recipe.key_ref);
        checkKeyAssociation(parent.association, association);
        const key = artifacts.read(material.dataRef.ref, 4096);
        const { key_ref, ...options } = recipe;
        recipe = { ...options, key: { encoding: 'hex', data: key.data.toString('hex') } };
        keySource = { ref: material.dataRef.ref, result_id: parent.id, sensitive: true, bytes: key.data.length, origin: { kind: 'recovered-key', producer: parent.id }, ...(parent.association ? { association: parent.association } : {}) };
      }
      const request = kind === 'crypto'
        ? { op: args.action, input: { encoding: 'hex', data: captured.data.toString('hex') }, recipe, recovery, expected: args.expected, offset: args.offset, length: args.length, output_limit: args.output_limit, preview_limit: args.preview_limit }
        : { action: args.action, data: captured.data.toString('hex'), encoding: 'hex', schema: args.schema, framing: args.framing, inference: args.inference, maxPackets: args.max_packets, maxFrames: args.max_frames, maxReassemblyBytes: args.max_reassembly_bytes, maxPreviewBytes: args.preview_limit };
      const value = await jobs.run(kind, request, mgr.scope?.getStore()?.signal);
      mgr.checkCancelled();
      const inputRef = artifacts.put(captured.data);
      const outputRef = value.output == null ? undefined : artifacts.put(Buffer.from(value.output));
      const result = externalize(value.result);
      const record = artifacts.save({ kind, action: args.action, association, input: { ...inputRef, origin: captured.origin }, output: outputRef, ...(keySource ? { keySource } : {}), result });
      return { result_id: record.id, kind, action: args.action, association, input: bindRefs(record.input, record.id), output: bindRefs(outputRef, record.id), ...(keySource ? { keySource } : {}), ...compactAnalysis(bindRefs(result, record.id)), note: 'Data-only analysis; no sample execution or database mutation. Recovery and inferred fields are bounded candidates; use explicit verification or independent holdout evidence before accepting them. Producer-marked sensitive key refs cannot be ordinary analysis input. Unbound refs and explicit local files retain raw data access; this preview guard is not a local secret access-control boundary.' };
    },
    dispose: async () => { await jobs.dispose(); await artifacts.dispose(); },
  };
}

export function defineAnalysisTools(mgr, cfg, render) {
  mgr.analysis ??= createAnalysisService(mgr, cfg);
  const common = { input: inputProperty, target: { type: 'string', description: 'Optional result association only; no open session needed for file/ref/inline input' }, result_id: { type: 'string' }, select: { type: 'string', description: 'For action=result, optional bounded dot path such as flows.0' }, preview_limit: { type: 'number' } };
  const tool = (name, kind, description, properties) => ({ name, description, parameters: { type: 'object', properties: { ...common, ...properties }, required: ['action'], additionalProperties: false }, output: { schema: { type: 'object', additionalProperties: true }, render }, execute: args => mgr.analysis.execute(kind, args) });
  return [
    tool('ig5_crypto', 'crypto', 'Inspect, decrypt XOR/AES-CBC/CTR/GCM, decompress or verify bounded bytes. action=recover searches bounded single/repeating XOR keys and validates supplied/extracted AES candidates; it does not exhaust strong AES key spaces. Candidate keys are sensitive SHA-256 refs; transform recipe.key_ref reuses a complete recover candidate without exposing key bytes. Producer-marked sensitive refs are rejected as ordinary input; unbound refs/local files keep raw access and are not a secret access-control boundary. Explicit expected or GCM authentication distinguishes verified plaintext from statistical guesses. No sample execution or database write. action=result reads a prior report.', {
      action: { type: 'string', enum: ['inspect', 'transform', 'recover', 'verify', 'result'] }, offset: { type: 'number' }, length: { type: 'number' }, output_limit: { type: 'number' }, expected: bytesProperty, recovery: recoveryProperty,
      recipe: { type: 'object', properties: { kind: { type: 'string', enum: ['xor', 'aes-cbc', 'aes-ctr', 'aes-gcm', 'gzip', 'zlib'] }, key: bytesProperty, key_ref: keyRefProperty, iv: bytesProperty, tag: bytesProperty, aad: bytesProperty, padding: { type: 'string', enum: ['none', 'pkcs7'] }, key_offset: { type: 'number', description: 'Explicit repeating XOR key start offset' } }, required: ['kind'], additionalProperties: false },
    }),
    tool('ig5_protocol', 'protocol', 'Inspect, parse PCAP/PCAPNG, reassemble directions or decode schemas. action=infer ranks bounded framing and field hypotheses from explicit messages/streams/captures, preserving unknown boundaries and holes; independent holdout validation is reported separately. Candidate framing/schema can be reused by decode. Field meanings, encryption and protocol state machines are not automatically proven. No live capture, network sends or sample execution. action=result reads a prior report.', {
      action: { type: 'string', enum: ['inspect', 'capture', 'decode', 'infer', 'result'] }, offset: { type: 'integer', minimum: 0, description: 'Relative input-byte offset; capture the bounded full source first, then select this range. Useful with infer candidate.decodeInput.startOffset.' }, length: { type: 'integer', minimum: 0, description: 'Selected byte length; preserve skipped prefix/tail in the source reference. Useful with infer candidate.decodeInput.byteLength.' }, max_packets: { type: 'number' }, max_frames: { type: 'number' }, max_reassembly_bytes: { type: 'number' }, inference: inferenceProperty,
      schema: { type: 'object', properties: { name: { type: 'string' }, fields: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, offset: { type: 'number' }, type: { type: 'string', enum: ['u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64', 'bytes', 'utf8', 'varint'] }, length: { type: 'number' }, endian: { type: 'string', enum: ['little', 'big'] } }, required: ['name', 'offset', 'type'], additionalProperties: false } } }, required: ['fields'], additionalProperties: false },
      framing: { type: 'object', properties: { type: { type: 'string', enum: ['fixed', 'length-prefix', 'delimiter', 'varint-prefix', 'tlv'] }, delimiterHex: { type: 'string', enum: ['0a', '0d0a'] }, includeDelimiter: { type: 'boolean' }, length: { type: 'number' }, offset: { type: 'number' }, size: { type: 'number', enum: [1, 2, 4] }, maxBytes: { type: 'integer', minimum: 1, maximum: 5 }, headerBytesAfterLength: { type: 'integer', minimum: 0, maximum: 4096 }, typeSize: { type: 'integer', enum: [1, 2] }, lengthSize: { type: 'integer', enum: [1, 2, 4] }, endian: { type: 'string', enum: ['little', 'big'] }, headerLength: { type: 'number' }, lengthIncludesHeader: { type: 'boolean' }, adjustment: { type: 'number' } }, required: ['type'], additionalProperties: false },
    }),
  ];
}
