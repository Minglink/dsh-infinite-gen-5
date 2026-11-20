import path from 'node:path';
import { AnalysisArtifacts, decodeInline, readStableFile, hashBytes } from './source/analysis_artifacts.js';
import { randomUUID } from 'node:crypto';
import { AnalysisJobs } from './source/analysis_jobs.js';
import { FirmwareJobs } from './source/firmware_jobs.js';
import { normalizeHex } from './source/address_ref.js';
import { analyzeJsApplicationStatic } from './source/native_rea_bridge.js';
import { diffTraces } from './source/analysis_trace_diff.js';

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const INPUT_LIMIT = { crypto: 1024 * 1024, protocol: 8 * 1024 * 1024 };
const bytesProperty = { type: 'object', properties: { encoding: { type: 'string', enum: ['hex', 'base64'] }, data: { type: 'string' } }, required: ['encoding', 'data'], additionalProperties: false };
const inputProperty = { type: 'object', properties: {
  encoding: { type: 'string', enum: ['hex', 'base64'] }, data: { type: 'string' },
  ref: { type: 'string' },
  result_id: { type: 'string' },
  path: { type: 'string' },
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
  key_source: inputProperty,
  known_plaintext: { type: 'array', maxItems: 16, items: { type: 'object', properties: { offset: { type: 'integer', minimum: 0 }, encoding: { type: 'string', enum: ['hex', 'base64'] }, data: { type: 'string' } }, required: ['offset', 'encoding', 'data'], additionalProperties: false } },
  aes: aesProperty,
}, required: [], additionalProperties: false };
const inferenceProperty = { type: 'object', properties: {
  format: { type: 'string', enum: ['auto', 'stream', 'messages', 'capture'] }, boundary: { type: 'string', enum: ['unknown', 'message-start'] },
  samples: { type: 'array', maxItems: 64, items: bytesProperty },
  holdout_samples: { type: 'array', maxItems: 64, items: bytesProperty },
  min_frames: { type: 'integer', minimum: 3, maximum: 64 }, max_candidates: { type: 'integer', minimum: 1, maximum: 8 }, max_scan_bytes: { type: 'integer', minimum: 1, maximum: 262144 }, max_work: { type: 'integer', minimum: 1, maximum: 2000000 },
}, required: [], additionalProperties: false };
const stateModelProperty = { type: 'object', properties: {
  result_id: { type: 'string' },
  model: { type: 'string', enum: ['prefix-tree', 'merged-hypothesis'] },
  merge: { type: 'string', enum: ['none', 'future-equivalent'] }, merge_depth: { type: 'integer', minimum: 1, maximum: 3 },
  max_traces: { type: 'integer', minimum: 1, maximum: 256 }, max_events: { type: 'integer', minimum: 1, maximum: 8192 },
  max_states: { type: 'integer', minimum: 2, maximum: 4096 }, max_work: { type: 'integer', minimum: 100, maximum: 2000000 },
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

/** Keep the saved firmware report under the artifact size limit by shortening per-file-system listings (counts stay exact). */
function trimListings(components, keep) {
  if (keep === Infinity) return;
  for (const component of components) {
    if (component.filesystem && component.filesystem.listing.length > keep) { component.filesystem.listing.length = keep; component.filesystem.listingTruncated = true; }
    for (const child of component.children || []) trimListings(child.components || [], keep);
  }
}
function outline(components, depth = 0, out = []) {
  for (const c of components) {
    if (out.length >= 60) break;
    out.push({ depth, id: c.id, format: c.format, offset: c.offset, size: c.size, valid: c.valid, notes: c.notes.length, files: c.filesystem?.files });
    for (const child of c.children || []) outline(child.components || [], depth + 1, out);
  }
  return out;
}

export function createAnalysisService(mgr, cfg) {
  const artifacts = new AnalysisArtifacts(path.join(cfg.artifactDir, 'analysis-data'));
  const jobs = new AnalysisJobs();
  // APKs are analysed from disk in a roomier worker: DEX tables are large and a minute is a fair budget for a 100 MB package.
  const apkJobs = new AnalysisJobs({ timeoutMs: 60000, memoryMb: 512 });
  const firmwareJobs = new FirmwareJobs(cfg);
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
    result(id, select) { const record = artifacts.get(id);const r=record.result||{},fusion=['cff-state','cff-overlay','bitvector-proposal','bitvector-verification','vm-instance-comparison','vm-instance-check'].includes(record.kind)?compactAnalysis({schema:r.schema,summary:r.summary,sourceRef:r.sourceRef,contractRef:r.contractRef,originalDigest:r.originalDigest,candidateDigest:r.candidateDigest,original:r.original,candidate:r.candidate,provider:r.provider,identities:r.identities,pairs:r.pairs,checks:r.checks?.map(({transcript,...c})=>c),status:r.status,acceptedScope:r.acceptedScope,historyRebound:false}):null;
      return { id: record.id, createdAt: record.createdAt, kind: record.kind, action: record.action, association: record.association, input: bindRefs(record.input, id), output: bindRefs(record.output, id), ...(record.keySource ? { keySource: record.keySource } : {}),...(fusion?{fusion:{...fusion,recordSha256:artifacts.metadata(id).result.recordSha256}}:{}), ...compactAnalysis(bindRefs(selectResult(record, select), id)) }; },
    observeNative(request, signal) { return request.phaseModel === true ? jobs.runSettled('vm-observations', request, signal) : jobs.run('vm-observations', request, signal); },
    sampleVmRoles(request, signal) { return jobs.run('vm-role-samples', request, signal); },
    selectVmFlow(request, signal) { return jobs.run('vm-flow-window', request, signal); },
    replayVmFlowWitnesses(request, signal) { return jobs.run('vm-flow-witness-replay', request, signal); },
    recurVmFlow(request, signal) { return jobs.run('vm-flow-recurrences', request, signal); },
    selectVmHandlers(request, signal) { return jobs.run('vm-handler-windows', request, signal); },
    assessVmHandler(request, signal) { return jobs.run('vm-handler-assessment', request, signal); },
    async executePackage(args) {
      if (args.action === 'result') {
        let record;
        try { record = artifacts.get(args.result_id); } catch (error) { if (error.code === 'ENOENT') fail('NOT_FOUND', 'No such analysis result'); throw error; }
        if (!['apk', 'firmware', 'js_app', 'trace_diff'].includes(record.kind)) fail('INVALID_REF', 'Result belongs to a different analysis lane');
        return this.result(args.result_id, args.select);
      }
      if (args.action === 'trace_diff') {
        if (!args.trace_diff || typeof args.trace_diff !== 'object') fail('INVALID_INPUT', 'trace_diff={trace_a, trace_b} is required for action=trace_diff');
        const diffReport = diffTraces(args.trace_diff.trace_a, args.trace_diff.trace_b, { allowSameRun: Boolean(args.trace_diff.allow_same_run) });
        const association = { target: args.target ? path.resolve(args.target) : diffReport.provenance.targetSha256 };
        const record = artifacts.save({ kind: 'trace_diff', action: 'trace_diff', association, input: { provenance: diffReport.provenance }, result: diffReport });
        return { result_id: record.id, kind: 'trace_diff', action: 'trace_diff', association, ...compactAnalysis(bindRefs(diffReport, record.id)),
          note: 'Offline differential trace alignment only; no target execution.' };
      }
      if (!['apk', 'firmware', 'unpack', 'js_app'].includes(args.action)) fail('INVALID_INPUT', 'action must be apk, firmware, unpack, js_app, trace_diff or result');
      const source = args.input;
      if (!source || typeof source !== 'object' || Array.isArray(source) || Object.keys(source).some(key => key !== 'path') || typeof source.path !== 'string') fail('INVALID_INPUT', 'ig5_package reads an explicit local file or directory: input={path}');
      if (args.select !== undefined || args.result_id !== undefined) fail('INVALID_INPUT', 'select and result_id are only used with action=result');
      const resolved = path.resolve(source.path), signal = mgr.scope?.getStore()?.signal;
      const association = { target: args.target ? path.resolve(args.target) : resolved };
      if (args.action === 'js_app') {
        const report = analyzeJsApplicationStatic(resolved, { cfg, signal });
        mgr.checkCancelled();
        const record = artifacts.save({ kind: 'js_app', action: 'js_app', association, input: { origin: { kind: 'directory-or-file', path: resolved } }, result: report });
        const brief = {
          schema: report.schema,
          executionPerformed: false,
          reaEngine: report.reaEngine,
          targetAppPath: report.targetAppPath,
          nativeArtifacts: report.nativeArtifacts,
          reaSummary: {
            entrypoints: report.reaAnalysis?.application_graph?.entrypoints || report.reaAnalysis?.entrypoints || [],
            ipcChannels: report.reaAnalysis?.application_graph?.ipc_channels || report.reaAnalysis?.ipc_channels || [],
            boundaries: report.reaAnalysis?.application_graph?.boundaries || report.reaAnalysis?.boundaries || [],
          },
        };
        const engineLabel = report.reaEngine?.provider === 'ig5-builtin-js-static'
          ? 'built-in ig5-builtin-js-static-v1'
          : `pinned rea@${report.reaEngine?.version || '6.4.0'}`;
        return { result_id: record.id, kind: 'js_app', action: 'js_app', association, input: record.input, ...compactAnalysis(bindRefs(brief, record.id)),
          note: `Static JS/Electron reconstruction via ${engineLabel}; nothing was executed. Read full evidence with action=result and select=reaAnalysis.` };
      }
      if (args.action === 'apk') {
        const report = await apkJobs.run('apk', { path: resolved }, signal);
        mgr.checkCancelled();
        const record = artifacts.save({ kind: 'apk', action: 'apk', association, input: { origin: { kind: 'file', path: resolved }, sha256: report.file.sha256, bytes: report.file.size }, result: report });
        const brief = { schema: report.schema, summary: report.summary, overview: report.overview, indicators: report.indicators.slice(0, 20), chains: report.capabilities.chains.map(({ id, strength, scope, libraryOnly }) => ({ id, strength, scope, libraryOnly })),
          limitsHit: report.limitsHit, notRun: report.notRun };
        return { result_id: record.id, kind: 'apk', action: 'apk', association, input: record.input, ...compactAnalysis(bindRefs(brief, record.id)),
          note: 'Static analysis only; the sample was not executed. Read a section with action=result and select: manifest, permissions, signatures, dex, nativeLibraries, nestedPayloads, capabilities.rules, capabilities.chains, classes.listed, strings, indicators.' };
      }
      const output = args.action === 'unpack' ? path.join(cfg.artifactDir, 'firmware', randomUUID()) : undefined;
      const report = await firmwareJobs.run({ action: args.action === 'unpack' ? 'extract' : 'scan', path: resolved, ...(output ? { output_dir: output } : {}), deadline_seconds: 300 }, signal);
      mgr.checkCancelled();
      trimListings(report.components, JSON.stringify(report).length > 6 * 1024 * 1024 ? 50 : Infinity);
      const record = artifacts.save({ kind: 'firmware', action: args.action, association, input: { origin: { kind: 'file', path: resolved }, sha256: report.file.sha256, bytes: report.file.size }, result: report });
      const brief = { schema: report.schema, file: report.file, summary: report.summary, outline: outline(report.components), limitsHit: report.limitsHit, notRun: report.notRun,
        ...(report.extraction ? { extraction: { root: report.extraction.root, files: report.extraction.files, bytes: report.extraction.bytes, skipped: report.extraction.skipped.length } } : {}) };
      return { result_id: record.id, kind: 'firmware', action: args.action, association, input: record.input, ...compactAnalysis(bindRefs(brief, record.id)),
        note: 'Static analysis only; nothing was executed. Extraction (action=unpack) writes sanitized names under the reported root and creates no links or devices. Read details with action=result and select: components, summary, extraction.items.' };
    },
    async execute(kind, args) {
      mgr.checkCancelled();
      if (kind === 'package') return this.executePackage(args);
      if (args.action === 'result') {
        if (args.recovery !== undefined || args.inference !== undefined || args.state_model !== undefined) fail('INVALID_INPUT', 'Recovery and inference options are not used when reading a report');
        if (kind === 'protocol' && (args.offset !== undefined || args.length !== undefined)) fail('INVALID_INPUT', 'Byte ranges are not used when reading a report');
        const record = artifacts.get(args.result_id);
        if (record.kind !== kind) fail('INVALID_REF', 'Result belongs to a different analysis lane');
        return this.result(args.result_id, args.select);
      }
      if (args.recovery !== undefined && (kind !== 'crypto' || args.action !== 'recover') || args.inference !== undefined && (kind !== 'protocol' || args.action !== 'infer')) fail('INVALID_INPUT', 'Recovery or inference options do not apply to this action');
      const stateAction = kind === 'protocol' && ['state_infer', 'state_validate'].includes(args.action);
      if (args.state_model !== undefined && !stateAction) fail('INVALID_INPUT', 'State model options do not apply to this action');
      if (stateAction && [args.offset, args.length, args.max_packets, args.max_frames, args.max_reassembly_bytes].some(value => value !== undefined)) fail('INVALID_INPUT', 'State actions consume a complete JSON trace manifest, without byte slicing or capture parsing options');
      if (kind === 'crypto' && args.recipe !== undefined && args.action !== 'transform' || kind === 'protocol' && (args.schema !== undefined || args.framing !== undefined) && !['capture', 'decode'].includes(args.action)) fail('INVALID_INPUT', 'Recipe, schema or framing options do not apply to this action');
      let prior;
      if (kind === 'protocol' && args.action === 'state_validate') {
        const producer = artifacts.get(args.state_model?.result_id);
        if (producer.kind !== 'protocol' || producer.action !== 'state_infer' || producer.result?.schemaVersion !== 'ig5.protocol-state.v1') fail('INVALID_REF', 'State validation requires a saved protocol state_infer report');
        const state = producer.result.state;
        prior = { training: state.training, options: state.options, observedDigest: state.modelDigest, mergedDigest: state.mergedDigest, resultId: producer.id };
      }
      const captured = await input(args, kind, args.input, stateAction ? 1024 * 1024 : INPUT_LIMIT[kind]);
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
        : { action: args.action, data: captured.data.toString('hex'), encoding: 'hex', schema: args.schema, framing: args.framing, inference: args.inference, state_model: args.state_model, prior, maxPackets: args.max_packets, maxFrames: args.max_frames, maxReassemblyBytes: args.max_reassembly_bytes, maxPreviewBytes: args.preview_limit };
      const value = await jobs.run(kind, request, mgr.scope?.getStore()?.signal);
      mgr.checkCancelled();
      const inputRef = artifacts.put(captured.data);
      const outputRef = value.output == null ? undefined : artifacts.put(Buffer.from(value.output));
      const result = externalize(value.result);
      const record = artifacts.save({ kind, action: args.action, association, input: { ...inputRef, origin: captured.origin }, output: outputRef, ...(keySource ? { keySource } : {}), result });
      return { result_id: record.id, kind, action: args.action, association, input: bindRefs(record.input, record.id), output: bindRefs(outputRef, record.id), ...(keySource ? { keySource } : {}), ...compactAnalysis(bindRefs(result, record.id)), note: 'Data-only analysis; no sample execution or database mutation. Recovery and inferred fields are bounded candidates; use explicit verification or independent holdout evidence before accepting them. Producer-marked sensitive key refs cannot be ordinary analysis input. Unbound refs and explicit local files retain raw data access; this preview guard is not a local secret access-control boundary.' };
    },
    dispose: async () => { await jobs.dispose(); await apkJobs.dispose(); await firmwareJobs.dispose(); await artifacts.dispose(); },
  };
}

export function defineAnalysisTools(mgr, cfg, render) {
  mgr.analysis ??= createAnalysisService(mgr, cfg);
  const common = { input: inputProperty, target: { type: 'string' }, result_id: { type: 'string' }, select: { type: 'string' }, preview_limit: { type: 'number' } };
  const tool = (name, kind, description, properties) => ({ name, description, parameters: { type: 'object', properties: { ...common, ...properties }, required: ['action'], additionalProperties: false }, output: { schema: { type: 'object', additionalProperties: true }, render }, execute: args => mgr.analysis.execute(kind, args) });
  return [
    tool('ig5_crypto', 'crypto', 'Static byte/crypto: inspect, transform (XOR/AES/gzip/zlib), recover XOR/AES keys, verify, or result.', {
      action: { type: 'string', enum: ['inspect', 'transform', 'recover', 'verify', 'result'] }, offset: { type: 'number' }, length: { type: 'number' }, output_limit: { type: 'number' }, expected: bytesProperty, recovery: recoveryProperty,
      recipe: { type: 'object', properties: { kind: { type: 'string', enum: ['xor', 'aes-cbc', 'aes-ctr', 'aes-gcm', 'gzip', 'zlib'] }, key: bytesProperty, key_ref: keyRefProperty, iv: bytesProperty, tag: bytesProperty, aad: bytesProperty, padding: { type: 'string', enum: ['none', 'pkcs7'] }, key_offset: { type: 'number' } }, required: ['kind'], additionalProperties: false },
    }),
    tool('ig5_package', 'package', 'Static package analysis: apk, js_app (Electron/JS graph + native inventory), trace_diff, firmware/unpack, or result.', {
      action: { type: 'string', enum: ['apk', 'firmware', 'unpack', 'js_app', 'trace_diff', 'result'] },
      input: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'], additionalProperties: false },
      trace_diff: {
        type: 'object',
        properties: {
          allow_same_run: { type: 'boolean' },
          trace_a: { type: 'object', additionalProperties: true },
          trace_b: { type: 'object', additionalProperties: true },
        },
        required: ['trace_a', 'trace_b'],
        additionalProperties: false,
      },
    }),
    tool('ig5_protocol', 'protocol', 'Static protocol/packet: inspect, capture (PCAP/PCAPNG), decode, infer, state_infer/state_validate, or result.', {
      action: { type: 'string', enum: ['inspect', 'capture', 'decode', 'infer', 'state_infer', 'state_validate', 'result'] }, offset: { type: 'integer', minimum: 0 }, length: { type: 'integer', minimum: 0 }, max_packets: { type: 'number' }, max_frames: { type: 'number' }, max_reassembly_bytes: { type: 'number' }, inference: inferenceProperty, state_model: stateModelProperty,
      schema: { type: 'object', properties: { name: { type: 'string' }, fields: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, offset: { type: 'number' }, type: { type: 'string', enum: ['u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64', 'bytes', 'utf8', 'varint'] }, length: { type: 'number' }, endian: { type: 'string', enum: ['little', 'big'] } }, required: ['name', 'offset', 'type'], additionalProperties: false } } }, required: ['fields'], additionalProperties: false },
      framing: { type: 'object', properties: { type: { type: 'string', enum: ['fixed', 'length-prefix', 'delimiter', 'varint-prefix', 'tlv'] }, delimiterHex: { type: 'string', enum: ['0a', '0d0a'] }, includeDelimiter: { type: 'boolean' }, length: { type: 'number' }, offset: { type: 'number' }, size: { type: 'number', enum: [1, 2, 4] }, maxBytes: { type: 'integer', minimum: 1, maximum: 5 }, headerBytesAfterLength: { type: 'integer', minimum: 0, maximum: 4096 }, typeSize: { type: 'integer', enum: [1, 2] }, lengthSize: { type: 'integer', enum: [1, 2, 4] }, endian: { type: 'string', enum: ['little', 'big'] }, headerLength: { type: 'number' }, lengthIncludesHeader: { type: 'boolean' }, adjustment: { type: 'number' } }, required: ['type'], additionalProperties: false },
    }),
  ];
}
