import { createHash } from 'node:crypto';

// Hypotheses describe observed byte relations, never protocol names or meanings.
const MAX_SAMPLE_BYTES = 1024 * 1024;
const MAX_SCAN_BYTES = 256 * 1024;
const MAX_WORK = 2000000;
const MAX_FRAMES = 128;
const CAPTURE_MAGIC = new Set(['d4c3b2a1', 'a1b2c3d4', '4d3cb2a1', 'a1b23c4d', '0a0d0d0a']);
function fail(message) { const error = new Error(message); error.code = 'INVALID_PROTOCOL_ARGUMENT'; throw error; }
function integer(value, name, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(`${name} is outside its bounded integer range`);
  return value;
}
function sha(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function encodedSamples(entries, name, state) {
  if (entries === undefined) return [];
  if (!Array.isArray(entries) || entries.length > 64) fail(`${name} must contain at most 64 encoded byte samples`);
  return entries.map(entry => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || typeof entry.data !== 'string')
      fail('Samples require explicit data and encoding');
    if (Object.keys(entry).some(key => !['data', 'encoding'].includes(key))) fail('Sample contains an unsupported property');
    if (++state.count > 64) fail('Training and holdout samples together exceed 64 entries');
    const encoding = entry.encoding ?? 'hex';
    let bytes;
    if (encoding === 'hex') {
      if (entry.data.length > (MAX_SAMPLE_BYTES - state.bytes) * 2 || entry.data.length % 2 || !/^[0-9a-f]*$/i.test(entry.data))
        fail('Sample hex encoding or aggregate byte budget is invalid');
      bytes = Buffer.from(entry.data, 'hex');
    } else if (encoding === 'base64') {
      if (entry.data.length > Math.ceil((MAX_SAMPLE_BYTES - state.bytes) / 3) * 4 || entry.data.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(entry.data))
        fail('Sample base64 encoding or aggregate byte budget is invalid');
      bytes = Buffer.from(entry.data, 'base64');
      if (bytes.toString('base64') !== entry.data) fail('Sample base64 must be canonical');
    } else fail('Sample encoding must be hex or base64');
    state.bytes += bytes.length;
    if (state.bytes > MAX_SAMPLE_BYTES || !bytes.length) fail('Samples must be nonempty and total at most 1 MiB');
    return bytes;
  });
}
function configuration(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) fail('inference must be an object');
  const allowed = new Set(['format', 'boundary', 'samples', 'holdout_samples', 'min_frames', 'max_candidates', 'max_scan_bytes', 'max_work']);
  if (Object.keys(options).some(key => !allowed.has(key))) fail('inference contains an unsupported property');
  const format = options.format ?? 'auto', boundary = options.boundary ?? 'unknown';
  if (!['auto', 'stream', 'messages', 'capture'].includes(format)) fail('Unsupported inference format');
  if (!['unknown', 'message-start'].includes(boundary)) fail('Unsupported inference boundary');
  const state = { bytes: 0, count: 0 };
  const samples = encodedSamples(options.samples, 'samples', state);
  const holdout = encodedSamples(options.holdout_samples, 'holdout_samples', state);
  return { format, boundary, samples, holdout,
    minFrames: integer(options.min_frames ?? 3, 'min_frames', 3, 64),
    maxCandidates: integer(options.max_candidates ?? 8, 'max_candidates', 1, 8),
    maxScanBytes: integer(options.max_scan_bytes ?? MAX_SCAN_BYTES, 'max_scan_bytes', 1, MAX_SCAN_BYTES),
    maxWork: integer(options.max_work ?? MAX_WORK, 'max_work', 1, MAX_WORK) };
}
class Budget {
  constructor(config) { this.maxWork = config.maxWork; this.maxBytes = config.maxScanBytes; this.usedWork = 0; this.scannedBytes = 0; this.reasons = new Set(); this.observationCache = new Map(); }
  work(cost = 1) {
    if (cost > this.maxWork - this.usedWork) { this.reasons.add('work-budget'); return false; }
    this.usedWork += cost; return true;
  }
  bytes(bytes, complete = false) {
    const count = Math.min(bytes.length, this.maxBytes - this.scannedBytes);
    this.scannedBytes += count;
    if (count < bytes.length) this.reasons.add('scan-byte-budget');
    return complete && count < bytes.length ? null : bytes.subarray(0, count);
  }
  get exhausted() { return this.reasons.has('work-budget'); }
  report() { return { usedWork: this.usedWork, maxWork: this.maxWork, scannedBytes: this.scannedBytes,
    maxScanBytes: this.maxBytes, exhausted: this.reasons.size > 0, reasons: [...this.reasons] }; }
}
function unsigned(bytes, offset, width, endian, budget) {
  if (!budget.work(width) || offset + width > bytes.length) return null;
  if (width === 1) return bytes[offset];
  if (width === 2) return endian === 'little' ? bytes.readUInt16LE(offset) : bytes.readUInt16BE(offset);
  return endian === 'little' ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
}
function varint(bytes, offset, budget) {
  let value = 0;
  for (let i = 0; i < 5; i++) {
    if (!budget.work() || offset + i >= bytes.length) return null;
    const byte = bytes[offset + i];
    if (i === 4 && (byte & 0xf0)) return null;
    value += (byte & 0x7f) * 2 ** (7 * i);
    if (!(byte & 0x80)) return i > 0 && byte === 0 ? null : { value, bytes: i + 1 };
  }
  return null;
}
function lengthFraming(offset, size, endian, delta) {
  const prefixEnd = offset + size;
  const payloadLength = delta >= prefixEnd && delta <= 16;
  return { type: 'length-prefix', offset, size, endian,
    headerLength: payloadLength ? delta : prefixEnd,
    lengthIncludesHeader: !payloadLength, adjustment: payloadLength ? 0 : delta };
}
function headerSize(framing, encodedBytes = 0) { return framing.type === 'varint-prefix' ? framing.offset + encodedBytes + framing.headerBytesAfterLength : framing.headerLength; }
function totalLength(raw, framing, encodedBytes = 0) { return raw + framing.adjustment + (framing.lengthIncludesHeader ? 0 : headerSize(framing, encodedBytes)); }
function numbers(values) { return { distinctValues: new Set(values).size, min: Math.min(...values), max: Math.max(...values), preview: values.slice(0, 16) }; }
const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, n) => {
  for (let i = 0; i < 8; i++) n = n & 1 ? 0xedb88320 ^ n >>> 1 : n >>> 1;
  return n >>> 0;
});
function observations(frames, holdout, framing, budget, independent, cacheKey) {
  let base = budget.observationCache.get(cacheKey);
  if (!base) {
    base = { complete: true, crossFieldRelations: [], crossFieldRelationsOmitted: 0, checksums: [], semantics: 'unknown' };
    const minimum = Math.min(...frames.map(b => b.length), 8);
    const validate = (predicate, cost) => {
      let checked = 0, passed = true;
      for (const frame of holdout) {
        if (!budget.work(cost(frame))) { base.complete = false; return { status: 'budget-exhausted', verified: false, checked }; }
        checked++; if (!predicate(frame)) passed = false;
      }
      return { status: !holdout.length ? 'not-requested' : !passed ? 'failed' : independent ? 'passed' : 'not-independent', verified: !!(holdout.length && independent && passed), checked,
        scope: 'Tested supplied byte relation; field roles and business semantics remain unknown.' };
    };
    for (let a = 0; a < minimum && !budget.exhausted; a++) for (let b = a + 1; b < minimum && !budget.exhausted; b++) {
      if (!budget.work(frames.length * 2)) { base.complete = false; break; }
      if (new Set(frames.map(f => f[a])).size < 2 || new Set(frames.map(f => f[b])).size < 2) continue;
      for (const relation of ['equal', 'sum', 'product']) {
        if (!budget.work(frames.length * 2)) { base.complete = false; break; }
        const calculate = f => relation === 'equal' ? f[a] - f[b] : relation === 'sum' ? f[a] + f[b] : f[a] * f[b];
        const delta = relation === 'equal' ? 0 : frames[0].length - calculate(frames[0]);
        if (delta < 0 || delta > 16 || !frames.every(f => relation === 'equal' ? calculate(f) === 0 : calculate(f) + delta === f.length)) continue;
        if (base.crossFieldRelations.length >= 4) { base.crossFieldRelationsOmitted++; continue; }
        base.crossFieldRelations.push({ relation: relation === 'equal' ? 'u8-fields-equal' : `u8-${relation}-plus-delta-equals-frame-length`, offsets: [a, b], delta,
          trainingSamples: frames.length, semanticMeaning: 'unknown', validation: validate(f => f.length > b && (relation === 'equal' ? calculate(f) === 0 : calculate(f) + delta === f.length), () => 2) });
      }
    }
    for (const algorithm of ['xor8', 'sum8', 'crc32-ieee']) for (const order of algorithm === 'crc32-ieee' ? ['big', 'little'] : ['big']) {
      if (budget.exhausted) { base.complete = false; break; }
      const width = algorithm === 'crc32-ieee' ? 4 : 1;
      if (frames.some(f => f.length < width + 2)) continue;
      const wanted = f => width === 1 ? f.at(-1) : order === 'big' ? f.readUInt32BE(f.length - 4) : f.readUInt32LE(f.length - 4);
      if (!budget.work(frames.length * width) || new Set(frames.map(wanted)).size < 2) continue;
      const calculate = f => {
        let value = algorithm === 'crc32-ieee' ? 0xffffffff : 0;
        for (let i = 0; i < f.length - width; i++) value = algorithm === 'xor8' ? value ^ f[i] : algorithm === 'sum8' ? (value + f[i]) & 255 : CRC_TABLE[(value ^ f[i]) & 255] ^ value >>> 8;
        return algorithm === 'crc32-ieee' ? (value ^ 0xffffffff) >>> 0 : value;
      };
      let matched = true;
      for (const frame of frames) {
        if (!budget.work(frame.length)) { base.complete = false; matched = false; break; }
        if (calculate(frame) !== wanted(frame)) { matched = false; break; }
      }
      if (matched) base.checksums.push({ algorithm, endian: order, field: { fromEnd: width, width }, coverage: { start: 0, excludesTailBytes: width }, trainingSamples: frames.length,
        meaning: 'Observed checksum relation; does not establish packet integrity or a protocol name.', validation: validate(f => f.length >= width + 2 && calculate(f) === wanted(f), f => f.length) });
    }
    if (budget.exhausted) base.complete = false;
    if (budget.observationCache.size < 32) budget.observationCache.set(cacheKey, base);
  }
  let sequence = { status: 'not-observed', semanticStatesInferred: false };
  if (framing.type === 'tlv') {
    const tags = frames.map(f => unsigned(f, 0, framing.typeSize, framing.endian, budget));
    if (!tags.some(tag => tag === null)) {
      const pairs = new Map();
      for (let i = 1; i < tags.length; i++) { if (!budget.work()) break; const key = `${tags[i - 1]}/${tags[i]}`; pairs.set(key, (pairs.get(key) ?? 0) + 1); }
      sequence = { status: 'observed-only', semanticStatesInferred: false, orderScope: 'Supplied message order in this single direction; no causality or request/response pairing is inferred.',
        tagPreview: tags.slice(0, 16), tagsOmitted: Math.max(0, tags.length - 16), transitions: [...pairs].slice(0, 16).map(([pair, count]) => ({ fromTag: Number(pair.split('/')[0]), toTag: Number(pair.split('/')[1]), count })),
        transitionsOmitted: Math.max(0, pairs.size - 16) };
    }
  }
  return { ...base, complete: base.complete && !budget.exhausted, sequence };
}
function fieldAnalysis(frames, framing, budget) {
  const minLength = Math.min(...frames.map(frame => frame.length));
  const observedHeader = framing.type === 'varint-prefix' ? framing.offset : framing.type === 'tlv' ? framing.headerLength : framing.type === 'length-prefix' ? Math.max(framing.headerLength, Math.min(16, minLength)) : Math.min(16, minLength);
  const observations = [], fields = [], described = new Set();
  const validation = { scope: 'training-observations', verified: false };
  if (framing.type === 'varint-prefix') {
    const values = frames.map(frame => varint(frame, framing.offset, budget)?.value);
    if (values.some(value => value === undefined)) return null;
    fields.push({ name: 'length', offset: framing.offset, type: 'varint', length: 5, role: 'length-candidate', confidence: 'relation-supported',
      evidence: { relation: 'canonical unsigned LEB128 length relation', sampleCount: frames.length, values: numbers(values), headerBytesAfterLength: framing.headerBytesAfterLength }, validation });
  }
  if (framing.type === 'length-prefix' || framing.type === 'tlv') {
    const values = frames.map(frame => unsigned(frame, framing.offset, framing.size, framing.endian, budget));
    if (values.some(value => value === null)) return null;
    for (let at = framing.offset; at < framing.offset + framing.size; at++) described.add(at);
    fields.push({ name: 'length', offset: framing.offset, type: `u${framing.size * 8}`, endian: framing.endian,
      role: 'length-candidate', confidence: 'relation-supported', evidence: { relation: 'frameLength = declaredLength + delta',
        delta: framing.adjustment + (framing.lengthIncludesHeader ? 0 : framing.headerLength), sampleCount: frames.length, values: numbers(values) }, validation });
    if (framing.type === 'tlv') {
      const tags = frames.map(frame => unsigned(frame, 0, framing.typeSize, framing.endian, budget));
      if (tags.some(tag => tag === null)) return null;
      for (let at = 0; at < framing.typeSize; at++) described.add(at);
      fields.unshift({ name: 'tag', offset: 0, type: `u${framing.typeSize * 8}`, endian: framing.endian, role: 'tag-candidate', confidence: 'observed-only', evidence: { values: numbers(tags), semanticMeaning: 'unknown' }, validation });
    }
  }
  for (let at = 0; at < observedHeader; at++) {
    if (!budget.work(frames.length)) return null;
    const values = frames.map(frame => frame[at]), distinct = new Set(values);
    observations.push({ offset: at, distinctValues: distinct.size, stable: distinct.size === 1,
      value: distinct.size === 1 ? values[0] : undefined, preview: [...distinct].slice(0, 8), sampleCount: frames.length });
  }
  // Extend the compulsory prefix only across a contiguous repeated prefix.
  // Never turn a payload length observed in training into a fixed payload field.
  let layoutEnd = framing.type === 'varint-prefix' ? framing.offset : ['length-prefix', 'tlv'].includes(framing.type) ? framing.headerLength : Math.min(2, observedHeader);
  while (layoutEnd < observedHeader && observations[layoutEnd].stable) layoutEnd++;
  if (layoutEnd < observedHeader && observations[layoutEnd].distinctValues <= 4 &&
      observations[layoutEnd].distinctValues < frames.length && observations[layoutEnd + 1]?.stable) {
    layoutEnd++;
    while (layoutEnd < observedHeader && observations[layoutEnd].stable) layoutEnd++;
  }
  let magicBytes = 0;
  for (let at = 0; at < layoutEnd;) {
    if (described.has(at)) { at++; continue; }
    const stable = observations[at]?.stable;
    let end = at + 1;
    while (end < layoutEnd && !described.has(end) && observations[end]?.stable === stable) end++;
    const length = end - at;
    if (stable) {
      magicBytes += length;
      fields.push({ name: `constant_${at}`, offset: at, type: 'bytes', length, role: 'stable-bytes', confidence: 'observed-only',
        evidence: { expectedHex: frames[0].subarray(at, end).toString('hex'), sampleCount: frames.length, semanticMeaning: 'unknown' }, validation });
    } else {
      // A low-cardinality value can be an opcode, flag or data. Keep that ambiguity explicit.
      if (length === 1 && observations[at].distinctValues <= 4 && observations[at].distinctValues < frames.length) {
        fields.push({ name: `unknown_${at}`, offset: at, type: 'u8', endian: 'big', role: 'opcode-candidate', confidence: 'low',
          evidence: { distinctValues: observations[at].distinctValues, sampleCount: frames.length, alternatives: ['opcode', 'flag', 'ordinary-data'] }, validation });
      } else fields.push({ name: `unknown_${at}`, offset: at, type: 'bytes', length, role: 'unknown', confidence: 'unknown',
        evidence: { sampleCount: frames.length }, validation });
    }
    at = end;
  }
  return { fields, schema: { fields: fields.map(({ name, offset, type, endian, length }) => ({ name, offset, type, ...(endian ? { endian } : {}), ...(length !== undefined ? { length } : {}) })) },
    observations, stableHeaderBytesOutsideLength: magicBytes, remainingPayload: framing.type === 'varint-prefix'
      ? { offset: null, after: 'decoded-varint-prefix', headerBytesAfterLength: framing.headerBytesAfterLength, layout: 'unknown' }
      : { offset: layoutEnd, layout: 'unknown' } };
}
function checkMessages(frames, framing, budget) {
  const failures = [];
  for (let index = 0; index < frames.length; index++) {
    if (!budget.work()) return { passed: false, incomplete: true, checked: index, failures };
    const bytes = frames[index];
    let valid;
    if (framing.type === 'fixed') valid = bytes.length === framing.length;
    else if (framing.type === 'delimiter') {
      const delimiter = Buffer.from(framing.delimiterHex, 'hex');
      if (!budget.work(bytes.length)) return { passed: false, incomplete: true, checked: index, failures };
      valid = bytes.length >= delimiter.length && bytes.indexOf(delimiter) === bytes.length - delimiter.length;
    } else if (framing.type === 'varint-prefix') {
      const raw = varint(bytes, framing.offset, budget);
      valid = raw !== null && bytes.length >= headerSize(framing, raw.bytes) && totalLength(raw.value, framing, raw.bytes) === bytes.length;
    } else {
      const raw = unsigned(bytes, framing.offset, framing.size, framing.endian, budget);
      valid = raw !== null && bytes.length >= framing.headerLength && totalLength(raw, framing) === bytes.length;
    }
    if (!valid && failures.length < 8) failures.push({ sampleIndex: index, reason: 'framing-relation-mismatch', byteLength: bytes.length });
  }
  return { passed: failures.length === 0, incomplete: false, checked: frames.length, failures };
}
function candidate(frames, framing, evidence, holdout, budget, config) {
  if (!budget.work()) return null;
  const analysis = fieldAnalysis(frames, framing, budget);
  if (!analysis) return null;
  if (evidence.boundaries === 'unverified-start-hypothesis' || evidence.boundaries === 'caller-asserted-start') {
    if (['length-prefix', 'varint-prefix', 'tlv'].includes(framing.type) && analysis.stableHeaderBytesOutsideLength < 2 &&
        !(frames.length >= 5 && analysis.stableHeaderBytesOutsideLength >= 1) && !holdout.length) return null;
  }
  if (!budget.work(frames.reduce((total, frame) => total + frame.length, 0) + holdout.reduce((total, frame) => total + frame.length, 0))) return null;
  const orderedHashes = frames.map(sha), holdoutHashes = holdout.map(sha);
  const trainHashes = new Set(orderedHashes);
  const independent = holdout.length > 0 && holdoutHashes.every(hash => !trainHashes.has(hash));
  const holdoutResult = holdout.length ? checkMessages(holdout, framing, budget) : null;
  // Validate field hypotheses separately. A contradicted "magic" interpretation
  // does not invalidate an independently matching framing relation. Unsupported
  // fixed spans are removed from the executable schema, but their rejected
  // hypotheses and training observations remain visible.
  const fieldChecks = new Map();
  if (holdoutResult && !holdoutResult.incomplete) for (const field of analysis.fields) {
    const failures = []; let available = true;
    const maximumWidth = field.length ?? Number(field.type.slice(1)) / 8;
    for (let index = 0; index < holdout.length; index++) {
      const encoded = field.type === 'varint' ? varint(holdout[index], field.offset, budget) : null;
      const width = encoded?.bytes ?? maximumWidth;
      if (!budget.work(width)) { holdoutResult.incomplete = true; holdoutResult.passed = false; break; }
      if (field.offset + width > holdout[index].length || field.type === 'varint' && !encoded) { available = false; failures.push({ sampleIndex: index, reason: 'field-span-unavailable' }); }
      else if (field.role === 'stable-bytes' && holdout[index].subarray(field.offset, field.offset + width).toString('hex') !== field.evidence.expectedHex)
        failures.push({ sampleIndex: index, reason: 'stable-bytes-mismatch' });
    }
    fieldChecks.set(field.name, { status: failures.length ? 'failed' : 'passed', available, failures: failures.slice(0, 8) });
  }
  const executableNames = new Set(analysis.fields.filter(field => fieldChecks.get(field.name)?.available !== false).map(field => field.name));
  analysis.schema.fields = analysis.schema.fields.filter(field => executableNames.has(field.name));
  const validation = { status: !holdout.length ? 'not-requested' : holdoutResult.incomplete ? 'budget-exhausted' : !holdoutResult.passed ? 'failed' : independent ? 'passed' : 'not-independent',
    verified: !!(independent && holdoutResult?.passed && !holdoutResult.incomplete),
    scope: 'Supplied framing holdout observations; field hypotheses have separate validation and semantic meaning remains unknown.',
    training: { sampleCount: frames.length, distinctLengths: new Set(frames.map(frame => frame.length)).size, verified: false },
    holdout: { sampleCount: holdout.length, independent, ...(holdoutResult ?? {}) } };
  const strong = analysis.stableHeaderBytesOutsideLength >= 2;
  const score = Number(Math.min(0.95, (['length-prefix', 'varint-prefix', 'tlv'].includes(framing.type) ? 0.58 : framing.type === 'delimiter' ? 0.62 : 0.35) +
    (strong ? 0.13 : 0) + Math.min(0.08, frames.length / 100) + (validation.verified ? 0.12 : 0)).toFixed(3));
  const id = sha(Buffer.from(JSON.stringify({ framing, start: evidence.startOffset ?? null,
    flowId: evidence.origin?.flowId ?? null, direction: evidence.origin?.direction ?? null }))).slice(0, 16);
  const observed = observations(frames, holdout, framing, budget, independent, orderedHashes.join(':') + '|' + holdoutHashes.join(':'));
  return { id, framing, schema: analysis.schema, score, confidence: validation.verified ? 'holdout-supported' : 'candidate',
    observations: observed,
    decodeInput: evidence.startOffset !== undefined ? { startOffset: evidence.startOffset,
      byteLength: evidence.consumedBytes ?? frames.reduce((n, frame) => n + frame.length, 0),
      instruction: 'Decode only this observed slice; preserve skipped prefix and trailing bytes separately.' } : { samples: 'decode each complete sample separately' },
    fields: analysis.fields.map(field => ({ ...field, includedInSchema: executableNames.has(field.name),
      validation: { ...field.validation, holdoutStatus: fieldChecks.get(field.name)?.status ?? 'not-requested',
        ...(fieldChecks.get(field.name) ?? {}) } })),
    evidence: { ...evidence, sampleCount: frames.length, lengths: numbers(frames.map(frame => frame.length)),
      stableHeaderBytesOutsideLength: analysis.stableHeaderBytesOutsideLength, bytePositions: analysis.observations,
      payload: analysis.remainingPayload, sampleHashes: [...trainHashes].slice(0, 16), sampleHashesOmitted: Math.max(0, trainHashes.size - 16) }, validation };
}
function addCandidate(result, entry, config) {
  if (!entry) return;
  if (entry.validation.status === 'failed' || entry.validation.status === 'budget-exhausted') {
    if (result.rejectedCandidates.length < config.maxCandidates) result.rejectedCandidates.push(entry);
    return;
  }
  if (result.candidates.some(old => old.id === entry.id)) return;
  result.candidates.push(entry);
  result.candidates.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  if (result.candidates.length > config.maxCandidates) { result.candidates.pop(); result.omittedCandidates++; }
}
function inferMessages(frames, holdout, config, budget, context = {}) {
  const result = { candidates: [], rejectedCandidates: [], omittedCandidates: 0 };
  if (frames.length < config.minFrames || !budget.work(frames.reduce((total, frame) => total + frame.length, 0))) return result;
  const hashes = frames.map(sha), unique = new Set(hashes);
  if (unique.size < 2) return result;
  if (budget.work(holdout.reduce((n, f) => n + f.length, 0))) {
    const holdoutHashes = holdout.map(sha);
    result.observations = observations(frames, holdout, { type: 'none' }, budget,
      holdout.length > 0 && holdoutHashes.every(h => !unique.has(h)), hashes.join(':') + '|' + holdoutHashes.join(':'));
    result.observations.boundaries = 'caller-supplied-complete-messages';
  }
  const distinctLengths = new Set(frames.map(bytes => bytes.length));
  if (distinctLengths.size >= 2) {
    for (let offset = 0; offset <= 8 && !budget.exhausted; offset++) for (const size of [1, 2, 4]) {
      if (offset + size > 16) continue;
      for (const endian of size === 1 ? ['big'] : ['big', 'little']) {
        if (!budget.work()) break;
        const first = unsigned(frames[0], offset, size, endian, budget);
        if (first === null) continue;
        const delta = frames[0].length - first;
        if (delta < -16 || delta > 16) continue;
        const framing = lengthFraming(offset, size, endian, delta);
        const checked = checkMessages(frames, framing, budget);
        if (checked.passed) {
          const entry = candidate(frames, framing, { ...context, boundaries: 'caller-supplied-complete-messages',
            relation: 'constant-length-difference', delta, lengthVariation: distinctLengths.size === 2 ? 'two-observed-sizes' : 'three-or-more-observed-sizes',
            headerInterpretation: 'Canonical representation; header semantics are not determined.' }, holdout, budget, config);
          if (!entry) continue;
          // Two sizes underdetermine many numeric relations. Retain only a
          // repeated prefix or a supplied independent holdout check, and report
          // the weaker size diversity rather than treating it as a proof.
          if (distinctLengths.size === 2) {
            if (entry.evidence.stableHeaderBytesOutsideLength < 2 && !entry.validation.verified) continue;
            entry.score = Number(Math.max(0, entry.score - 0.1).toFixed(3));
          }
          addCandidate(result, entry, config);
        }
      }
    }
  } else if (distinctLengths.size === 1) {
    addCandidate(result, candidate(frames, { type: 'fixed', length: frames[0].length }, { ...context,
      boundaries: 'caller-supplied-complete-messages', ambiguity: 'Equal observed sizes do not distinguish fixed framing from an unobserved variable-length protocol.' }, holdout, budget, config), config);
  }
  for (const delimiterHex of ['0d0a', '0a']) {
    const framing = { type: 'delimiter', delimiterHex, includeDelimiter: true };
    if (checkMessages(frames, framing, budget).passed) addCandidate(result, candidate(frames, framing, { ...context,
      boundaries: 'caller-supplied-complete-messages', delimiterHex }, holdout, budget, config), config);
  }
  inferStructuredMessages(frames, holdout, config, budget, context, result);
  return result;
}
function inferStructuredMessages(frames, holdout, config, budget, context, result) {
  if (frames.length < config.minFrames || new Set(frames.map(b => b.length)).size < 2) return;
  for (let offset = 0; offset <= 8 && !budget.exhausted; offset++) {
    const values = frames.map(bytes => varint(bytes, offset, budget));
    if (values.some(value => !value) || !values.some(value => value.bytes >= 2)) continue;
    for (const includes of [false, true]) {
      const delta = frames[0].length - values[0].value - (includes ? 0 : offset + values[0].bytes);
      if (includes ? delta < -8 || delta > 8 : delta < 0 || delta > 8) continue;
      const framing = { type: 'varint-prefix', offset, maxBytes: 5, headerBytesAfterLength: includes ? 0 : delta, lengthIncludesHeader: includes, adjustment: includes ? delta : 0 };
      if (checkMessages(frames, framing, budget).passed) addCandidate(result, candidate(frames, framing,
        { ...context, boundaries: 'caller-supplied-complete-messages', encoding: 'canonical-unsigned-leb128', relation: 'length-relation', semanticMeaning: 'unknown' }, holdout, budget, config), config);
    }
  }
  for (const typeSize of [1, 2]) for (const lengthSize of [1, 2, 4]) for (const order of ['big', 'little']) {
    if (budget.exhausted) return;
    const tags = frames.map(bytes => unsigned(bytes, 0, typeSize, order, budget));
    if (tags.some(tag => tag === null) || new Set(tags).size < 2) continue;
    for (const includes of [false, true]) {
      const framing = { type: 'tlv', typeSize, lengthSize, offset: typeSize, size: lengthSize, endian: order,
        headerLength: typeSize + lengthSize, lengthIncludesHeader: includes, adjustment: 0 };
      if (checkMessages(frames, framing, budget).passed) addCandidate(result, candidate(frames, framing,
        { ...context, boundaries: 'caller-supplied-complete-messages', relation: 'tagged-length-records', tagSemantics: 'unknown', alternatives: ['tag', 'opcode', 'ordinary-header-data'] }, holdout, budget, config), config);
    }
  }
}
function splitLengthStream(bytes, start, framing, budget) {
  const frames = [], spans = []; let cursor = start;
  while (cursor < bytes.length && frames.length < MAX_FRAMES) {
    if (!budget.work()) break;
    const encoded = framing.type === 'varint-prefix' ? varint(bytes, cursor + framing.offset, budget) : null;
    const raw = framing.type === 'varint-prefix' ? encoded?.value ?? null : unsigned(bytes, cursor + framing.offset, framing.size, framing.endian, budget);
    const minimum = headerSize(framing, encoded?.bytes ?? 0);
    if (raw === null || bytes.length - cursor < minimum) break;
    const length = totalLength(raw, framing, encoded?.bytes ?? 0);
    if (length < minimum || length > bytes.length - cursor) break;
    frames.push(bytes.subarray(cursor, cursor + length)); spans.push({ offset: cursor, length }); cursor += length;
  }
  return { frames, spans, consumed: cursor - start, tail: bytes.length - cursor, tailOffset: cursor };
}
function inferLines(bytes, holdout, config, budget, context, result) {
  // Inspect the clear separator hypothesis first; unsuccessful binary hypotheses
  // must not consume the entire work budget before an obvious text stream.
  for (const delimiterHex of ['0d0a', '0a']) {
    if (budget.exhausted || !budget.work(bytes.length)) break;
    const delimiter = Buffer.from(delimiterHex, 'hex'), frames = [], spans = []; let cursor = 0, end;
    while ((end = bytes.indexOf(delimiter, cursor)) >= 0 && frames.length < MAX_FRAMES) {
      if (!budget.work(end - cursor + 1)) break;
      const frame = bytes.subarray(cursor, end + delimiter.length);
      if (frame.length <= delimiter.length || frame.subarray(0, -delimiter.length).some(b => b !== 9 && b !== 13 && (b < 32 || b > 126))) { frames.length = 0; break; }
      frames.push(frame); spans.push({ offset: cursor, length: frame.length }); cursor = end + delimiter.length;
    }
    if (frames.length < config.minFrames) continue;
    const entry = candidate(frames, { type: 'delimiter', delimiterHex, includeDelimiter: true },
      { ...context, boundaries: config.boundary === 'message-start' ? 'caller-asserted-start' : 'unverified-start-hypothesis', startOffset: 0,
        leadingLineMayBePartial: config.boundary !== 'message-start', frameSpans: spans.slice(0, 32),
        frameSpansOmitted: Math.max(0, spans.length - 32), consumedBytes: cursor,
        trailingBytes: bytes.length - cursor, tailOffset: cursor, printableLinesOnly: true, frameLimitReached: frames.length === MAX_FRAMES }, holdout, budget, config);
    if (entry && frames.length === MAX_FRAMES && cursor < bytes.length) budget.reasons.add('frame-budget');
    addCandidate(result, entry, config);
  }
}
function inferStream(bytes, holdout, config, budget, context = {}) {
  const result = { candidates: [], rejectedCandidates: [], omittedCandidates: 0 };
  inferLines(bytes, holdout, config, budget, context, result);
  // Only caller-established starts or repeated prefix/holdout evidence can support structured streams.
  const structuredStarts = config.boundary === 'message-start' ? 0 : Math.min(16, bytes.length - 1);
  for (let start = 0; start <= structuredStarts && !budget.exhausted; start++) {
    for (let offset = 0; offset <= 4 && !budget.exhausted; offset++) for (let headerAfter = 0; headerAfter <= 4 && !budget.exhausted; headerAfter++) {
      const framing = { type: 'varint-prefix', offset, maxBytes: 5, headerBytesAfterLength: headerAfter, lengthIncludesHeader: false, adjustment: 0 };
      const split = splitLengthStream(bytes, start, framing, budget);
      if (split.frames.length < config.minFrames || new Set(split.frames.map(b => b.length)).size < 3 || split.consumed < (bytes.length - start) * 0.65) continue;
      const entry = candidate(split.frames, framing, { ...context, boundaries: config.boundary === 'message-start' ? 'caller-asserted-start' : 'unverified-start-hypothesis', startOffset: start,
        frameSpans: split.spans.slice(0, 32), consumedBytes: split.consumed, trailingBytes: split.tail, tailOffset: split.tailOffset, encoding: 'canonical-unsigned-leb128', frameLimitReached: split.frames.length === MAX_FRAMES }, holdout, budget, config);
      if (entry && split.frames.length === MAX_FRAMES && split.tail) budget.reasons.add('frame-budget');
      addCandidate(result, entry, config);
    }
    if (config.boundary === 'message-start' || holdout.length) for (const typeSize of [1, 2]) for (const lengthSize of [1, 2, 4]) for (const order of ['big', 'little']) {
      if (budget.exhausted) break;
      const framing = { type: 'tlv', typeSize, lengthSize, offset: typeSize, size: lengthSize, endian: order, headerLength: typeSize + lengthSize, lengthIncludesHeader: false, adjustment: 0 };
      const split = splitLengthStream(bytes, start, framing, budget);
      if (split.frames.length < config.minFrames || new Set(split.frames.map(b => b.length)).size < 3 || split.consumed < (bytes.length - start) * 0.65) continue;
      const tags = split.frames.map(b => unsigned(b, 0, typeSize, order, budget));
      if (tags.some(tag => tag === null) || new Set(tags).size < 2) continue;
      const entry = candidate(split.frames, framing, { ...context, boundaries: config.boundary === 'message-start' ? 'caller-asserted-start' : 'unverified-start-hypothesis', startOffset: start,
        frameSpans: split.spans.slice(0, 32), consumedBytes: split.consumed, trailingBytes: split.tail, tailOffset: split.tailOffset, relation: 'tagged-length-records', tagSemantics: 'unknown', frameLimitReached: split.frames.length === MAX_FRAMES }, holdout, budget, config);
      if (entry && split.frames.length === MAX_FRAMES && split.tail) budget.reasons.add('frame-budget');
      addCandidate(result, entry, config);
    }
  }
  const starts = config.boundary === 'message-start' ? 0 : Math.min(64, bytes.length - 1);
  for (let start = 0; start <= starts && !budget.exhausted; start++) for (let offset = 0; offset <= 8 && !budget.exhausted; offset++) {
    for (const size of [1, 2, 4]) for (const endian of size === 1 ? ['big'] : ['big', 'little']) {
      for (let delta = -16; delta <= 16 && !budget.exhausted; delta++) {
        if (!budget.work()) break;
        const framing = lengthFraming(offset, size, endian, delta);
        const split = splitLengthStream(bytes, start, framing, budget);
        if (split.frames.length < config.minFrames || new Set(split.frames.map(frame => frame.length)).size < 3 ||
            split.consumed < (bytes.length - start) * 0.65) continue;
        const entry = candidate(split.frames, framing, { ...context, boundaries: config.boundary === 'message-start' ? 'caller-asserted-start' : 'unverified-start-hypothesis',
          startOffset: start, skippedPrefixBytes: start, startSearchLimit: starts, frameSpans: split.spans.slice(0, 32),
          frameSpansOmitted: Math.max(0, split.spans.length - 32), consumedBytes: split.consumed,
          trailingBytes: split.tail, tailOffset: split.tailOffset,
          frameLimitReached: split.frames.length === MAX_FRAMES, headerInterpretation: 'Canonical representation of a numeric relation; header semantics remain unknown.' }, holdout, budget, config);
        if (!entry) continue;
        // Length-prefix parsing alone is tautological on random streams. Require a
        // repeated non-length header or independent message evidence before ranking.
        if (entry.evidence.stableHeaderBytesOutsideLength < 2 &&
            !(split.frames.length >= 5 && entry.evidence.stableHeaderBytesOutsideLength >= 1) && !entry.validation.verified) continue;
        if (split.frames.length === MAX_FRAMES && split.tail) budget.reasons.add('frame-budget');
        addCandidate(result, entry, config);
      }
    }
  }
  return result;
}
function packetOrigins(capture, direction) {
  const byIndex = new Map(capture.packets.map(packet => [packet.index, packet]));
  const indices = direction.packetIndices.slice(0, 32);
  return { packetIndices: indices, packetIndicesOmitted: Math.max(0, direction.packetIndices.length - indices.length),
    captureSpans: indices.map(index => { const packet = byIndex.get(index); return packet ? { packetIndex: index,
      captureOffset: packet.captureOffset, capturedLength: packet.capturedLength, timestamp: packet.timestamp ?? null } : { packetIndex: index, spanUnavailable: true }; }),
    spanScope: 'Captured packet bytes, not an exact mapping of reassembled bytes; retransmission alternatives stay in capture evidence.' };
}

export function inferProtocol(input, options = {}, adapters = {}) {
  if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) fail('Explicit byte input is required');
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const config = configuration(options), budget = new Budget(config);
  let format = config.format;
  if (format === 'auto') format = config.samples.length ? 'messages' : CAPTURE_MAGIC.has(bytes.subarray(0, 4).toString('hex')) ? 'capture' : 'stream';
  if (format !== 'messages' && config.samples.length) fail('Explicit complete samples require messages or auto format');
  if (format === 'capture' && config.holdout.length) fail('Capture holdout requires a separate direction-specific messages inference');
  const result = { status: 'insufficient-evidence', format, candidates: [], rejectedCandidates: [], omittedCandidates: 0,
    semantics: 'unknown', boundariesVerified: false, limitations: [
      'Candidates are observed byte relations, not protocol identity, semantic proof, decryption, or a reconstructed state machine.',
      'Length field interpretations and header lengths may be ambiguous. Unobserved messages can invalidate every candidate.',
      'No holdout means unverified; duplicate training bytes are not independent validation.',
      'Stream starts are searched only in the first 65 bytes. No fixed-size boundaries are guessed for an unknown stream.' ] };
  const coverage = { status: 'complete', eligibleGroups: 0, analyzedGroups: 0, skippedGroups: 0,
    skipped: [], skippedOmitted: 0, reasons: [], inputPartial: false, previewTruncated: false, previewReasons: [] };
  function partial(reason) { coverage.status = 'partial'; if (!coverage.reasons.includes(reason)) coverage.reasons.push(reason); }
  function skip(group, reason) {
    group.skipped = reason; coverage.skippedGroups++;
    if (coverage.skipped.length < 32) coverage.skipped.push({ flowId: group.flowId, direction: group.direction, reason });
    else coverage.skippedOmitted++;
    partial(reason);
  }
  if (format === 'capture') {
    if (typeof adapters.parseCapture !== 'function') fail('Capture parser adapter is required');
    const capture = adapters.parseCapture(bytes);
    result.capture = { container: capture.container, packetCount: capture.packetCount, complete: capture.complete,
      truncated: capture.truncated, truncationReasons: capture.truncationReasons, issues: capture.issues.slice(0, 8),
      unsupportedSummary: capture.unsupportedSummary, checksumVerified: false };
    coverage.parsedPackets = capture.packetCount;
    coverage.unsupportedPackets = capture.unsupportedPacketCount;
    for (const reason of capture.truncationReasons ?? []) {
      if (reason === 'packet-preview-budget') { coverage.previewTruncated = true; coverage.previewReasons.push(reason); }
      else { coverage.inputPartial = true; partial(`capture:${reason}`); }
    }
    if (capture.parseComplete === false) { coverage.inputPartial = true; partial('capture:parse-incomplete'); }
    result.groups = [];
    for (const flow of capture.flows) for (const direction of flow.directions) {
      if (!direction.payloadBytesObserved) continue;
      coverage.eligibleGroups++;
      const group = { flowId: flow.id, incarnation: flow.incarnation, protocol: flow.tuple.protocol,
        direction: direction.direction, from: direction.from, to: direction.to, origin: packetOrigins(capture, direction),
        candidates: [], rejectedCandidates: [], status: 'insufficient-evidence' };
      result.groups.push(group);
      if (result.candidates.length >= config.maxCandidates || budget.exhausted) {
        skip(group, result.candidates.length >= config.maxCandidates ? 'global-candidate-budget' : 'global-work-budget'); continue;
      }
      if (direction.ambiguous || direction.holes.length || direction.truncated || direction.unsupported) {
        skip(group, direction.ambiguous ? 'conflicting-retransmission' : direction.holes.length ? 'tcp-holes' : 'truncated-or-unsupported');
        group.holes = direction.holes.slice(0, 8); group.conflicts = direction.conflicts.slice(0, 8); continue;
      }
      let found;
      const remainingConfig = { ...config, maxCandidates: config.maxCandidates - result.candidates.length };
      if (flow.tuple.protocol === 'tcp') {
        if (!direction.streamStartEstablished || direction.chunks.length !== 1 || direction.chunks[0].relativeOffset !== 0) {
          skip(group, 'capture-start-does-not-establish-boundary'); continue;
        }
        const chunk = budget.bytes(Buffer.from(direction.chunks[0].dataHex, 'hex'));
        found = inferStream(chunk, [], { ...remainingConfig, boundary: 'unknown' }, budget,
          { origin: { flowId: flow.id, direction: direction.direction, streamStartEstablished: true, ...group.origin } });
      } else {
        const samples = [];
        for (const datagram of direction.datagrams.slice(0, 64)) {
          const sample = budget.bytes(Buffer.from(datagram.dataHex, 'hex'), true);
          if (sample) samples.push(sample);
        }
        found = inferMessages(samples, [], remainingConfig, budget, { origin: { flowId: flow.id, direction: direction.direction, ...group.origin } });
      }
      group.candidates = found.candidates; group.rejectedCandidates = found.rejectedCandidates;
      if (found.observations) group.observations = found.observations;
      coverage.analyzedGroups++;
      group.status = found.candidates.length ? 'candidate' : budget.exhausted ? 'budget-exhausted' : 'insufficient-evidence';
      for (const entry of found.candidates) addCandidate(result, entry, config);
      result.omittedCandidates += found.omittedCandidates;
    }
    result.observedTransitions = { status: 'not-inferred', reason: 'Framing and direction observations do not establish application state or message semantics.' };
  } else {
    const holdout = [], frames = [];
    // Reserve holdout first: validation must never silently reuse or truncate it.
    for (const sample of config.holdout) { const scanned = budget.bytes(sample, true); if (scanned) holdout.push(scanned); }
    let found;
    if (holdout.length !== config.holdout.length) {
      result.validationSkipped = 'holdout-scan-budget'; found = { candidates: [], rejectedCandidates: [], omittedCandidates: 0 };
    } else if (format === 'messages') {
      const inputs = config.samples.length ? config.samples : bytes.length ? [bytes] : [];
      for (const sample of inputs) { const scanned = budget.bytes(sample, true); if (scanned) frames.push(scanned); }
      found = inferMessages(frames, holdout, config, budget);
      result.suppliedSamples = { training: inputs.length, fullyScannedTraining: frames.length, holdout: config.holdout.length,
        primaryInputUsed: !config.samples.length };
    } else found = inferStream(budget.bytes(bytes), holdout, config, budget);
    Object.assign(result, found);
  }
  result.budget = budget.report();
  for (const reason of result.budget.reasons) partial(reason);
  if (result.omittedCandidates) { coverage.previewTruncated = true; coverage.previewReasons.push('candidate-preview-budget'); }
  result.coverage = coverage;
  result.truncated = coverage.status === 'partial';
  result.truncationReasons = coverage.reasons;
  const byteRelations = (result.observations?.crossFieldRelations.length ?? 0) + (result.observations?.checksums.length ?? 0);
  result.status = result.candidates.length || byteRelations ? 'candidate' : result.budget.exhausted ? 'budget-exhausted' : 'insufficient-evidence';
  result.ambiguity = { retainedCandidates: result.candidates.length, multipleCandidates: result.candidates.length > 1,
    rankingIsProof: false, omittedCandidates: result.omittedCandidates, byteRelationCandidates: byteRelations };
  return result;
}
