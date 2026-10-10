import assert from 'node:assert/strict';
import { analyzeProtocol, decodeFrames } from '../source/protocol_analysis.js';

let passed = 0;
function test(name, run) { run(); passed++; process.stdout.write(`ok ${passed} ${name}\n`); }
function encoded(bytes, encoding = 'hex') { encoding = typeof encoding === 'string' ? encoding : 'hex'; return { data: bytes.toString(encoding), encoding }; }
function infer(bytes, options = {}) { return analyzeProtocol({ action: 'infer', ...encoded(bytes), inference: options }).inference; }
function message(payloadLength, options = {}) {
  const size = options.size ?? 2, offset = options.offset ?? 2, header = options.header ?? offset + size + 2;
  const bytes = Buffer.alloc(header + payloadLength);
  for (let index = 0; index < bytes.length; index++) bytes[index] = (options.seed ?? 17) + index * 13 & 255;
  if (offset >= 2) { bytes[0] = 0x49; bytes[1] = 0x47; }
  if (header > offset + size) { bytes[offset + size] = options.opcode ?? 1; bytes[offset + size + 1] = 0; }
  const raw = options.includesHeader ? bytes.length - (options.adjustment ?? 0) : payloadLength;
  if (size === 1) bytes[offset] = raw;
  else if (size === 2) options.endian === 'little' ? bytes.writeUInt16LE(raw, offset) : bytes.writeUInt16BE(raw, offset);
  else options.endian === 'little' ? bytes.writeUInt32LE(raw, offset) : bytes.writeUInt32BE(raw, offset);
  return bytes;
}
const defaultFrames = [3, 7, 11, 16].map((n, i) => message(n, { seed: 40 + i * 9 }));
function matching(result, predicate) { return result.candidates.find(predicate); }
function matchesPrefix(entry, offset, size, endian) { return entry.framing.type === 'length-prefix' && entry.framing.offset === offset && entry.framing.size === size && entry.framing.endian === endian; }
function assertDecodes(candidate, frames) {
  const decoded = decodeFrames(Buffer.concat(frames), { framing: candidate.framing, schema: candidate.schema });
  assert.equal(decoded.complete, true); assert.equal(decoded.remainingBytes, 0);
  assert.deepEqual(decoded.frames.map(frame => frame.dataHex), frames.map(frame => frame.toString('hex')));
  assert(decoded.frames.every(frame => frame.valid));
}
function ipv4(payload, protocol, reverse = false) {
  const h = Buffer.alloc(20); h[0] = 0x45; h.writeUInt16BE(h.length + payload.length, 2); h[8] = 64; h[9] = protocol;
  h.set(reverse ? [10, 0, 0, 2] : [10, 0, 0, 1], 12); h.set(reverse ? [10, 0, 0, 1] : [10, 0, 0, 2], 16);
  return Buffer.concat([h, payload]);
}
function tcp(payload, sequence, flags = 0x18, reverse = false) {
  const h = Buffer.alloc(20); h.writeUInt16BE(reverse ? 8080 : 12000, 0); h.writeUInt16BE(reverse ? 12000 : 8080, 2);
  h.writeUInt32BE(sequence, 4); h[12] = 0x50; h[13] = flags; return ipv4(Buffer.concat([h, payload]), 6, reverse);
}
function udp(payload, reverse = false) {
  const h = Buffer.alloc(8); h.writeUInt16BE(reverse ? 5001 : 5000, 0); h.writeUInt16BE(reverse ? 5000 : 5001, 2);
  h.writeUInt16BE(payload.length + 8, 4); return ipv4(Buffer.concat([h, payload]), 17, reverse);
}
function pcap(packets) {
  const header = Buffer.alloc(24); Buffer.from('d4c3b2a1', 'hex').copy(header); header.writeUInt16LE(2, 4); header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16); header.writeUInt32LE(101, 20);
  return Buffer.concat([header, ...packets.flatMap((bytes, index) => { const record = Buffer.alloc(16);
    record.writeUInt32LE(index + 1, 0); record.writeUInt32LE(bytes.length, 8); record.writeUInt32LE(bytes.length, 12); return [record, bytes]; })]);
}

test('cross-message BE payload length and evidence remain candidate without holdout', () => {
  const result = infer(Buffer.alloc(0), { samples: defaultFrames.map(encoded) });
  const candidate = matching(result, entry => matchesPrefix(entry, 2, 2, 'big'));
  assert(candidate); assert.equal(candidate.framing.headerLength, 6); assert.equal(candidate.validation.verified, false);
  assert.equal(candidate.validation.status, 'not-requested'); assert.equal(result.semantics, 'unknown');
  assertDecodes(candidate, defaultFrames);
});
test('LE16 offset prefix has directly executable schema and framing', () => {
  const frames = [4, 9, 14].map((n, i) => message(n, { endian: 'little', seed: 11 + i }));
  const entry = matching(infer(Buffer.alloc(0), { format: 'messages', samples: frames.map(encoded) }), c => matchesPrefix(c, 2, 2, 'little'));
  assert(entry); assertDecodes(entry, frames);
});
test('BE32 and LE32 lengths never round integers', () => {
  for (const endian of ['big', 'little']) {
    const frames = [4, 300, 511].map(n => message(n, { size: 4, endian }));
    const entry = matching(infer(Buffer.alloc(0), { samples: frames.map(encoded) }), c => matchesPrefix(c, 2, 4, endian));
    assert(entry); assertDecodes(entry, frames); assert.equal(entry.fields[0].evidence.values.preview[2], 511);
  }
});
test('total length and bounded negative adjustment are both inferred', () => {
  for (const adjustment of [0, -2]) {
    const frames = [3, 8, 12].map(n => message(n, { includesHeader: true, adjustment }));
    const entry = matching(infer(Buffer.alloc(0), { samples: frames.map(encoded) }), c => matchesPrefix(c, 2, 2, 'big'));
    assert(entry); assert.equal(entry.framing.lengthIncludesHeader, true); assert.equal(entry.framing.adjustment, adjustment);
    assertDecodes(entry, frames);
  }
});
test('single or only two messages cannot support automatic framing', () => {
  for (const frames of [defaultFrames.slice(0, 1), defaultFrames.slice(0, 2)]) {
    const r = infer(Buffer.alloc(0), { samples: frames.map(encoded) }); assert.equal(r.status, 'insufficient-evidence'); assert.equal(r.candidates.length, 0);
  }
});
test('two sizes with a repeated magic prefix yield an explicitly weaker candidate', () => {
  const frames = [3, 3, 7, 7].map((n, i) => message(n, { seed: 10 + i }));
  const entry = matching(infer(Buffer.alloc(0), { samples: frames.map(encoded) }), c => matchesPrefix(c, 2, 2, 'big'));
  assert(entry); assert.equal(entry.evidence.lengthVariation, 'two-observed-sizes');
  assert.equal(entry.validation.training.distinctLengths, 2); assert.equal(entry.validation.verified, false); assertDecodes(entry, frames);
});
test('two sizes without repeated header evidence remain insufficient until independently tested', () => {
  const frame = (length, seed) => { const bytes = Buffer.alloc(length); bytes[0] = length - 1;
    for (let at = 1; at < bytes.length; at++) bytes[at] = seed + at * 19 & 255; return bytes; };
  const train = [frame(17, 11), frame(23, 30), frame(17, 59)];
  const noHoldout = infer(Buffer.alloc(0), { samples: train.map(encoded) }); assert.equal(noHoldout.candidates.length, 0);
  const holdout = frame(31, 120);
  const entry = matching(infer(Buffer.alloc(0), { samples: train.map(encoded), holdout_samples: [encoded(holdout)] }), c => matchesPrefix(c, 0, 1, 'big'));
  assert(entry); assert.equal(entry.validation.verified, true); assertDecodes(entry, train); assertDecodes(entry, [holdout]);
  const invalid = frame(31, 120); invalid[0] = 4;
  assert.equal(infer(Buffer.alloc(0), { samples: train.map(encoded), holdout_samples: [encoded(invalid)] }).candidates.length, 0);
});
test('equal-size complete samples suggest fixed framing with explicit ambiguity', () => {
  const frames = [20, 30, 40].map(seed => message(7, { seed }));
  const entry = matching(infer(Buffer.alloc(0), { samples: frames.map(encoded) }), c => c.framing.type === 'fixed');
  assert(entry); assert.match(entry.evidence.ambiguity, /do not distinguish/); assert.equal(entry.validation.verified, false);
  assertDecodes(entry, frames);
});
test('duplicate identical samples are not independent evidence', () => {
  const r = infer(Buffer.alloc(0), { samples: [defaultFrames[0], defaultFrames[0], defaultFrames[0]].map(encoded) });
  assert.equal(r.candidates.length, 0);
});
test('mixed incompatible messages reject a learned length relation', () => {
  const frames = [...defaultFrames]; frames[2] = Buffer.from(frames[2]); frames[2].writeUInt16BE(0xffff, 2);
  const r = infer(Buffer.alloc(0), { samples: frames.map(encoded) }); assert.equal(r.candidates.length, 0);
});
test('independent holdout passes framing while shorter payload fields are removed', () => {
  const holdout = [message(1, { seed: 60 }), message(2, { seed: 80 })];
  const r = infer(Buffer.concat(defaultFrames), { format: 'stream', boundary: 'message-start', holdout_samples: holdout.map(encoded) });
  const entry = matching(r, c => matchesPrefix(c, 2, 2, 'big'));
  assert(entry); assert.equal(entry.validation.status, 'passed'); assert.equal(entry.validation.verified, true);
  assertDecodes(entry, defaultFrames); assertDecodes(entry, holdout);
  assert(entry.schema.fields.every(field => field.offset + (field.length ?? Number(field.type.slice(1)) / 8) <= Math.min(...holdout.map(b => b.length))));
});
test('invalid holdout rejects framing rather than confirming training', () => {
  const bad = message(4); bad.writeUInt16BE(255, 2);
  const r = infer(Buffer.alloc(0), { samples: defaultFrames.map(encoded), holdout_samples: [encoded(bad)] });
  assert.equal(r.candidates.length, 0); assert(r.rejectedCandidates.some(c => c.validation.status === 'failed'));
});
test('varying opcode and one stable flag can be supported by independent holdout', () => {
  const frame = (text, opcode) => { const payload = Buffer.concat([Buffer.from([opcode, 0x80]), Buffer.from(text)]);
    const header = Buffer.alloc(2); header.writeUInt16BE(payload.length); return Buffer.concat([header, payload]); };
  const train = [frame('hello', 1), frame('a longer request', 2), frame('third payload varies again', 1), frame('bye now', 3)];
  const holdout = [frame('independent validation message', 4), frame('ok', 5)];
  const entry = matching(infer(Buffer.concat(train), { boundary: 'message-start', holdout_samples: holdout.map(encoded) }), c => matchesPrefix(c, 0, 2, 'big'));
  assert(entry); assert.equal(entry.validation.verified, true); assertDecodes(entry, train); assertDecodes(entry, holdout);
  assert(entry.fields.some(f => f.role === 'opcode-candidate' && f.evidence.alternatives.includes('ordinary-data')));
});
test('reusing a training message as holdout never becomes verified', () => {
  const r = infer(Buffer.alloc(0), { samples: defaultFrames.map(encoded), holdout_samples: [encoded(defaultFrames[1])] });
  assert(r.candidates.length); assert(r.candidates.every(c => !c.validation.verified && c.validation.status === 'not-independent'));
});
test('field magic contradictions remain visible without discarding valid framing', () => {
  const holdout = message(2); holdout[0] = 0x58;
  const r = infer(Buffer.alloc(0), { samples: defaultFrames.map(encoded), holdout_samples: [encoded(holdout)] });
  const entry = matching(r, c => matchesPrefix(c, 2, 2, 'big'));
  assert(entry); assert.equal(entry.validation.status, 'passed'); assert(entry.fields.some(f => f.validation.holdoutStatus === 'failed'));
  assertDecodes(entry, [holdout]);
});
test('established stream retains exact frame spans and incomplete tail', () => {
  const stream = Buffer.concat([...defaultFrames, message(9).subarray(0, 4)]);
  const entry = matching(infer(stream, { boundary: 'message-start' }), c => matchesPrefix(c, 2, 2, 'big'));
  assert(entry); assert.equal(entry.evidence.trailingBytes, 4); assert.equal(entry.evidence.frameSpans.length, 4);
  assert.equal(entry.evidence.boundaries, 'caller-asserted-start'); assert.equal(entry.decodeInput.byteLength, Buffer.concat(defaultFrames).length);
});
test('unknown prefix becomes an explicit start hypothesis, not silently discarded', () => {
  const stream = Buffer.concat([Buffer.from('fffefdfcfb', 'hex'), ...defaultFrames]);
  const entry = matching(infer(stream), c => matchesPrefix(c, 2, 2, 'big') && c.evidence.startOffset === 5);
  assert(entry); assert.equal(entry.evidence.skippedPrefixBytes, 5); assert.equal(entry.evidence.boundaries, 'unverified-start-hypothesis');
  assertDecodes(entry, defaultFrames);
});
test('explicit start does not search ahead for a valid frame boundary', () => {
  const r = infer(Buffer.concat([Buffer.from('fffefdfc', 'hex'), ...defaultFrames]), { boundary: 'message-start' });
  assert(!r.candidates.some(c => c.evidence.startOffset > 0));
});
test('unknown fixed-length streams do not invent frame boundaries', () => {
  const r = infer(Buffer.concat([message(10, { seed: 1 }), message(10, { seed: 2 }), message(10, { seed: 3 })]));
  assert(!r.candidates.some(c => c.framing.type === 'fixed'));
});
test('deterministic noise is not promoted by tautological prefix walking', () => {
  const noise = Buffer.alloc(8192); let state = 0x5730abdf;
  for (let i = 0; i < noise.length; i++) { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; noise[i] = state & 255; }
  const r = infer(noise, { max_work: 150000 }); assert.equal(r.candidates.length, 0); assert(r.budget.usedWork <= 150000);
});
test('empty, one random block, and high-entropy single sample stay insufficient', () => {
  for (const input of [Buffer.alloc(0), Buffer.from('0af293dbbbab66ff47', 'hex')]) assert.equal(infer(input).candidates.length, 0);
  assert.equal(infer(Buffer.alloc(0), { samples: [encoded(Buffer.alloc(300, 0xa5))] }).candidates.length, 0);
});
test('newline and CRLF candidates decode exactly and preserve an unfinished line', () => {
  for (const delimiter of ['\n', '\r\n']) {
    const frames = ['GET one', 'GET longer-two', 'GET x'].map(line => Buffer.from(line + delimiter));
    const r = infer(Buffer.concat([...frames, Buffer.from('unfinished')]), { boundary: 'message-start' });
    const entry = matching(r, c => c.framing.type === 'delimiter' && c.framing.delimiterHex === Buffer.from(delimiter).toString('hex'));
    assert(entry); assertDecodes(entry, frames); assert.equal(entry.evidence.trailingBytes, 10);
    const partial = decodeFrames(Buffer.concat([...frames, Buffer.from('unfinished')]), { framing: entry.framing });
    assert.equal(partial.frames.length, 3); assert.equal(partial.remainingBytes, 10); assert.equal(partial.complete, false);
  }
});
test('delimiter schemas cannot silently drop separators or accept arbitrary strings', () => {
  assert.throws(() => decodeFrames(Buffer.from('a\nb\n'), { framing: { type: 'delimiter', delimiterHex: '0a', includeDelimiter: false } }), e => e.code === 'INVALID_PROTOCOL_SCHEMA');
  assert.throws(() => decodeFrames(Buffer.from('a|b|'), { framing: { type: 'delimiter', delimiterHex: '7c', includeDelimiter: true } }), e => e.code === 'INVALID_PROTOCOL_SCHEMA');
});
test('long obvious text stream remains a candidate when binary search exhausts its budget', () => {
  const input = Buffer.from(Array(2000).fill('GET /hello 1\n').join(''));
  const r = infer(input); const entry = matching(r, c => c.framing.type === 'delimiter');
  assert(entry); assert.equal(entry.evidence.frameLimitReached, true); assert(entry.evidence.trailingBytes > 0);
  assert(r.budget.reasons.includes('frame-budget')); assert(r.budget.usedWork <= r.budget.maxWork);
});
test('base64 sample decoding is canonical and primary input is not implicit training', () => {
  const r = infer(Buffer.alloc(4, 0xff), { samples: defaultFrames.map(b => encoded(b, 'base64')) });
  assert(r.candidates.length); assert.equal(r.suppliedSamples.primaryInputUsed, false);
  for (const sample of [{ data: 'AP9=', encoding: 'base64' }, { data: '00 ff', encoding: 'hex' }, { data: '0', encoding: 'hex' }, { data: '', encoding: 'hex' }])
    assert.throws(() => infer(Buffer.alloc(0), { samples: [sample] }), e => e.code === 'INVALID_PROTOCOL_ARGUMENT');
});
test('all inference dimensions enforce exact hard upper limits', () => {
  for (const options of [{ min_frames: 2 }, { min_frames: 65 }, { max_candidates: 9 }, { max_scan_bytes: 262145 }, { max_work: 2000001 },
    { max_work: 0 }, { boundary: 'guess' }, { format: 'http' }, { samples: Array(65).fill(encoded(Buffer.from([1]))) },
    { samples: Array(33).fill(encoded(Buffer.from([1]))), holdout_samples: Array(32).fill(encoded(Buffer.from([2]))) },
    { samples: [encoded(Buffer.alloc(1024 * 1024 + 1))] }, { format: 'stream', samples: [encoded(Buffer.from([1]))] },
    { extra: 'ignored' }, { samples: [{ data: '00', unexpected: true }] }])
    assert.throws(() => infer(Buffer.alloc(0), options), e => e.code === 'INVALID_PROTOCOL_ARGUMENT');
});
test('work and scan exhaustion are explicit and do not exceed budgets', () => {
  const r = infer(Buffer.concat(defaultFrames), { max_work: 5, max_scan_bytes: 10 });
  assert(r.budget.usedWork <= 5); assert.equal(r.budget.scannedBytes, 10); assert.equal(r.status, 'budget-exhausted');
  assert(r.budget.reasons.includes('scan-byte-budget')); assert(r.budget.reasons.includes('work-budget'));
});
test('a partially scanned holdout prevents candidate verification', () => {
  const r = infer(Buffer.alloc(0), { samples: defaultFrames.map(encoded), holdout_samples: [encoded(message(40))], max_scan_bytes: 10 });
  assert.equal(r.candidates.length, 0); assert.equal(r.validationSkipped, 'holdout-scan-budget');
});
test('opaque uint64 payload stays exact bytes rather than guessed floating point numbers', () => {
  const frames = [8, 12, 16].map(n => { const b = message(n); b.writeBigUInt64BE(0xfffffffffffffff1n, b.length - 8); return b; });
  const entry = matching(infer(Buffer.alloc(0), { samples: frames.map(encoded) }), c => matchesPrefix(c, 2, 2, 'big'));
  assert(entry); assert(!entry.schema.fields.some(f => f.type === 'u64')); assertDecodes(entry, frames);
});
test('capture auto mode uses one consistent TCP direction and exact retransmissions', () => {
  const stream = Buffer.concat(defaultFrames);
  const r = infer(pcap([tcp(Buffer.alloc(0), 100, 2), tcp(stream, 101), tcp(stream, 101)]));
  assert.equal(r.format, 'capture'); const group = r.groups.find(g => g.protocol === 'tcp'); assert(group.candidates.length);
  assert.equal(group.origin.packetIndices.length, 3); assert(group.origin.captureSpans.every(s => Number.isSafeInteger(s.captureOffset)));
  assert.equal(group.candidates[0].evidence.origin.streamStartEstablished, true); assert.equal(r.observedTransitions.status, 'not-inferred');
});
test('TCP capture holes and conflicting retransmissions skip inference', () => {
  const stream = Buffer.concat(defaultFrames), bad = Buffer.from(stream); bad[5] ^= 0xff;
  for (const [packets, reason] of [
    [[tcp(Buffer.alloc(0), 100, 2), tcp(stream.subarray(0, 10), 101), tcp(stream.subarray(12), 113)], 'tcp-holes'],
    [[tcp(Buffer.alloc(0), 100, 2), tcp(stream, 101), tcp(bad, 101)], 'conflicting-retransmission']]) {
    const r = infer(pcap(packets)); assert.equal(r.candidates.length, 0); assert.equal(r.groups[0].skipped, reason);
  }
});
test('TCP without observed SYN never asserts a protocol boundary', () => {
  const r = infer(pcap([tcp(Buffer.concat(defaultFrames), 100)])); assert.equal(r.candidates.length, 0);
  assert.equal(r.groups[0].skipped, 'capture-start-does-not-establish-boundary');
});
test('UDP direction grouping never combines opposite-direction samples', () => {
  const forward = [3, 7].map(n => udp(message(n))), reverse = [11, 15].map(n => udp(message(n), true));
  const r = infer(pcap([...forward, ...reverse])); assert.equal(r.groups.length, 2); assert.equal(r.candidates.length, 0);
  assert(r.groups.every(g => g.status === 'insufficient-evidence'));
});
test('UDP candidates retain flow direction and packet capture spans', () => {
  const packets = [...defaultFrames.map(b => udp(b)), ...defaultFrames.map(b => udp(b, true))];
  const r = infer(pcap(packets)); assert.equal(r.groups.length, 2); assert(r.groups.every(g => g.candidates.length));
  assert(r.candidates.every(c => c.evidence.origin.flowId === 'flow-0'));
  assert(r.candidates.length <= 8); assert.equal(new Set(r.candidates.map(c => c.id)).size, r.candidates.length);
});
test('capture inference honors smaller user packet budgets and forbids directionless holdout', () => {
  const input = pcap(defaultFrames.map(b => udp(b)));
  const r = analyzeProtocol({ action: 'infer', ...encoded(input), maxPackets: 2 }).inference;
  assert.equal(r.capture.packetCount, 2); assert.equal(r.candidates.length, 0); assert(r.capture.truncated);
  assert.throws(() => infer(input, { holdout_samples: [encoded(message(4))] }), e => e.code === 'INVALID_PROTOCOL_ARGUMENT');
});

test('global candidate cap reports skipped capture coverage at both inference and public levels', () => {
  const packets = [0, 1000].flatMap(delta => defaultFrames.map(b => { const p = udp(b); p.writeUInt16BE(5000 + delta, 20); return p; }));
  const r = analyzeProtocol({ action: 'infer', ...encoded(pcap(packets)), inference: { max_candidates: 1 } });
  assert.equal(r.truncated, true); assert.equal(r.inference.truncated, true);
  assert.equal(r.inference.coverage.eligibleGroups, 2); assert.equal(r.inference.coverage.analyzedGroups, 1);
  assert.equal(r.inference.coverage.skippedGroups, 1); assert(r.truncationReasons.includes('global-candidate-budget'));
  assert.equal(r.inference.groups[1].skipped, 'global-candidate-budget');
});
test('capture packet truncation remains partial even when every parsed group was visited', () => {
  const r = analyzeProtocol({ action: 'infer', ...encoded(pcap(defaultFrames.map(b => udp(b)))), maxPackets: 2 });
  assert.equal(r.truncated, true); assert.equal(r.inference.coverage.inputPartial, true);
  assert(r.inference.coverage.reasons.some(r => r.startsWith('capture:')));
});
test('candidate preview omission is separate from incomplete input or skipped analysis', () => {
  const r = infer(Buffer.alloc(0), { samples: defaultFrames.map(encoded), max_candidates: 1 });
  assert.equal(r.truncated, false); assert.equal(r.coverage.status, 'complete');
  assert.equal(r.coverage.previewTruncated, true); assert(r.coverage.previewReasons.includes('candidate-preview-budget'));
});
function leb(n) { const out=[];do{const b=n&127;n=Math.floor(n/128);out.push(b|(n?128:0));}while(n);return Buffer.from(out); }
function varMessage(n, seed=1) { return Buffer.concat([Buffer.from('IG'),leb(n),Buffer.alloc(n,seed)]); }
function tagged(n, tag, typeSize=1, lengthSize=2, order='little') {
  const h=Buffer.alloc(typeSize+lengthSize);h[typeSize-1]=tag;
  if(lengthSize===1)h[typeSize]=n;else if(lengthSize===2) order==='little'?h.writeUInt16LE(n,typeSize):h.writeUInt16BE(n,typeSize);
  else order==='little'?h.writeUInt32LE(n,typeSize):h.writeUInt32BE(n,typeSize);
  return Buffer.concat([h,Buffer.alloc(n,0x40+tag)]);
}
test('canonical varint lengths with changing encoded widths infer executable framing and independent holdout', () => {
  const train=[3,140,300].map((n,i)=>varMessage(n,i+1)),holdout=varMessage(20,9);
  const r=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(holdout)]});
  const c=matching(r,c=>c.framing.type==='varint-prefix'&&c.framing.offset===2&&!c.framing.lengthIncludesHeader);
  assert(c);assert.equal(c.validation.verified,true);assertDecodes(c,train);assertDecodes(c,[holdout]);
  const d=decodeFrames(Buffer.concat(train),{framing:c.framing,schema:c.schema});
  assert.deepEqual(d.frames.map(f=>f.lengthPrefix.span.length),[1,2,2]);assert.equal(c.evidence.payload.offset,null);
});
test('invalid, duplicate and budget-limited varint holdout never becomes independent verification', () => {
  const train=[3,140,300].map((n,i)=>varMessage(n,i+1));
  const bad=varMessage(20,9);bad[2]=21;
  for(const h of [[encoded(bad)],[encoded(train[0])]]){
    const r=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:h});
    assert(!r.candidates.some(c=>c.framing.type==='varint-prefix'&&c.validation.verified));
  }
  const limited=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(varMessage(20,9))],max_work:5});
  assert(limited.budget.usedWork<=5);assert(!limited.candidates.some(c=>c.validation.verified));
});
test('TLV type and length bytes infer exact spans without tag semantic claims', () => {
  for(const order of ['big','little']){
    const train=[tagged(3,1,1,2,order),tagged(7,2,1,2,order),tagged(11,1,1,2,order)];
    const h=tagged(17,3,1,2,order);
    const r=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(h)]});
    const c=matching(r,c=>c.framing.type==='tlv'&&c.framing.typeSize===1&&c.framing.lengthSize===2&&c.framing.endian===order&&!c.framing.lengthIncludesHeader);
    assert(c);assert.equal(c.validation.verified,true);assertDecodes(c,train);assertDecodes(c,[h]);
    const d=decodeFrames(Buffer.concat(train),{framing:c.framing,schema:c.schema});
    assert.deepEqual(d.frames.map(f=>f.tlv.type),[1,2,1]);assert.equal(d.frames[0].tlv.valueSpan.length,3);
    assert(c.fields.some(f=>f.role==='tag-candidate'&&f.evidence.semanticMeaning==='unknown'));
  }
});
test('invalid TLV holdout is rejected and stream candidates retain observed slices only', () => {
  const train=[tagged(3,1),tagged(7,2),tagged(11,3)],bad=tagged(17,4);bad.writeUInt16LE(18,1);
  const no=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(bad)]});
  assert(!no.candidates.some(c=>c.framing.type==='tlv'&&c.validation.verified));
  const yes=infer(Buffer.concat(train),{boundary:'message-start',holdout_samples:[encoded(tagged(19,7))]});
  const c=matching(yes,c=>c.framing.type==='tlv'&&c.framing.typeSize===1&&c.framing.lengthSize===2&&c.framing.endian==='little');
  assert(c);assert.equal(c.decodeInput.byteLength,Buffer.concat(train).length);assertDecodes(c,train);
});
test('cross-field arithmetic is a tested relation with independent holdout, not field meaning', () => {
  const frame=n=>{const b=Buffer.alloc(n*2+1,0xaa);b[0]=n;b[1]=n+1;return b;};
  const train=[2,3,4].map(frame), h=frame(5);
  const r=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(h)]});
  const relation=r.observations.crossFieldRelations.find(r=>r.relation==='u8-sum-plus-delta-equals-frame-length'&&r.offsets[0]===0&&r.offsets[1]===1);
  assert(relation);assert.equal(relation.delta,0);assert.equal(relation.validation.verified,true);assert.equal(relation.semanticMeaning,'unknown');
  assert.equal(r.status,'candidate');
  const bad=frame(5);bad[1]++;
  const no=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(bad)]});
  assert.equal(no.observations.crossFieldRelations.find(r=>r.offsets[0]===0&&r.offsets[1]===1).validation.status,'failed');
});
test('independent CRC32 vectors support exact tail byte relations and reject mutated holdout', () => {
  // Fixed vectors independently checked with standard-library zlib CRC32.
  const entry=(text,crc)=>{const tail=Buffer.alloc(4);tail.writeUInt32LE(crc);return Buffer.concat([Buffer.from(text),tail]);};
  const train=[entry('12345678',0x9ae0daaf),entry('abcdefgh',0xaeef2a50),entry('87654321',0x00e6bf4f)];
  const holdout=entry('independ',0x273aac0f);
  const r=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(holdout)]});
  const c=r.observations.checksums.find(c=>c.algorithm==='crc32-ieee'&&c.endian==='little');
  assert(c);assert.equal(c.validation.verified,true);assert.equal(c.coverage.excludesTailBytes,4);
  const bad=Buffer.from(holdout);bad[0]^=1;
  const no=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(bad)]});
  assert.equal(no.observations.checksums.find(c=>c.algorithm==='crc32-ieee'&&c.endian==='little').validation.status,'failed');
});
test('sum8/xor8 checks retain exact coverage and duplicate holdout is not independent', () => {
  for(const algorithm of ['sum8','xor8']){
    const frame=n=>{const b=Buffer.from([0x49,0x47,n,n+2,n+5]);const checksum=[...b].reduce((a,v)=>algorithm==='sum8'?(a+v)&255:a^v,0);return Buffer.concat([b,Buffer.from([checksum])]);};
    const train=[1,3,8].map(frame),h=frame(13);
    const yes=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(h)]});
    assert.equal(yes.observations.checksums.find(c=>c.algorithm===algorithm).validation.verified,true);
    const duplicate=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(train[0])]});
    assert.equal(duplicate.observations.checksums.find(c=>c.algorithm===algorithm).validation.status,'not-independent');
  }
});
test('TLV tag transitions observe supplied order without claiming an application state machine', () => {
  const train=[tagged(3,1),tagged(7,2),tagged(11,1)];
  const r=infer(Buffer.alloc(0),{samples:train.map(encoded)});
  const c=matching(r,c=>c.framing.type==='tlv'&&c.framing.typeSize===1&&c.framing.lengthSize===2&&c.framing.endian==='little');
  assert(c);assert.equal(c.observations.sequence.status,'observed-only');assert.equal(c.observations.sequence.semanticStatesInferred,false);
  assert.deepEqual(c.observations.sequence.transitions,[{fromTag:1,toTag:2,count:1},{fromTag:2,toTag:1,count:1}]);
});
test('optional relation observations remain within work budgets and cannot fabricate checksum verification', () => {
  const train=[message(1000,{seed:1}),message(1500,{seed:2}),message(2000,{seed:3})],holdout=message(2200,{seed:5});
  const r=infer(Buffer.alloc(0),{samples:train.map(encoded),holdout_samples:[encoded(holdout)],max_work:4700});
  assert(r.budget.usedWork<=4700);assert(r.budget.exhausted);assert(!r.observations?.checksums?.some(c=>c.validation.verified));
});
process.stdout.write(JSON.stringify({ ok: true, tests: passed, scope: 'Bounded offline framing and byte-field hypotheses with independent holdout and directional capture provenance' }) + '\n');
