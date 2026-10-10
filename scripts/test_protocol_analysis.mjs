import assert from 'node:assert/strict';
import { analyzeProtocol, decodeFrames, inspectBytes, parseCapture, parseProtocolBytes } from '../source/protocol_analysis.js';

let passed = 0;
function test(name, run) { run(); passed++; process.stdout.write(`ok ${passed} ${name}\n`); }
function rejects(fn, code) { assert.throws(fn, e => e.code === code); }
const bytes = (value) => Buffer.from(value, 'hex');
const schema = fields => ({ fields });

function ipv4(payload, protocol = 6, options = {}) {
  const h = Buffer.alloc(20);
  h[0] = 0x45; h.writeUInt16BE(h.length + payload.length, 2); h[8] = 64; h[9] = protocol;
  h.writeUInt16BE(options.fragment ?? 0, 6);
  Buffer.from((options.src ?? '10.0.0.1').split('.').map(Number)).copy(h, 12);
  Buffer.from((options.dst ?? '10.0.0.2').split('.').map(Number)).copy(h, 16);
  return Buffer.concat([h, payload]);
}
function tcp(payload = Buffer.alloc(0), options = {}) {
  const h = Buffer.alloc(20);
  h.writeUInt16BE(options.srcPort ?? 12000, 0); h.writeUInt16BE(options.dstPort ?? 8080, 2);
  h.writeUInt32BE((options.seq ?? 100) >>> 0, 4); h.writeUInt32BE((options.ack ?? 0) >>> 0, 8);
  h[12] = 0x50; h[13] = options.flags ?? 0x18;
  return ipv4(Buffer.concat([h, payload]), 6, options);
}
function udp(payload, options = {}) {
  const h = Buffer.alloc(8);
  h.writeUInt16BE(options.srcPort ?? 5000, 0); h.writeUInt16BE(options.dstPort ?? 5001, 2);
  h.writeUInt16BE(payload.length + 8, 4);
  return ipv4(Buffer.concat([h, payload]), 17, options);
}
function ip6udp(payload, options = {}) {
  const udpHeader = Buffer.alloc(8);
  udpHeader.writeUInt16BE(5000, 0); udpHeader.writeUInt16BE(5001, 2); udpHeader.writeUInt16BE(payload.length + 8, 4);
  const extension = options.extension ? Buffer.from([options.fragment ? 44 : 17, 0, 0, 0, 0, 0, 0, 0]) : Buffer.alloc(0);
  const h = Buffer.alloc(40); h[0] = 0x60; h[6] = options.extension ? 0 : 17; h[7] = 64;
  h.writeUInt16BE(extension.length + udpHeader.length + payload.length, 4);
  h.writeUInt16BE(0x2001, 8); h.writeUInt16BE(1, 22); h.writeUInt16BE(0x2001, 24); h.writeUInt16BE(2, 38);
  return Buffer.concat([h, extension, udpHeader, payload]);
}
function ethernet(packet, vlan = false) {
  const h = Buffer.alloc(vlan ? 18 : 14);
  h.writeUInt16BE(vlan ? 0x8100 : packet[0] >>> 4 === 6 ? 0x86dd : 0x0800, 12);
  if (vlan) { h.writeUInt16BE(7, 14); h.writeUInt16BE(packet[0] >>> 4 === 6 ? 0x86dd : 0x0800, 16); }
  return Buffer.concat([h, packet]);
}
function pcap(packets, options = {}) {
  const little = options.little !== false, nano = options.nano === true;
  const u16 = (b, n, at) => little ? b.writeUInt16LE(n, at) : b.writeUInt16BE(n, at);
  const u32 = (b, n, at) => little ? b.writeUInt32LE(n, at) : b.writeUInt32BE(n, at);
  const h = Buffer.alloc(24); bytes(little ? nano ? '4d3cb2a1' : 'd4c3b2a1' : nano ? 'a1b23c4d' : 'a1b2c3d4').copy(h);
  u16(h, 2, 4); u16(h, 4, 6); u32(h, options.snaplen ?? 65535, 16); u32(h, options.linkType ?? 101, 20);
  const records = packets.map((entry, index) => {
    const data = Buffer.isBuffer(entry) ? entry : entry.data;
    const originalLength = Buffer.isBuffer(entry) ? data.length : entry.originalLength ?? data.length;
    const rh = Buffer.alloc(16); u32(rh, index + 1, 0); u32(rh, 123, 4); u32(rh, data.length, 8); u32(rh, originalLength, 12);
    return Buffer.concat([rh, data]);
  });
  return Buffer.concat([h, ...records]);
}
function ngBlock(type, body, little = true) {
  const h = Buffer.alloc(8), end = Buffer.alloc(4), length = body.length + 12;
  little ? h.writeUInt32LE(type) : h.writeUInt32BE(type);
  little ? h.writeUInt32LE(length, 4) : h.writeUInt32BE(length, 4);
  little ? end.writeUInt32LE(length) : end.writeUInt32BE(length);
  return Buffer.concat([h, body, end]);
}
function pcapng(packets, options = {}) {
  const little = options.little !== false;
  const u16 = (b, n, at) => little ? b.writeUInt16LE(n, at) : b.writeUInt16BE(n, at);
  const u32 = (b, n, at) => little ? b.writeUInt32LE(n, at) : b.writeUInt32BE(n, at);
  const sh = Buffer.alloc(16); bytes(little ? '4d3c2b1a' : '1a2b3c4d').copy(sh); u16(sh, 1, 4); sh.fill(0xff, 8);
  const id = Buffer.alloc(options.tsresol === undefined ? 8 : 20); u16(id, options.linkType ?? 101, 0); u32(id, 65535, 4);
  if (options.tsresol !== undefined) { u16(id, 9, 8); u16(id, 1, 10); id[12] = options.tsresol; }
  const blocks = packets.map((data, index) => {
    const padded = Buffer.alloc(Math.ceil(data.length / 4) * 4); data.copy(padded);
    if (options.simple) { const h = Buffer.alloc(4); u32(h, data.length, 0); return ngBlock(3, Buffer.concat([h, padded]), little); }
    const h = Buffer.alloc(20); u32(h, 0, 0); u32(h, 0x12345678, 4); u32(h, index + 5, 8); u32(h, data.length, 12); u32(h, data.length, 16);
    return ngBlock(6, Buffer.concat([h, padded]), little);
  });
  return Buffer.concat([ngBlock(0x0a0d0d0a, sh, little), ngBlock(1, id, little), ...blocks]);
}
function tcpDirection(result, direction = 0) { return result.flows[0].directions[direction]; }

test('strict hex/base64 evidence and no implicit path input', () => {
  assert.equal(parseProtocolBytes('00ff', 'hex').toString('hex'), '00ff');
  assert.equal(parseProtocolBytes('AP8=', 'base64').toString('hex'), '00ff');
  for (const data of ['0', 'gg', 'C:\\capture.pcap', '00 ff']) rejects(() => parseProtocolBytes(data), 'INVALID_PROTOCOL_ENCODING');
  for (const data of ['AP9=', 'YQ', ' YQ==', 'YQ===']) rejects(() => parseProtocolBytes(data, 'base64'), 'INVALID_PROTOCOL_ENCODING');
  rejects(() => parseProtocolBytes('00'.repeat(11), 'hex', { maxInputBytes: 10 }), 'PROTOCOL_INPUT_LIMIT');
  rejects(() => parseProtocolBytes('AQID', 'base64', { maxInputBytes: 2 }), 'PROTOCOL_INPUT_LIMIT');
  rejects(() => analyzeProtocol({ data: '00', action: 'network' }), 'INVALID_PROTOCOL_ARGUMENT');
});
test('inspection reports observations without identifying encryption/protocol', () => {
  const r = inspectBytes(bytes('000641424344'));
  assert.equal(r.schemaVersion, 'ig5.protocol.v1');
  assert.equal(r.observations[0].relation, 'total-byte-length');
  assert.equal(r.strings[0].value, 'ABCD');
  assert.match(r.interpretation, /do not identify/); assert.equal(r.input.sha256.length, 64);
  assert.equal(inspectBytes(Buffer.alloc(10)).entropyBitsPerByte, 0);
});
test('decode exact little/big numeric fields including 64-bit precision', () => {
  const r = decodeFrames(bytes('fe341278563412ffffffffffffffff'), { schema: schema([
    { name: 'signed', offset: 0, type: 'i8' }, { name: 'word', offset: 1, type: 'u16', endian: 'little' },
    { name: 'dword', offset: 3, type: 'u32', endian: 'little' }, { name: 'wide', offset: 7, type: 'u64' },
    { name: 'negative', offset: 7, type: 'i64' }]) });
  assert.equal(r.frames[0].fields[0].value, -2); assert.equal(r.frames[0].fields[1].value, 0x1234);
  assert.equal(r.frames[0].fields[2].value, 0x12345678); assert.equal(r.frames[0].fields[3].value, '18446744073709551615');
  assert.equal(r.frames[0].fields[4].value, '-1'); assert.equal(r.complete, true);
});
test('schema spans, UTF8 validation, bounded string value and field truncation', () => {
  const r = decodeFrames(Buffer.from('中文'), { schema: schema([{ name: 'text', offset: 0, length: 6, type: 'utf8' }]) });
  assert.equal(r.frames[0].fields[0].value, '中文'); assert.deepEqual(r.frames[0].fields[0].span, { offset: 0, inputOffset: 0, length: 6 });
  assert.equal(decodeFrames(bytes('ff'), { schema: schema([{ name: 's', offset: 0, length: 1, type: 'utf8' }]) }).frames[0].fields[0].error, 'invalid-utf8');
  const short = decodeFrames(bytes('01'), { schema: schema([{ name: 'v', offset: 0, type: 'u32' }]) });
  assert.equal(short.complete, false); assert.equal(short.frames[0].fields[0].availableBytes, 1);
  const long = decodeFrames(Buffer.alloc(300, 65), { schema: schema([{ name: 's', offset: 0, length: 300, type: 'utf8' }]) });
  assert.equal(long.frames[0].fields[0].value.length, 256); assert.equal(long.frames[0].fields[0].valueTruncated, true);
  assert.equal(long.frames[0].fields[0].dataHex, undefined);
});
test('unsigned LEB128 terminator/overflow/length boundaries', () => {
  const s = schema([{ name: 'v', offset: 0, type: 'varint' }]);
  const normal = decodeFrames(bytes('ac02'), { schema: s }).frames[0].fields[0];
  assert.equal(normal.value, '300'); assert.equal(normal.span.length, 2);
  assert.equal(decodeFrames(bytes('80'), { schema: s }).frames[0].fields[0].error, 'field-truncated');
  assert.equal(decodeFrames(bytes('ffffffffffffffffff02'), { schema: s }).frames[0].fields[0].error, 'varint-overflow');
  const limited = decodeFrames(bytes('8000'), { schema: schema([{ name: 'v', offset: 0, type: 'varint', length: 1 }]) });
  assert.equal(limited.frames[0].fields[0].error, 'unterminated-varint');
});
test('reject duplicate/reserved field names and invalid schema', () => {
  for (const name of ['__proto__', 'constructor', 'prototype']) rejects(() => decodeFrames(bytes('01'), { schema: schema([{ name, offset: 0, type: 'u8' }]) }), 'INVALID_PROTOCOL_SCHEMA');
  rejects(() => decodeFrames(bytes('01'), { schema: schema([{ name: 'v', offset: 0, type: 'u8' }, { name: 'v', offset: 0, type: 'u8' }]) }), 'INVALID_PROTOCOL_SCHEMA');
  rejects(() => decodeFrames(bytes('01'), { schema: schema([{ name: 'v', offset: -1, type: 'u8' }]) }), 'INVALID_PROTOCOL_ARGUMENT');
  rejects(() => decodeFrames(bytes('01'), { schema: schema([{ name: 'v', offset: 0, type: 'pointer' }]) }), 'INVALID_PROTOCOL_SCHEMA');
  rejects(() => decodeFrames(bytes('01'), { framing: { type: 'length-prefix', size: 3 } }), 'INVALID_PROTOCOL_SCHEMA');
});
test('fixed framing preserves incomplete remainder and exact frame spans', () => {
  const r = decodeFrames(bytes('0102030405'), { framing: { type: 'fixed', length: 2 }, schema: schema([{ name: 'v', offset: 0, type: 'u16' }]) });
  assert.deepEqual(r.frames.map(f => f.dataHex), ['0102', '0304']); assert.equal(r.frames[1].fields[0].span.inputOffset, 2);
  assert.equal(r.remainder.dataHex, '05'); assert.equal(r.complete, false); assert.ok(r.truncationReasons.includes('incomplete-frame'));
});
test('length-prefix framing handles payload and total lengths, endian, adjustment', () => {
  const r = decodeFrames(bytes('0300414243010044'), { framing: { type: 'length-prefix', endian: 'little' } });
  assert.deepEqual(r.frames.map(f => f.dataHex), ['0300414243', '010044']);
  assert.equal(r.frames[1].lengthPrefix.span.inputOffset, 5);
  assert.equal(decodeFrames(bytes('0005414243'), { framing: { type: 'length-prefix', lengthIncludesHeader: true } }).frames[0].length, 5);
  assert.equal(decodeFrames(bytes('0002414243'), { framing: { type: 'length-prefix', adjustment: 1 } }).frames[0].length, 5);
});
test('invalid/oversized/incomplete prefixes stop rather than resynchronizing invented frames', () => {
  assert.equal(decodeFrames(bytes('000001'), { framing: { type: 'length-prefix', lengthIncludesHeader: true } }).issues[0].code, 'invalid-frame-length');
  assert.equal(decodeFrames(bytes('ffff01'), { framing: { type: 'length-prefix' }, maxFrameBytes: 100 }).issues[0].code, 'frame-size-budget');
  assert.equal(decodeFrames(bytes('00'), { framing: { type: 'length-prefix' } }).issues[0].code, 'incomplete-frame-header');
});
test('frame, decoded-field, field-byte and input budgets are explicit', () => {
  const r = decodeFrames(bytes('01020304'), { framing: { type: 'fixed', length: 1 }, maxFrames: 2 });
  assert.equal(r.frames.length, 2); assert.equal(r.remainder.dataHex, '0304'); assert.ok(r.truncated);
  const fields = schema([{ name: 'a', offset: 0, type: 'u8' }, { name: 'b', offset: 0, type: 'u8' }]);
  const f = decodeFrames(bytes('0102'), { framing: { type: 'fixed', length: 1 }, schema: fields, maxDecodedFields: 1 });
  assert.equal(f.fieldsDecoded, 1); assert.ok(f.truncationReasons.includes('decoded-field-budget'));
  const b = decodeFrames(bytes('0102'), { schema: schema([{ name: 'a', offset: 0, type: 'bytes', length: 2 }]), maxFieldBytes: 1 });
  assert.equal(b.frames[0].omittedFields, 1); assert.ok(b.truncationReasons.includes('field-byte-budget'));
  rejects(() => decodeFrames(Buffer.alloc(2), { maxInputBytes: 1 }), 'PROTOCOL_INPUT_LIMIT');
  rejects(() => decodeFrames(bytes('01'), { maxFrames: 1001 }), 'INVALID_PROTOCOL_ARGUMENT');
});
test('PCAP big/little micro/nano raw-IP captures parse correctly', () => {
  for (const little of [true, false]) for (const nano of [true, false]) {
    const r = parseCapture(pcap([udp(bytes('4142'))], { little, nano }));
    assert.equal(r.packetCount, 1); assert.equal(r.packets[0].network.src, '10.0.0.1');
    assert.equal(r.packets[0].timestamp.unitsPerSecond, nano ? 1e9 : 1e6);
    assert.equal(r.flows[0].directions[0].datagrams[0].dataHex, '4142'); assert.equal(r.evidence.checksumVerified, false);
  }
});
test('Ethernet VLAN and mixed IPv4/IPv6 UDP datagrams retain payload evidence', () => {
  const r = parseCapture(pcap([ethernet(udp(bytes('4142')), true), ethernet(ip6udp(bytes('4344')))], { linkType: 1 }));
  assert.deepEqual(r.packets[0].vlanTags, [7]); assert.equal(r.flows.length, 2); assert.equal(r.packets[1].network.version, 6);
  assert.equal(r.flows[1].directions[0].datagrams[0].dataHex, '4344');
});
test('IPv6 finite extension headers parse; fragments/ESP/jumbograms explicitly unsupported', () => {
  const r = parseCapture(pcap([ip6udp(bytes('4142'), { extension: true })]));
  assert.equal(r.packets[0].extensions[0].length, 8); assert.equal(r.flows[0].directions[0].datagrams[0].dataHex, '4142');
  const fragmented = parseCapture(pcap([ip6udp(bytes('4142'), { extension: true, fragment: true })]));
  assert.equal(fragmented.packets[0].unsupported.reason, 'ipv6-fragment-reassembly-not-supported');
  const esp = ip6udp(bytes('4142')); esp[6] = 50;
  assert.equal(parseCapture(pcap([esp])).packets[0].unsupported.reason, 'ipv6-esp-not-supported');
  const jumbo = ip6udp(bytes('4142')); jumbo.writeUInt16BE(0, 4);
  assert.equal(parseCapture(pcap([jumbo])).packets[0].unsupported.reason, 'ipv6-jumbogram-not-supported');
});
test('IPv4 fragments and unsupported link/IP protocols are not treated as TCP/UDP', () => {
  const r = parseCapture(pcap([tcp(bytes('01'), { fragment: 0x2000 })]));
  assert.equal(r.flows.length, 0); assert.equal(r.packets[0].unsupported.reason, 'ipv4-fragment-reassembly-not-supported');
  assert.equal(parseCapture(pcap([tcp(bytes('01'))], { linkType: 147 })).packets[0].unsupported.reason, 'unsupported-link-type');
  const icmp = ipv4(bytes('0102'), 1);
  assert.equal(parseCapture(pcap([icmp])).packets[0].unsupported.reason, 'unsupported-ip-protocol');
});
test('TCP out-of-order and exact retransmissions reconstruct observed bytes once', () => {
  const r = parseCapture(pcap([tcp(Buffer.from('DEF'), { seq: 103 }), tcp(Buffer.from('ABC'), { seq: 100 }), tcp(Buffer.from('BCD'), { seq: 101 })]));
  const d = tcpDirection(r);
  assert.equal(d.chunks.length, 1); assert.equal(d.chunks[0].dataHex, Buffer.from('ABCDEF').toString('hex'));
  assert.equal(d.chunks[0].relativeOffset, -3); assert.equal(d.uniqueBytesRetained, 6); assert.equal(d.retransmittedBytes, 3); assert.equal(d.ambiguous, false);
});
test('TCP two directions use canonical bidirectional tuple', () => {
  const r = parseCapture(pcap([tcp(Buffer.from('request')), tcp(Buffer.from('reply'), { src: '10.0.0.2', dst: '10.0.0.1', srcPort: 8080, dstPort: 12000, seq: 1000 })]));
  assert.equal(r.flows.length, 1); assert.equal(tcpDirection(r, 0).chunks[0].dataHex, Buffer.from('request').toString('hex'));
  assert.equal(tcpDirection(r, 1).chunks[0].dataHex, Buffer.from('reply').toString('hex'));
});
test('TCP sequence wrap does not allocate a 4GiB gap', () => {
  const r = parseCapture(pcap([tcp(Buffer.from('ABC'), { seq: 0xfffffffd }), tcp(Buffer.from('DEF'), { seq: 0 })]));
  assert.equal(tcpDirection(r).chunks[0].dataHex, Buffer.from('ABCDEF').toString('hex')); assert.equal(tcpDirection(r).holes.length, 0);
});
test('TCP holes remain distinct chunks and are never decoded across missing bytes', () => {
  const r = parseCapture(pcap([tcp(Buffer.alloc(0), { seq: 99, flags: 2 }), tcp(bytes('000141'), { seq: 100 }), tcp(bytes('000142'), { seq: 110 })]), { framing: { type: 'length-prefix' } });
  const d = tcpDirection(r); assert.equal(d.chunks.length, 2); assert.equal(d.holes[0].length, 7);
  assert.equal(d.decodes[0].result.frames[0].dataHex, '000141'); assert.equal(d.decodes[1].skipped, 'frame-boundary-unknown-after-hole');
  assert.equal(r.complete, false);
});
test('TCP conflicting retransmissions retain first evidence, report alternatives, disable decode', () => {
  const r = parseCapture(pcap([tcp(Buffer.from('ABC'), { seq: 100 }), tcp(Buffer.from('AXC'), { seq: 100 })]), { framing: { type: 'fixed', length: 3 } });
  const d = tcpDirection(r); assert.equal(d.chunks[0].dataHex, Buffer.from('ABC').toString('hex')); assert.equal(d.ambiguous, true);
  assert.equal(d.conflictingByteObservations, 1); assert.equal(d.conflicts[0].earlierPreviewHex, '42'); assert.equal(d.conflicts[0].laterPreviewHex, '58');
  assert.equal(d.decodeSkipped, 'conflicting-retransmission'); assert.equal(r.complete, false);
});
test('SYN/FIN make observable prefix/tail gaps explicit', () => {
  const r = parseCapture(pcap([tcp(Buffer.alloc(0), { seq: 99, flags: 2 }), tcp(Buffer.from('CDE'), { seq: 102 }), tcp(Buffer.alloc(0), { seq: 110, flags: 0x11 })]));
  const d = tcpDirection(r); assert.equal(d.holes[0].position, 'prefix'); assert.equal(d.holes[0].length, 2);
  assert.equal(d.holes[1].position, 'tail'); assert.equal(d.holes[1].length, 5); assert.equal(d.chunks[0].dataHex, Buffer.from('CDE').toString('hex'));
});
test('mid-capture framing is not assumed aligned', () => {
  const r = parseCapture(pcap([tcp(bytes('000141'))]), { framing: { type: 'length-prefix' } });
  assert.equal(tcpDirection(r).decodes[0].skipped, 'capture-start-does-not-establish-frame-boundary');
});
test('distinct SYN creates a new connection incarnation rather than conflating streams', () => {
  const r = parseCapture(pcap([tcp(Buffer.alloc(0), { seq: 99, flags: 2 }), tcp(Buffer.from('old'), { seq: 100 }),
    tcp(Buffer.alloc(0), { seq: 999, flags: 2 }), tcp(Buffer.from('new'), { seq: 1000 })]));
  assert.equal(r.flows.length, 2); assert.equal(r.flows[1].incarnation, 1);
  assert.equal(r.flows[0].directions[0].chunks[0].dataHex, Buffer.from('old').toString('hex'));
  assert.equal(r.flows[1].directions[0].chunks[0].dataHex, Buffer.from('new').toString('hex'));
});
test('huge TCP sequence distance is rejected with evidence and no sparse allocation', () => {
  const r = parseCapture(pcap([tcp(Buffer.from('A'), { seq: 100 }), tcp(Buffer.from('B'), { seq: 0x40000000 })]));
  assert.equal(tcpDirection(r).chunks.length, 1); assert.equal(tcpDirection(r).unsupported.reason, 'sequence-distance-exceeds-32MiB-window');
  assert.ok(r.truncationReasons.includes('tcp-sequence-window'));
});
test('PCAP truncation, snaplen truncation and invalid record length are surfaced', () => {
  const complete = pcap([tcp(Buffer.from('ABC'))]);
  assert.ok(parseCapture(complete.subarray(0, complete.length - 1)).truncationReasons.includes('truncated-container'));
  const original = tcp(Buffer.from('ABCDEFG'));
  const sliced = parseCapture(pcap([{ data: original.subarray(0, 43), originalLength: original.length }]));
  assert.equal(sliced.truncatedPacketCount, 1); assert.equal(tcpDirection(sliced).chunks[0].dataHex, Buffer.from('ABC').toString('hex'));
  assert.ok(sliced.truncationReasons.includes('capture-packet-truncated'));
  const invalid = pcap([tcp(Buffer.from('ABC'))]); invalid.writeUInt32LE(1, 36);
  assert.equal(parseCapture(invalid).issues[0].code, 'invalid-pcap-record-length');
});
test('packet/flow/reassembly/preview budgets never silently drop data', () => {
  const cap = pcap([tcp(Buffer.from('ABC')), tcp(Buffer.from('DEF'), { seq: 103 })]);
  assert.ok(parseCapture(cap, { maxPackets: 1 }).truncationReasons.includes('packet-budget'));
  const r = parseCapture(cap, { maxReassemblyBytes: 3 }); assert.equal(tcpDirection(r).uniqueBytesRetained, 3); assert.ok(r.truncationReasons.includes('reassembly-byte-budget'));
  assert.ok(parseCapture(cap, { maxPacketPreviews: 0 }).truncationReasons.includes('packet-preview-budget'));
  const many = pcap([udp(bytes('01')), udp(bytes('02'), { srcPort: 6000 })]);
  assert.ok(parseCapture(many, { maxFlows: 1 }).truncationReasons.includes('flow-budget'));
  rejects(() => parseCapture(cap, { maxPackets: 4001 }), 'INVALID_PROTOCOL_ARGUMENT');
  rejects(() => parseCapture(cap, { maxReassemblyBytes: 2 * 1024 * 1024 + 1 }), 'INVALID_PROTOCOL_ARGUMENT');
});
test('PCAPNG enhanced packets handle both endian modes and exact uint64 timestamps', () => {
  for (const little of [true, false]) {
    const r = parseCapture(pcapng([udp(bytes('4142'))], { little, tsresol: 9 }));
    assert.equal(r.flows[0].directions[0].datagrams[0].dataHex, '4142');
    assert.equal(r.packets[0].timestamp.ticks, ((0x12345678n << 32n) | 5n).toString());
    assert.equal(r.packets[0].timestamp.exponent, 9); assert.equal(r.container.sections[0].endian, little ? 'little' : 'big');
  }
});
test('PCAPNG simple packet block and mixed-endian sections reset interfaces', () => {
  const simple = parseCapture(pcapng([udp(bytes('01'))], { simple: true }));
  assert.equal(simple.packets[0].timestampUnavailable, true); assert.equal(simple.flows[0].directions[0].datagrams[0].dataHex, '01');
  const mixed = parseCapture(Buffer.concat([pcapng([udp(bytes('01'))]), pcapng([udp(bytes('02'))], { little: false, tsresol: 0x85 })]));
  assert.equal(mixed.container.sections.length, 2); assert.equal(mixed.packets[1].sectionIndex, 1);
  assert.equal(mixed.packets[1].timestamp.base, 2); assert.equal(mixed.packets[1].timestamp.exponent, 5);
});
test('PCAPNG block corruption/truncation and unknown interface fail clearly', () => {
  const original = pcapng([udp(bytes('01'))]);
  const mismatch = Buffer.from(original); mismatch.writeUInt32LE(123, mismatch.length - 4);
  assert.equal(parseCapture(mismatch).issues[0].code, 'pcapng-block-length-mismatch');
  assert.ok(parseCapture(original.subarray(0, original.length - 1)).truncationReasons.includes('truncated-container'));
  const unknown = Buffer.from(original); unknown.writeUInt32LE(7, 28 + 20 + 8);
  assert.equal(parseCapture(unknown).issues[0].code, 'unknown-pcapng-interface');
});
test('UDP schema decode stays per datagram and capture frame budget is shared', () => {
  const r = parseCapture(pcap([udp(bytes('000141')), udp(bytes('000142'))]), { framing: { type: 'length-prefix' }, maxFrames: 1 });
  const d = r.flows[0].directions[0]; assert.equal(d.decodes.length, 1); assert.equal(d.decodes[0].result.frames[0].dataHex, '000141');
  assert.ok(r.truncationReasons.includes('capture-decode-budget'));
});
test('maximum accepted input and repeated fragmented segments stay bounded', () => {
  const packets = Array.from({ length: 4000 }, (_, i) => tcp(Buffer.from([i & 255]), { seq: 100 + i }));
  const r = parseCapture(pcap(packets), { maxPackets: 4000, maxPacketPreviews: 0 });
  const d = tcpDirection(r); assert.equal(d.chunks.length, 1); assert.equal(d.uniqueBytesRetained, 4000);
  assert.equal(d.chunks[0].dataHex.length, 8000); assert.ok(d.chunks[0].packetIndicesOmitted > 0);
  assert.equal(d.packetIndices.length, 4000);
});
test('capture integrity and decode completeness remain distinct', () => {
  const r = parseCapture(pcap([udp(bytes('000341'))]), { framing: { type: 'length-prefix' } });
  assert.equal(r.parseComplete, true); assert.equal(r.reassemblyComplete, true); assert.equal(r.decodingComplete, false); assert.equal(r.complete, false);
  const mid = parseCapture(pcap([tcp(bytes('000141'))]), { framing: { type: 'length-prefix' } });
  assert.equal(mid.decodingComplete, false); assert.equal(mid.complete, false);
});
test('unsupported packets beyond the preview budget retain reason counts', () => {
  const r = parseCapture(pcap([udp(bytes('01')), ipv4(bytes('00'), 1)]), { maxPacketPreviews: 1 });
  assert.equal(r.packets.length, 1); assert.equal(r.unsupportedSummary[0].reason, 'unsupported-ip-protocol');
  assert.equal(r.unsupportedSummary[0].packetCount, 1); assert.deepEqual(r.unsupportedSummary[0].packetIndices, [1]);
});
test('late huge SYNACK and FIN distances do not imply giant missing ranges', () => {
  const r = parseCapture(pcap([tcp(Buffer.from('A'), { seq: 100 }), tcp(Buffer.alloc(0), { seq: 0x40000000, flags: 0x12 }),
    tcp(Buffer.alloc(0), { seq: 0x50000000, flags: 0x11 })]));
  assert.equal(tcpDirection(r).holes.length, 0); assert.equal(tcpDirection(r).streamStartEstablished, false);
  assert.ok(r.truncationReasons.includes('tcp-sequence-window')); assert.equal(tcpDirection(r).sequenceRejectedPackets.length, 2);
});
test('PCAPNG simple packet length and section minor version are validated', () => {
  const spb = pcapng([udp(bytes('01'))], { simple: true });
  const extra = Buffer.concat([spb.subarray(0, spb.length - 4), Buffer.alloc(4), spb.subarray(spb.length - 4)]);
  extra.writeUInt32LE(extra.length - 48, 52); extra.writeUInt32LE(extra.length - 48, extra.length - 4);
  assert.equal(parseCapture(extra).issues[0].code, 'invalid-pcapng-captured-length');
  const minor = pcapng([udp(bytes('01'))]); minor.writeUInt16LE(1, 14);
  assert.equal(parseCapture(minor).issues[0].code, 'unsupported-pcapng-section-version');
});
test('automatic capture decode shares field-byte and decoded-field budgets across datagrams', () => {
  const s = schema([{ name: 'v', offset: 0, type: 'u8' }]);
  const cap = pcap([udp(bytes('01')), udp(bytes('02'))]);
  const r = parseCapture(cap, { schema: s, maxDecodedFields: 1 });
  assert.equal(r.flows[0].directions[0].decodes.length, 1); assert.ok(r.truncationReasons.includes('capture-decode-budget'));
  const b = parseCapture(cap, { schema: s, maxFieldBytes: 1 });
  assert.equal(b.flows[0].directions[0].decodes.length, 1); assert.ok(b.truncationReasons.includes('capture-decode-budget'));
});

test('unknown long field types never echo input values or bypass the error budget', () => {
  const supplied = 'sensitive-type-value:' + 'A'.repeat(30000);
  assert.throws(() => analyzeProtocol({ action: 'decode', data: '00', schema: schema([{ name: 'x', offset: 0, type: supplied }]) }), error => {
    assert.equal(error.code, 'INVALID_PROTOCOL_SCHEMA');
    assert.ok(error.message.length < 128);
    assert.equal(error.message.includes('sensitive-type-value:'), false);
    assert.match(error.message, /schema\.fields\[0\]/);
    return true;
  });
});

test('maximum 8 MiB canonical base64 is inspected without regex stack overflow', () => {
  const maximum = 8 * 1024 * 1024;
  const data = Buffer.alloc(maximum, 0xff).toString('base64');
  const result = analyzeProtocol({ action: 'inspect', encoding: 'base64', data, maxPreviewBytes: 1 });
  assert.equal(result.input.byteLength, maximum);
  assert.equal(result.input.previewHex, 'ff');
  assert.equal(result.entropyBitsPerByte, 0);
  rejects(() => parseProtocolBytes(Buffer.alloc(maximum + 1).toString('base64'), 'base64'), 'PROTOCOL_INPUT_LIMIT');
  rejects(() => parseProtocolBytes('Zh==', 'base64'), 'INVALID_PROTOCOL_ENCODING');
});

test('canonical varint prefix decoding rejects overlong, overflow, unfinished and invalid dynamic lengths', () => {
  const framing={type:'varint-prefix'};
  const ok=decodeFrames(bytes('0141024243'),{framing,schema:{fields:[{name:'length',offset:0,type:'varint',length:5}]}});
  assert.equal(ok.complete,true);assert.deepEqual(ok.frames.map(f=>f.length),[2,3]);
  for(const [input,code] of [['8000','noncanonical-varint-prefix'],['ffffffff1f','varint-prefix-overflow'],['80','incomplete-varint-prefix'],['8181818181','varint-prefix-overflow']]){
    const r=decodeFrames(bytes(input),{framing});assert.equal(r.complete,false);assert.equal(r.frames.length,0);assert.equal(r.issues[0].code,code);
  }
  const malformed=decodeFrames(bytes('00'),{framing:{type:'varint-prefix',lengthIncludesHeader:true}});assert.equal(malformed.issues[0].code,'invalid-frame-length');
  rejects(()=>decodeFrames(bytes('01'),{framing:{type:'varint-prefix',maxBytes:6}}),'INVALID_PROTOCOL_ARGUMENT');
});
test('TLV decoding enforces lengths, bounds and exact tag/value spans', () => {
  const r=decodeFrames(bytes('010200414202010043'),{framing:{type:'tlv',typeSize:1,lengthSize:2,endian:'little'}});
  assert.equal(r.complete,true);assert.deepEqual(r.frames.map(f=>f.tlv.type),[1,2]);assert.deepEqual(r.frames.map(f=>f.tlv.valueSpan.length),[2,1]);
  assert.equal(decodeFrames(bytes('0103004142'),{framing:{type:'tlv',lengthSize:2,endian:'little'}}).issues[0].code,'incomplete-frame');
  rejects(()=>decodeFrames(bytes('00'),{framing:{type:'tlv',lengthSize:3}}),'INVALID_PROTOCOL_SCHEMA');
});
process.stdout.write(JSON.stringify({ ok: true, tests: passed, scope: 'Offline byte/capture evidence and explicit-schema decoding; no network or process execution' }) + '\n');
