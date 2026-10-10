import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { inferProtocol } from './protocol_inference.js';

const VERSION = 'ig5.protocol.v1';
const MAX_INPUT = 8 * 1024 * 1024;
const MAX_REASSEMBLY = 2 * 1024 * 1024;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const LIMITS = Object.freeze({ maxInputBytes: MAX_INPUT, maxPackets: 1000, maxFlows: 64,
  maxReassemblyBytes: MAX_REASSEMBLY, maxFrames: 128, maxFrameBytes: 1024 * 1024,
  maxPreviewBytes: 96, maxPacketPreviews: 128, maxIssues: 64,
  maxDecodedFields: 2048, maxFieldBytes: 256 * 1024 });

function fail(code, message) { const e = new Error(message); e.code = code; throw e; }
function int(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    fail('INVALID_PROTOCOL_ARGUMENT', `${name} must be an integer between ${minimum} and ${maximum}`);
  return value;
}
function object(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('INVALID_PROTOCOL_ARGUMENT', `${name} must be an object`);
  return value;
}
function limits(options = {}) {
  return {
    maxInputBytes: int(options.maxInputBytes ?? LIMITS.maxInputBytes, 'maxInputBytes', 1, MAX_INPUT),
    maxPackets: int(options.maxPackets ?? LIMITS.maxPackets, 'maxPackets', 1, 4000),
    maxFlows: int(options.maxFlows ?? LIMITS.maxFlows, 'maxFlows', 1, 128),
    maxReassemblyBytes: int(options.maxReassemblyBytes ?? LIMITS.maxReassemblyBytes, 'maxReassemblyBytes', 1, MAX_REASSEMBLY),
    maxFrames: int(options.maxFrames ?? LIMITS.maxFrames, 'maxFrames', 1, 1000),
    maxFrameBytes: int(options.maxFrameBytes ?? LIMITS.maxFrameBytes, 'maxFrameBytes', 1, 1024 * 1024),
    maxPreviewBytes: int(options.maxPreviewBytes ?? LIMITS.maxPreviewBytes, 'maxPreviewBytes', 0, 1024),
    maxPacketPreviews: int(options.maxPacketPreviews ?? LIMITS.maxPacketPreviews, 'maxPacketPreviews', 0, 512),
    maxIssues: int(options.maxIssues ?? LIMITS.maxIssues, 'maxIssues', 1, 128),
    maxDecodedFields: int(options.maxDecodedFields ?? LIMITS.maxDecodedFields, 'maxDecodedFields', 1, 8192),
    maxFieldBytes: int(options.maxFieldBytes ?? LIMITS.maxFieldBytes, 'maxFieldBytes', 1, MAX_REASSEMBLY),
  };
}
function inputBuffer(buffer, budget) {
  if (!Buffer.isBuffer(buffer) && !(buffer instanceof Uint8Array)) fail('INVALID_PROTOCOL_ARGUMENT', 'Explicit byte input is required');
  if (buffer.byteLength > budget.maxInputBytes) fail('PROTOCOL_INPUT_LIMIT', 'Input exceeds the explicit byte budget');
  return Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer.buffer, buffer.byteOffset, buffer.byteLength);
}
function sha(buffer) { return createHash('sha256').update(buffer).digest('hex'); }
function byteEvidence(buffer, budget, full = true) {
  return { byteLength: buffer.length, sha256: sha(buffer), previewHex: buffer.subarray(0, budget.maxPreviewBytes).toString('hex'),
    previewTruncated: buffer.length > budget.maxPreviewBytes, ...(full ? { dataHex: buffer.toString('hex') } : {}) };
}
function base(action, buffer, budget) {
  return { schemaVersion: VERSION, action, input: byteEvidence(buffer, budget, false),
    evidence: { source: 'supplied-bytes', checksumVerified: false }, limits: budget,
    truncated: false, truncationReasons: [] };
}
function truncate(result, reason) {
  result.truncated = true;
  if (!result.truncationReasons.includes(reason)) result.truncationReasons.push(reason);
}
function issue(result, entry, budget) {
  result.issues ??= [];
  if (result.issues.length < budget.maxIssues) result.issues.push(entry);
  else { result.omittedIssues = (result.omittedIssues ?? 0) + 1; truncate(result, 'issue-budget'); }
}

// No path, URL or implicit text conversion is accepted here. Check lengths before decoding.
export function parseProtocolBytes(data, encoding = 'hex', options = {}) {
  const budget = limits(options);
  if (typeof data !== 'string') fail('INVALID_PROTOCOL_ARGUMENT', 'data must be an explicitly encoded string');
  if (encoding === 'hex') {
    if (data.length > budget.maxInputBytes * 2) fail('PROTOCOL_INPUT_LIMIT', 'Hex input exceeds the byte budget');
    if (data.length % 2 || !/^[0-9a-f]*$/i.test(data)) fail('INVALID_PROTOCOL_ENCODING', 'Hex data must have an even number of hexadecimal digits');
    return Buffer.from(data, 'hex');
  }
  if (encoding === 'base64') {
    if (data.length > Math.ceil(budget.maxInputBytes / 3) * 4) fail('PROTOCOL_INPUT_LIMIT', 'Base64 input exceeds the byte budget');
    if (data.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(data))
      fail('INVALID_PROTOCOL_ENCODING', 'Base64 data must be canonical and padded');
    const buffer = Buffer.from(data, 'base64');
    if (buffer.toString('base64') !== data) fail('INVALID_PROTOCOL_ENCODING', 'Base64 data contains non-canonical padding bits');
    return inputBuffer(buffer, budget);
  }
  fail('INVALID_PROTOCOL_ENCODING', 'encoding must be hex or base64');
}

function readUnsigned(buffer, offset, width, endian) {
  if (width === 1) return BigInt(buffer[offset]);
  if (width === 2) return BigInt(endian === 'little' ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset));
  if (width === 4) return BigInt(endian === 'little' ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset));
  return endian === 'little' ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset);
}
function endian(value = 'big') {
  if (!['big', 'little'].includes(value)) fail('INVALID_PROTOCOL_SCHEMA', 'endian must be big or little');
  return value;
}
function schemaFields(schema) {
  if (schema === undefined) return [];
  object(schema, 'schema');
  if (!Array.isArray(schema.fields) || schema.fields.length > 128) fail('INVALID_PROTOCOL_SCHEMA', 'schema.fields must contain at most 128 fields');
  const names = new Set();
  return schema.fields.map((f, index) => {
    object(f, `schema.fields[${index}]`);
    if (typeof f.name !== 'string' || !f.name || f.name.length > 128 || names.has(f.name) || ['__proto__', 'constructor', 'prototype'].includes(f.name))
      fail('INVALID_PROTOCOL_SCHEMA', 'Field names must be nonempty, unique, and at most 128 characters');
    names.add(f.name);
    const field = { name: f.name, offset: int(f.offset, `${f.name}.offset`, 0, MAX_INPUT), type: f.type, endian: endian(f.endian) };
    if (['bytes', 'utf8'].includes(f.type)) field.length = int(f.length, `${f.name}.length`, 0, 1024 * 1024);
    else if (f.type === 'varint') field.length = int(f.length ?? 10, `${f.name}.length`, 1, 10);
    else if (f.type === 'signed') field.length = int(f.length, `${f.name}.length`, 1, 8);
    else if (/^[ui](8|16|32|64)$/.test(f.type ?? '')) field.length = Number(f.type.slice(1)) / 8;
    else fail('INVALID_PROTOCOL_SCHEMA', `Unsupported field type at schema.fields[${index}]`);
    if (f.type === 'signed' && ![1, 2, 4, 8].includes(field.length)) fail('INVALID_PROTOCOL_SCHEMA', 'signed length must be 1, 2, 4, or 8');
    return field;
  });
}
function normalizeFraming(framing) {
  if (framing === undefined) return { type: 'none' };
  object(framing, 'framing');
  if (framing.type === 'none') return { type: 'none' };
  if (framing.type === 'fixed') return { type: 'fixed', length: int(framing.length, 'framing.length', 1, 1024 * 1024) };
  if (framing.type === 'delimiter') {
    if (!['0a', '0d0a'].includes(framing.delimiterHex) || framing.includeDelimiter !== true)
      fail('INVALID_PROTOCOL_SCHEMA', 'delimiter framing requires delimiterHex 0a or 0d0a and includeDelimiter=true');
    return { type: 'delimiter', delimiterHex: framing.delimiterHex, includeDelimiter: true };
  }
  if (framing.type === 'varint-prefix') {
    if (framing.lengthIncludesHeader !== undefined && typeof framing.lengthIncludesHeader !== 'boolean') fail('INVALID_PROTOCOL_SCHEMA', 'lengthIncludesHeader must be a boolean');
    return { type: 'varint-prefix', offset: int(framing.offset ?? 0, 'framing.offset', 0, 1024),
      maxBytes: int(framing.maxBytes ?? 5, 'framing.maxBytes', 1, 5),
      headerBytesAfterLength: int(framing.headerBytesAfterLength ?? 0, 'framing.headerBytesAfterLength', 0, 4096),
      lengthIncludesHeader: framing.lengthIncludesHeader ?? false, adjustment: int(framing.adjustment ?? 0, 'framing.adjustment', -4096, 4096) };
  }
  if (framing.type === 'tlv') {
    const typeSize = int(framing.typeSize ?? 1, 'framing.typeSize', 1, 2);
    const lengthSize = int(framing.lengthSize ?? 1, 'framing.lengthSize', 1, 4);
    if (![1, 2, 4].includes(lengthSize)) fail('INVALID_PROTOCOL_SCHEMA', 'TLV lengthSize must be 1, 2, or 4');
    if (framing.lengthIncludesHeader !== undefined && typeof framing.lengthIncludesHeader !== 'boolean') fail('INVALID_PROTOCOL_SCHEMA', 'lengthIncludesHeader must be a boolean');
    return { type: 'tlv', typeSize, lengthSize, offset: typeSize, size: lengthSize, endian: endian(framing.endian),
      headerLength: typeSize + lengthSize, lengthIncludesHeader: framing.lengthIncludesHeader ?? false,
      adjustment: int(framing.adjustment ?? 0, 'framing.adjustment', -4096, 4096) };
  }
  if (framing.type !== 'length-prefix') fail('INVALID_PROTOCOL_SCHEMA', 'Unsupported framing type');
  const offset = int(framing.offset ?? 0, 'framing.offset', 0, 1024);
  const size = int(framing.size ?? 2, 'framing.size', 1, 4);
  if (![1, 2, 4].includes(size)) fail('INVALID_PROTOCOL_SCHEMA', 'Length prefix size must be 1, 2, or 4');
  const headerLength = int(framing.headerLength ?? offset + size, 'framing.headerLength', offset + size, 4096);
  if (framing.lengthIncludesHeader !== undefined && typeof framing.lengthIncludesHeader !== 'boolean')
    fail('INVALID_PROTOCOL_SCHEMA', 'lengthIncludesHeader must be a boolean');
  return { type: 'length-prefix', offset, size, endian: endian(framing.endian), headerLength,
    lengthIncludesHeader: framing.lengthIncludesHeader ?? false,
    adjustment: int(framing.adjustment ?? 0, 'framing.adjustment', -4096, 4096) };
}
function framingVarint(buffer, offset, maxBytes) {
  let value = 0;
  for (let i = 0; i < maxBytes; i++) {
    if (offset + i >= buffer.length) return { error: 'incomplete-varint-prefix' };
    const byte = buffer[offset + i];
    if (i === 4 && (byte & 0xf0)) return { error: 'varint-prefix-overflow' };
    value += (byte & 0x7f) * 2 ** (i * 7);
    if (!(byte & 0x80)) return i > 0 && byte === 0 ? { error: 'noncanonical-varint-prefix' } : { value, bytes: i + 1 };
  }
  return { error: 'unterminated-varint-prefix' };
}
function fieldValue(buffer, field, frameOffset, budget) {
  const start = field.offset;
  const result = { name: field.name, type: field.type, endian: field.endian, span: { offset: start, inputOffset: frameOffset + start, length: field.length } };
  if (field.type === 'varint') {
    let value = 0n;
    let consumed = 0;
    for (; consumed < field.length && start + consumed < buffer.length; consumed++) {
      const octet = buffer[start + consumed];
      if (consumed === 9 && octet > 1) { result.error = 'varint-overflow'; consumed++; break; }
      value |= BigInt(octet & 0x7f) << BigInt(consumed * 7);
      if (!(octet & 0x80)) { consumed++; result.value = value.toString(10); result.hexValue = `0x${value.toString(16)}`; break; }
    }
    result.span.length = consumed;
    if (result.value === undefined && !result.error) result.error = consumed >= field.length ? 'unterminated-varint' : 'field-truncated';
    const raw = buffer.subarray(Math.min(start, buffer.length), Math.min(start + consumed, buffer.length));
    return { ...result, ...byteEvidence(raw, budget, false) };
  }
  if (start > buffer.length || field.length > buffer.length - start) {
    result.error = 'field-truncated';
    result.availableBytes = Math.max(0, buffer.length - start);
    return result;
  }
  const raw = buffer.subarray(start, start + field.length);
  if (field.type === 'bytes') return { ...result, ...byteEvidence(raw, budget, false) };
  if (field.type === 'utf8') {
    try { const value = UTF8.decode(raw); result.value = value.slice(0, 256); result.valueTruncated = value.length > 256; } catch { result.error = 'invalid-utf8'; }
    return { ...result, ...byteEvidence(raw, budget, false) };
  }
  let value = readUnsigned(buffer, start, field.length, field.endian);
  if (field.type.startsWith('i') || field.type === 'signed') value = BigInt.asIntN(field.length * 8, value);
  result.value = field.length === 8 ? value.toString(10) : Number(value);
  result.hexValue = `0x${readUnsigned(buffer, start, field.length, field.endian).toString(16)}`;
  return { ...result, ...byteEvidence(raw, budget, false) };
}

export function decodeFrames(input, options = {}) {
  const budget = limits(options), buffer = inputBuffer(input, budget);
  const fields = schemaFields(options.schema), framing = normalizeFraming(options.framing);
  const result = { ...base('decode', buffer, budget), framing, schema: { fields }, frames: [], issues: [], complete: true };
  let offset = 0, decodedFields = 0, fieldBytes = 0;
  while (offset < buffer.length) {
    if (result.frames.length >= budget.maxFrames) { truncate(result, 'frame-budget'); break; }
    let length;
    let prefix = null;
    if (framing.type === 'fixed') length = framing.length;
    else if (framing.type === 'none') length = buffer.length;
    else if (framing.type === 'delimiter') {
      const delimiter = Buffer.from(framing.delimiterHex, 'hex'), end = buffer.indexOf(delimiter, offset);
      if (end < 0) { issue(result, { code: 'incomplete-delimited-frame', offset, availableBytes: buffer.length - offset }, budget); truncate(result, 'incomplete-delimited-frame'); break; }
      length = end - offset + delimiter.length;
    }
    else if (framing.type === 'varint-prefix') {
      const decoded = framingVarint(buffer, offset + framing.offset, framing.maxBytes);
      if (decoded.error) { issue(result, { code: decoded.error, offset }, budget); truncate(result, decoded.error); break; }
      const headerLength = framing.offset + decoded.bytes + framing.headerBytesAfterLength;
      length = decoded.value + framing.adjustment + (framing.lengthIncludesHeader ? 0 : headerLength);
      prefix = { declaredLength: decoded.value, encoding: 'canonical-unsigned-leb128', span: { offset: framing.offset, inputOffset: offset + framing.offset, length: decoded.bytes } };
      if (length < headerLength) { issue(result, { code: 'invalid-frame-length', offset, declaredLength: decoded.value, computedLength: length }, budget); break; }
    }
    else {
      if (buffer.length - offset < framing.headerLength) { issue(result, { code: 'incomplete-frame-header', offset, availableBytes: buffer.length - offset }, budget); truncate(result, 'incomplete-frame-header'); break; }
      const declared = Number(readUnsigned(buffer, offset + framing.offset, framing.size, framing.endian));
      length = declared + framing.adjustment + (framing.lengthIncludesHeader ? 0 : framing.headerLength);
      prefix = { declaredLength: declared, span: { offset: framing.offset, inputOffset: offset + framing.offset, length: framing.size } };
      if (length < framing.headerLength) { issue(result, { code: 'invalid-frame-length', offset, declaredLength: declared, computedLength: length }, budget); break; }
    }
    if (length > budget.maxFrameBytes) { issue(result, { code: 'frame-size-budget', offset, declaredLength: length }, budget); truncate(result, 'frame-size-budget'); break; }
    if (length > buffer.length - offset) { issue(result, { code: 'incomplete-frame', offset, expectedBytes: length, availableBytes: buffer.length - offset }, budget); truncate(result, 'incomplete-frame'); break; }
    const bytes = buffer.subarray(offset, offset + length);
    const decoded = [];
    for (const f of fields) {
      if (decodedFields >= budget.maxDecodedFields) { truncate(result, 'decoded-field-budget'); break; }
      const cost = Math.min(f.length, Math.max(0, bytes.length - f.offset));
      if (cost > budget.maxFieldBytes - fieldBytes) { truncate(result, 'field-byte-budget'); break; }
      decoded.push(fieldValue(bytes, f, offset, budget)); decodedFields++; fieldBytes += cost;
    }
    const frame = { index: result.frames.length, offset, length, ...(prefix ? { lengthPrefix: prefix } : {}),
      ...(framing.type === 'tlv' ? { tlv: { type: Number(readUnsigned(bytes, 0, framing.typeSize, framing.endian)),
        typeSpan: { offset: 0, inputOffset: offset, length: framing.typeSize }, valueSpan: { offset: framing.headerLength, inputOffset: offset + framing.headerLength, length: length - framing.headerLength }, semantics: 'unknown' } } : {}),
      ...byteEvidence(bytes, budget), fields: decoded, omittedFields: fields.length - decoded.length,
      valid: decoded.length === fields.length && decoded.every(f => !f.error) };
    if (!frame.valid) result.complete = false;
    result.frames.push(frame);
    offset += length;
  }
  result.consumedBytes = offset;
  result.fieldBytesProcessed = fieldBytes;
  result.fieldsDecoded = decodedFields;
  result.remainingBytes = buffer.length - offset;
  if (result.remainingBytes) result.remainder = { offset, ...byteEvidence(buffer.subarray(offset), budget) };
  if (result.truncated || result.issues.length) result.complete = false;
  return result;
}

export function inspectBytes(input, options = {}) {
  const budget = limits(options), buffer = inputBuffer(input, budget);
  const counts = new Uint32Array(256);
  for (const b of buffer) counts[b]++;
  let entropy = 0;
  for (const n of counts) if (n) { const probability = n / buffer.length; entropy -= probability * Math.log2(probability); }
  const result = { ...base('inspect', buffer, budget), entropyBitsPerByte: entropy,
    observations: [], strings: [], interpretation: 'Observations are byte evidence; they do not identify encryption, a protocol, or a complete format.' };
  for (const size of [1, 2, 4]) if (buffer.length >= size) for (const order of size === 1 ? ['big'] : ['big', 'little']) {
    const value = Number(readUnsigned(buffer, 0, size, order));
    if (value === buffer.length || value === buffer.length - size)
      result.observations.push({ kind: 'length-prefix-candidate', offset: 0, size, endian: order, value,
        relation: value === buffer.length ? 'total-byte-length' : 'bytes-after-prefix', previewHex: buffer.subarray(0, size).toString('hex') });
  }
  let start = -1;
  for (let i = 0; i <= buffer.length; i++) {
    const printable = i < buffer.length && buffer[i] >= 32 && buffer[i] <= 126;
    if (printable && start < 0) start = i;
    if (!printable && start >= 0) {
      if (i - start >= 4) {
        if (result.strings.length < 32) result.strings.push({ offset: start, byteLength: i - start,
          value: buffer.subarray(start, Math.min(i, start + 256)).toString('ascii'), truncated: i - start > 256 });
        else { truncate(result, 'string-preview-budget'); break; }
      }
      start = -1;
    }
  }
  return result;
}

function ipv4(buffer, offset) { return [...buffer.subarray(offset, offset + 4)].join('.'); }
function ipv6(buffer, offset) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(buffer.readUInt16BE(offset + i).toString(16));
  return groups.join(':');
}
function packetProblem(packet, reason, extra = {}) { packet.unsupported = { reason, ...extra }; return packet; }
function parseNetwork(bytes, linkType, packet) {
  let offset = 0, etherType;
  if (linkType === 1) {
    if (bytes.length < 14) return packetProblem(packet, 'truncated-ethernet-header');
    etherType = bytes.readUInt16BE(12); offset = 14; packet.vlanTags = [];
    while ([0x8100, 0x88a8, 0x9100].includes(etherType)) {
      if (packet.vlanTags.length >= 2) return packetProblem(packet, 'vlan-depth-limit');
      if (bytes.length - offset < 4) return packetProblem(packet, 'truncated-vlan-header');
      packet.vlanTags.push(bytes.readUInt16BE(offset)); etherType = bytes.readUInt16BE(offset + 2); offset += 4;
    }
    if (![0x0800, 0x86dd].includes(etherType)) return packetProblem(packet, 'unsupported-ether-type', { etherType });
  } else if (linkType === 101) {
    if (!bytes.length) return packetProblem(packet, 'truncated-raw-ip');
    const version = bytes[0] >>> 4;
    etherType = version === 4 ? 0x0800 : version === 6 ? 0x86dd : 0;
  } else if (linkType === 228) etherType = 0x0800;
  else if (linkType === 229) etherType = 0x86dd;
  else return packetProblem(packet, 'unsupported-link-type', { linkType });
  let protocol, end;
  if (etherType === 0x0800) {
    if (bytes.length - offset < 20) return packetProblem(packet, 'truncated-ipv4-header');
    const header = (bytes[offset] & 15) * 4, length = bytes.readUInt16BE(offset + 2);
    if (bytes[offset] >>> 4 !== 4 || header < 20 || length < header) return packetProblem(packet, 'invalid-ipv4-header');
    if (bytes.length - offset < header) return packetProblem(packet, 'truncated-ipv4-options');
    packet.network = { version: 4, src: ipv4(bytes, offset + 12), dst: ipv4(bytes, offset + 16), declaredLength: length, headerLength: header };
    const fragment = bytes.readUInt16BE(offset + 6);
    if (fragment & 0x3fff) return packetProblem(packet, 'ipv4-fragment-reassembly-not-supported', { fragmentOffset: (fragment & 0x1fff) * 8, moreFragments: Boolean(fragment & 0x2000) });
    protocol = bytes[offset + 9]; end = Math.min(bytes.length, offset + length);
    if (offset + length > bytes.length) packet.truncated = true;
    offset += header;
  } else if (etherType === 0x86dd) {
    if (bytes.length - offset < 40) return packetProblem(packet, 'truncated-ipv6-header');
    if (bytes[offset] >>> 4 !== 6) return packetProblem(packet, 'invalid-ipv6-header');
    const payloadLength = bytes.readUInt16BE(offset + 4);
    packet.network = { version: 6, src: ipv6(bytes, offset + 8), dst: ipv6(bytes, offset + 24), declaredLength: payloadLength + 40, headerLength: 40 };
    protocol = bytes[offset + 6]; end = Math.min(bytes.length, offset + 40 + payloadLength);
    if (offset + 40 + payloadLength > bytes.length) packet.truncated = true;
    offset += 40;
    if (!payloadLength) return packetProblem(packet, 'ipv6-jumbogram-not-supported');
    let count = 0;
    while ([0, 43, 60, 51, 44, 50].includes(protocol)) {
      if (++count > 8) return packetProblem(packet, 'ipv6-extension-depth-limit');
      if (protocol === 44) return packetProblem(packet, 'ipv6-fragment-reassembly-not-supported');
      if (protocol === 50) return packetProblem(packet, 'ipv6-esp-not-supported');
      if (end - offset < 2) return packetProblem(packet, 'truncated-ipv6-extension');
      const extensionType = protocol;
      const length = (bytes[offset + 1] + (protocol === 51 ? 2 : 1)) * (protocol === 51 ? 4 : 8);
      if (extensionType === 51 && length < 12) return packetProblem(packet, 'invalid-ipv6-authentication-header-length');
      if (end - offset < length) return packetProblem(packet, 'truncated-ipv6-extension');
      packet.extensions ??= [];
      packet.extensions.push({ type: extensionType, offset, length });
      protocol = bytes[offset]; offset += length;
    }
  } else return packetProblem(packet, 'unsupported-raw-ip-version');
  packet.network.protocol = protocol;
  if (protocol === 6) {
    if (end - offset < 20) return packetProblem(packet, 'truncated-tcp-header');
    const header = (bytes[offset + 12] >>> 4) * 4;
    if (header < 20) return packetProblem(packet, 'invalid-tcp-header');
    if (end - offset < header) return packetProblem(packet, 'truncated-tcp-options');
    const flags = bytes[offset + 13], seq = bytes.readUInt32BE(offset + 4);
    packet.transport = { protocol: 'tcp', srcPort: bytes.readUInt16BE(offset), dstPort: bytes.readUInt16BE(offset + 2),
      sequence: seq, payloadSequence: (seq + ((flags & 2) ? 1 : 0)) >>> 0, acknowledgement: bytes.readUInt32BE(offset + 8),
      flags, syn: Boolean(flags & 2), ack: Boolean(flags & 16), fin: Boolean(flags & 1), rst: Boolean(flags & 4), headerLength: header };
    packet.payloadOffset = offset + header; packet._payload = bytes.subarray(offset + header, end);
  } else if (protocol === 17) {
    if (end - offset < 8) return packetProblem(packet, 'truncated-udp-header');
    const length = bytes.readUInt16BE(offset + 4);
    if (length < 8) return packetProblem(packet, 'invalid-udp-length');
    if (length > end - offset) packet.truncated = true;
    packet.transport = { protocol: 'udp', srcPort: bytes.readUInt16BE(offset), dstPort: bytes.readUInt16BE(offset + 2), length };
    packet.payloadOffset = offset + 8; packet._payload = bytes.subarray(offset + 8, Math.min(end, offset + length));
  } else return packetProblem(packet, protocol === 59 ? 'ipv6-no-next-header' : 'unsupported-ip-protocol', { protocol });
  packet.payloadLength = packet._payload.length;
  return packet;
}

function parsePcap(buffer, budget, result) {
  if (buffer.length < 24) { issue(result, { code: 'truncated-pcap-header', offset: 0 }, budget); truncate(result, 'truncated-container');
    result.parsedContainerBytes = 0; result.remainingContainerBytes = buffer.length; return []; }
  const magic = buffer.subarray(0, 4).toString('hex');
  const little = ['d4c3b2a1', '4d3cb2a1'].includes(magic), nano = ['4d3cb2a1', 'a1b23c4d'].includes(magic);
  const u16 = offset => little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
  const u32 = offset => little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
  const major = u16(4), minor = u16(6), snaplen = u32(16), rawNetwork = u32(20), linkType = rawNetwork & 0xffff;
  result.container = { format: 'pcap', endian: little ? 'little' : 'big', timestampResolution: nano ? 'nanoseconds' : 'microseconds', version: `${major}.${minor}`, snaplen, linkType };
  if (major !== 2 || minor !== 4) { issue(result, { code: 'unsupported-pcap-version', major, minor }, budget); return []; }
  const packets = [];
  let offset = 24;
  while (offset < buffer.length) {
    if (packets.length >= budget.maxPackets) { truncate(result, 'packet-budget'); break; }
    if (buffer.length - offset < 16) { issue(result, { code: 'truncated-pcap-record-header', offset }, budget); truncate(result, 'truncated-container'); break; }
    const seconds = u32(offset), fraction = u32(offset + 4), capturedLength = u32(offset + 8), originalLength = u32(offset + 12);
    if (capturedLength > originalLength || (snaplen && capturedLength > snaplen)) { issue(result, { code: 'invalid-pcap-record-length', offset, capturedLength, originalLength }, budget); break; }
    if (fraction >= (nano ? 1e9 : 1e6)) issue(result, { code: 'invalid-pcap-timestamp-fraction', offset, fraction }, budget);
    if (capturedLength > buffer.length - offset - 16) { issue(result, { code: 'truncated-pcap-record-data', offset, capturedLength, availableBytes: buffer.length - offset - 16 }, budget); truncate(result, 'truncated-container'); break; }
    const bytes = buffer.subarray(offset + 16, offset + 16 + capturedLength);
    packets.push(parseNetwork(bytes, linkType, { index: packets.length, captureOffset: offset + 16, capturedLength, originalLength,
      timestamp: { seconds, fraction, unitsPerSecond: nano ? 1e9 : 1e6 }, truncated: capturedLength < originalLength, linkType }));
    offset += 16 + capturedLength;
  }
  result.parsedContainerBytes = offset;
  result.remainingContainerBytes = buffer.length - offset;
  return packets;
}

function parsePcapng(buffer, budget, result) {
  const packets = [], interfaces = [];
  let offset = 0, little = null, sectionIndex = -1, blocks = 0, skipped = 0;
  result.container = { format: 'pcapng', sections: [], interfaces: [] };
  while (offset < buffer.length) {
    if (packets.length >= budget.maxPackets) { truncate(result, 'packet-budget'); break; }
    if (++blocks > budget.maxPackets * 4 + 1024) { truncate(result, 'block-budget'); break; }
    if (buffer.length - offset < 12) { issue(result, { code: 'truncated-pcapng-block-header', offset }, budget); truncate(result, 'truncated-container'); break; }
    const sectionHeader = buffer.readUInt32LE(offset) === 0x0a0d0d0a;
    if (sectionHeader) {
      if (buffer.length - offset < 28) { issue(result, { code: 'truncated-pcapng-section-header', offset }, budget); truncate(result, 'truncated-container'); break; }
      const bom = buffer.subarray(offset + 8, offset + 12).toString('hex');
      if (!['4d3c2b1a', '1a2b3c4d'].includes(bom)) { issue(result, { code: 'invalid-pcapng-byte-order', offset }, budget); break; }
      little = bom === '4d3c2b1a';
    } else if (little === null) { issue(result, { code: 'pcapng-section-required', offset }, budget); break; }
    const u16 = pos => little ? buffer.readUInt16LE(pos) : buffer.readUInt16BE(pos);
    const u32 = pos => little ? buffer.readUInt32LE(pos) : buffer.readUInt32BE(pos);
    const type = u32(offset), length = u32(offset + 4);
    if (length < 12 || length % 4) { issue(result, { code: 'invalid-pcapng-block-length', offset, length }, budget); break; }
    if (length > buffer.length - offset) { issue(result, { code: 'truncated-pcapng-block', offset, length, availableBytes: buffer.length - offset }, budget); truncate(result, 'truncated-container'); break; }
    if (u32(offset + length - 4) !== length) { issue(result, { code: 'pcapng-block-length-mismatch', offset }, budget); break; }
    if (sectionHeader) {
      if (length < 28 || u16(offset + 12) !== 1 || u16(offset + 14) !== 0) { issue(result, { code: 'unsupported-pcapng-section-version', offset }, budget); break; }
      if (result.container.sections.length >= 128) { truncate(result, 'section-budget'); break; }
      sectionIndex++; interfaces.length = 0;
      result.container.sections.push({ index: sectionIndex, offset, endian: little ? 'little' : 'big', version: `${u16(offset + 12)}.${u16(offset + 14)}` });
    } else if (type === 1) {
      if (length < 20) { issue(result, { code: 'invalid-pcapng-interface-block', offset }, budget); break; }
      if (result.container.interfaces.length >= 128) { issue(result, { code: 'pcapng-interface-budget', offset }, budget); truncate(result, 'interface-budget'); break; }
      const iface = { id: interfaces.length, sectionIndex, linkType: u16(offset + 8), snaplen: u32(offset + 12), timestampResolution: '0.000001', timestampBase: 10, timestampExponent: 6 };
      let cursor = offset + 16;
      while (cursor < offset + length - 4) {
        if (offset + length - 4 - cursor < 4) { issue(result, { code: 'truncated-pcapng-option-header', offset: cursor }, budget); break; }
        const code = u16(cursor), size = u16(cursor + 2); cursor += 4;
        if (Math.ceil(size / 4) * 4 > offset + length - 4 - cursor) { issue(result, { code: 'truncated-pcapng-option', offset: cursor, size }, budget); break; }
        if (!code) break;
        if (code === 9 && size === 1) {
          const exponent = buffer[cursor]; iface.timestampBase = exponent & 0x80 ? 2 : 10;
          iface.timestampExponent = exponent & 0x7f;
          iface.timestampResolution = `${iface.timestampBase}^-${iface.timestampExponent}`;
        }
        cursor += (size + 3) & ~3;
      }
      interfaces.push(iface); result.container.interfaces.push({ ...iface });
    } else if (type === 6 || type === 3) {
      if (length < (type === 6 ? 32 : 16)) { issue(result, { code: 'invalid-pcapng-packet-block', offset }, budget); break; }
      const interfaceId = type === 6 ? u32(offset + 8) : 0, iface = interfaces[interfaceId];
      if (!iface) { issue(result, { code: 'unknown-pcapng-interface', offset, interfaceId }, budget); offset += length; continue; }
      const originalLength = u32(offset + (type === 6 ? 24 : 8));
      const capturedLength = type === 6 ? u32(offset + 20) : Math.min(originalLength, iface.snaplen || originalLength);
      const dataOffset = offset + (type === 6 ? 28 : 12);
      const paddedLength = Math.ceil(capturedLength / 4) * 4;
      if (capturedLength > originalLength || (iface.snaplen && capturedLength > iface.snaplen) || paddedLength > offset + length - 4 - dataOffset
        || (type === 3 && paddedLength !== offset + length - 4 - dataOffset)) {
        issue(result, { code: 'invalid-pcapng-captured-length', offset, capturedLength, originalLength }, budget); break;
      }
      let timestamp;
      if (type === 6) timestamp = { ticks: ((BigInt(u32(offset + 12)) << 32n) | BigInt(u32(offset + 16))).toString(10), base: iface.timestampBase, exponent: iface.timestampExponent };
      const bytes = buffer.subarray(dataOffset, dataOffset + capturedLength);
      packets.push(parseNetwork(bytes, iface.linkType, { index: packets.length, captureOffset: dataOffset, capturedLength, originalLength,
        ...(timestamp ? { timestamp } : { timestampUnavailable: true }), interfaceId, sectionIndex,
        truncated: capturedLength < originalLength, linkType: iface.linkType }));
    } else { skipped++; if ([2, 4, 5].includes(type)) issue(result, { code: 'unsupported-pcapng-block', offset, blockType: type }, budget); }
    offset += length;
  }
  result.container.skippedBlocks = skipped;
  result.parsedContainerBytes = offset;
  result.remainingContainerBytes = buffer.length - offset;
  return packets;
}

function endpoint(address, port) { return { address, port, label: `${address.includes(':') ? `[${address}]` : address}:${port}` }; }
function sequenceDelta(sequence, anchor) { return ((sequence - anchor + 0x80000000) >>> 0) - 0x80000000; }
function insertSegment(direction, packet, budget) {
  const bytes = packet._payload;
  if (!bytes.length) return;
  if (direction.anchor === null) direction.anchor = packet.transport.payloadSequence;
  const start = sequenceDelta(packet.transport.payloadSequence, direction.anchor), end = start + bytes.length;
  if (Math.abs(start) > 32 * 1024 * 1024 || Math.abs(end) > 32 * 1024 * 1024) {
    direction.sequenceRejectedPackets.push(packet.index); direction.truncated = true; return;
  }
  let cursor = start, retransmitted = 0;
  const added = [];
  for (const chunk of direction._chunks) {
    const overlapStart = Math.max(start, chunk.start), overlapEnd = Math.min(end, chunk.end);
    if (overlapStart >= overlapEnd) continue;
    if (cursor < overlapStart) added.push({ start: cursor, end: overlapStart, bytes: bytes.subarray(cursor - start, overlapStart - start),
      ownerPacketIndex: packet.index, packetIndices: [packet.index] });
    retransmitted += overlapEnd - overlapStart;
    let mismatchStart = -1;
    for (let at = overlapStart; at <= overlapEnd; at++) {
      const mismatches = at < overlapEnd && bytes[at - start] !== chunk.bytes[at - chunk.start];
      if (mismatches) { direction.conflictingByteObservations++; if (mismatchStart < 0) mismatchStart = at; }
      else if (mismatchStart >= 0) {
        if (direction.conflicts.length < budget.maxIssues) direction.conflicts.push({ start: mismatchStart, end: at,
          retainedFromPacket: chunk.ownerPacketIndex, earlierObservedPackets: chunk.packetIndices.slice(0, 16), laterPacket: packet.index,
          earlierPreviewHex: chunk.bytes.subarray(mismatchStart - chunk.start, Math.min(at - chunk.start, mismatchStart - chunk.start + 16)).toString('hex'),
          laterPreviewHex: bytes.subarray(mismatchStart - start, Math.min(at - start, mismatchStart - start + 16)).toString('hex') });
        else direction.omittedConflicts++;
        mismatchStart = -1;
      }
    }
    if (!chunk.packetIndices.includes(packet.index)) {
      if (chunk.packetIndices.length < 128) chunk.packetIndices.push(packet.index);
      else chunk.packetIndicesOmitted = (chunk.packetIndicesOmitted ?? 0) + 1;
    }
    cursor = Math.max(cursor, overlapEnd);
  }
  if (cursor < end) added.push({ start: cursor, end, bytes: bytes.subarray(cursor - start), ownerPacketIndex: packet.index, packetIndices: [packet.index] });
  direction.retransmittedBytes += retransmitted;
  direction._chunks.push(...added); direction._chunks.sort((a, b) => a.start - b.start);
}
function coalesceChunks(chunks) {
  const merged = [];
  for (const chunk of chunks) {
    const prior = merged.at(-1);
    if (prior && prior.end === chunk.start) {
      prior.parts.push(chunk.bytes); prior.end = chunk.end;
      const combined = [...new Set([...prior.packetIndices, ...chunk.packetIndices])];
      prior.packetIndicesOmitted = (prior.packetIndicesOmitted ?? 0) + (chunk.packetIndicesOmitted ?? 0) + Math.max(0, combined.length - 128);
      prior.packetIndices = combined.slice(0, 128);
    } else merged.push({ ...chunk, parts: [chunk.bytes] });
  }
  return merged.map(chunk => ({ ...chunk, bytes: chunk.parts.length === 1 ? chunk.parts[0] : Buffer.concat(chunk.parts) }));
}
function createDirection() {
  return { anchor: null, packetIndices: [], payloadBytesObserved: 0, retransmittedBytes: 0, conflictingByteObservations: 0,
    conflicts: [], omittedConflicts: 0, sequenceRejectedPackets: [], truncated: false, _chunks: [], datagrams: [],
    streamStartEstablished: false, endSequence: null };
}
function buildFlows(packets, budget, result, options) {
  const flows = [], current = new Map();
  let retainedBytes = 0, retainedPackets = 0;
  for (const packet of packets) {
    if (!packet.transport) continue;
    const a = endpoint(packet.network.src, packet.transport.srcPort), b = endpoint(packet.network.dst, packet.transport.dstPort);
    const endpoints = [a, b].sort((x, y) => x.label < y.label ? -1 : x.label > y.label ? 1 : 0);
    const directionIndex = a.label === endpoints[0].label ? 0 : 1;
    const key = `${packet.network.version}/${packet.transport.protocol}/${endpoints[0].label}/${endpoints[1].label}`;
    let flow = current.get(key);
    const syn = packet.transport.protocol === 'tcp' && packet.transport.syn && !packet.transport.ack;
    const freshSyn = flow && syn && (flow.terminated || flow.initialSyn === undefined || flow.initialSyn !== packet.transport.sequence);
    if (!flow || freshSyn) {
      if (flows.length >= budget.maxFlows) { truncate(result, 'flow-budget'); continue; }
      flow = { id: `flow-${flows.length}`, tuple: { ipVersion: packet.network.version, protocol: packet.transport.protocol, endpoints },
        incarnation: flow ? flow.incarnation + 1 : 0, startsWithSyn: syn, initialSyn: syn ? packet.transport.sequence : undefined,
        terminated: false, finDirections: new Set(), directions: [createDirection(), createDirection()] };
      flows.push(flow); current.set(key, flow);
    } else if (syn && flow.initialSyn === undefined) flow.initialSyn = packet.transport.sequence;
    packet.flowId = flow.id; packet.direction = directionIndex;
    const direction = flow.directions[directionIndex];
    direction.packetIndices.push(packet.index); direction.payloadBytesObserved += packet._payload.length;
    direction.truncated ||= packet.truncated;
    if (packet.transport.syn && !direction.streamStartEstablished) {
      const newAnchor = (packet.transport.sequence + 1) >>> 0;
      let accepted = true;
      if (direction.anchor !== null) {
        const adjustment = sequenceDelta(direction.anchor, newAnchor);
        if (Math.abs(adjustment) > 32 * 1024 * 1024) { direction.sequenceRejectedPackets.push(packet.index); direction.truncated = true; accepted = false; }
        else for (const chunk of direction._chunks) { chunk.start += adjustment; chunk.end += adjustment; }
      }
      if (accepted) { direction.anchor = newAnchor; direction.streamStartEstablished = true; }
    }
    if (packet.transport.rst) flow.terminated = true;
    if (packet.transport.fin) { direction.endSequence = (packet.transport.payloadSequence + packet._payload.length) >>> 0; direction.finPacketIndex = packet.index;
      flow.finDirections.add(directionIndex); flow.terminated ||= flow.finDirections.size === 2; }
    if (!packet._payload.length) continue;
    // Budget counts observed bytes, including retransmissions. No gap-sized allocation is made.
    if (packet._payload.length > budget.maxReassemblyBytes - retainedBytes) { direction.truncated = true; truncate(result, 'reassembly-byte-budget'); continue; }
    retainedBytes += packet._payload.length; retainedPackets++;
    if (packet.transport.protocol === 'udp') direction.datagrams.push({ packetIndex: packet.index, ...byteEvidence(packet._payload, budget) });
    else insertSegment(direction, packet, budget);
  }
  let frameBudget = budget.maxFrames, decodedFieldsBudget = budget.maxDecodedFields, fieldByteBudget = budget.maxFieldBytes;
  for (const flow of flows) {
    delete flow.initialSyn; delete flow.finDirections;
    flow.directions = flow.directions.map((direction, index) => {
      direction._chunks = coalesceChunks(direction._chunks);
      const chunks = direction._chunks.map(chunk => ({ sequenceStart: (direction.anchor + chunk.start) >>> 0,
        relativeOffset: chunk.start, packetIndices: chunk.packetIndices, packetIndicesOmitted: chunk.packetIndicesOmitted ?? 0,
        packetIndexScope: 'Supporting packet index preview; omissions count observations, not necessarily distinct packets. Full direction packetIndices are retained.',
        ...byteEvidence(chunk.bytes, budget) }));
      const holes = [];
      if (direction.streamStartEstablished && direction._chunks.length && direction._chunks[0].start > 0)
        holes.push({ relativeOffset: 0, length: direction._chunks[0].start, sequenceStart: direction.anchor, position: 'prefix' });
      for (let i = 1; i < direction._chunks.length; i++) holes.push({ relativeOffset: direction._chunks[i - 1].end,
        length: direction._chunks[i].start - direction._chunks[i - 1].end,
        sequenceStart: (direction.anchor + direction._chunks[i - 1].end) >>> 0 });
      if (direction.endSequence !== null && direction.anchor !== null) {
        const end = sequenceDelta(direction.endSequence, direction.anchor), lastEnd = direction._chunks.at(-1)?.end ?? 0;
        if (Math.abs(end) > 32 * 1024 * 1024) { direction.sequenceRejectedPackets.push(direction.finPacketIndex); direction.truncated = true; }
        else if (end > lastEnd) holes.push({ relativeOffset: lastEnd, length: end - lastEnd, sequenceStart: (direction.anchor + lastEnd) >>> 0, position: 'tail' });
      }
      const value = { ...direction, direction: index, from: flow.tuple.endpoints[index], to: flow.tuple.endpoints[1 - index],
        anchorSequence: direction.anchor, chunks, holes, uniqueBytesRetained: chunks.reduce((n, c) => n + c.byteLength, 0),
        ambiguous: direction.conflictingByteObservations > 0,
        contiguous: chunks.length <= 1, completeness: 'Only observed bytes are reconstructed; capture start/end and missing prefixes/tails are not inferred.' };
      delete value._chunks; delete value.anchor;
      if (value.sequenceRejectedPackets.length) { value.unsupported = { reason: 'sequence-distance-exceeds-32MiB-window', packetIndices: value.sequenceRejectedPackets }; truncate(result, 'tcp-sequence-window'); }
      if (value.ambiguous) value.reconstructionPolicy = 'First captured bytes are retained as an explicit hypothesis; conflicting alternatives are recorded. Automatic decoding is disabled.';
      else value.reconstructionPolicy = 'First captured bytes, duplicate retransmissions compared, holes preserved as separate chunks.';
      if (value.omittedConflicts) truncate(result, 'conflict-evidence-budget');
      if (options.schema || options.framing) {
        if (value.ambiguous) value.decodeSkipped = 'conflicting-retransmission';
        else {
          const sources = flow.tuple.protocol === 'tcp' ? chunks : value.datagrams;
          value.decodes = [];
          for (let i = 0; i < sources.length; i++) {
            if (frameBudget <= 0 || decodedFieldsBudget <= 0 || fieldByteBudget <= 0) { truncate(result, 'capture-decode-budget'); break; }
            // Framing after a TCP hole has no established alignment. Do not invent a new boundary.
            if (flow.tuple.protocol === 'tcp' && i > 0) { value.decodes.push({ chunkIndex: i, skipped: 'frame-boundary-unknown-after-hole' }); continue; }
            if (flow.tuple.protocol === 'tcp' && (!value.streamStartEstablished || chunks[i].relativeOffset !== 0) && normalizeFraming(options.framing).type !== 'none') {
              value.decodes.push({ chunkIndex: i, skipped: 'capture-start-does-not-establish-frame-boundary' }); continue;
            }
            const decoded = decodeFrames(Buffer.from(sources[i].dataHex, 'hex'), { ...options, maxFrames: frameBudget,
              maxDecodedFields: decodedFieldsBudget, maxFieldBytes: fieldByteBudget });
            frameBudget -= decoded.frames.length;
            decodedFieldsBudget -= decoded.fieldsDecoded; fieldByteBudget -= decoded.fieldBytesProcessed;
            value.decodes.push({ ...(flow.tuple.protocol === 'tcp' ? { chunkIndex: i } : { packetIndex: sources[i].packetIndex }), result: decoded });
          }
        }
      }
      return value;
    });
  }
  result.reassembly = { observedBytesBudgeted: retainedBytes, retainedPayloadPackets: retainedPackets,
    sequenceArithmetic: 'Modulo 2^32 relative to the first observed payload, bounded to +/-32MiB.',
    sessionScope: 'Bidirectional 5-tuples; a distinct initial SYN or terminated connection creates a new incarnation. Mid-capture missing handshakes remain unknown.' };
  return flows;
}

export function parseCapture(input, options = {}) {
  const budget = limits(options), buffer = inputBuffer(input, budget);
  // Validate decode options even if there are no packets to decode.
  if (options.schema !== undefined) schemaFields(options.schema);
  if (options.framing !== undefined) normalizeFraming(options.framing);
  const result = { ...base('capture', buffer, budget), issues: [], packets: [], flows: [], complete: true };
  const magic = buffer.subarray(0, 4).toString('hex');
  let packets;
  if (['d4c3b2a1', 'a1b2c3d4', '4d3cb2a1', 'a1b23c4d'].includes(magic)) packets = parsePcap(buffer, budget, result);
  else if (magic === '0a0d0d0a') packets = parsePcapng(buffer, budget, result);
  else fail('UNSUPPORTED_CAPTURE_FORMAT', 'Input is not a supported PCAP or PCAPNG capture');
  result.packetCount = packets.length;
  result.unsupportedPacketCount = packets.filter(p => p.unsupported).length;
  const unsupported = new Map();
  for (const packet of packets) if (packet.unsupported) {
    let summary = unsupported.get(packet.unsupported.reason);
    if (!summary) { summary = { reason: packet.unsupported.reason, packetCount: 0, packetIndices: [] }; unsupported.set(summary.reason, summary); }
    summary.packetCount++; if (summary.packetIndices.length < 16) summary.packetIndices.push(packet.index);
  }
  result.unsupportedSummary = [...unsupported.values()];
  result.truncatedPacketCount = packets.filter(p => p.truncated).length;
  result.flows = buildFlows(packets, budget, result, options);
  result.packets = packets.slice(0, budget.maxPacketPreviews).map(packet => {
    const value = { ...packet };
    if (value._payload) { value.payload = byteEvidence(value._payload, budget, false); delete value._payload; }
    return value;
  });
  result.packetPreviewsOmitted = Math.max(0, packets.length - result.packets.length);
  if (result.packetPreviewsOmitted) truncate(result, 'packet-preview-budget');
  if (result.truncatedPacketCount) truncate(result, 'capture-packet-truncated');
  result.parseComplete = !result.remainingContainerBytes && !result.issues.length && !result.unsupportedPacketCount;
  result.reassemblyComplete = !result.flows.some(f => f.directions.some(d => d.ambiguous || d.holes.length || d.truncated));
  result.decodingComplete = !result.flows.some(f => f.directions.some(d => d.decodeSkipped || d.decodes?.some(item => item.skipped || !item.result?.complete)));
  result.complete = !result.truncated && result.parseComplete && result.reassemblyComplete && result.decodingComplete;
  result.evidence.checksumVerified = false;
  result.evidence.limitations = ['No IP fragment reassembly, OS execution, decryption, checksum validation, or unknown-protocol identification.',
    'TCP holes are separate chunks. Conflicting retransmissions disable automatic decoding. Streams may begin or end outside the capture.'];
  return result;
}

export function analyzeProtocol(options = {}) {
  object(options, 'options');
  const buffer = parseProtocolBytes(options.data, options.encoding ?? 'hex', options);
  if (options.action === 'capture') return parseCapture(buffer, options);
  if (options.action === 'decode') return decodeFrames(buffer, options);
  if (options.action === 'infer') {
    const budget = limits(options);
    const inference = inferProtocol(buffer, options.inference ?? {}, { parseCapture: bytes => parseCapture(bytes,
      { ...options, framing: undefined, schema: undefined, maxPackets: Math.min(budget.maxPackets, 512),
        maxFlows: Math.min(budget.maxFlows, 32), maxPacketPreviews: 512 }) });
    const result = { ...base('infer', buffer, budget), inference };
    if (inference.budget.exhausted) for (const reason of inference.budget.reasons) truncate(result, reason);
    if (inference.truncated) for (const reason of inference.truncationReasons) truncate(result, reason);
    return result;
  }
  if (options.action === 'inspect' || options.action === undefined) return inspectBytes(buffer, options);
  fail('INVALID_PROTOCOL_ARGUMENT', 'action must be inspect, decode, capture, or infer');
}

export const PROTOCOL_LIMITS = LIMITS;
