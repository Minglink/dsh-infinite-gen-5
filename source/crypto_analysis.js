import { createDecipheriv, createHash, timingSafeEqual } from 'node:crypto';
import { gunzipSync, inflateSync } from 'node:zlib';
import { TextDecoder } from 'node:util';
import { recoverCrypto } from './crypto_recovery.js';

/** Pure local buffer analysis. No files, sample execution, engine, or network. */
export const CRYPTO_LIMITS = Object.freeze({
  inputBytes: 1024 * 1024,
  outputBytes: 1024 * 1024,
  previewBytes: 4096,
  defaultPreviewBytes: 256,
  keyBytes: 4096,
  parameterBytes: 1024,
});

export class CryptoAnalysisError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CryptoAnalysisError';
    this.code = code;
  }
}

function fail(code, message) { throw new CryptoAnalysisError(code, message); }

function object(value, name, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Buffer.isBuffer(value)) {
    fail('INVALID_ARGUMENT', `${name} must be an object`);
  }
  if (Object.keys(value).some(key => !keys.includes(key))) fail('INVALID_ARGUMENT', `${name} has unsupported fields`);
  return value;
}

function integer(value, name, min, max, fallback) {
  if (value === undefined && fallback !== undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    fail('INVALID_ARGUMENT', `${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

/** Canonical, bounded bytes. Rejects Node's otherwise permissive base64/hex truncation. */
export function decodeCryptoBytes(value, name = 'input', maxBytes = CRYPTO_LIMITS.inputBytes) {
  integer(maxBytes, 'maxBytes', 0, CRYPTO_LIMITS.inputBytes);
  object(value, name, ['encoding', 'data']);
  if (typeof value.data !== 'string') fail('INVALID_BYTES', `${name}.data must be a string`);
  if (value.encoding === 'hex') {
    if (value.data.length > maxBytes * 2) fail('INPUT_LIMIT', `${name} exceeds the byte budget`);
    if ((value.data.length & 1) || !/^[0-9a-fA-F]*$/.test(value.data)) {
      fail('INVALID_BYTES', `${name} must contain complete hex byte pairs without separators`);
    }
    return Buffer.from(value.data, 'hex');
  }
  if (value.encoding === 'base64') {
    if (value.data.length > 4 * Math.ceil(maxBytes / 3)) fail('INPUT_LIMIT', `${name} exceeds the byte budget`);
    if (value.data.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value.data)) {
      fail('INVALID_BYTES', `${name} must contain canonical padded base64 without whitespace`);
    }
    const bytes = Buffer.from(value.data, 'base64');
    if (bytes.length > maxBytes) fail('INPUT_LIMIT', `${name} exceeds the byte budget`);
    if (bytes.toString('base64') !== value.data) fail('INVALID_BYTES', `${name} has noncanonical base64 padding bits`);
    return bytes;
  }
  fail('INVALID_BYTES', `${name}.encoding must be hex or base64`);
}

function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

function utf8(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { return null; }
}

function preview(bytes, limit) {
  const prefix = bytes.subarray(0, limit);
  const decoded = utf8(prefix);
  return {
    length: prefix.length,
    hex: prefix.toString('hex'),
    ascii: prefix.toString('latin1').replace(/[^\x20-\x7e]/g, '.'),
    // JSON escaping keeps control characters explicit; this is not HTML or a terminal escape stream.
    utf8_json: decoded === null ? null : JSON.stringify(decoded),
    valid_utf8: decoded !== null,
    truncated: prefix.length < bytes.length,
  };
}

function summary(bytes, limit) { return { length: bytes.length, sha256: hash(bytes), preview: preview(bytes, limit) }; }

function verify(bytes, expected) {
  if (expected === undefined) return { status: 'not-requested', matched: null };
  const wanted = decodeCryptoBytes(expected, 'expected');
  const matched = bytes.length === wanted.length && timingSafeEqual(bytes, wanted);
  let mismatch = null;
  if (!matched) {
    const common = Math.min(bytes.length, wanted.length);
    let index = 0;
    while (index < common && bytes[index] === wanted[index]) index++;
    mismatch = index;
  }
  return {
    status: matched ? 'matched' : 'mismatched',
    matched,
    expected_length: wanted.length,
    actual_length: bytes.length,
    expected_sha256: hash(wanted),
    actual_sha256: hash(bytes),
    first_mismatch_offset: mismatch,
  };
}

function inspect(bytes) {
  const counts = new Uint32Array(256);
  let printable = 0;
  for (const byte of bytes) {
    counts[byte]++;
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 9 || byte === 10 || byte === 13) printable++;
  }
  let entropy = 0;
  for (const count of counts) {
    if (count) { const probability = count / bytes.length; entropy -= probability * Math.log2(probability); }
  }
  const evidence = [];
  if (bytes.length >= 3 && bytes[0] === 0x1f && bytes[1] === 0x8b && bytes[2] === 8) {
    evidence.push({ kind: 'gzip-header', offset: 0, length: 3, validated_payload: false });
  }
  if (bytes.length >= 2 && (bytes[0] & 0xf) === 8 && (bytes[0] >>> 4) <= 7 && ((bytes[0] << 8) + bytes[1]) % 31 === 0) {
    evidence.push({ kind: 'zlib-header', offset: 0, length: 2, dictionary_required: Boolean(bytes[1] & 0x20), validated_payload: false });
  }
  if (bytes.length && bytes.every(byte => byte < 128)) {
    const text = bytes.toString('ascii');
    if (!(text.length & 1) && /^[0-9a-fA-F]+$/.test(text)) evidence.push({ kind: 'hex-text', offset: 0, length: bytes.length, decoded_length: text.length / 2 });
    if (/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) {
      const decoded = Buffer.from(text, 'base64');
      if (decoded.toString('base64') === text) evidence.push({ kind: 'base64-text', offset: 0, length: bytes.length, decoded_length: decoded.length });
    }
  }
  return {
    entropy_bits_per_byte: Math.round(entropy * 1000000) / 1000000,
    entropy_sample_bytes: bytes.length,
    printable_ascii_fraction: bytes.length ? printable / bytes.length : null,
    zero_bytes: counts[0],
    distinct_bytes: counts.reduce((sum, count) => sum + Boolean(count), 0),
    valid_utf8: utf8(bytes) !== null,
    block_aligned_16: bytes.length > 0 && bytes.length % 16 === 0,
    evidence,
    interpretation: 'Encoding patterns, compression headers, block alignment, and entropy are evidence only; they do not establish encryption, an algorithm, a key, or successful decryption.',
  };
}

function noFields(recipe, fields) {
  if (fields.some(field => recipe[field] !== undefined)) fail('INVALID_RECIPE', 'Recipe has parameters that do not apply to this operation');
}

function transform(bytes, recipe, outputLimit, validateOnly = false, prepared = null) {
  object(recipe, 'recipe', ['kind', 'key', 'iv', 'tag', 'aad', 'padding', 'key_offset']);
  if (recipe.kind === 'xor') {
    noFields(recipe, ['iv', 'tag', 'aad', 'padding']);
    const key = decodeCryptoBytes(recipe.key, 'recipe.key', CRYPTO_LIMITS.keyBytes);
    if (!key.length) fail('INVALID_KEY', 'XOR requires an explicit nonempty key');
    const keyOffset = integer(recipe.key_offset, 'recipe.key_offset', 0, key.length - 1, 0);
    if (bytes.length > outputLimit) fail('OUTPUT_LIMIT', 'Transform output exceeds the byte budget');
    const output = Buffer.allocUnsafe(bytes.length);
    for (let i = 0; i < bytes.length; i++) output[i] = bytes[i] ^ key[(i + keyOffset) % key.length];
    return { output, recipe: { kind: 'xor', key_bytes: key.length, key_offset: keyOffset, key_redacted: true }, authentication: { status: 'not-provided' } };
  }
  if (recipe.kind === 'gzip' || recipe.kind === 'zlib') {
    noFields(recipe, ['key', 'iv', 'tag', 'aad', 'padding', 'key_offset']);
    try {
      const decoded = (recipe.kind === 'gzip' ? gunzipSync : inflateSync)(bytes, { maxOutputLength: outputLimit, info: true });
      if (decoded.engine.bytesWritten !== bytes.length) fail('TRAILING_COMPRESSED_DATA', 'Compressed input has trailing bytes; select its exact offset and length');
      const output = decoded.buffer;
      return { output, recipe: { kind: recipe.kind }, authentication: { status: 'not-provided' } };
    } catch (error) {
      if (error instanceof CryptoAnalysisError) throw error;
      if (error?.code === 'ERR_BUFFER_TOO_LARGE') fail('OUTPUT_LIMIT', 'Decompressed output exceeds the byte budget');
      fail('DECOMPRESSION_FAILED', 'Compressed input failed format or checksum validation; no output is returned');
    }
  }
  if (!['aes-cbc', 'aes-ctr', 'aes-gcm'].includes(recipe.kind)) fail('INVALID_RECIPE', 'Unsupported transform; use xor, aes-cbc, aes-ctr, aes-gcm, gzip, or zlib');
  noFields(recipe, ['key_offset']);
  const key = decodeCryptoBytes(recipe.key, 'recipe.key', 32);
  if (![16, 24, 32].includes(key.length)) fail('INVALID_KEY', 'AES requires an explicit 16, 24, or 32 byte key');
  // Internal recovery caches already-validated AES metadata once; public recipes cannot supply it.
  const iv = prepared?.iv ?? decodeCryptoBytes(recipe.iv, 'recipe.iv', recipe.kind === 'aes-gcm' ? CRYPTO_LIMITS.parameterBytes : 16);
  if (recipe.kind !== 'aes-gcm' && iv.length !== 16) fail('INVALID_IV', 'AES CBC/CTR requires an explicit 16 byte IV or initial counter block');
  if (recipe.kind === 'aes-gcm' && !iv.length) fail('INVALID_IV', 'AES GCM requires an explicit nonempty IV');
  if (!['none', 'pkcs7'].includes(recipe.padding)) fail('INVALID_PADDING', 'AES padding must be explicitly none or pkcs7');
  if (recipe.kind !== 'aes-cbc' && recipe.padding !== 'none') fail('INVALID_PADDING', 'AES CTR/GCM requires padding=none');
  if (recipe.kind === 'aes-cbc' && (bytes.length % 16 || (recipe.padding === 'pkcs7' && !bytes.length))) fail('INVALID_BLOCK_LENGTH', 'AES CBC ciphertext must contain complete blocks, with at least one block for PKCS7');
  if (recipe.padding !== 'pkcs7' && bytes.length > outputLimit) fail('OUTPUT_LIMIT', 'Transform output exceeds the byte budget');
  let tag;
  let aad;
  if (recipe.kind === 'aes-gcm') {
    tag = prepared?.tag ?? decodeCryptoBytes(recipe.tag, 'recipe.tag', 16);
    if (![4, 8, 12, 13, 14, 15, 16].includes(tag.length)) fail('INVALID_TAG', 'AES GCM requires an explicit 4, 8, or 12–16 byte authentication tag');
    aad = prepared?.aad ?? (recipe.aad === undefined ? Buffer.alloc(0) : decodeCryptoBytes(recipe.aad, 'recipe.aad'));
  } else noFields(recipe, ['tag', 'aad']);
  if (validateOnly) return { validated: true, prepared: { iv, tag, aad } };
  let decipher;
  try {
    const mode = recipe.kind.slice(4);
    decipher = createDecipheriv(`aes-${key.length * 8}-${mode}`, key, iv, tag ? { authTagLength: tag.length } : undefined);
    decipher.setAutoPadding(recipe.padding === 'pkcs7');
    if (tag) { decipher.setAuthTag(tag); decipher.setAAD(aad); }
  } catch {
    fail('CIPHER_INITIALIZATION_FAILED', 'AES parameters are not supported by the local crypto runtime; no output is returned');
  }
  try {
    // Never publish update() plaintext before final() authenticates GCM or checks CBC padding.
    const provisional = decipher.update(bytes);
    const final = decipher.final();
    const output = Buffer.concat([provisional, final]);
    if (output.length > outputLimit) fail('OUTPUT_LIMIT', 'Transform output exceeds the byte budget');
    return {
      output,
      recipe: { kind: recipe.kind, direction: 'decrypt', key_bits: key.length * 8, key_redacted: true, iv_bytes: iv.length, padding: recipe.padding, ...(tag ? { tag_bytes: tag.length, aad_bytes: aad.length } : {}) },
      authentication: { status: tag ? 'passed' : 'not-provided', ...(tag ? { scope: 'Supplied ciphertext, key, IV, AAD, and tag; this does not identify the algorithm used by a binary.' } : {}) },
    };
  } catch (error) {
    if (error instanceof CryptoAnalysisError) throw error;
    if (tag) fail('AUTHENTICATION_FAILED', 'AES GCM authentication failed; no plaintext is returned');
    fail('DECRYPTION_FAILED', 'AES decryption or PKCS7 validation failed; no output is returned');
  }
}

/**
 * Return serializable bounded evidence separately from complete output bytes.
 * The caller alone may publish output through its artifact layer. Never serialize this entire return value.
 * Recovery returns bounded hypotheses and publishes output only after strong verification.
 */
export function analyzeCrypto(request) {
  object(request, 'request', ['op', 'input', 'offset', 'length', 'preview_limit', 'output_limit', 'recipe', 'expected', 'recovery']);
  if (!['inspect', 'transform', 'verify', 'recover'].includes(request.op)) fail('INVALID_OPERATION', 'op must be inspect, transform, verify, or recover');
  const input = decodeCryptoBytes(request.input);
  const offset = integer(request.offset, 'offset', 0, input.length, 0);
  const length = integer(request.length, 'length', 0, input.length - offset, input.length - offset);
  const limit = integer(request.preview_limit, 'preview_limit', 0, CRYPTO_LIMITS.previewBytes, CRYPTO_LIMITS.defaultPreviewBytes);
  const outputLimit = integer(request.output_limit, 'output_limit', 1, CRYPTO_LIMITS.outputBytes, CRYPTO_LIMITS.outputBytes);
  const bytes = input.subarray(offset, offset + length);
  if (request.op !== 'transform' && request.recipe !== undefined) fail('INVALID_RECIPE', 'Only transform accepts a recipe');
  if (request.op !== 'recover' && request.recovery !== undefined) fail('INVALID_RECOVERY', 'Only recover accepts recovery parameters');
  if (request.op === 'verify' && request.expected === undefined) fail('EXPECTED_REQUIRED', 'verify requires explicit expected bytes');
  // Validate expected before processing a transform (and before doing cryptographic work).
  if (request.expected !== undefined) decodeCryptoBytes(request.expected, 'expected');
  const base = {
    schema: 'ig5.crypto.v1',
    op: request.op,
    action: request.op,
    range: { offset, length, input_length: input.length },
    input: summary(bytes, limit),
    limits: { input_bytes: CRYPTO_LIMITS.inputBytes, output_bytes: outputLimit, preview_bytes: limit },
  };
  if (request.op === 'inspect') return { result: { ...base, analysis: inspect(bytes), verification: verify(bytes, request.expected) }, output: null };
  if (request.op === 'verify') return { result: { ...base, verification: verify(bytes, request.expected) }, output: null };
  if (request.op === 'recover') {
    const recovered = recoverCrypto(bytes, request.recovery ?? {}, { expected: request.expected === undefined ? undefined : decodeCryptoBytes(request.expected, 'expected'), outputLimit, previewLimit: limit }, { decodeBytes: decodeCryptoBytes, fail, transform, summary });
    return { result: { ...base, recovery: recovered.recovery, ...(recovered.output ? { output: summary(recovered.output, limit) } : {}), authentication: recovered.authentication, verification: recovered.verification }, output: recovered.output };
  }
  const transformed = transform(bytes, request.recipe, outputLimit);
  return {
    result: { ...base, recipe: transformed.recipe, output: summary(transformed.output, limit), authentication: transformed.authentication, verification: verify(transformed.output, request.expected) },
    output: transformed.output,
  };
}
