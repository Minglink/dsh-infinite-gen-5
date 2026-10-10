import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import { gzipSync, deflateSync } from 'node:zlib';
import { analyzeCrypto, decodeCryptoBytes, CRYPTO_LIMITS, CryptoAnalysisError } from '../source/crypto_analysis.js';

const hex = data => ({ encoding: 'hex', data: Buffer.isBuffer(data) ? data.toString('hex') : data });
const b64 = data => ({ encoding: 'base64', data });
const fail = (fn, code) => assert.throws(fn, error => error instanceof CryptoAnalysisError && error.code === code);
const run = (input, recipe, extra = {}) => analyzeCrypto({ op: 'transform', input: hex(input), recipe, ...extra });
const key128 = '2b7e151628aed2a6abf7158809cf4f3c';
const iv = '000102030405060708090a0b0c0d0e0f';
const plain = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710';
const aes = (kind, key = key128, init = iv, extra = {}) => ({ kind, key: hex(key), iv: hex(init), padding: 'none', ...extra });

test('strict hex decoding rejects truncation, separators, paths, and unsupported fields', () => {
  assert.equal(decodeCryptoBytes(hex('AA00ff')).toString('hex'), 'aa00ff');
  assert.equal(decodeCryptoBytes(hex('')).length, 0);
  for (const value of ['a', 'aa zz', 'aa\n', '0xaa', 'file://sample']) fail(() => decodeCryptoBytes(hex(value)), 'INVALID_BYTES');
  fail(() => decodeCryptoBytes({ encoding: 'hex', data: 12 }), 'INVALID_BYTES');
  fail(() => decodeCryptoBytes({ encoding: 'hex', data: '00', path: 'anything' }), 'INVALID_ARGUMENT');
  fail(() => decodeCryptoBytes({ encoding: 'utf8', data: 'sample' }), 'INVALID_BYTES');
});

test('base64 is canonical with complete padding and zero pad bits', () => {
  assert.equal(decodeCryptoBytes(b64('Zg==')).toString(), 'f');
  assert.equal(decodeCryptoBytes(b64('Zm9v')).toString(), 'foo');
  assert.equal(decodeCryptoBytes(b64('')).length, 0);
  for (const value of ['Zg', 'Zg=', 'Zh==', 'Zm9=', 'Zg==\n', '-w==', 'Zg====', ' Zg==']) fail(() => decodeCryptoBytes(b64(value)), 'INVALID_BYTES');
});

test('encoded and decoded byte budgets are checked before permissive decoders can allocate large buffers', () => {
  fail(() => decodeCryptoBytes(hex('00'.repeat(CRYPTO_LIMITS.inputBytes + 1))), 'INPUT_LIMIT');
  fail(() => decodeCryptoBytes(b64('AAAA'), 'input', 1), 'INPUT_LIMIT');
  assert.equal(decodeCryptoBytes(b64('AA=='), 'input', 1).length, 1);
  fail(() => decodeCryptoBytes(hex('00'), 'input', 0), 'INPUT_LIMIT');
});

test('range selection is explicit, bounded, and preserves original offsets', () => {
  const result = analyzeCrypto({ op: 'verify', input: hex('aabb010203cc'), offset: 2, length: 3, expected: hex('010203') }).result;
  assert.deepEqual(result.range, { offset: 2, length: 3, input_length: 6 });
  assert.equal(result.verification.matched, true);
  for (const extra of [{ offset: -1 }, { offset: 7 }, { offset: true }, { offset: 0.5 }, { length: 7 }, { offset: 2, length: 5 }]) {
    fail(() => analyzeCrypto({ op: 'inspect', input: hex('00'.repeat(6)), ...extra }), 'INVALID_ARGUMENT');
  }
});

test('preview never includes complete output beyond its limit, and invalid UTF8 is explicit', () => {
  const data = Buffer.alloc(6000, 0xff);
  const { result, output } = run(data, { kind: 'xor', key: hex('00') }, { preview_limit: 3 });
  assert.equal(output.length, 6000);
  assert.equal(result.output.preview.hex, 'ffffff');
  assert.equal(result.output.preview.ascii, '...');
  assert.equal(result.output.preview.utf8_json, null);
  assert.equal(result.output.preview.valid_utf8, false);
  assert.equal(result.output.preview.truncated, true);
  assert.equal(run(data, { kind: 'xor', key: hex('00') }, { preview_limit: 0 }).result.output.preview.hex, '');
  fail(() => run(data, { kind: 'xor', key: hex('00') }, { preview_limit: 4097 }), 'INVALID_ARGUMENT');
});

test('UTF8 previews escape control sequences rather than emitting terminal escape streams', () => {
  const { result } = analyzeCrypto({ op: 'inspect', input: hex(Buffer.from('中文\n\x1b[31m')), preview_limit: 64 });
  assert.equal(result.input.preview.valid_utf8, true);
  assert.equal(result.input.preview.utf8_json, '"中文\\n\\u001b[31m"');
});

test('XOR uses only the supplied key and explicit key offset with no secret in evidence', () => {
  const input = hex('00112233445566');
  const recipe = { kind: 'xor', key: hex('deadbeef'), key_offset: 1 };
  const original = JSON.stringify({ input, recipe });
  const { result, output } = analyzeCrypto({ op: 'transform', input, recipe });
  assert.equal(output.toString('hex'), 'adafcdede9eb89');
  assert.equal(JSON.stringify({ input, recipe }), original);
  assert.equal(JSON.stringify(result).includes('deadbeef'), false);
  assert.deepEqual(result.recipe, { kind: 'xor', key_bytes: 4, key_offset: 1, key_redacted: true });
  fail(() => run('00', { kind: 'xor', key: hex('') }), 'INVALID_KEY');
  fail(() => run('00', { kind: 'xor', key: hex('ff'), key_offset: 1 }), 'INVALID_ARGUMENT');
});

// Fixed independent known-answer vectors: NIST SP 800-38A Appendix F.2.2/4/6.
// https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
for (const [bits, key, ciphertext] of [
  [128, key128, '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7'],
  [192, '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', '4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd'],
  [256, '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b'],
]) {
  test(`AES-${bits} CBC decrypt matches all four fixed NIST blocks`, () => {
    const { result, output } = run(ciphertext, aes('aes-cbc', key), { expected: hex(plain) });
    assert.equal(output.toString('hex'), plain);
    assert.equal(result.recipe.key_bits, bits);
    assert.equal(result.verification.status, 'matched');
    assert.equal(result.authentication.status, 'not-provided');
    assert.equal(JSON.stringify(result).includes(key), false);
  });
}

test('AES CTR matches fixed NIST F.5.2 including a partial final block', () => {
  const ciphertext = '874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee';
  const recipe = aes('aes-ctr', key128, 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  assert.equal(run(ciphertext, recipe).output.toString('hex'), plain);
  assert.equal(run(ciphertext.slice(0, 74), recipe).output.toString('hex'), plain.slice(0, 74));
});

// AES GCM standard zero-key/zero-IV vectors. NIST CAVP reference:
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
const gcm = aes('aes-gcm', '00'.repeat(16), '00'.repeat(12), { tag: hex('ab6e47d42cec13bdf53a67b21257bddf') });
test('AES GCM authenticates its fixed ciphertext and tag before returning known plaintext', () => {
  const { output, result } = run('0388dace60b6a392f328c2b971b2fe78', gcm, { expected: hex('00'.repeat(16)) });
  assert.equal(output.toString('hex'), '00'.repeat(16));
  assert.equal(result.authentication.status, 'passed');
  assert.equal(result.verification.status, 'matched');
});

test('AES GCM authenticates zero-length plaintext as a distinct valid result', () => {
  const { output, result } = run('', { ...gcm, tag: hex('58e2fccefa7e3061367f1d57a4e7455a') }, { expected: hex('') });
  assert.equal(output.length, 0);
  assert.equal(result.verification.status, 'matched');
});

test('AES GCM rejects altered tags without attaching plaintext or parameters to errors', () => {
  try {
    run('0388dace60b6a392f328c2b971b2fe78', { ...gcm, tag: hex('aa6e47d42cec13bdf53a67b21257bddf') });
    assert.fail('modified tag must fail');
  } catch (error) {
    assert.equal(error.code, 'AUTHENTICATION_FAILED');
    assert.deepEqual(Object.keys(error).sort(), ['code', 'name']);
    assert.equal(error.message.includes('0388dace'), false);
    assert.equal(error.output, undefined);
  }
});

test('AES GCM binds supplied AAD to authentication', () => {
  const key = Buffer.from(key128, 'hex');
  const init = Buffer.from('11'.repeat(12), 'hex');
  const aad = Buffer.from('ig5-config:v1');
  const text = Buffer.from('{"endpoint":"local","retry":3}');
  const cipher = createCipheriv('aes-128-gcm', key, init);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  const recipe = aes('aes-gcm', key128, init.toString('hex'), { tag: hex(cipher.getAuthTag()), aad: hex(aad) });
  assert.equal(run(encrypted, recipe, { expected: hex(text) }).result.verification.matched, true);
  fail(() => run(encrypted, { ...recipe, aad: hex(Buffer.from('ig5-config:v2')) }), 'AUTHENTICATION_FAILED');
});

test('CBC PKCS7 output budget measures plaintext after valid padding removal', () => {
  const text = Buffer.from('config=ok');
  const cipher = createCipheriv('aes-128-cbc', Buffer.from(key128, 'hex'), Buffer.from(iv, 'hex'));
  const ciphertext = Buffer.concat([cipher.update(text), cipher.final()]);
  const { output } = run(ciphertext, aes('aes-cbc', key128, iv, { padding: 'pkcs7' }), { output_limit: text.length });
  assert.equal(output.toString(), 'config=ok');
  fail(() => run(ciphertext, aes('aes-cbc', key128, iv, { padding: 'pkcs7' }), { output_limit: text.length - 1 }), 'OUTPUT_LIMIT');
});

test('AES padding and parameter errors are explicit instead of silently defaulting', () => {
  fail(() => run('00'.repeat(16), { ...aes('aes-cbc'), padding: undefined }), 'INVALID_PADDING');
  fail(() => run('00'.repeat(16), aes('aes-ctr', key128, iv, { padding: 'pkcs7' })), 'INVALID_PADDING');
  fail(() => run('00', aes('aes-cbc')), 'INVALID_BLOCK_LENGTH');
  fail(() => run('', aes('aes-cbc', key128, iv, { padding: 'pkcs7' })), 'INVALID_BLOCK_LENGTH');
  fail(() => run('00'.repeat(16), aes('aes-cbc', '00'.repeat(15))), 'INVALID_KEY');
  fail(() => run('00'.repeat(16), aes('aes-cbc', key128, '00'.repeat(15))), 'INVALID_IV');
  fail(() => run('00', { ...gcm, tag: undefined }), 'INVALID_ARGUMENT');
  fail(() => run('00', { ...gcm, tag: hex('00'.repeat(9)) }), 'INVALID_TAG');
  fail(() => run('00', { ...gcm, iv: hex('') }), 'INVALID_IV');
  fail(() => run('7649abac8119b246cee98e9b12e9197d', aes('aes-cbc', key128, iv, { padding: 'pkcs7' })), 'DECRYPTION_FAILED');
});

test('gzip and zlib decompress exact streams with verified plaintext', () => {
  const text = Buffer.from('{"中文":"配置","port":443}');
  for (const [kind, compressor] of [['gzip', gzipSync], ['zlib', deflateSync]]) {
    const { result, output } = run(compressor(text), { kind }, { expected: hex(text) });
    assert.deepEqual(output, text);
    assert.equal(result.verification.status, 'matched');
    assert.equal(result.authentication.status, 'not-provided');
  }
});

test('decompression bombs and invalid compressed input fail without partial output', () => {
  const text = Buffer.alloc(100000, 65);
  for (const [kind, compressor] of [['gzip', gzipSync], ['zlib', deflateSync]]) {
    fail(() => run(compressor(text), { kind }, { output_limit: 128 }), 'OUTPUT_LIMIT');
    const valid = compressor(Buffer.from('hello'));
    valid[valid.length - 1] ^= 1;
    fail(() => run(valid, { kind }), 'DECOMPRESSION_FAILED');
    fail(() => run(Buffer.from([0, 0, 0]), { kind }), 'DECOMPRESSION_FAILED');
  }
});

test('zlib trailing garbage cannot disappear silently during extraction', () => {
  const valid = deflateSync(Buffer.from('hello'));
  const blob = Buffer.concat([valid, Buffer.from('trailing')]);
  fail(() => run(blob, { kind: 'zlib' }), 'TRAILING_COMPRESSED_DATA');
  assert.equal(run(blob, { kind: 'zlib' }, { length: valid.length }).output.toString(), 'hello');
});

test('inspection reports encoding/compression evidence without claiming encryption identification', () => {
  const uniform = Buffer.from(Array.from({ length: 256 }, (_, index) => index));
  const high = analyzeCrypto({ op: 'inspect', input: hex(uniform) });
  assert.equal(high.output, null);
  assert.equal(high.result.analysis.entropy_bits_per_byte, 8);
  assert.equal(high.result.analysis.evidence.length, 0);
  assert.equal(high.result.verification.status, 'not-requested');
  assert.match(high.result.analysis.interpretation, /do not establish encryption/);
  const zero = analyzeCrypto({ op: 'inspect', input: hex(Buffer.alloc(100)) }).result;
  assert.equal(zero.analysis.entropy_bits_per_byte, 0);
  assert.equal(zero.analysis.zero_bytes, 100);
  const encoded = analyzeCrypto({ op: 'inspect', input: hex(Buffer.from('aGVsbG8=')) }).result;
  assert.equal(encoded.analysis.evidence[0].kind, 'base64-text');
  const compressed = analyzeCrypto({ op: 'inspect', input: hex(gzipSync(Buffer.from('hello'))) }).result;
  assert.equal(compressed.analysis.evidence[0].kind, 'gzip-header');
  assert.equal(compressed.analysis.evidence[0].validated_payload, false);
});

test('verification requires explicit expected bytes and distinguishes content from length mismatch', () => {
  fail(() => analyzeCrypto({ op: 'verify', input: hex('00') }), 'EXPECTED_REQUIRED');
  for (const [expected, offset] of [['010003', 1], ['0102', 2], ['01020304', 3]]) {
    const v = analyzeCrypto({ op: 'verify', input: hex('010203'), expected: hex(expected) }).result.verification;
    assert.equal(v.matched, false);
    assert.equal(v.status, 'mismatched');
    assert.equal(v.first_mismatch_offset, offset);
  }
  const result = run('010203', { kind: 'xor', key: hex('00') }, { expected: hex('000000') }).result;
  assert.equal(result.verification.status, 'mismatched');
});

test('encrypted configuration extraction is reproducible with explicit AES and compression stages', () => {
  const config = Buffer.from('{"server":"127.0.0.1","port":9001,"feature":true}');
  const compressed = gzipSync(config);
  const init = Buffer.from('22'.repeat(12), 'hex');
  const cipher = createCipheriv('aes-128-gcm', Buffer.from(key128, 'hex'), init);
  const encrypted = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const decrypted = run(encrypted, aes('aes-gcm', key128, init.toString('hex'), { tag: hex(cipher.getAuthTag()) }));
  assert.equal(decrypted.result.authentication.status, 'passed');
  assert.equal(decrypted.result.verification.status, 'not-requested');
  const unpacked = run(decrypted.output, { kind: 'gzip' }, { expected: hex(config) });
  assert.deepEqual(unpacked.output, config);
  assert.equal(unpacked.result.verification.status, 'matched');
});

test('unsupported operations, unexpected recipe fields, and budgets fail closed', () => {
  fail(() => analyzeCrypto({ op: 'brute-force', input: hex('00') }), 'INVALID_OPERATION');
  fail(() => analyzeCrypto({ op: 'inspect', input: hex('00'), recipe: { kind: 'xor', key: hex('00') } }), 'INVALID_RECIPE');
  fail(() => run('00', { kind: 'rc4', key: hex('00') }), 'INVALID_RECIPE');
  fail(() => run('00', { kind: 'xor', key: hex('00'), iv: hex('00') }), 'INVALID_RECIPE');
  fail(() => run('00', { kind: 'xor', key: hex('00'), brute_force: true }), 'INVALID_ARGUMENT');
  fail(() => run('00', { kind: 'gzip', key: hex('00') }), 'INVALID_RECIPE');
  fail(() => run('0000', { kind: 'xor', key: hex('00') }, { output_limit: 1 }), 'OUTPUT_LIMIT');
  fail(() => run('00', { kind: 'xor', key: hex('00') }, { output_limit: 0 }), 'INVALID_ARGUMENT');
  fail(() => run('00', { kind: 'xor', key: hex('00') }, { output_limit: CRYPTO_LIMITS.outputBytes + 1 }), 'INVALID_ARGUMENT');
});
