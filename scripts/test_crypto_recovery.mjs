import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { analyzeCrypto, CryptoAnalysisError } from '../source/crypto_analysis.js';

const hex = bytes => ({ encoding: 'hex', data: Buffer.from(bytes).toString('hex') });
const fromHex = data => ({ encoding: 'hex', data });
const x = (bytes, key) => Buffer.from(bytes.map((b, i) => b ^ key[i % key.length]));
const recover = (bytes, recovery = {}, rest = {}) => analyzeCrypto({ op: 'recover', input: hex(bytes), recovery, ...rest });
const failures = (call, code) => assert.throws(call, error => error instanceof CryptoAnalysisError && error.code === code);
const english = Buffer.from('When the application receives a message from the client, it checks the protocol header and reads the data. The function returns a clear error if the length is not valid. This configuration contains the server address and the connection timeout. A good test compares every byte with the expected result, and the parser keeps each message separate. We need the original evidence to understand how the program handles a request and to explain the result to another analyst.\n'.repeat(3));
const xorKey = Buffer.from('ICE');
const key = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const iv = Buffer.from('010203040506070809101112', 'hex');
const aad = Buffer.from('ig5-recovery-fixture-v1');
function encrypted(plaintext = english, mode = 'aes-gcm', candidateKey = key, tagLength = 16) {
  const init = mode === 'aes-gcm' ? iv : Buffer.alloc(16, 0x2a);
  const cipher = createCipheriv(`aes-${candidateKey.length * 8}-${mode.slice(4)}`, candidateKey, init, mode === 'aes-gcm' ? { authTagLength: tagLength } : undefined);
  if (mode === 'aes-gcm') cipher.setAAD(aad);
  if (mode === 'aes-ctr') cipher.setAutoPadding(false);
  const bytes = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { bytes, aes: { kind: mode, iv: hex(init), padding: mode === 'aes-cbc' ? 'pkcs7' : 'none', ...(mode === 'aes-gcm' ? { tag: hex(cipher.getAuthTag()), aad: hex(aad) } : {}) } };
}

test('all 256 one-byte XOR keys are ranked without promoting text to verified output', () => {
  const plaintext = Buffer.from('The quick brown fox jumps over the lazy dog. This is a protocol message with clear English text.');
  const { result, output } = recover(x(plaintext, Buffer.from([0xb7])), { method: 'xor-single' });
  assert.equal(result.recovery.trials, 256);
  assert.equal(result.recovery.status, 'candidate');
  assert.equal(output, null);
  const top = result.recovery.candidates[0];
  assert.equal(top.keyMaterial.dataHex, 'b7');
  assert.equal(top.plaintext.dataHex, plaintext.toString('hex'));
  assert.equal(top.verification, 'statistical-candidate');
  assert.equal(top.keyComplete, true);
  assert.equal(top.keyMaterial.known_mask, '01');
  assert.equal(top.keyMaterial.unknown_mask, '00');
});

test('full expected plaintext verifies recovered one-byte XOR rather than text score', () => {
  const plain = Buffer.from('arbitrary\x00binary\xffdata', 'latin1');
  const answer = recover(x(plain, Buffer.from([0x71])), { method: 'xor-single' }, { expected: hex(plain) });
  assert.equal(answer.result.recovery.status, 'verified');
  assert.deepEqual(answer.output, plain);
  assert.equal(answer.result.verification.status, 'matched');
  assert.equal(answer.result.recovery.candidates[0].keyMaterial.dataHex, '71');
});

test('repeating XOR key is recovered without a crib or expected value, then independently verified', () => {
  const cipher = x(english, xorKey);
  const candidate = recover(cipher, { method: 'xor-repeat', max_key_bytes: 12 });
  assert.equal(candidate.output, null);
  assert.equal(candidate.result.recovery.status, 'candidate');
  assert.equal(candidate.result.recovery.candidates[0].keyMaterial.dataHex, xorKey.toString('hex'));
  assert.equal(candidate.result.recovery.candidates[0].plaintext.dataHex, english.toString('hex'));
  assert.equal(candidate.result.recovery.candidates[0].verification, 'statistical-candidate');
  assert.ok(candidate.result.recovery.evidence.some(e => e.kind === 'key-length-ranking'));
  const independent = recover(cipher, { method: 'xor-repeat', max_key_bytes: 12 }, { expected: hex(english) });
  assert.equal(independent.result.recovery.status, 'verified');
  assert.deepEqual(independent.output, english);
  assert.equal(independent.result.recovery.strong_hypotheses, 1);
});

test('known plaintext periodic constraints recover a repeating key while remaining candidate evidence', () => {
  const bytes = x(english, xorKey);
  const out = recover(bytes, { method: 'xor-repeat', key_lengths: [3], known_plaintext: [{ offset: 3, ...hex(english.subarray(3, 21)) }] });
  assert.equal(out.output, null);
  assert.equal(out.result.recovery.status, 'candidate');
  assert.equal(out.result.recovery.candidates[0].keyMaterial.dataHex, '494345');
  assert.equal(out.result.recovery.candidates[0].verification, 'known-plaintext-constraints');
});

test('short incomplete cribs return masks and never execute unknown key bytes', () => {
  const plain = Buffer.from('abcde');
  const candidate = recover(x(plain, Buffer.from('secret')), { method: 'xor-repeat', key_lengths: [6], known_plaintext: [{ offset: 1, ...hex(plain.subarray(1, 3)) }] });
  const top = candidate.result.recovery.candidates[0];
  assert.equal(top.keyComplete, false);
  assert.equal(top.keyMaterial.keyComplete, false);
  assert.equal(top.keyMaterial.known_mask, '000101000000');
  assert.equal(top.keyMaterial.unknown_mask, '010000010101');
  assert.equal(top.plaintext, null);
  assert.equal(candidate.output, null);
});

test('contradictory repeated-key cribs reject rather than silently overwrite recovered bytes', () => {
  const out = recover(Buffer.from([1, 2, 3, 4]), { method: 'xor-repeat', key_lengths: [2], known_plaintext: [{ offset: 0, ...hex(Buffer.from([0, 0, 0])) }] });
  assert.equal(out.result.recovery.status, 'not-found');
  assert.equal(out.result.recovery.candidates.length, 0);
});

test('selected input offsets keep crib offsets relative to the selected ciphertext', () => {
  const ciphertext = x(english, xorKey);
  const whole = Buffer.concat([Buffer.from('prefix'), ciphertext, Buffer.from('suffix')]);
  const out = recover(whole, { method: 'xor-repeat', key_lengths: [3], known_plaintext: [{ offset: 0, ...hex(english.subarray(0, 9)) }] }, { offset: 6, length: ciphertext.length, expected: hex(english) });
  assert.equal(out.result.range.offset, 6);
  assert.deepEqual(out.output, english);
});

test('flat, deterministic random, short, and empty data do not produce plausible text or verified guesses', () => {
  let state = 0x31415926;
  const random = Buffer.from(Array.from({ length: 1024 }, () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state & 255; }));
  for (const bytes of [Buffer.alloc(1024), Buffer.alloc(512, 0x31), random, Buffer.from([1, 2, 3]), Buffer.alloc(0)]) {
    const out = recover(bytes, { method: 'auto', max_key_bytes: 8 });
    assert.equal(out.output, null);
    assert.equal(out.result.recovery.status, 'not-found');
  }
});

test('budget exhaustion is a structured unresolved result and counts unsuccessful candidates', () => {
  const out = recover(x(english, xorKey), { method: 'xor-single', max_trials: 2 });
  assert.equal(out.result.recovery.trials, 2);
  assert.equal(out.result.recovery.search_truncated, true);
  assert.ok(out.result.recovery.truncation_reasons.includes('max_trials'));
  assert.equal(out.output, null);
  const noWork = recover(english, { method: 'xor-single', max_work_bytes: 1 });
  assert.ok(noWork.result.recovery.work_bytes <= 1);
  assert.ok(noWork.result.recovery.truncation_reasons.includes('max_work_bytes'));
});

test('AES GCM searches bounded candidates and returns only authenticated matching plaintext', () => {
  const { bytes, aes } = encrypted();
  const out = recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(Buffer.alloc(16, 7)), hex(key)] });
  assert.equal(out.result.recovery.trials, 2);
  assert.equal(out.result.recovery.rejected, 1);
  assert.equal(out.result.recovery.status, 'verified');
  assert.equal(out.result.authentication.status, 'passed');
  assert.deepEqual(out.output, english);
  assert.equal(out.result.recovery.candidates[0].keyMaterial.dataHex, key.toString('hex'));
  assert.equal(out.result.recovery.candidates[0].evidence[0].source, 'explicit-candidate');
});

test('ASCII hex key material and aligned raw windows automatically locate keys', () => {
  const { bytes, aes } = encrypted();
  for (const [material, source] of [[Buffer.from(`noise:key=${key.toString('hex')};end`), 'material-ascii-hex'], [Buffer.concat([Buffer.alloc(16, 0xa5), key, Buffer.alloc(16, 0x7b)]), 'material-raw-window']]) {
    const out = recover(bytes, { method: 'aes-candidates', aes, key_material: hex(material) });
    assert.equal(out.result.recovery.status, 'verified');
    assert.deepEqual(out.output, english);
    assert.equal(out.result.recovery.candidates[0].evidence[0].source, source);
  }
});

test('AES-256 is included in automatic raw material windows by default', () => {
  const strongKey = Buffer.from('42'.repeat(32), 'hex');
  const { bytes, aes } = encrypted(english, 'aes-gcm', strongKey);
  const out = recover(bytes, { method: 'aes-candidates', aes, key_material: hex(Buffer.concat([Buffer.alloc(16, 1), strongKey])) });
  assert.equal(out.result.recovery.status, 'verified');
  assert.equal(out.result.recovery.candidates[0].key_bytes, 32);
  assert.deepEqual(out.output, english);
});

test('wrong GCM keys or altered tags expose neither unauthenticated plaintext nor candidate keys', () => {
  const { bytes, aes } = encrypted();
  const out = recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(Buffer.alloc(16, 7))] });
  assert.equal(out.result.recovery.status, 'not-found');
  assert.equal(out.result.recovery.trials, 1);
  assert.equal(out.output, null);
  assert.equal(JSON.stringify(out.result).includes(Buffer.alloc(16, 7).toString('hex')), false);
  const altered = { ...aes, tag: fromHex('00'.repeat(16)) };
  assert.equal(recover(bytes, { method: 'aes-candidates', aes: altered, key_candidates: [hex(key)] }).result.recovery.candidates.length, 0);
});

test('short GCM authentication tags remain candidate evidence unless full expected independently matches', () => {
  const { bytes, aes } = encrypted(english, 'aes-gcm', key, 4);
  const out = recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(key)] });
  assert.equal(out.result.recovery.status, 'candidate');
  assert.equal(out.output, null);
  assert.equal(out.result.recovery.candidates[0].verification, 'short-tag-candidate');
  assert.equal(out.result.recovery.candidates[0].evidence[1].strength, 'weak-short-tag');
  assert.deepEqual(recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(key)] }, { expected: hex(english) }).output, english);
});

test('CBC padding and CTR text do not prove keys; full expected verifies them', () => {
  for (const mode of ['aes-cbc', 'aes-ctr']) {
    const { bytes, aes } = encrypted(english, mode);
    const candidate = recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(key)] });
    assert.equal(candidate.result.recovery.status, 'candidate');
    assert.equal(candidate.output, null);
    assert.deepEqual(recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(key)] }, { expected: hex(english) }).output, english);
  }
});

test('an explicit expected mismatch cannot be overridden by valid GCM authentication', () => {
  const { bytes, aes } = encrypted();
  const out = recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(key)] }, { expected: hex(Buffer.from('wrong expected')) });
  assert.equal(out.output, null);
  assert.equal(out.result.recovery.status, 'not-found');
});

test('duplicate equivalent XOR periods and AES keys collapse, while genuine ambiguity stays unresolved', () => {
  const out = recover(x(english, xorKey), { method: 'xor-repeat', key_lengths: [3, 6, 9, 12] }, { expected: hex(english) });
  assert.equal(out.result.recovery.strong_hypotheses, 1);
  assert.equal(out.result.recovery.candidates.length, 1);
  const { bytes, aes } = encrypted();
  const duplicate = recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(key), hex(key)] });
  assert.equal(duplicate.result.recovery.trials, 1);
  assert.equal(duplicate.result.recovery.status, 'verified');
  // Empty CTR plaintext independently matches every candidate key, so it cannot identify a key.
  const ambiguous = recover(Buffer.alloc(0), { method: 'aes-candidates', aes: { kind: 'aes-ctr', iv: hex(Buffer.alloc(16)), padding: 'none' }, key_candidates: [hex(key), hex(Buffer.alloc(16, 8))] }, { expected: hex(Buffer.alloc(0)) });
  assert.equal(ambiguous.result.recovery.ambiguity, true);
  assert.equal(ambiguous.result.recovery.status, 'candidate');
  assert.equal(ambiguous.output, null);
});

test('budget-truncated search does not automatically publish an authenticated candidate', () => {
  const { bytes, aes } = encrypted();
  const out = recover(bytes, { method: 'aes-candidates', aes, max_trials: 1, key_candidates: [hex(key), hex(Buffer.alloc(16, 8))] });
  assert.equal(out.result.recovery.status, 'candidate');
  assert.equal(out.result.recovery.candidates[0].status, 'verified-hypothesis');
  assert.equal(out.result.recovery.search_truncated, true);
  assert.equal(out.output, null);
});

test('candidate plaintext previews are bounded and supplied IV, tag, AAD are not persisted in evidence', () => {
  const { bytes, aes } = encrypted();
  const out = recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(key), hex(Buffer.alloc(16, 9))] }, { preview_limit: 3 });
  assert.equal(out.result.recovery.candidates[0].plaintext.preview.length, 3);
  const serialized = JSON.stringify(out.result);
  for (const secret of [aes.iv.data, aes.tag.data, aes.aad.data, Buffer.alloc(16, 9).toString('hex')]) assert.equal(serialized.includes(secret), false);
  assert.equal(Object.hasOwn(out.result.recovery, 'aes'), false);
});

test('strict budgets, canonical secrets, invalid modes, unsupported fields and output limits reject safely', () => {
  for (const recovery of [{ max_trials: 4097 }, { max_key_bytes: 33 }, { max_candidates: 9 }, { sample_bytes: 65537 }, { max_work_bytes: 67108865 }, { material_stride: 0 }, { known_plaintext: [{ offset: 0, ...hex(Buffer.alloc(0)) }] }, { key_lengths: [1, 1] }, { typo: 'secret-value' }]) failures(() => recover(english, recovery), 'INVALID_RECOVERY');
  failures(() => recover(english, { method: 'aes-candidates' }), 'INVALID_RECOVERY');
  failures(() => recover(english, { method: 'aes-candidates', aes: { kind: 'aes-cbc', iv: hex(Buffer.alloc(16)), padding: 'none', key: hex(key) } }), 'INVALID_RECOVERY');
  failures(() => recover(english, { key_candidates: [hex(key)] }), 'INVALID_RECOVERY');
  failures(() => recover(english, { known_plaintext: [{ offset: english.length, ...hex(Buffer.from('a')) }] }), 'INVALID_RECOVERY');
  failures(() => recover(english, { method: 'xor-single' }, { output_limit: 2 }), 'OUTPUT_LIMIT');
  failures(() => analyzeCrypto({ op: 'inspect', input: hex(english), recovery: {} }), 'INVALID_RECOVERY');
  try { recover(english, { method: 'user-secret-is-not-a-method' }); assert.fail(); }
  catch (error) { assert.equal(error.message.includes('user-secret'), false); assert.deepEqual(Object.keys(error).sort(), ['code', 'name']); }
});

test('search leaves all caller buffers and request objects unchanged', () => {
  const { bytes, aes } = encrypted();
  const request = { op: 'recover', input: hex(bytes), recovery: { method: 'aes-candidates', aes, key_material: hex(Buffer.concat([Buffer.alloc(16, 0x77), key])), key_candidates: [hex(key)] } };
  const before = JSON.stringify(request);
  analyzeCrypto(request);
  assert.equal(JSON.stringify(request), before);
});

test('XOR expected used for recovery is labeled non-independent and one-period overfitting stays unresolved', () => {
  const plain = Buffer.from([1, 2, 3, 4, 5]);
  const cipher = Buffer.from([7, 2, 9, 0, 0]);
  const out = recover(cipher, { method: 'xor-repeat', key_lengths: [5] }, { expected: hex(plain) });
  assert.equal(out.result.recovery.status, 'candidate');
  assert.equal(out.output, null);
  assert.equal(out.result.recovery.candidates[0].underdetermined, true);
  assert.equal(out.result.recovery.candidates[0].usedForRecovery, true);
  assert.equal(out.result.recovery.candidates[0].independent, false);
  const relation = recover(x(english, xorKey), { method: 'xor-repeat', key_lengths: [3] }, { expected: hex(english) });
  assert.equal(relation.result.recovery.status, 'verified');
  assert.equal(relation.result.verification.usedForRecovery, true);
  assert.equal(relation.result.verification.independent, false);
});

test('empty and very short unauthenticated expected plaintext cannot validate AES keys', () => {
  for (const mode of ['aes-ctr', 'aes-cbc']) {
    const aes = { kind: mode, iv: hex(Buffer.alloc(16)), padding: 'none' };
    const out = recover(Buffer.alloc(0), { method: 'aes-candidates', aes, key_candidates: [hex(key)] }, { expected: hex(Buffer.alloc(0)) });
    assert.equal(out.result.recovery.status, 'candidate');
    assert.equal(out.result.recovery.candidates[0].underdetermined, true);
    assert.equal(out.output, null);
  }
  const { bytes, aes } = encrypted(Buffer.from('a'), 'aes-ctr');
  assert.equal(recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(key)] }, { expected: hex(Buffer.from('a')) }).output, null);
  const authEmpty = encrypted(Buffer.alloc(0));
  const authentic = recover(authEmpty.bytes, { method: 'aes-candidates', aes: authEmpty.aes, key_candidates: [hex(key)] }, { expected: hex(Buffer.alloc(0)) });
  assert.equal(authentic.result.recovery.status, 'verified');
  assert.equal(authentic.output.length, 0);
});

test('unaligned isolated ASCII key tokens are harvested and auto selects supplied AES evidence', () => {
  const tokenKey = Buffer.from('SecretKey1234567');
  const { bytes, aes } = encrypted(english, 'aes-gcm', tokenKey);
  const out = recover(bytes, { method: 'auto', aes, key_material: hex(Buffer.from('key="SecretKey1234567"; other=no')) });
  assert.equal(out.result.recovery.status, 'verified');
  assert.deepEqual(out.output, english);
  assert.equal(out.result.recovery.candidates[0].evidence[0].source, 'material-ascii-token');
  assert.equal(out.result.recovery.candidates[0].evidence[0].offset, 5);
  assert.ok(out.result.recovery.evidence.some(e => e.kind === 'method-selection' && e.selected === 'aes-candidates'));
});

test('complete one MiB expected comparison avoids per-period duplicated full-buffer work', () => {
  const plain = Buffer.alloc(1024 * 1024);
  for (let i = 0; i < plain.length; i++) plain[i] = i % 251;
  const out = recover(x(plain, xorKey), { method: 'xor-repeat' }, { expected: hex(plain), preview_limit: 0 });
  assert.equal(out.result.recovery.status, 'verified');
  assert.equal(out.result.recovery.search_truncated, false);
  assert.equal(out.result.recovery.candidates.length, 1);
  assert.deepEqual(out.output, plain);
});

test('raw material generation, rejected trials and inner scoring honor independent work and trial caps', () => {
  const { bytes, aes } = encrypted(Buffer.from('bounded authenticated message'));
  let state = 0x24681357;
  const material = Buffer.from(Array.from({ length: 65536 }, () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state & 255; }));
  const out = recover(bytes, { method: 'aes-candidates', aes, key_material: hex(material), material_stride: 1, max_trials: 17 });
  assert.equal(out.result.recovery.trials, 17);
  assert.equal(out.result.recovery.rejected, 17);
  assert.equal(out.result.recovery.search_truncated, true);
  assert.ok(out.result.recovery.work_bytes <= out.result.recovery.limits.max_work_bytes);
  const limited = recover(x(english, xorKey), { method: 'xor-repeat', key_lengths: [3], max_work_bytes: 1000 });
  assert.equal(limited.output, null);
  assert.equal(limited.result.recovery.search_truncated, true);
  assert.ok(limited.result.recovery.work_bytes <= 1000);
});

test('AES key byte budgets apply to supplied candidates and harvested materials consistently', () => {
  const aesKey = Buffer.alloc(32, 0x5b);
  const { bytes, aes } = encrypted(english, 'aes-gcm', aesKey);
  failures(() => recover(bytes, { method: 'aes-candidates', aes, max_key_bytes: 16, key_candidates: [hex(aesKey)] }), 'INVALID_KEY');
  const out = recover(bytes, { method: 'aes-candidates', aes, max_key_bytes: 16, key_material: hex(Buffer.from(aesKey.toString('hex'))) });
  assert.equal(out.result.recovery.status, 'not-found');
  failures(() => recover(bytes, { method: 'xor-single', aes }), 'INVALID_RECOVERY');
});

test('large GCM AAD and IV cannot bypass decode or authentication work budgets', () => {
  const bigAad = Buffer.alloc(65536, 0x41);
  const bigIv = Buffer.alloc(64, 0x52);
  const cipher = createCipheriv('aes-128-gcm', key, bigIv);
  cipher.setAAD(bigAad);
  const bytes = Buffer.concat([cipher.update(Buffer.alloc(0)), cipher.final()]);
  const aes = { kind: 'aes-gcm', iv: hex(bigIv), tag: hex(cipher.getAuthTag()), aad: hex(bigAad), padding: 'none' };
  const refused = recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(key)], max_work_bytes: 16 });
  assert.equal(refused.result.recovery.status, 'not-found');
  assert.equal(refused.result.recovery.trials, 0);
  assert.equal(refused.output, null);
  assert.equal(refused.result.recovery.search_truncated, true);
  assert.ok(refused.result.recovery.work_bytes <= 16);
  const sufficient = recover(bytes, { method: 'aes-candidates', aes, key_candidates: [hex(key)], max_work_bytes: 500000 });
  assert.equal(sufficient.result.recovery.status, 'verified');
  assert.equal(sufficient.output.length, 0);
  assert.ok(sufficient.result.recovery.work_bytes >= bigAad.length + bigIv.length);
  assert.equal(sufficient.result.recovery.limits.aes_parameter_bytes, 65536 + 64 + 16);
});

test('every failed GCM trial includes AAD authentication while canonical parameters are decoded once', () => {
  const bigAad = Buffer.alloc(65536, 0x41);
  const cipher = createCipheriv('aes-128-gcm', key, iv);
  cipher.setAAD(bigAad);
  const bytes = Buffer.concat([cipher.update(Buffer.alloc(0)), cipher.final()]);
  const aes = { kind: 'aes-gcm', iv: hex(iv), tag: hex(cipher.getAuthTag()), aad: { encoding: 'base64', data: bigAad.toString('base64') }, padding: 'none' };
  const wrong = [hex(Buffer.alloc(16, 1)), hex(Buffer.alloc(16, 2)), hex(Buffer.alloc(16, 3))];
  const first = recover(bytes, { method: 'aes-candidates', aes, key_candidates: wrong.slice(0, 1) });
  const twice = recover(bytes, { method: 'aes-candidates', aes, key_candidates: wrong.slice(0, 2) });
  assert.equal(twice.result.recovery.trials, 2);
  assert.equal(twice.result.recovery.rejected, 2);
  const oneTrialWork = bigAad.length + iv.length + 16 + 16 + key.length * 6;
  assert.equal(twice.result.recovery.work_bytes - first.result.recovery.work_bytes, oneTrialWork);
  assert.equal(twice.result.recovery.limits.aes_parameter_decode_work, first.result.recovery.limits.aes_parameter_decode_work);
  const limited = recover(bytes, { method: 'aes-candidates', aes, key_candidates: wrong, max_work_bytes: first.result.recovery.limits.aes_parameter_decode_work + oneTrialWork });
  assert.equal(limited.result.recovery.rejected, 1);
  assert.equal(limited.result.recovery.search_truncated, true);
  assert.ok(limited.result.recovery.work_bytes <= limited.result.recovery.limits.max_work_bytes);
});
test('UTF8 Chinese XOR is ranked using explicit multilingual evidence and remains unverified', () => {
  const plain = Buffer.from('这是中文协议消息，这里包含服务器地址与连接参数。'.repeat(20));
  const out = recover(x(plain, Buffer.from([0x71])), { method: 'xor-single' });
  assert.equal(out.result.recovery.trials, 256); assert.equal(out.result.recovery.status, 'candidate');
  assert.equal(out.result.recovery.candidates[0].keyMaterial.dataHex, '71');
  assert.equal(out.result.recovery.candidates[0].plaintext.dataHex, plain.toString('hex'));
  assert(out.result.recovery.candidates[0].evidence.some(e => e.language === 'utf8-cjk-heuristic'));
  assert.equal(out.output, null);
});
test('gzip and binary executable headers support XOR candidates without claiming payload validity', () => {
  const pe = Buffer.alloc(256, 0xa7);pe[0]=0x4d;pe[1]=0x5a;pe.writeUInt32LE(128,0x3c);Buffer.from('50450000','hex').copy(pe,128);
  for (const plain of [gzipSync(Buffer.from('中文配置协议'.repeat(10))), pe]) {
    const out = recover(x(plain, Buffer.from([0xcc])), { method: 'xor-single' });
    assert.equal(out.result.recovery.candidates[0].keyMaterial.dataHex, 'cc');
    const text = out.result.recovery.candidates[0].evidence.find(e => e.kind === 'text-score');
    assert(text.format_evidence.every(e => e.payload_validated === false)); assert.equal(out.output, null);
  }
});
