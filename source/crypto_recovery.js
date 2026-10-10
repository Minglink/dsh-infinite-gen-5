import { createHash, timingSafeEqual } from 'node:crypto';
import { TextDecoder } from 'node:util';

/** Bounded hypotheses over local bytes. Scores are evidence, never authentication. */
export const RECOVERY_LIMITS = Object.freeze({
  maxKeyBytes: 32, maxCandidates: 8, maxTrials: 4096, keyCandidates: 256,
  keyMaterialBytes: 65536, knownPlaintextBytes: 65536, sampleBytes: 65536,
  workBytes: 67108864,
});

const kinds = ['auto', 'xor-single', 'xor-repeat', 'aes-candidates'];
const byteWeights = new Float64Array(256).fill(-6);
const frequency = { ' ': 18, e: 12.7, t: 9.1, a: 8.2, o: 7.5, i: 7, n: 6.7, s: 6.3, h: 6.1, r: 6, d: 4.3, l: 4, c: 2.8, u: 2.8, m: 2.4, w: 2.4, f: 2.2, g: 2, y: 2, p: 1.9, b: 1.5, v: 1, k: 0.8, j: 0.15, x: 0.15, q: 0.1, z: 0.07 };
for (let b = 32; b <= 126; b++) byteWeights[b] = -0.5;
for (const [letter, weight] of Object.entries(frequency)) {
  byteWeights[letter.charCodeAt(0)] = Math.log(weight / 18) + 2;
  if (letter !== ' ') byteWeights[letter.toUpperCase().charCodeAt(0)] = Math.log(weight / 18) + 1.6;
}
for (const b of [9, 10, 13]) byteWeights[b] = 0.4;
for (let b = 48; b <= 57; b++) byteWeights[b] = 0.3;
for (const b of Buffer.from('.,;:\"\'{}[]()/-_=!?')) byteWeights[b] = 0.2;
const popcount = Uint8Array.from({ length: 256 }, (_, n) => {
  let total = 0;
  for (; n; n &= n - 1) total++;
  return total;
});
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

function equal(a, b) { return a.length === b.length && timingSafeEqual(a, b); }

function period(key) {
  for (let length = 1; length <= key.length; length++) {
    if (key.length % length) continue;
    let valid = true;
    for (let i = length; i < key.length; i++) if (key[i] !== key[i % length]) { valid = false; break; }
    if (valid) return key.subarray(0, length);
  }
  return key;
}

function xor(bytes, key) {
  const output = Buffer.allocUnsafe(bytes.length);
  for (let i = 0; i < bytes.length; i++) output[i] = bytes[i] ^ key[i % key.length];
  return output;
}

function constraints(bytes, cribs, keyLength) {
  const key = Buffer.alloc(keyLength);
  const mask = Buffer.alloc(keyLength);
  let count = 0;
  for (const crib of cribs) {
    for (let i = 0; i < crib.bytes.length; i++) {
      const position = (crib.offset + i) % keyLength;
      const value = bytes[crib.offset + i] ^ crib.bytes[i];
      if (mask[position] && key[position] !== value) return null;
      if (!mask[position]) count++;
      mask[position] = 1;
      key[position] = value;
    }
  }
  return { key, mask, count };
}

const UTF8 = new TextDecoder('utf-8', { fatal: true });
function formatEvidence(bytes) {
  const entries = [];
  const match = (hex, name, minimum) => { if (bytes.length >= minimum && bytes.subarray(0, hex.length / 2).toString('hex') === hex) entries.push({ kind: 'format-header', format: name, offset: 0, payload_validated: false }); };
  match('1f8b08', 'gzip', 10); match('89504e470d0a1a0a', 'png', 24);
  match('7f454c46', 'elf', 16); match('504b0304', 'zip-local-header', 30);
  match('ffd8ff', 'jpeg', 8); match('255044462d', 'pdf', 8);
  match('53514c69746520666f726d6174203300', 'sqlite3', 100);
  if (bytes.length >= 6 && (bytes[0] & 15) === 8 && (bytes[0] >>> 4) <= 7 && ((bytes[0] << 8) + bytes[1]) % 31 === 0)
    entries.push({ kind: 'format-header', format: 'zlib', offset: 0, payload_validated: false });
  if (bytes.length >= 64 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
    const pe = bytes.readUInt32LE(0x3c);
    if (pe >= 64 && pe + 24 <= bytes.length && bytes.subarray(pe, pe + 4).equals(Buffer.from('50450000', 'hex')))
      entries.push({ kind: 'format-header', format: 'pe', offset: 0, secondaryOffset: pe, payload_validated: false });
  }
  return entries;
}
// Multilingual/format scores remain hypotheses, and never authenticate decrypted data.
function scoreText(bytes) {
  if (!bytes.length) return { score: -100, plausible: false, printable_ratio: 0, language: 'latin-text-heuristic', distinct_bytes: 0 };
  let weighted = 0;
  let printable = 0;
  let letters = 0;
  let spaces = 0;
  let asciiOnly = true;
  const distinct = new Set();
  for (const b of bytes) {
    weighted += byteWeights[b];
    if ((b >= 32 && b <= 126) || [9, 10, 13].includes(b)) printable++;
    if ((b >= 65 && b <= 90) || (b >= 97 && b <= 122)) letters++;
    if (b === 32) spaces++;
    if (b >= 128) asciiOnly = false;
    distinct.add(b);
  }
  const text = bytes.toString('latin1').toLowerCase();
  const words = text.match(/\b(?:the|and|this|that|with|from|for|are|you|not|have|key|data|message|protocol|return|true|false|function)\b/g) || [];
  const trigrams = text.match(/the|and|ing|ion|ent|her|for|tha|ere|ter|est|ers|ati|hat|ate|all|eth|hes|ver|his/g) || [];
  const score = weighted / bytes.length + (words.length * 5 + trigrams.length * 1.3) / bytes.length;
  const latin = {
    score: Number(score.toFixed(6)),
    plausible: bytes.length >= 24 && printable / bytes.length >= 0.94 && letters / bytes.length >= 0.35 && distinct.size >= 8 && score >= 0.4,
    printable_ratio: Number((printable / bytes.length).toFixed(6)),
    language: 'latin-text-heuristic', distinct_bytes: distinct.size, words: words.length,
  };
  let decoded = null, utf8Tail = 0;
  if (!asciiOnly) {
    // Locate only an unfinished final UTF8 sequence, then decode once rather than retrying full buffers.
    let lead = bytes.length - 1;
    while (lead > 0 && (bytes[lead] & 0xc0) === 0x80 && bytes.length - 1 - lead < 3) lead--;
    const first = bytes[lead], width = first >= 0xc2 && first <= 0xdf ? 2 : first >= 0xe0 && first <= 0xef ? 3 : first >= 0xf0 && first <= 0xf4 ? 4 : 0;
    if (width && bytes.length - lead < width) utf8Tail = bytes.length - lead;
    try { decoded = UTF8.decode(bytes.subarray(0, bytes.length - utf8Tail)); } catch { /* Invalid UTF8 is not promoted by the language heuristic. */ }
  }
  if (decoded !== null) {
    let cjk = 0, visible = 0, chars = 0;
    for (const char of decoded) {
      const cp = char.codePointAt(0); chars++;
      if (cp >= 0x3400 && cp <= 0x9fff || cp >= 0xf900 && cp <= 0xfaff || cp >= 0x20000 && cp <= 0x2fa1f) cjk++;
      if (cp >= 32 && cp !== 127 && !(cp >= 0x80 && cp <= 0x9f) || [9, 10, 13].includes(cp)) visible++;
    }
    const bigrams = decoded.match(/这是|中文|协议|消息|这里|包含|服务器|地址|连接|参数|数据|请求|返回|配置|函数|分析|文件|用户|验证|密钥|加密|解密|安全|测试|长度|结果|程序|错误|网络|报文|读取|响应|端口|输入|输出|系统|代码|一个|我们|需要|可以|没有|成功|失败|处理/g) || [];
    if (chars >= 8 && cjk / chars >= 0.3 && visible / chars >= 0.95 && distinct.size >= 8) {
      const unicodeScore = 1.5 + cjk / chars + Math.min(1.5, bigrams.length * 2 / chars);
      if (unicodeScore > latin.score) Object.assign(latin, { score: Number(unicodeScore.toFixed(6)), plausible: true,
        language: 'utf8-cjk-heuristic', valid_utf8: true, cjk_ratio: Number((cjk / chars).toFixed(6)), known_bigrams: bigrams.length, sample_tail_bytes_excluded: utf8Tail });
    }
  }
  const formats = formatEvidence(bytes);
  if (formats.length) Object.assign(latin, { score: Math.max(latin.score, formats.some(e => ['png', 'pe', 'elf', 'sqlite3'].includes(e.format)) ? 5 : 4), plausible: true, format_evidence: formats });
  return latin;
}

/** Internal API: host-facing canonical decoding and errors are supplied by crypto_analysis. */
export function recoverCrypto(bytes, value, options, api) {
  const { decodeBytes, fail, transform, summary } = api;
  const allowed = ['method', 'max_key_bytes', 'max_candidates', 'max_trials', 'key_candidates', 'key_material', 'known_plaintext', 'aes', 'sample_bytes', 'max_work_bytes', 'material_stride', 'key_lengths'];
  function obj(v, name, keys) {
    if (!v || typeof v !== 'object' || Array.isArray(v) || Buffer.isBuffer(v) || Object.keys(v).some(key => !keys.includes(key))) fail('INVALID_RECOVERY', `${name} must be an object with supported fields`);
    return v;
  }
  function integer(v, name, min, max, fallback) {
    if (v === undefined) return fallback;
    if (!Number.isSafeInteger(v) || v < min || v > max) fail('INVALID_RECOVERY', `${name} is outside its integer budget`);
    return v;
  }
  const recovery = obj(value, 'recovery', allowed);
  const method = recovery.method ?? 'auto';
  if (!kinds.includes(method)) fail('INVALID_RECOVERY', 'Unsupported recovery method');
  const maxKey = integer(recovery.max_key_bytes, 'max_key_bytes', 1, 32, 32);
  const maxCandidates = integer(recovery.max_candidates, 'max_candidates', 1, 8, 5);
  const maxTrials = integer(recovery.max_trials, 'max_trials', 1, 4096, 4096);
  const sampleBytes = integer(recovery.sample_bytes, 'sample_bytes', 256, 65536, 8192);
  const maxWork = integer(recovery.max_work_bytes, 'max_work_bytes', 1, RECOVERY_LIMITS.workBytes, 16777216);
  const stride = integer(recovery.material_stride, 'material_stride', 1, 32, 16);
  let keyLengths = recovery.key_lengths;
  if (keyLengths !== undefined) {
    if (!Array.isArray(keyLengths) || !keyLengths.length || keyLengths.length > 32 || keyLengths.some(n => !Number.isSafeInteger(n) || n < 1 || n > maxKey) || new Set(keyLengths).size !== keyLengths.length) fail('INVALID_RECOVERY', 'key_lengths must contain distinct bounded key lengths');
    keyLengths = [...keyLengths];
  } else keyLengths = Array.from({ length: maxKey }, (_, i) => i + 1);
  if (method === 'xor-single') keyLengths = [1];
  if (method === 'xor-repeat') keyLengths = keyLengths.filter(n => n > 1);
  if (method === 'xor-repeat' && !keyLengths.length) fail('INVALID_RECOVERY', 'xor-repeat requires a key length greater than one');
  const expected = options.expected;
  const supplied = recovery.key_candidates ?? [];
  if (!Array.isArray(supplied) || supplied.length > RECOVERY_LIMITS.keyCandidates) fail('INVALID_RECOVERY', 'key_candidates exceeds its item budget');
  const keys = supplied.map(v => decodeBytes(v, 'recovery.key_candidate', 32));
  if (keys.some(key => ![16, 24, 32].includes(key.length) || key.length > maxKey)) fail('INVALID_KEY', 'AES candidate keys must contain 16, 24, or 32 bytes within the key byte budget');
  const material = recovery.key_material === undefined ? null : decodeBytes(recovery.key_material, 'recovery.key_material', RECOVERY_LIMITS.keyMaterialBytes);
  const inputCribs = recovery.known_plaintext ?? [];
  if (!Array.isArray(inputCribs) || inputCribs.length > 16) fail('INVALID_RECOVERY', 'known_plaintext exceeds its item budget');
  let cribBytes = 0;
  const cribs = inputCribs.map(v => {
    obj(v, 'known_plaintext item', ['offset', 'encoding', 'data']);
    const offset = integer(v.offset, 'known_plaintext offset', 0, bytes.length, undefined);
    if (offset === undefined) fail('INVALID_RECOVERY', 'known_plaintext requires an explicit offset');
    const decoded = decodeBytes({ encoding: v.encoding, data: v.data }, 'known_plaintext', RECOVERY_LIMITS.knownPlaintextBytes);
    cribBytes += decoded.length;
    if (!decoded.length || decoded.length > bytes.length - offset || cribBytes > RECOVERY_LIMITS.knownPlaintextBytes) fail('INVALID_RECOVERY', 'known_plaintext must be nonempty and fit its range and aggregate budget');
    return { offset, bytes: decoded };
  });
  if (recovery.aes !== undefined) obj(recovery.aes, 'recovery.aes', ['kind', 'iv', 'tag', 'aad', 'padding']);
  if (method.startsWith('xor-') && recovery.aes !== undefined) fail('INVALID_RECOVERY', 'XOR recovery does not accept AES parameters');
  if (method === 'aes-candidates' && recovery.aes === undefined) fail('INVALID_RECOVERY', 'AES candidate recovery requires explicit mode, IV, padding, and GCM tag when applicable');
  if (recovery.aes === undefined && (keys.length || material)) fail('INVALID_RECOVERY', 'AES key sources require recovery.aes');
  const reasons = new Set();
  const evidence = [];
  const hypotheses = new Map();
  let work = 0;
  let trials = 0;
  let rejected = 0;
  let materialWindows = 0;
  function spend(amount) {
    if (amount > maxWork - work) { reasons.add('max_work_bytes'); return false; }
    work += amount;
    return true;
  }
  function trial() {
    if (trials >= maxTrials) { reasons.add('max_trials'); return false; }
    trials++;
    return true;
  }
  let preparedAes = null;
  let parameterDecodeWork = 0;
  // Bound encoded validation, canonical decoding/re-encoding, and copies before allocating metadata.
  function parameterCost(value, maxBytes) {
    if (!value || typeof value !== 'object' || typeof value.data !== 'string') return 0;
    const encoded = value.data.length;
    if (value.encoding === 'hex') {
      if (encoded > maxBytes * 2) fail('INPUT_LIMIT', 'AES recovery parameter exceeds its byte budget');
      return encoded * 2 + Math.ceil(encoded / 2) * 2;
    }
    if (value.encoding === 'base64') {
      if (encoded > 4 * Math.ceil(maxBytes / 3)) fail('INPUT_LIMIT', 'AES recovery parameter exceeds its byte budget');
      return encoded * 2 + Math.ceil(encoded * 3 / 4) * 2;
    }
    return encoded * 2;
  }
  // Prepare once. Repeating a large AAD or long GCM IV must never bypass the per-trial budget.
  if (recovery.aes !== undefined) {
    if (!['aes-cbc', 'aes-ctr', 'aes-gcm'].includes(recovery.aes.kind)) fail('INVALID_RECIPE', 'Recovery AES kind must be aes-cbc, aes-ctr, or aes-gcm');
    parameterDecodeWork = 96 + parameterCost(recovery.aes.iv, recovery.aes.kind === 'aes-gcm' ? 1024 : 16) + parameterCost(recovery.aes.tag, 16) + parameterCost(recovery.aes.aad, 1024 * 1024);
    if (spend(parameterDecodeWork)) {
      preparedAes = transform(bytes, { ...recovery.aes, key: { encoding: 'hex', data: '00'.repeat(16) } }, options.outputLimit, true).prepared;
    }
  }
  const sample = bytes.subarray(0, sampleBytes);
  const candidateKey = (key, mask) => ({
    dataHex: key.toString('hex'), keyComplete: mask.every(n => n === 1),
    known_mask: mask.toString('hex'), unknown_mask: Buffer.from(Uint8Array.from(mask, n => n ? 0 : 1)).toString('hex'),
  });
  function record(key, mask, info) {
    const complete = mask.every(n => n === 1);
    const actualKey = complete && info.kind === 'xor' ? period(key) : key;
    const actualMask = complete ? Buffer.alloc(actualKey.length, 1) : mask;
    const identity = `${info.kind}:${actualKey.toString('hex')}:${actualMask.toString('hex')}`;
    const previous = hypotheses.get(identity);
    if (!previous || Number(info.strong) > Number(previous.strong) || info.score > previous.score) {
      hypotheses.set(identity, { ...info, key: actualKey, mask: actualMask, keyComplete: complete });
    }
  }
  function checkCribs(plain) {
    for (const crib of cribs) {
      if (!spend(crib.bytes.length)) return null;
      if (!equal(plain.subarray(crib.offset, crib.offset + crib.bytes.length), crib.bytes)) return false;
    }
    return true;
  }
  function evaluateXor(key, mask, info, countedTrial = false) {
    if (mask.every(n => n === 1)) {
      key = period(key);
      mask = Buffer.alloc(key.length, 1);
      if (hypotheses.has(`xor:${key.toString('hex')}:${mask.toString('hex')}`)) return true;
    }
    if (!countedTrial && !trial()) return false;
    if (!mask.every(n => n === 1)) {
      if (mask.some(n => n === 1)) record(key, mask, { kind: 'xor', score: -100, strong: false, evidence: info.evidence, verification: 'partial-key', plaintext: null });
      return true;
    }
    if (bytes.length > options.outputLimit) fail('OUTPUT_LIMIT', 'Recovery plaintext exceeds the output byte budget');
    if (!info.text && !spend(sample.length * 9)) return false;
    const text = info.text ?? scoreText(xor(sample, key));
    // Only the full expected value or authentication may promote a guess. Cribs add constraints only.
    if (!expected && !cribs.length && !text.plausible) { rejected++; return true; }
    if (!spend(bytes.length)) return false;
    const plain = xor(bytes, key);
    const cribMatch = checkCribs(plain);
    if (cribMatch !== true) { rejected++; return true; }
    let matched = null;
    if (expected !== undefined) {
      if (!spend(Math.max(plain.length, expected.length))) return false;
      matched = equal(plain, expected);
      if (!matched) { rejected++; return true; }
    }
    const underdetermined = matched === true && bytes.length < key.length * 2;
    record(key, mask, { kind: 'xor', score: text.score, strong: matched === true && !underdetermined, plaintext: plain,
      usedForRecovery: expected !== undefined, independent: false, underdetermined,
      evidence: [...info.evidence, { kind: 'text-score', ...text, evaluated_bytes: sample.length, proves_plaintext: false }, ...(matched ? [{ kind: 'full-expected-periodic-relation', usedForRecovery: true, independent: false, key_periods_observed: bytes.length / key.length, underdetermined }] : [])],
      verification: matched ? 'full-expected-match' : cribs.length ? 'known-plaintext-constraints' : 'statistical-candidate', authentication: 'not-provided' });
    return true;
  }
  function keyLengthRank(lengths) {
    const ranked = [];
    for (const length of lengths) {
      const blocks = Math.min(8, Math.floor(sample.length / length));
      if (blocks < 2) { ranked.push({ length, distance: null }); continue; }
      const cost = (blocks - 1) * length;
      if (!spend(cost)) break;
      let distance = 0;
      for (let b = 0; b < blocks - 1; b++) for (let i = 0; i < length; i++) distance += popcount[sample[b * length + i] ^ sample[(b + 1) * length + i]];
      ranked.push({ length, distance: distance / cost });
    }
    return ranked.sort((a, b) => (a.distance ?? Infinity) - (b.distance ?? Infinity) || a.length - b.length);
  }
  // Auto with explicit AES parameters selects bounded AES key search. Without a mode it ranks XOR.
  if (method !== 'aes-candidates' && recovery.aes === undefined && bytes.length) {
    // An explicit expected value can supply complete periodic XOR constraints, independent of text.
    const expectedCribs = expected !== undefined && expected.length === bytes.length ? [{ offset: 0, bytes: expected.subarray(0, Math.min(expected.length, maxKey * 2)) }] : cribs;
    if (expectedCribs.length) {
      for (const length of keyLengths) {
        if (!spend(expectedCribs.reduce((n, v) => n + v.bytes.length, 0))) break;
        const constrained = constraints(bytes, expectedCribs, length);
        if (!constrained) { rejected++; continue; }
        const { key, mask, count } = constrained;
        // Fill only well-supported columns; otherwise return a visibly partial key with no plaintext.
        if (count < length && sample.length >= 64) {
          for (let column = 0; column < length; column++) {
            if (mask[column]) continue;
            const columnLength = Math.floor((sample.length - 1 - column) / length) + 1;
            // Histogram construction, both 256-entry passes, and every candidate/nonempty-bin pair.
            if (columnLength < 8 || !spend(columnLength + 512 + 256 * Math.min(256, columnLength))) continue;
            const histogram = new Uint32Array(256);
            for (let i = column; i < sample.length; i += length) histogram[sample[i]]++;
            const present = [...histogram.keys()].filter(b => histogram[b]);
            let best = -Infinity;
            let bestKey = 0;
            for (let k = 0; k < 256; k++) {
              let score = 0;
              for (const b of present) score += histogram[b] * byteWeights[b ^ k];
              if (score > best) { best = score; bestKey = k; }
            }
            key[column] = bestKey;
            mask[column] = 1;
          }
        }
        if (!evaluateXor(key, mask, { evidence: [{ kind: 'xor-periodic-constraints', key_bytes: length, constrained_key_bytes: count, total_key_bytes: length, crib_bytes: expectedCribs.reduce((n, c) => n + c.bytes.length, 0), independent_verification: false }] })) break;
      }
    } else {
      if (method !== 'xor-repeat' && keyLengths.includes(1)) {
        const histogram = new Uint32Array(256);
        if (!spend(sample.length + 256)) {
          reasons.add('max_work_bytes');
        } else {
          for (const b of sample) histogram[b]++;
          const present = [...histogram.keys()].filter(b => histogram[b]);
          const ranked = [];
        for (let k = 0; k < 256; k++) {
            if (!trial() || !spend(present.length)) break;
            let weight = 0;
            for (const b of present) weight += histogram[b] * byteWeights[b ^ k];
            if (!spend(sample.length * 7)) break;
            const text = scoreText(xor(sample, Buffer.from([k])));
            ranked.push({ key: k, score: text.score, text, frequencyScore: weight / sample.length });
          }
          ranked.sort((a, b) => b.score - a.score || a.key - b.key);
          for (const candidate of ranked.slice(0, 16)) {
            if (!evaluateXor(Buffer.from([candidate.key]), Buffer.from([1]), { text: candidate.text, evidence: [{ kind: 'single-byte-xor-enumeration', keyspace_size: 256, ranked_keys: ranked.length, full_text_rerank_keys: Math.min(ranked.length, 16) }] }, true)) break;
          }
        }
      }
      if (method !== 'xor-single' && sample.length >= 64) {
        // Top six lengths reduce work while full-text ranking and minimal periods handle harmonics.
        const ranked = keyLengthRank(keyLengths.filter(n => n > 1 && Math.floor(sample.length / n) >= 8));
        const chosen = ranked.slice(0, 6);
        evidence.push({ kind: 'key-length-ranking', evaluated_bytes: sample.length, candidates: ranked.map(v => ({ key_bytes: v.length, normalized_hamming: Number(v.distance?.toFixed(6)) })), selected_count: chosen.length });
        for (const item of chosen) {
          const key = Buffer.alloc(item.length);
          const mask = Buffer.alloc(item.length);
          for (let column = 0; column < item.length; column++) {
            const columnLength = Math.floor((sample.length - 1 - column) / item.length) + 1;
            if (!spend(columnLength + 512 + 256 * Math.min(256, columnLength))) break;
            const histogram = new Uint32Array(256);
            for (let i = column; i < sample.length; i += item.length) histogram[sample[i]]++;
            const present = [...histogram.keys()].filter(b => histogram[b]);
            let best = -Infinity;
            for (let k = 0; k < 256; k++) {
              let score = 0;
              for (const b of present) score += histogram[b] * byteWeights[b ^ k];
              if (score > best) { best = score; key[column] = k; }
            }
            mask[column] = 1;
          }
          if (!mask.every(n => n === 1)) break;
          if (!evaluateXor(key, mask, { evidence: [{ kind: 'repeating-xor-statistics', key_bytes: item.length, normalized_hamming: Number(item.distance.toFixed(6)), independent_verification: false }] })) break;
        }
      }
    }
  }
  if (preparedAes && (method === 'auto' || method === 'aes-candidates')) {
    const seen = new Set();
    function attempt(key, source) {
      const identity = key.toString('hex');
      if (seen.has(identity)) return true;
      seen.add(identity);
      const trialWork = Math.max(bytes.length, 16) + preparedAes.iv.length + (preparedAes.tag?.length ?? 0) + (preparedAes.aad?.length ?? 0) + key.length * 6;
      if (!trial() || !spend(trialWork)) return false;
      let decoded;
      try { decoded = transform(bytes, { ...recovery.aes, key: { encoding: 'hex', data: identity } }, options.outputLimit, false, preparedAes); }
      catch (error) { if (['DECRYPTION_FAILED', 'AUTHENTICATION_FAILED'].includes(error.code)) { rejected++; return true; } throw error; }
      if (!spend(Math.min(decoded.output.length, sampleBytes) * 8)) return false;
      const text = scoreText(decoded.output.subarray(0, sampleBytes));
      const cribMatch = checkCribs(decoded.output);
      if (cribMatch !== true) { rejected++; return true; }
      let matched = null;
      if (expected !== undefined) {
        if (!spend(Math.max(decoded.output.length, expected.length))) return false;
        matched = equal(decoded.output, expected);
        if (!matched) { rejected++; return true; }
      }
      const tagBytes = preparedAes.tag?.length ?? 0;
      const auth = decoded.authentication.status === 'passed';
      const underdetermined = matched === true && !auth && decoded.output.length < 16;
      const strong = (matched === true && !underdetermined) || ((expected === undefined || matched === true) && auth && tagBytes >= 12);
      if (!strong && !auth && !cribs.length && !text.plausible && matched !== true) { rejected++; return true; }
      record(key, Buffer.alloc(key.length, 1), { kind: recovery.aes.kind, plaintext: decoded.output, score: text.score, strong,
        usedForRecovery: false, independent: strong, underdetermined,
        verification: matched ? 'full-expected-match' : auth ? (tagBytes >= 12 ? 'authenticated-candidate' : 'short-tag-candidate') : cribs.length ? 'known-plaintext-constraints' : 'statistical-candidate',
        authentication: auth ? 'passed' : 'not-provided',
        evidence: [{ kind: 'aes-key-source', ...source, key_bytes: key.length }, ...(auth ? [{ kind: 'gcm-authentication', tag_bytes: tagBytes, strength: tagBytes >= 12 ? 'strong' : 'weak-short-tag', algorithm_identification: false }] : []), { kind: 'text-score', ...text, evaluated_bytes: Math.min(decoded.output.length, sampleBytes), proves_plaintext: false }, ...(matched ? [{ kind: 'full-expected-comparison', plaintext_bytes: decoded.output.length, independent: strong, underdetermined }] : [])] });
      return true;
    }
    for (let i = 0; i < keys.length; i++) if (!attempt(keys[i], { source: 'explicit-candidate', index: i })) break;
    if (material && spend(material.length)) {
      // Harvest isolated ASCII hex runs first; then bounded aligned raw byte windows.
      const text = material.toString('latin1');
      const regex = /[0-9a-fA-F]+/g;
      let match;
      while ((match = regex.exec(text))) {
        if (![32, 48, 64].includes(match[0].length) || match[0].length / 2 > maxKey) continue;
        materialWindows++;
        if (!spend(match[0].length) || !attempt(Buffer.from(match[0], 'hex'), { source: 'material-ascii-hex', offset: match.index, encoded_bytes: match[0].length })) break;
      }
      // Isolated printable key tokens need not share the raw-window alignment. No passphrases/KDF guessing.
      if (spend(material.length)) {
        const tokenRegex = /[A-Za-z0-9+\/_-]+/g;
        while ((match = tokenRegex.exec(text))) {
          if (![16, 24, 32].includes(match[0].length) || match[0].length > maxKey) continue;
          materialWindows++;
          if (!spend(match[0].length) || !attempt(Buffer.from(match[0], 'latin1'), { source: 'material-ascii-token', offset: match.index, token_bytes: match[0].length })) break;
        }
      }
      outer: for (let offset = 0; offset < material.length; offset += stride) {
        for (const length of [16, 24, 32]) {
          if (length > maxKey || offset + length > material.length) continue;
          materialWindows++;
          if (!spend(length) || !attempt(material.subarray(offset, offset + length), { source: 'material-raw-window', offset, stride })) break outer;
        }
      }
    }
  }
  const sorted = [...hypotheses.values()].sort((a, b) => Number(b.strong) - Number(a.strong) || Number(b.keyComplete) - Number(a.keyComplete) || b.score - a.score || a.key.length - b.key.length || a.key.compare(b.key));
  const strong = sorted.filter(c => c.strong);
  // Never automatically publish a guess or a result whose bounded search concealed an ambiguity.
  const verified = strong.length === 1 && reasons.size === 0;
  const selected = sorted.slice(0, maxCandidates);
  const candidates = selected.map((candidate, index) => ({
    rank: index + 1, kind: candidate.kind, key_bytes: candidate.key.length, keyComplete: candidate.keyComplete,
    keyMaterial: candidateKey(candidate.key, candidate.mask),
    status: candidate.strong ? 'verified-hypothesis' : 'candidate', verification: candidate.verification,
    usedForRecovery: candidate.usedForRecovery ?? false, independent: candidate.independent ?? false, underdetermined: candidate.underdetermined ?? false,
    authentication: { status: candidate.authentication ?? 'not-provided' },
    score: candidate.score, evidence: candidate.evidence,
    plaintext: candidate.plaintext ? { dataHex: candidate.plaintext.toString('hex'), ...summary(candidate.plaintext, options.previewLimit) } : null,
  }));
  const output = verified ? strong[0].plaintext : null;
  return {
    recovery: {
      status: verified ? 'verified' : sorted.length ? 'candidate' : 'not-found',
      method, trials, work_bytes: work, rejected, candidates,
      candidate_count: sorted.length, returned_candidates: candidates.length,
      truncated: reasons.size > 0 || sorted.length > maxCandidates,
      search_truncated: reasons.size > 0, truncation_reasons: [...reasons, ...(sorted.length > maxCandidates ? ['max_candidates'] : [])],
      ambiguity: strong.length > 1 || sorted.filter(c => c.underdetermined).length > 1, strong_hypotheses: strong.length,
      underdetermined: sorted.some(c => c.underdetermined),
      evidence: [...evidence, { kind: 'source-availability', explicit_key_candidates: keys.length, key_material_bytes: material?.length ?? 0, known_plaintext_bytes: cribBytes }, { kind: 'verification-scope', scope: 'supplied ciphertext and tested hypotheses', full_expected: expected !== undefined, expected_used_for_recovery: sorted.some(c => c.usedForRecovery), known_plaintext_constraints: cribs.length, algorithm_identification: false }, ...(method === 'auto' ? [{ kind: 'method-selection', selected: recovery.aes !== undefined ? 'aes-candidates' : 'xor', reason: recovery.aes !== undefined ? 'explicit-aes-parameters' : 'no-aes-parameters' }] : [])],
      limits: { max_key_bytes: maxKey, max_candidates: maxCandidates, max_trials: maxTrials, sample_bytes: sampleBytes, max_work_bytes: maxWork, material_stride: stride, key_material_bytes: material?.length ?? 0, material_windows: materialWindows, aes_parameter_bytes: preparedAes ? preparedAes.iv.length + (preparedAes.tag?.length ?? 0) + (preparedAes.aad?.length ?? 0) : null, aes_parameter_decode_work: parameterDecodeWork },
      interpretation: 'XOR/text scores and known plaintext constraints are hypotheses. Only a unique full expected match or sufficiently long GCM authentication may publish output. AES recovery searches supplied key candidates and bounded material windows; it does not exhaust the AES key space.',
    }, output,
    authentication: { status: output && strong[0].authentication === 'passed' ? 'passed' : 'not-provided' },
    verification: { status: output && expected !== undefined ? 'matched' : output ? 'authenticated' : expected !== undefined ? 'unresolved' : 'not-requested', matched: output && expected !== undefined ? true : null, usedForRecovery: output ? Boolean(strong[0].usedForRecovery) : sorted.some(c => c.usedForRecovery), independent: output ? !strong[0].usedForRecovery : null },
  };
}
