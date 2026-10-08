import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeHex, createAddressRef, convertAddress } from '../source/address_ref.js';

const ref = (value, kind = 'rva', extra = {}) => ({ artifactId: 'artifact_A', space: 'static', kind, value, ...extra });
const mapping = { imageBase: '0xfffff80000000000', imageSize: '0x6000', sections: [
  { rva: '0x1000', virtualSize: '0x1000', fileOffset: '0x400', fileSize: '0x800' },
  { rva: '0x3000', virtualSize: '0x1000', fileSize: '0x0' },
] };
const module = { artifactId: 'artifact_A', moduleId: 'sample', runId: 'run_A', moduleLoadEpoch: 3, stopSeq: 7, base: '0x7fff12340000', size: '0x6000', loaded: true };
const fails = (fn, code) => assert.throws(fn, error => error.code === code);

test('normalizes full-width addresses without a Number conversion', () => {
  assert.equal(normalizeHex('0XFFFFF80000001234'), '0xfffff80000001234');
  assert.equal(normalizeHex(0xffffffffffffffffn), '0xffffffffffffffff');
  assert.equal(normalizeHex('0x000001'), '0x1');
  fails(() => normalizeHex(Number.MAX_SAFE_INTEGER), 'INVALID_ADDRESS');
  fails(() => normalizeHex('9007199254740993'), 'INVALID_ADDRESS');
  fails(() => normalizeHex(1n << 64n), 'ADDRESS_OVERFLOW');
  fails(() => normalizeHex(-1n), 'ADDRESS_OVERFLOW');
});

test('static VA and RVA round trip above the safe integer range', () => {
  const va = convertAddress(ref('0x1234'), 'va', mapping);
  assert.equal(va.value, '0xfffff80000001234');
  assert.equal(convertAddress(va, 'rva', mapping).value, '0x1234');
  fails(() => convertAddress(va, 'rva'), 'MAPPING_REQUIRED');
  fails(() => convertAddress(ref('0x100', 'va'), 'rva', mapping), 'UNMAPPED_ADDRESS');
});

test('file mapping is section-based and preserves exact offsets', () => {
  for (let delta = 0n; delta < 0x800n; delta += 37n) {
    const rva = ref(normalizeHex(0x1000n + delta));
    const file = convertAddress(rva, 'file', mapping);
    assert.equal(file.space, 'file');
    assert.equal(file.value, normalizeHex(0x400n + delta));
    assert.equal(convertAddress(file, 'rva', mapping).value, rva.value);
  }
});

test('BSS, section tails, unloaded data, and missing maps cannot become file bytes', () => {
  fails(() => convertAddress(ref('0x1800'), 'file', mapping), 'NOT_FILE_BACKED');
  fails(() => convertAddress(ref('0x3000'), 'file', mapping), 'NOT_FILE_BACKED');
  fails(() => convertAddress(ref('0x5000'), 'file', mapping), 'UNMAPPED_ADDRESS');
  fails(() => convertAddress(ref('0x1000'), 'file'), 'MAPPING_REQUIRED');
  fails(() => convertAddress(ref('0x1000'), 'file', { sections: [{ ...mapping.sections[0], loaded: false }] }), 'UNMAPPED_ADDRESS');
});

test('overlapping sections and file-only padding are rejected', () => {
  fails(() => convertAddress(ref('0x1100'), 'file', { sections: [mapping.sections[0], mapping.sections[0]] }), 'AMBIGUOUS_MAPPING');
  fails(() => convertAddress({ ...ref('0x900', 'file'), space: 'file' }, 'rva', { sections: [{ rva: '0x1000', virtualSize: '0x100', fileOffset: '0x400', fileSize: '0x800' }] }), 'UNMAPPED_ADDRESS');
});

test('runtime conversion requires the exact loaded artifact and pause', () => {
  const runtime = convertAddress(ref('0x1234'), { space: 'runtime', kind: 'va' }, { module });
  assert.deepEqual(runtime, { artifactId: 'artifact_A', space: 'runtime', kind: 'va', value: '0x7fff12341234', moduleId: 'sample', runId: 'run_A', moduleLoadEpoch: 3, stopSeq: 7 });
  assert.equal(convertAddress(runtime, 'rva', { module }).value, '0x1234');
  assert.equal(convertAddress(runtime, 'va', { ...mapping, module }).value, '0xfffff80000001234');
  for (const [key, value] of [['runId', 'run_B'], ['moduleLoadEpoch', 4], ['stopSeq', 8]]) {
    fails(() => convertAddress(runtime, 'rva', { module: { ...module, [key]: value } }), 'STALE_RUNTIME_CONTEXT');
  }
  fails(() => convertAddress(runtime, 'rva', { module: { ...module, artifactId: 'other' } }), 'ADDRESS_IDENTITY_MISMATCH');
  fails(() => convertAddress(runtime, 'rva', { module: { ...module, loaded: false } }), 'MAPPING_REQUIRED');
});

test('runtime refs and module range boundaries fail closed', () => {
  fails(() => createAddressRef({ ...ref('0x1', 'va'), space: 'runtime' }), 'INVALID_CONTEXT');
  fails(() => convertAddress(ref('0x6000'), { space: 'runtime', kind: 'va' }, { module }), 'UNMAPPED_ADDRESS');
  const runtime = convertAddress(ref('0x0'), { space: 'runtime', kind: 'va' }, { module });
  fails(() => convertAddress({ ...runtime, value: '0x7fff1233ffff' }, 'rva', { module }), 'UNMAPPED_ADDRESS');
  fails(() => convertAddress(ref('0x1'), { space: 'runtime', kind: 'va' }, { module: { ...module, base: '0xffffffffffffffff' } }), 'INVALID_MAPPING');
});

test('engine-specific spaces never use RVA formulas or inherit runtime metadata', () => {
  for (const space of ['stack', 'register', 'unique', 'external', 'overlay']) {
    const input = { ...ref('0x4', 'offset'), space };
    assert.equal(createAddressRef(input).space, space);
    fails(() => convertAddress(input, 'rva', mapping), 'UNSUPPORTED_ADDRESS_SPACE');
  }
  fails(() => createAddressRef({ ...ref('0x1'), runId: 'old' }), 'ADDRESS_SPACE_MISMATCH');
  fails(() => createAddressRef({ ...ref('0x1'), space: 'overlay' }), 'ADDRESS_SPACE_MISMATCH');
});

test('mapped output overflow and image bounds are rejected', () => {
  fails(() => convertAddress(ref('0x10'), 'va', { imageBase: '0xfffffffffffffff8' }), 'ADDRESS_OVERFLOW');
  fails(() => convertAddress(ref('0x6000'), 'va', mapping), 'UNMAPPED_ADDRESS');
});

test('a unique file source cannot map into overlapping virtual destinations', () => {
  const sections = [
    { rva: '0x1000', virtualSize: '0x100', fileOffset: '0x200', fileSize: '0x100' },
    { rva: '0x1000', virtualSize: '0x100', fileOffset: '0x400', fileSize: '0x100' },
  ];
  fails(() => convertAddress({ ...ref('0x210', 'file'), space: 'file' }, 'rva', { sections }), 'AMBIGUOUS_MAPPING');
  fails(() => convertAddress({ ...ref('0x410', 'file'), space: 'file' }, 'va', { imageBase: '0x400000', sections }), 'AMBIGUOUS_MAPPING');
});

test('a unique virtual source cannot map into overlapping file destinations', () => {
  const sections = [
    { rva: '0x1000', virtualSize: '0x100', fileOffset: '0x200', fileSize: '0x100' },
    { rva: '0x2000', virtualSize: '0x100', fileOffset: '0x200', fileSize: '0x100' },
  ];
  fails(() => convertAddress(ref('0x1010'), 'file', { sections }), 'AMBIGUOUS_MAPPING');
  fails(() => convertAddress(ref('0x2010'), 'file', { sections }), 'AMBIGUOUS_MAPPING');
});
