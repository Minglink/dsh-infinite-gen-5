import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const rol8 = (v, s) => (((v & 0xff) << (s & 7)) | ((v & 0xff) >>> (8 - (s & 7)))) & 0xff;
const ror8 = (v, s) => (((v & 0xff) >>> (s & 7)) | ((v & 0xff) << (8 - (s & 7)))) & 0xff;

/**
 * Build a deterministic x64 PE32+ helper executable supporting:
 *   - `mode = "cli"` (validates optional `cwdSuffix`, required CLI `flag1`, and `argPrefix + <8-char-hex-or-4B-ascii>`, writes 8-char lowercase hex + `\n` to `STD_OUTPUT_HANDLE` AND stores raw 4-byte output at `outBufRva`)
 *   - `mode = "stdin"` (reads 6 bytes from `STD_INPUT_HANDLE`: 2-byte framing magic `[m0, m1]` + 4-byte payload; rejects standalone CLI runs that lack framed stdin with exit code 2; writes 8-char lowercase hex + `\n` to `STD_OUTPUT_HANDLE` AND stores raw 4-byte output at `outBufRva`)
 */
export function buildNativeHelperPe64({
  binaryName = 'helper.exe',
  mode = 'cli', // 'cli' | 'stdin'
  cwdSuffix = null, // e.g. '\\worker_bay'
  flag1 = '--lane=prod',
  argPrefix = 'F=',
  inputIsHex8 = false, // if true, expects 8 hex chars after argPrefix; if false, 4 raw ASCII bytes
  stdinMagic = [0x54, 0x4b], // 'TK'
  constants = [0x41, 0x97, 0x2c, 0xd5],
  rot = 3,
  cascadeXor = null, // if number, runs stage-2 cascade b[i+1] ^= (b[i] + cascadeXor) & 0xff
  outBufRva = 0x3180,
} = {}) {
  const image = Buffer.alloc(0x1e00, 0);
  const base = 0x140000000n;
  const optional = 0x98;
  const u16 = (off, v) => image.writeUInt16LE(v, off);
  const u32 = (off, v) => image.writeUInt32LE(v >>> 0, off);
  const u64 = (off, v) => image.writeBigUInt64LE(BigInt(v), off);
  const text = (off, v) => image.write(v, off, 'ascii');
  const raw = (rva) => (rva < 0x2000 ? 0x400 + rva - 0x1000 : rva < 0x3000 ? 0x800 + rva - 0x2000 : 0xe00 + rva - 0x3000);

  text(0, 'MZ'); u32(0x3c, 0x80); text(0x80, 'PE\0\0');
  u16(0x84, 0x8664); u16(0x86, 3); u16(0x94, 0xf0); u16(0x96, 0x22);
  u16(optional, 0x20b); image[optional + 2] = 14;
  u32(optional + 4, 0x400); u32(optional + 8, 0x1600);
  u32(optional + 16, 0x1000); u32(optional + 20, 0x1000); u64(optional + 24, base);
  u32(optional + 32, 0x1000); u32(optional + 36, 0x200);
  u16(optional + 40, 6); u16(optional + 48, 6);
  u32(optional + 56, 0x4000); u32(optional + 60, 0x400);
  u16(optional + 68, 3); u16(optional + 70, 0x100);
  u64(optional + 72, 0x100000); u64(optional + 80, 0x1000);
  u64(optional + 88, 0x100000); u64(optional + 96, 0x1000);
  u32(optional + 108, 16);
  u32(optional + 120, 0x2200); u32(optional + 124, 0x28);

  for (const [idx, name, rva, offset, size, flags] of [
    [0, '.text', 0x1000, 0x400, 0x400, 0x60000020],
    [1, '.rdata', 0x2000, 0x800, 0x600, 0x40000040],
    [2, '.data', 0x3000, 0xe00, 0x1000, 0xc0000040],
  ]) {
    const hdr = optional + 0xf0 + idx * 40;
    text(hdr, name); u32(hdr + 8, size); u32(hdr + 12, rva);
    u32(hdr + 16, size); u32(hdr + 20, offset); u32(hdr + 36, flags);
  }

  const imports = [
    ['GetCommandLineA', 0x2310, 0x2400],
    ['GetCurrentDirectoryA', 0x2328, 0x2408],
    ['GetStdHandle', 0x2348, 0x2410],
    ['ReadFile', 0x2360, 0x2418],
    ['WriteFile', 0x2374, 0x2420],
    ['ExitProcess', 0x2388, 0x2428],
  ];
  u32(raw(0x2200), 0x22c0); u32(raw(0x2200) + 12, 0x2260); u32(raw(0x2200) + 16, 0x2400);
  text(raw(0x2260), 'KERNEL32.dll\0');
  imports.forEach(([fnName, nameRva], idx) => {
    u64(raw(0x22c0) + idx * 8, nameRva);
    u64(raw(0x2400) + idx * 8, nameRva);
    u16(raw(nameRva), 0);
    text(raw(nameRva) + 2, fnName + '\0');
  });

  text(raw(0x2080), '0123456789abcdef');
  if (cwdSuffix) text(raw(0x20a0), `${cwdSuffix}\0`);
  text(raw(0x20c0), `${flag1}\0`);
  text(raw(0x20e0), `${argPrefix}\0`);
  Buffer.from(constants).copy(image, raw(0x2100));

  const inBufRva = 0x3080;
  const ioCountRva = 0x3090;
  const hexOutBufRva = 0x30a0;
  const cwdBufRva = 0x3200;
  const tokPtrsRva = 0x3400;
  const tokLensRva = 0x3440;
  const transformRva = 0x11c0;

  function assembleAt(startRva, buildFn) {
    const chunks = [];
    const labels = new Map();
    const fixups = [];
    let pc = startRva;
    const emitHex = (h) => { const b = Buffer.from(h, 'hex'); chunks.push(b); pc += b.length; };
    const label = (n) => labels.set(n, pc);
    const emitRel32 = (pHex, target) => {
      const p = Buffer.from(pHex, 'hex');
      const patchOff = pc - startRva + p.length;
      const nextPc = pc + p.length + 4;
      chunks.push(p, Buffer.alloc(4));
      fixups.push({ patchOff, nextPc, target });
      pc = nextPc;
    };
    buildFn({ emitHex, label, emitRel32 });
    const code = Buffer.concat(chunks);
    for (const f of fixups) {
      const tRva = typeof f.target === 'number' ? f.target : labels.get(f.target);
      if (tRva === undefined) throw new Error(`Unresolved label ${f.target}`);
      code.writeInt32LE(tRva - f.nextPc, f.patchOff);
    }
    if (startRva + code.length > 0x1400) throw new Error(`.text overflow 0x${(startRva + code.length).toString(16)}`);
    code.copy(image, raw(startRva));
    return labels;
  }

  // mem_eq_n at 0x1260
  assembleAt(0x1260, (a) => {
    a.emitHex('4531c9');
    a.label('lp');
    a.emitHex('4539c1'); a.emitRel32('0f83', 'eq');
    a.emitHex('420fb60409'); a.emitHex('460fb6140a'); a.emitHex('4439d0'); a.emitRel32('0f85', 'ne');
    a.emitHex('41ffc1'); a.emitRel32('e9', 'lp');
    a.label('eq'); a.emitHex('b801000000'); a.emitHex('c3');
    a.label('ne'); a.emitHex('31c0'); a.emitHex('c3');
  });

  // parse_cli_tokens at 0x12a0
  assembleAt(0x12a0, (a) => {
    a.emitHex('4531c9');
    a.label('sw');
    a.emitHex('0fb601'); a.emitHex('84c0'); a.emitRel32('0f84', 'dn');
    a.emitHex('3c20'); a.emitRel32('0f85', 'ts');
    a.emitHex('48ffc1'); a.emitRel32('e9', 'sw');
    a.label('ts');
    a.emitHex('4183f908'); a.emitRel32('0f83', 'dn');
    a.emitHex('3c22'); a.emitRel32('0f85', 'ut');
    a.emitHex('48ffc1'); a.emitHex('4a890cca'); a.emitHex('4531d2');
    a.label('ql');
    a.emitHex('0fb601'); a.emitHex('84c0'); a.emitRel32('0f84', 'qe');
    a.emitHex('3c22'); a.emitRel32('0f84', 'qc');
    a.emitHex('48ffc1'); a.emitHex('41ffc2'); a.emitRel32('e9', 'ql');
    a.label('qc'); a.emitHex('48ffc1');
    a.label('qe'); a.emitHex('47891488'); a.emitHex('41ffc1'); a.emitRel32('e9', 'sw');
    a.label('ut');
    a.emitHex('4a890cca'); a.emitHex('4531d2');
    a.label('ul');
    a.emitHex('0fb601'); a.emitHex('84c0'); a.emitRel32('0f84', 'ue');
    a.emitHex('3c20'); a.emitRel32('0f84', 'ue');
    a.emitHex('48ffc1'); a.emitHex('41ffc2'); a.emitRel32('e9', 'ul');
    a.label('ue'); a.emitHex('47891488'); a.emitHex('41ffc1'); a.emitRel32('e9', 'sw');
    a.label('dn'); a.emitHex('4489c8'); a.emitHex('c3');
  });

  // write_hex4_stdout(rcx = out4Ptr) at 0x1340: formats 8 lowercase hex chars + '\n' and calls WriteFile(STD_OUTPUT_HANDLE)
  assembleAt(0x1340, (a) => {
    a.emitHex('4883ec38');
    a.emitRel32('4c8d05', 0x2080);              // r8 = "0123456789abcdef"
    a.emitRel32('4c8d0d', hexOutBufRva);        // r9 = hexOutBuf
    a.emitHex('31d2');                          // edx = 0..3
    a.label('hlp');
    a.emitHex('0fb60411');                      // movzx eax, byte ptr [rcx + rdx]
    a.emitHex('4489c0');                        // wait: preserve eax! Use r10d = eax >> 4, eax &= 15
    a.emitHex('4489c2');                        // careful: edx is loop counter! Let's use r10d, r11d
  });
  image.fill(0, raw(0x1340), raw(0x1340) + 0xb0);
  assembleAt(0x1340, (a) => {
    a.emitHex('4883ec38');
    a.emitRel32('4c8d05', 0x2080);              // r8 = hexchars
    a.emitRel32('4c8d0d', hexOutBufRva);        // r9 = hexOutBuf
    a.emitHex('31d2');                          // edx = i (0..3)
    a.label('hlp');
    a.emitHex('0fb60411');                      // movzx eax, byte ptr [rcx + rdx]
    a.emitHex('4189c2');                        // mov r10d, eax
    a.emitHex('41c1ea04');                      // shr r10d, 4
    a.emitHex('83e00f');                        // and eax, 15
    a.emitHex('470fb61410');                    // movzx r10d, byte ptr [r8 + r10]
    a.emitHex('45881451');                      // mov [r9 + rdx*2], r10b
    a.emitHex('410fb60400');                    // movzx eax, byte ptr [r8 + rax]
    a.emitHex('4188445101');                    // mov [r9 + rdx*2 + 1], al
    a.emitHex('ffc2');                          // inc edx
    a.emitHex('83fa04');                        // cmp edx, 4
    a.emitRel32('0f82', 'hlp');
    a.emitHex('41c641080a');                    // mov byte ptr [r9 + 8], '\n'

    // GetStdHandle(STD_OUTPUT_HANDLE = -11 = 0xfffffff5)
    a.emitHex('b9f5ffffff');
    a.emitRel32('ff15', 0x2410);
    a.emitHex('4889c1');                        // rcx = hStdout
    a.emitRel32('488d15', hexOutBufRva);        // rdx = hexOutBuf
    a.emitHex('41b809000000');                  // r8d = 9
    a.emitRel32('4c8d0d', ioCountRva);          // r9 = &ioCount
    a.emitHex('48c744242000000000');
    a.emitRel32('ff15', 0x2420);                // WriteFile
    a.emitHex('4883c438');
    a.emitHex('c3');
  });

  // Transform at 0x11c0:
  // Stage 1: out[i] = rol8((in4[i] + constants[i]) & 0xff, rot)
  // Optional Stage 2 (if cascadeXor !== null): for i=0..2: out[i+1] ^= (out[i] + cascadeXor) & 0xff
  assembleAt(transformRva, (a) => {
    a.emitRel32('4c8d05', 0x2100);              // r8 = constants
    a.emitHex('4531c9');                        // r9d = 0
    a.label('st1');
    a.emitHex('420fb60409');                    // movzx eax, byte ptr [rcx + r9]
    a.emitHex('43020408');                      // add al, byte ptr [r8 + r9]
    a.emitHex('c0c0' + Buffer.from([rot & 7]).toString('hex')); // rol al, rot
    a.emitHex('4288040a');                      // mov [rdx + r9], al
    a.emitHex('41ffc1');
    a.emitHex('4183f904');
    a.emitRel32('0f82', 'st1');

    if (cascadeXor !== null) {
      a.emitHex('4531c9');
      a.label('st2');
      a.emitHex('420fb6040a');                  // movzx eax, byte ptr [rdx + r9]
      a.emitHex('04' + Buffer.from([cascadeXor & 0xff]).toString('hex')); // add al, cascadeXor
      a.emitHex('4230440a01');                  // xor byte ptr [rdx + r9 + 1], al
      a.emitHex('41ffc1');
      a.emitHex('4183f903');
      a.emitRel32('0f82', 'st2');
    }
    a.emitHex('8b02');
    a.emitHex('c3');
  });

  // Entry at 0x1000
  const labels = assembleAt(0x1000, (a) => {
    a.emitHex('4883ec48');

    if (cwdSuffix) {
      const sLen = cwdSuffix.length;
      const lenHex = Buffer.from([sLen]).toString('hex');
      const len32Hex = Buffer.alloc(4); len32Hex.writeUInt32LE(sLen, 0);
      a.emitHex('b904010000');
      a.emitRel32('488d15', cwdBufRva);
      a.emitRel32('ff15', 0x2408);              // GetCurrentDirectoryA
      a.emitHex('83f8' + lenHex);
      a.emitRel32('0f82', 'fail');
      a.emitHex('89c1');
      a.emitHex('83e9' + lenHex);
      a.emitRel32('488d15', cwdBufRva);
      a.emitHex('4801d1');
      a.emitRel32('488d15', 0x20a0);
      a.emitHex('41b8' + len32Hex.toString('hex'));
      a.emitRel32('e8', 0x1260);
      a.emitHex('85c0');
      a.emitRel32('0f84', 'fail');
    }

    if (mode === 'stdin') {
      // Read 6 bytes from STD_INPUT_HANDLE (-10 = 0xfffffff6) into inBufRva
      a.emitHex('b9f6ffffff');
      a.emitRel32('ff15', 0x2410);              // GetStdHandle(STD_INPUT_HANDLE)
      a.emitHex('4885c0');
      a.emitRel32('0f84', 'fail');
      a.emitHex('4883f8ff');
      a.emitRel32('0f84', 'fail');
      a.emitHex('4889c1');
      a.emitRel32('488d15', inBufRva);
      a.emitHex('41b806000000');                // read 6 bytes
      a.emitRel32('4c8d0d', ioCountRva);
      a.emitHex('48c744242000000000');
      a.emitRel32('ff15', 0x2418);              // ReadFile
      a.emitHex('85c0');
      a.emitRel32('0f84', 'fail');
      a.emitRel32('8b05', ioCountRva);
      a.emitHex('83f806');
      a.emitRel32('0f85', 'fail');
      // Verify 2-byte framing magic [m0, m1]
      a.emitRel32('488d0d', inBufRva);
      a.emitHex('8039' + Buffer.from([stdinMagic[0]]).toString('hex'));
      a.emitRel32('0f85', 'fail');
      a.emitHex('807901' + Buffer.from([stdinMagic[1]]).toString('hex'));
      a.emitRel32('0f85', 'fail');
      a.emitHex('4883c102');                    // rcx = inBuf + 2 (4B payload)
    } else {
      // CLI mode: argc == 3 (exe, flag1, argPrefix + payload)
      const fLen = Buffer.alloc(4); fLen.writeUInt32LE(flag1.length, 0);
      const pLen = argPrefix.length;
      const pLen32 = Buffer.alloc(4); pLen32.writeUInt32LE(pLen, 0);
      const expectedArg2Len = pLen + (inputIsHex8 ? 8 : 4);

      a.emitRel32('ff15', 0x2400);              // GetCommandLineA
      a.emitHex('4889c1');
      a.emitRel32('488d15', tokPtrsRva);
      a.emitRel32('4c8d05', tokLensRva);
      a.emitRel32('e8', 0x12a0);
      a.emitHex('83f803');
      a.emitRel32('0f85', 'fail');

      // argv[1] == flag1
      a.emitRel32('8b05', tokLensRva + 4);
      a.emitHex('3d' + fLen.toString('hex'));
      a.emitRel32('0f85', 'fail');
      a.emitRel32('488b0d', tokPtrsRva + 8);
      a.emitRel32('488d15', 0x20c0);
      a.emitHex('41b8' + fLen.toString('hex'));
      a.emitRel32('e8', 0x1260);
      a.emitHex('85c0');
      a.emitRel32('0f84', 'fail');

      // argv[2] len & prefix
      a.emitRel32('8b05', tokLensRva + 8);
      a.emitHex('83f8' + Buffer.from([expectedArg2Len]).toString('hex'));
      a.emitRel32('0f85', 'fail');
      a.emitRel32('488b0d', tokPtrsRva + 16);
      a.emitRel32('488d15', 0x20e0);
      a.emitHex('41b8' + pLen32.toString('hex'));
      a.emitRel32('e8', 0x1260);
      a.emitHex('85c0');
      a.emitRel32('0f84', 'fail');

      a.emitRel32('488b35', tokPtrsRva + 16);
      a.emitHex('4883c6' + Buffer.from([pLen]).toString('hex')); // rsi = payload ptr

      if (inputIsHex8) {
        // Decode 8 ASCII hex chars at [rsi] into 4 bytes at inBufRva
        a.emitRel32('488d3d', inBufRva);        // rdi = inBuf
        a.emitHex('31c9');                      // ecx = 0..3
        a.label('hdec');
        // high nibble: al = [rsi + rcx*2]
        a.emitHex('0fb6044e');                  // movzx eax, byte ptr [rsi + rcx*2]
        a.emitHex('3c39'); a.emitRel32('0f86', 'hd1_num');
        a.emitHex('0c20'); a.emitHex('2c57'); a.emitRel32('e9', 'hd1_ok');
        a.label('hd1_num'); a.emitHex('2c30');
        a.label('hd1_ok');
        a.emitHex('c1e004');                    // shl eax, 4
        a.emitHex('89c2');                      // edx = high << 4
        a.emitHex('0fb6444e01');                // movzx eax, byte ptr [rsi + rcx*2 + 1]
        a.emitHex('3c39'); a.emitRel32('0f86', 'hd2_num');
        a.emitHex('0c20'); a.emitHex('2c57'); a.emitRel32('e9', 'hd2_ok');
        a.label('hd2_num'); a.emitHex('2c30');
        a.label('hd2_ok');
        a.emitHex('09d0');                      // or eax, edx
        a.emitHex('88040f');                    // mov [rdi + rcx], al
        a.emitHex('ffc1');
        a.emitHex('83f904');
        a.emitRel32('0f82', 'hdec');
        a.emitRel32('488d0d', inBufRva);
      } else {
        a.emitHex('4889f1');                    // rcx = rsi
      }
    }

    a.emitRel32('488d15', outBufRva);           // rdx = outBuf
    a.emitRel32('e8', transformRva);
    a.label('after_transform');
    a.emitRel32('488d0d', outBufRva);
    a.emitRel32('e8', 0x1340);                  // write_hex4_stdout
    a.emitHex('31c9');
    a.emitRel32('ff15', 0x2428);                // ExitProcess(0)

    a.label('fail');
    a.emitHex('b902000000');
    a.emitRel32('ff15', 0x2428);                // ExitProcess(2)
  });

  const computeHelperHex = (in4Buf) => {
    const b = Buffer.alloc(4);
    for (let i = 0; i < 4; i++) {
      b[i] = rol8((in4Buf[i] + constants[i]) & 0xff, rot);
    }
    if (cascadeXor !== null) {
      for (let i = 0; i < 3; i++) {
        b[i + 1] = (b[i + 1] ^ ((b[i] + cascadeXor) & 0xff)) & 0xff;
      }
    }
    return b.toString('hex');
  };

  return {
    binaryName,
    image,
    sha256: sha256(image),
    mode,
    cwdSuffix,
    flag1,
    argPrefix,
    inputIsHex8,
    stdinMagic,
    transformRva: '0x' + transformRva.toString(16),
    afterTransformRva: '0x' + labels.get('after_transform').toString(16),
    outBufRva: '0x' + outBufRva.toString(16),
    computeHelperHex,
  };
}

/**
 * Materialize an Electron + Native Helper fixture app directory for M3 dev or sealed evaluation.
 */
export function materializeElectronAppFixture(rootDir, spec) {
  fs.mkdirSync(rootDir, { recursive: true });
  const binDir = spec.helperSubdir ? path.join(rootDir, spec.helperSubdir) : path.join(rootDir, 'bin');
  fs.mkdirSync(binDir, { recursive: true });

  const helperBuilt = buildNativeHelperPe64(spec.helper);
  const helperPath = path.join(binDir, helperBuilt.binaryName);
  fs.writeFileSync(helperPath, helperBuilt.image);

  let decoyBuilt = null;
  let decoyPath = null;
  if (spec.decoyHelper) {
    decoyBuilt = buildNativeHelperPe64(spec.decoyHelper);
    decoyPath = path.join(binDir, decoyBuilt.binaryName);
    fs.writeFileSync(decoyPath, decoyBuilt.image);
  }

  fs.writeFileSync(path.join(rootDir, 'package.json'), JSON.stringify({
    name: spec.appName,
    version: '1.0.0',
    main: 'main.js',
  }, null, 2) + '\n', 'utf8');

  const preloadCode = [
    `const { contextBridge, ipcRenderer } = require('electron');`,
    `contextBridge.exposeInMainWorld(${JSON.stringify(spec.bridgeGlobal || 'codecBridge')}, {`,
    `  submitPayload: (hexOrText, opts) => ipcRenderer.invoke(${JSON.stringify(spec.ipcChannel)}, { payload: hexOrText, ...(opts || {}) }),`,
    `  resetState: () => ipcRenderer.invoke(${JSON.stringify(spec.ipcChannel + ':reset')}),`,
    `});`,
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(rootDir, 'preload.js'), preloadCode, 'utf8');

  const htmlCode = [
    `<!doctype html>`,
    `<html><head><meta charset="utf-8"><title>${spec.appName}</title></head>`,
    `<body>`,
    `  <input id="payload-input" value="41424344" />`,
    `  <button id="${spec.buttonId || 'btn-submit'}">Run</button>`,
    `  <pre id="result-box">idle</pre>`,
    `  <script>`,
    `    const btn = document.getElementById(${JSON.stringify(spec.buttonId || 'btn-submit')});`,
    `    btn.addEventListener('click', async () => {`,
    `      const raw = document.getElementById('payload-input').value;`,
    `      const res = await window[${JSON.stringify(spec.bridgeGlobal || 'codecBridge')}].submitPayload(raw);`,
    `      document.getElementById('result-box').textContent = JSON.stringify(res);`,
    `    });`,
    `  </script>`,
    `</body></html>`,
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(rootDir, 'index.html'), htmlCode, 'utf8');

  const jsXorByte = spec.jsPreXorByte ?? 0;
  const useMemoCache = Boolean(spec.enableMemoCache);
  const helperRelDir = spec.helperSubdir || 'bin';
  const mainLines = [
    `const { app, BrowserWindow, ipcMain } = require('electron');`,
    `const fs = require('node:fs');`,
    `const path = require('node:path');`,
    `const { spawnSync } = require('node:child_process');`,
    `const cacheFile = path.join(__dirname, '.memo_cache.json');`,
    `function readMemoCache() {`,
    `  try { return JSON.parse(fs.readFileSync(cacheFile, 'utf8')); } catch { return {}; }`,
    `}`,
    `function writeMemoCache(obj) {`,
    `  try { fs.writeFileSync(cacheFile, JSON.stringify(obj), 'utf8'); } catch {}`,
    `}`,
    ``,
    ...(decoyBuilt ? [
      `// Legacy unused encoder retained in source tree`,
      `function legacyUnusedRoute(buf) {`,
      `  const p = path.join(__dirname, ${JSON.stringify(helperRelDir)}, ${JSON.stringify(decoyBuilt.binaryName)});`,
      `  return spawnSync(p, ['--legacy', 'X=' + buf.toString('hex')], { encoding: 'utf8' });`,
      `}`,
      ``,
    ] : []),
    `function preprocessPayload(rawInput) {`,
    `  const clean = String(rawInput || '').trim();`,
    `  const buf = /^[0-9a-fA-F]{8}$/.test(clean) ? Buffer.from(clean, 'hex') : Buffer.from(clean.slice(0, 4), 'utf8');`,
    `  if (buf.length !== 4) throw new Error('Expected 4-byte payload');`,
    `  const staged = Buffer.alloc(4);`,
    `  for (let i = 0; i < 4; i++) staged[i] = (buf[i] ^ ${jsXorByte}) & 0xff;`,
    `  return { originalHex: buf.toString('hex'), staged };`,
    `}`,
    ``,
    `function runBusinessChain(rawInput, opts = {}) {`,
    `  const { originalHex, staged } = preprocessPayload(rawInput);`,
    `  const memoObj = ${useMemoCache} ? readMemoCache() : {};`,
    `  if (${useMemoCache} && !opts.bypassCache && Object.prototype.hasOwnProperty.call(memoObj, originalHex)) {`,
    `    return { ok: true, cached: true, helperSpawned: false, outputHex: memoObj[originalHex] };`,
    `  }`,
    `  const workDir = path.join(__dirname, ${JSON.stringify(helperRelDir)});`,
    `  const helperExe = path.join(workDir, ${JSON.stringify(helperBuilt.binaryName)});`,
    ...(helperBuilt.mode === 'stdin' ? [
      `  const frame = Buffer.concat([Buffer.from(${JSON.stringify(helperBuilt.stdinMagic)}), staged]);`,
      `  const child = spawnSync(helperExe, [], { cwd: workDir, input: frame, windowsHide: true });`,
    ] : [
      `  const argVal = ${helperBuilt.inputIsHex8} ? staged.toString('hex') : staged.toString('latin1');`,
      `  const child = spawnSync(helperExe, [${JSON.stringify(helperBuilt.flag1)}, ${JSON.stringify(helperBuilt.argPrefix)} + argVal], { cwd: workDir, windowsHide: true });`,
    ]),
    `  if (child.status !== 0) {`,
    `    return { ok: false, exitCode: child.status, error: 'helper_rejected' };`,
    `  }`,
    `  const outputHex = child.stdout.toString('utf8').trim().toLowerCase();`,
    `  if (${useMemoCache}) { memoObj[originalHex] = outputHex; writeMemoCache(memoObj); }`,
    `  return { ok: true, cached: false, helperSpawned: true, outputHex };`,
    `}`,
    ``,
    `ipcMain.handle(${JSON.stringify(spec.ipcChannel)}, async (_ev, req) => runBusinessChain(req?.payload, req));`,
    `ipcMain.handle(${JSON.stringify(spec.ipcChannel + ':reset')}, async () => { try { fs.unlinkSync(cacheFile); } catch {} return { reset: true }; });`,
    ``,
    `app.whenReady().then(async () => {`,
    `  if (process.env.IG5_HEADLESS_IPC_PAYLOAD) {`,
    `    const out = runBusinessChain(process.env.IG5_HEADLESS_IPC_PAYLOAD, { bypassCache: process.env.IG5_BYPASS_CACHE === '1' });`,
    `    process.stdout.write('IG5_ELECTRON_RESULT=' + JSON.stringify(out) + '\\n');`,
    `    app.quit();`,
    `    return;`,
    `  }`,
    `  const win = new BrowserWindow({`,
    `    width: 640, height: 480, show: false,`,
    `    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false },`,
    `  });`,
    `  await win.loadFile(path.join(__dirname, 'index.html'));`,
    `  if (process.env.IG5_AUTO_CLICK_PAYLOAD) {`,
    `    await win.webContents.executeJavaScript(`,
    `      'document.getElementById("payload-input").value = ' + JSON.stringify(process.env.IG5_AUTO_CLICK_PAYLOAD) + '; document.getElementById(' + JSON.stringify(${JSON.stringify(spec.buttonId || 'btn-submit')}) + ').click();'`,
    `    );`,
    `    setTimeout(async () => {`,
    `      const text = await win.webContents.executeJavaScript('document.getElementById("result-box").textContent');`,
    `      process.stdout.write('IG5_ELECTRON_UI_RESULT=' + text + '\\n');`,
    `      app.quit();`,
    `    }, 250);`,
    `  }`,
    `});`,
  ];
  fs.writeFileSync(path.join(rootDir, 'main.js'), mainLines.join('\n') + '\n', 'utf8');

  const computeEndToEndHex = (in4Buf) => {
    const staged = Buffer.alloc(4);
    for (let i = 0; i < 4; i++) staged[i] = (in4Buf[i] ^ jsXorByte) & 0xff;
    return helperBuilt.computeHelperHex(staged);
  };

  return {
    appDir: rootDir,
    appName: spec.appName,
    ipcChannel: spec.ipcChannel,
    buttonId: spec.buttonId || 'btn-submit',
    jsPreXorByte: jsXorByte,
    helperPath,
    helperBuilt,
    decoyPath,
    decoyBuilt,
    computeEndToEndHex,
  };
}
