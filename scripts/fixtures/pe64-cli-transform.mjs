// Deterministic, self-produced benign PE64 CLI fixture for M1 dynamic experiment verification.
// Imports only GetCommandLineA, GetCurrentDirectoryA, and ExitProcess from KERNEL32.dll.
// Behavior:
//   1) Records current working directory into .data RVA 0x3200 via GetCurrentDirectoryA.
//   2) Scans GetCommandLineA() for "X=<4-bytes>". If absent, calls ExitProcess(0) directly
//      without invoking transform_block (RVA 0x1080).
//   3) If "X=<4-bytes>" is present, calls transform_block(in4, outBuf@0x3100):
//        out[i] = ((in[i] ^ KEY[i]) + (i * 7 + 3)) & 0xff, KEY = [0x5a, 0xa5, 0x33, 0xcc] @ 0x3000
//      then lands at afterTransformRva before ExitProcess(0).

export const CLI_TRANSFORM_KEY = [0x5a, 0xa5, 0x33, 0xcc];

export function computeExpectedCliTransformHex(fourByteBuf) {
  if (fourByteBuf.length !== 4) throw new Error('Expected 4-byte input buffer');
  const out = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) {
    out[i] = ((fourByteBuf[i] ^ CLI_TRANSFORM_KEY[i]) + (i * 7 + 3)) & 0xff;
  }
  return out.toString('hex');
}

export function buildCliTransformPE64() {
  const image = Buffer.alloc(0x1e00, 0);
  const base = 0x140000000n;
  const optional = 0x98;
  const u16 = (off, v) => image.writeUInt16LE(v, off);
  const u32 = (off, v) => image.writeUInt32LE(v >>> 0, off);
  const u64 = (off, v) => image.writeBigUInt64LE(BigInt(v), off);
  const raw = rva => (rva < 0x2000 ? 0x400 + rva - 0x1000 : rva < 0x3000 ? 0x800 + rva - 0x2000 : 0xe00 + rva - 0x3000);
  const text = (off, v) => image.write(v, off, 'ascii');
  const addrHex = rva => '0x' + (base + BigInt(rva)).toString(16);

  // DOS + PE64 headers
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

  // Imports in .rdata
  const imports = [
    ['GetCommandLineA', 0x2340, 0x2400],
    ['GetCurrentDirectoryA', 0x2360, 0x2408],
    ['ExitProcess', 0x2390, 0x2410],
  ];
  u32(raw(0x2200), 0x2300); u32(raw(0x2200) + 12, 0x2280); u32(raw(0x2200) + 16, 0x2400);
  text(raw(0x2280), 'KERNEL32.dll\0');
  imports.forEach(([fnName, nameRva], idx) => {
    u64(raw(0x2300) + idx * 8, nameRva);
    u64(raw(0x2400) + idx * 8, nameRva);
    u16(raw(nameRva), 0);
    text(raw(nameRva) + 2, fnName + '\0');
  });

  // Initialized .data key table at RVA 0x3000
  const keyRva = 0x3000;
  const outBufRva = 0x3100;
  const cwdBufRva = 0x3200;
  Buffer.from(CLI_TRANSFORM_KEY).copy(image, raw(keyRva));

  // Label-resolving mini-assembler for .text
  function assembleAt(startRva, buildFn) {
    const chunks = [];
    const labels = new Map();
    const fixups = [];
    let pc = startRva;

    const emitHex = hex => {
      const b = Buffer.from(hex, 'hex');
      chunks.push(b);
      pc += b.length;
    };
    const label = name => labels.set(name, pc);
    const emitRel32 = (prefixHex, target) => {
      const p = Buffer.from(prefixHex, 'hex');
      const patchOffsetInStream = pc - startRva + p.length;
      const nextPc = pc + p.length + 4;
      chunks.push(p, Buffer.alloc(4));
      fixups.push({ patchOffsetInStream, nextPc, target });
      pc = nextPc;
    };

    buildFn({ emitHex, label, emitRel32, pc: () => pc });

    const code = Buffer.concat(chunks);
    for (const f of fixups) {
      const targetRva = typeof f.target === 'number' ? f.target : labels.get(f.target);
      if (targetRva === undefined) throw new Error(`Unresolved label: ${f.target}`);
      code.writeInt32LE(targetRva - f.nextPc, f.patchOffsetInStream);
    }
    code.copy(image, raw(startRva));
    return labels;
  }

  const transformRva = 0x1080;

  // Assemble entry() at RVA 0x1000
  const entryLabels = assembleAt(0x1000, a => {
    a.emitHex('4883ec28');                     // sub rsp, 0x28
    a.emitHex('b904010000');                   // mov ecx, 260
    a.emitRel32('488d15', cwdBufRva);          // lea rdx, [rip + cwdBuf]
    a.emitRel32('ff15', 0x2408);               // call [GetCurrentDirectoryA]
    a.emitRel32('ff15', 0x2400);               // call [GetCommandLineA]

    a.label('scan_loop');
    a.emitHex('0fb608');                       // movzx ecx, byte ptr [rax]
    a.emitHex('84c9');                         // test cl, cl
    a.emitRel32('0f84', 'exit_clean');         // jz exit_clean
    a.emitHex('668138583d');                   // cmp word ptr [rax], 'X=' (0x3d58)
    a.emitRel32('0f84', 'found_marker');       // je found_marker
    a.emitHex('48ffc0');                       // inc rax
    a.emitRel32('e9', 'scan_loop');            // jmp scan_loop

    a.label('found_marker');
    a.emitHex('488d4802');                     // lea rcx, [rax + 2]
    a.emitRel32('488d15', outBufRva);          // lea rdx, [rip + outBuf]
    a.emitRel32('e8', transformRva);           // call transform_block

    a.label('after_transform');
    a.emitHex('90');                           // nop (breakpoint observation site)

    a.label('exit_clean');
    a.emitHex('31c9');                         // xor ecx, ecx
    a.emitRel32('ff15', 0x2410);               // call [ExitProcess]
    a.emitHex('cc');                           // int3
  });

  // Assemble transform_block(rcx=in4, rdx=out4) at RVA 0x1080
  assembleAt(transformRva, a => {
    a.emitRel32('4c8d05', keyRva);             // lea r8, [rip + keyTable]
    a.emitHex('4531c9');                       // xor r9d, r9d
    a.label('loop_top');
    a.emitHex('420fb60409');                   // movzx eax, byte ptr [rcx + r9]
    a.emitHex('470fb61408');                   // movzx r10d, byte ptr [r8 + r9]
    a.emitHex('4431d0');                       // xor eax, r10d
    a.emitHex('456bd907');                     // imul r11d, r9d, 7
    a.emitHex('4183c303');                     // add r11d, 3
    a.emitHex('4401d8');                       // add eax, r11d
    a.emitHex('4288040a');                     // mov byte ptr [rdx + r9], al
    a.emitHex('41ffc1');                       // inc r9d
    a.emitHex('4183f904');                     // cmp r9d, 4
    a.emitRel32('0f82', 'loop_top');           // jb loop_top
    a.emitHex('8b02');                         // mov eax, dword ptr [rdx]
    a.emitHex('c3');                           // ret
  });

  const afterTransformRva = entryLabels.get('after_transform');
  return {
    image,
    base: '0x140000000',
    entryRva: '0x1000',
    entryVa: addrHex(0x1000),
    transformRva: '0x' + transformRva.toString(16),
    transformVa: addrHex(transformRva),
    afterTransformRva: '0x' + afterTransformRva.toString(16),
    afterTransformVa: addrHex(afterTransformRva),
    keyRva: '0x' + keyRva.toString(16),
    keyVa: addrHex(keyRva),
    outBufRva: '0x' + outBufRva.toString(16),
    outBufVa: addrHex(outBufRva),
    cwdBufRva: '0x' + cwdBufRva.toString(16),
    cwdBufVa: addrHex(cwdBufRva),
  };
}
