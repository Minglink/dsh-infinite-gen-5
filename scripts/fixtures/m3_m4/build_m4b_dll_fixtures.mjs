import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const rol8 = (v, s) => (((v & 0xff) << (s & 7)) | ((v & 0xff) >>> (8 - (s & 7)))) & 0xff;

function makeAssembler(image, rawFn, maxRva) {
  return function assembleAt(startRva, buildFn) {
    const chunks = [];
    const labels = new Map();
    const fixups = [];
    let pc = startRva;
    const emitHex = (hex) => {
      const b = Buffer.from(hex, 'hex');
      chunks.push(b);
      pc += b.length;
    };
    const label = (name) => labels.set(name, pc);
    const emitRel32 = (prefixHex, target) => {
      const p = Buffer.from(prefixHex, 'hex');
      const patchOff = pc - startRva + p.length;
      const nextPc = pc + p.length + 4;
      chunks.push(p, Buffer.alloc(4));
      fixups.push({ patchOff, nextPc, target });
      pc = nextPc;
    };
    buildFn({ emitHex, label, emitRel32, pc: () => pc });
    const code = Buffer.concat(chunks);
    for (const f of fixups) {
      const tRva = typeof f.target === 'number' ? f.target : labels.get(f.target);
      if (tRva === undefined) throw new Error(`Unresolved label: ${f.target}`);
      code.writeInt32LE(tRva - f.nextPc, f.patchOff);
    }
    if (startRva + code.length > maxRva) {
      throw new Error(`.text overflow at 0x${(startRva + code.length).toString(16)}`);
    }
    code.copy(image, rawFn(startRva));
    return labels;
  };
}

/**
 * Build a genuine Windows x64 PE32+ DYNAMIC_BASE (.reloc-enabled ASLR) DLL (`calc_engine.dll`)
 * exporting `EngineInit` and `EngineTransform`.
 *
 * Stateful contract:
 *   - `DllMain` sets `g_dllLoaded = 1`, `g_initialized = 0`.
 *   - `EngineInit(uint32_t seed)` derives `g_state[0..3]` from `seed` and sets `g_initialized = 1`.
 *   - `EngineTransform(const uint8_t* in4, uint8_t* out4)`:
 *       - If `g_initialized != 1`: writes `0xef, 0xbe, 0xad, 0xde` and returns `-1` (`0xffffffff`).
 *       - If `g_initialized == 1`: computes `out4[i] = rol8(((in4[i] ^ g_state[i]) + C[i]) & 0xff, rot)`
 *         and returns `0`.
 */
export function buildStatefulAslrDll64({
  dllName = 'calc_engine.dll',
  constants = [0x37, 0x9c, 0x52, 0xe1],
  rot = 3,
  seedXor = 0x5a3c96e1,
} = {}) {
  // Layout:
  // Headers: 0x000..0x3ff
  // .text  : RVA 0x1000..0x1fff (raw 0x400..0x7ff, size 0x400)
  // .rdata : RVA 0x2000..0x2fff (raw 0x800..0xdff, size 0x600) - Export Directory
  // .data  : RVA 0x3000..0x3fff (raw 0xe00..0x11ff, size 0x400) - Stateful globals
  // .reloc : RVA 0x4000..0x4fff (raw 0x1200..0x13ff, size 0x200) - Base Relocation Table for ASLR
  const image = Buffer.alloc(0x1400, 0);
  const preferredBase = 0x180000000n;
  const optional = 0x98;
  const u16 = (off, v) => image.writeUInt16LE(v, off);
  const u32 = (off, v) => image.writeUInt32LE(v >>> 0, off);
  const u64 = (off, v) => image.writeBigUInt64LE(BigInt(v), off);
  const text = (off, v) => image.write(v, off, 'ascii');
  const raw = (rva) => {
    if (rva >= 0x1000 && rva < 0x2000) return 0x400 + (rva - 0x1000);
    if (rva >= 0x2000 && rva < 0x3000) return 0x800 + (rva - 0x2000);
    if (rva >= 0x3000 && rva < 0x4000) return 0xe00 + (rva - 0x3000);
    if (rva >= 0x4000 && rva < 0x5000) return 0x1200 + (rva - 0x4000);
    throw new Error(`Unmapped DLL RVA 0x${rva.toString(16)}`);
  };

  text(0, 'MZ'); u32(0x3c, 0x80); text(0x80, 'PE\0\0');
  u16(0x84, 0x8664); // AMD64
  u16(0x86, 4);      // 4 sections (.text, .rdata, .data, .reloc)
  u16(0x94, 0xf0);   // SizeOfOptionalHeader
  u16(0x96, 0x2022); // IMAGE_FILE_EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL

  u16(optional, 0x20b); image[optional + 2] = 14;
  u32(optional + 4, 0x400);
  u32(optional + 8, 0xc00);
  u32(optional + 16, 0x1000); // AddressOfEntryPoint = DllMain at RVA 0x1000
  u32(optional + 20, 0x1000);
  u64(optional + 24, preferredBase);
  u32(optional + 32, 0x1000); // SectionAlignment
  u32(optional + 36, 0x200);  // FileAlignment
  u16(optional + 40, 6); u16(optional + 48, 6);
  u32(optional + 56, 0x5000); // SizeOfImage
  u32(optional + 60, 0x400);  // SizeOfHeaders
  u16(optional + 68, 3);      // Subsystem CUI
  u16(optional + 70, 0x0160); // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT
  u64(optional + 72, 0x100000); u64(optional + 80, 0x1000);
  u64(optional + 88, 0x100000); u64(optional + 96, 0x1000);
  u32(optional + 108, 16);    // NumberOfRvaAndSizes

  // DataDirectory[0] = Export Table at RVA 0x2000, size 0xa0
  u32(optional + 112, 0x2000); u32(optional + 116, 0xa0);
  // DataDirectory[5] = Base Relocation Table at RVA 0x4000, size 12
  u32(optional + 112 + 5 * 8, 0x4000); u32(optional + 116 + 5 * 8, 12);

  const sections = [
    ['.text', 0x1000, 0x400, 0x400, 0x60000020],
    ['.rdata', 0x2000, 0x800, 0x600, 0x40000040],
    ['.data', 0x3000, 0xe00, 0x400, 0xc0000040],
    ['.reloc', 0x4000, 0x1200, 0x200, 0x42000040],
  ];
  sections.forEach(([name, rva, fileOff, sz, flags], idx) => {
    const hdr = optional + 0xf0 + idx * 40;
    text(hdr, name);
    u32(hdr + 8, sz);
    u32(hdr + 12, rva);
    u32(hdr + 16, sz);
    u32(hdr + 20, fileOff);
    u32(hdr + 36, flags);
  });

  // .reloc block covering page 0x1000 with 2 IMAGE_REL_BASED_ABSOLUTE padding entries (valid for pure RIP-relative code)
  u32(raw(0x4000), 0x1000); // VirtualAddress
  u32(raw(0x4000) + 4, 12); // SizeOfBlock (8-byte header + 4 bytes of type-0 entries)
  u16(raw(0x4000) + 8, 0);
  u16(raw(0x4000) + 10, 0);

  // Constants in .rdata at 0x2100
  const constRva = 0x2100;
  Buffer.from(constants).copy(image, raw(constRva));

  // Globals in .data:
  // 0x3000: g_dllLoaded (u32)
  // 0x3004: g_initialized (u32)
  // 0x3010: g_state[4] (4 bytes)
  // 0x3100: g_lastOutput[4] (4 bytes, convenient memory witness inside DLL RVA space!)
  const gDllLoadedRva = 0x3000;
  const gInitRva = 0x3004;
  const gStateRva = 0x3010;
  const gLastOutRva = 0x3100;

  const dllMainRva = 0x1000;
  const engineInitRva = 0x1040;
  const engineTransformRva = 0x1090;

  // Export Directory at 0x2000 (alphabetical names: EngineInit, EngineTransform)
  const expDir = raw(0x2000);
  u32(expDir + 12, 0x2050); // Name RVA
  u32(expDir + 16, 1);      // Base ordinal = 1
  u32(expDir + 20, 2);      // NumberOfFunctions = 2
  u32(expDir + 24, 2);      // NumberOfNames = 2
  u32(expDir + 28, 0x2028); // AddressOfFunctions RVA
  u32(expDir + 32, 0x2030); // AddressOfNames RVA
  u32(expDir + 36, 0x2038); // AddressOfNameOrdinals RVA

  u32(raw(0x2028), engineInitRva);
  u32(raw(0x2028) + 4, engineTransformRva);
  u32(raw(0x2030), 0x2068);
  u32(raw(0x2030) + 4, 0x2078);
  u16(raw(0x2038), 0);
  u16(raw(0x2038) + 2, 1);
  text(raw(0x2050), `${dllName}\0`);
  text(raw(0x2068), 'EngineInit\0');
  text(raw(0x2078), 'EngineTransform\0');

  const assembleAt = makeAssembler(image, raw, 0x1400);

  // DllMain(hinstDLL=rcx, fdwReason=edx, lpvReserved=r8) -> TRUE (1)
  assembleAt(dllMainRva, (a) => {
    a.emitHex('83fa01');                        // cmp edx, DLL_PROCESS_ATTACH (1)
    a.emitRel32('0f85', 'done');
    a.emitRel32('c705', gDllLoadedRva);         // mov dword ptr [rip + g_dllLoaded], 1 (note: c7 05 <disp32> <imm32>!)
    // Wait: c7 05 has a 4-byte imm32 AFTER disp32, so nextPc in RIP-relative addressing is +8, not +4!
    // Always use `lea r9, [rip + rva]` + `mov dword ptr [r9], imm32` so emitRel32 is exact!
    a.label('done');
  });
  // Re-emit DllMain cleanly using `lea r9, [rip + ...]` so RIP-relative displacement has 0 trailing immediate bytes!
  image.fill(0, raw(dllMainRva), raw(dllMainRva) + 64);
  assembleAt(dllMainRva, (a) => {
    a.emitHex('83fa01');                        // cmp edx, 1 (DLL_PROCESS_ATTACH)
    a.emitRel32('0f85', 'ret_true');
    a.emitRel32('4c8d0d', gDllLoadedRva);       // lea r9, [rip + g_dllLoaded]
    a.emitHex('41c70101000000');                // mov dword ptr [r9], 1
    a.emitRel32('4c8d0d', gInitRva);            // lea r9, [rip + g_initialized]
    a.emitHex('41c70100000000');                // mov dword ptr [r9], 0
    a.label('ret_true');
    a.emitHex('b801000000');                    // mov eax, 1
    a.emitHex('c3');
  });

  // EngineInit(ecx = seed):
  //   derived = seed ^ seedXor
  //   store derived (little-endian 4 bytes) into g_state[0..3]
  //   g_initialized = 1
  //   return 0
  const seedXorBytes = Buffer.alloc(4);
  seedXorBytes.writeUInt32LE(seedXor >>> 0, 0);
  assembleAt(engineInitRva, (a) => {
    a.emitHex('89c8');                          // mov eax, ecx
    a.emitHex('35' + seedXorBytes.toString('hex')); // xor eax, seedXor
    a.emitRel32('4c8d0d', gStateRva);           // lea r9, [rip + g_state]
    a.emitHex('418901');                        // mov [r9], eax
    a.emitRel32('4c8d0d', gInitRva);            // lea r9, [rip + g_initialized]
    a.emitHex('41c70101000000');                // mov dword ptr [r9], 1
    a.emitHex('31c0');                          // xor eax, eax
    a.emitHex('c3');
  });

  // EngineTransform(rcx = in4Ptr, rdx = out4Ptr) -> eax (0 if initialized, -1 if uninitialized)
  const labels = assembleAt(engineTransformRva, (a) => {
    a.emitRel32('4c8d0d', gInitRva);
    a.emitHex('418b01');                        // mov eax, [r9]
    a.emitHex('83f801');                        // cmp eax, 1
    a.emitRel32('0f85', 'uninit');

    a.emitRel32('4c8d05', gStateRva);           // lea r8, [rip + g_state]
    a.emitRel32('4c8d15', constRva);            // lea r10, [rip + constants]
    a.emitHex('4531c9');                        // xor r9d, r9d (i = 0)
    a.label('loop');
    a.emitHex('420fb60409');                    // movzx eax, byte ptr [rcx + r9]
    a.emitHex('43320408');                      // xor al, byte ptr [r8 + r9]
    a.emitHex('4302040a');                      // add al, byte ptr [r10 + r9]
    a.emitHex('c0c0' + Buffer.from([rot & 7]).toString('hex')); // rol al, rot
    a.emitHex('4288040a');                      // mov byte ptr [rdx + r9], al
    a.emitHex('41ffc1');                        // inc r9d
    a.emitHex('4183f904');                      // cmp r9d, 4
    a.emitRel32('0f82', 'loop');

    // Also mirror 4-byte output into DLL's own g_lastOutput (RVA 0x3100) for DLL-RVA memory receipt verification!
    a.emitHex('8b02');                          // mov eax, [rdx]
    a.emitRel32('4c8d0d', gLastOutRva);         // lea r9, [rip + g_lastOutput]
    a.emitHex('418901');                        // mov [r9], eax
    a.label('after_store');
    a.emitHex('31c0');                          // xor eax, eax (return 0)
    a.emitHex('c3');

    a.label('uninit');
    a.emitHex('c702efbeadde');                  // mov dword ptr [rdx], 0xdeadbeef
    a.emitRel32('4c8d0d', gLastOutRva);         // lea r9, [rip + g_lastOutput]
    a.emitHex('41c701efbeadde');                // mov dword ptr [r9], 0xdeadbeef
    a.emitHex('b8ffffffff');                    // mov eax, -1
    a.emitHex('c3');
  });

  const computeExpectedHex = (in4Buf, hostSeed = 0x13572468) => {
    const derived = (hostSeed ^ seedXor) >>> 0;
    const stateBytes = [derived & 0xff, (derived >>> 8) & 0xff, (derived >>> 16) & 0xff, (derived >>> 24) & 0xff];
    const out = Buffer.alloc(4);
    for (let i = 0; i < 4; i++) {
      out[i] = rol8(((in4Buf[i] ^ stateBytes[i]) + constants[i]) & 0xff, rot);
    }
    return out.toString('hex');
  };

  return {
    dllName,
    image,
    sha256: sha256(image),
    preferredBase: '0x180000000',
    exports: {
      EngineInit: '0x' + engineInitRva.toString(16),
      EngineTransform: '0x' + engineTransformRva.toString(16),
    },
    afterStoreRva: '0x' + labels.get('after_store').toString(16),
    gLastOutRva: '0x' + gLastOutRva.toString(16),
    gStateRva: '0x' + gStateRva.toString(16),
    computeExpectedHex,
  };
}

/**
 * Build a native x64 PE32+ Host Executable (`dll_host_runner.exe`) that:
 *   1. Reserves `0x180000000` with `VirtualAlloc` BEFORE `LoadLibraryA("calc_engine.dll")` so Windows
 *      is GUARANTEED to relocate `calc_engine.dll` away from its preferred base `0x180000000` (proving live ASLR!).
 *   2. Supports `--mode=host X=<4B>` (normal initialized host call: `EngineInit(hostSeed)` -> `EngineTransform(in4, out4)`),
 *      `--mode=uninit X=<4B>` (skips `EngineInit` to demonstrate standalone/uninitialized counterexample!),
 *      and `--mode=reload X=<4B>` (loads DLL #1, calls `EngineInit`, `FreeLibrary`, reserves DLL #1's base so
 *      `LoadLibraryA` #2 maps `calc_engine.dll` at a SECOND distinct ASLR base, then calls `EngineInit` + `EngineTransform`!).
 */
export function buildDllHostRunnerPe64({
  dllName = 'calc_engine.dll',
  hostSeed = 0x13572468,
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
    ['VirtualAlloc', 0x2328, 0x2408],
    ['LoadLibraryA', 0x2340, 0x2410],
    ['GetProcAddress', 0x2358, 0x2418],
    ['FreeLibrary', 0x2370, 0x2420],
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

  // Strings in .rdata
  text(raw(0x2080), `${dllName}\0`);
  text(raw(0x20a0), 'EngineInit\0');
  text(raw(0x20b8), 'EngineTransform\0');
  text(raw(0x20d0), '--mode=host\0');    // len 11
  text(raw(0x20e0), '--mode=uninit\0');  // len 13
  text(raw(0x20f8), '--mode=reload\0');  // len 13
  text(raw(0x2110), 'X=\0');             // len 2

  // Globals in .data:
  // 0x3010: firstModuleBase (u64)
  // 0x3018: activeModuleBase (u64)
  // 0x3120: hostOutBuf[4]
  // 0x3400: tokPtrs[8], 0x3440: tokLens[8]
  const firstBaseRva = 0x3010;
  const activeBaseRva = 0x3018;
  const hostOutBufRva = 0x3120;

  const assembleAt = makeAssembler(image, raw, 0x1400);

  // mem_eq_n at 0x1260, parse_cli_tokens at 0x12b0
  assembleAt(0x1260, (a) => {
    a.emitHex('4531c9');
    a.label('lp');
    a.emitHex('4539c1'); a.emitRel32('0f83', 'eq');
    a.emitHex('420fb60409'); a.emitHex('460fb6140a'); a.emitHex('4439d0'); a.emitRel32('0f85', 'ne');
    a.emitHex('41ffc1'); a.emitRel32('e9', 'lp');
    a.label('eq'); a.emitHex('b801000000'); a.emitHex('c3');
    a.label('ne'); a.emitHex('31c0'); a.emitHex('c3');
  });
  assembleAt(0x12b0, (a) => {
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

  const seedBytes = Buffer.alloc(4);
  seedBytes.writeUInt32LE(hostSeed >>> 0, 0);

  const labels = assembleAt(0x1000, (a) => {
    a.emitHex('4883ec48');

    // Parse CLI tokens: argc must be 3 (exe, --mode=..., X=<4B>)
    a.emitRel32('ff15', 0x2400); // GetCommandLineA
    a.emitHex('4889c1');
    a.emitRel32('488d15', 0x3400);
    a.emitRel32('4c8d05', 0x3440);
    a.emitRel32('e8', 0x12b0);
    a.emitHex('83f803');
    a.emitRel32('0f85', 'fail');

    // Determine mode in r12d: 1=host, 2=uninit, 3=reload
    a.emitHex('4531e4');
    // Check --mode=host (len 11)
    a.emitRel32('8b05', 0x3440 + 4);
    a.emitHex('83f80b');
    a.emitRel32('0f85', 'chk_uninit');
    a.emitRel32('488b0d', 0x3400 + 8);
    a.emitRel32('488d15', 0x20d0);
    a.emitHex('41b80b000000');
    a.emitRel32('e8', 0x1260);
    a.emitHex('85c0');
    a.emitRel32('0f84', 'chk_uninit');
    a.emitHex('41bc01000000');
    a.emitRel32('e9', 'chk_x');

    a.label('chk_uninit');
    a.emitRel32('8b05', 0x3440 + 4);
    a.emitHex('83f80d');
    a.emitRel32('0f85', 'fail');
    a.emitRel32('488b0d', 0x3400 + 8);
    a.emitRel32('488d15', 0x20e0);
    a.emitHex('41b80d000000');
    a.emitRel32('e8', 0x1260);
    a.emitHex('85c0');
    a.emitRel32('0f84', 'chk_reload');
    a.emitHex('41bc02000000');
    a.emitRel32('e9', 'chk_x');

    a.label('chk_reload');
    a.emitRel32('488b0d', 0x3400 + 8);
    a.emitRel32('488d15', 0x20f8);
    a.emitHex('41b80d000000');
    a.emitRel32('e8', 0x1260);
    a.emitHex('85c0');
    a.emitRel32('0f84', 'fail');
    a.emitHex('41bc03000000');

    a.label('chk_x');
    a.emitRel32('8b05', 0x3440 + 8);
    a.emitHex('83f806');
    a.emitRel32('0f85', 'fail');
    a.emitRel32('488b0d', 0x3400 + 16);
    a.emitRel32('488d15', 0x2110);
    a.emitHex('41b802000000');
    a.emitRel32('e8', 0x1260);
    a.emitHex('85c0');
    a.emitRel32('0f84', 'fail');

    // Reserve preferred DLL base 0x180000000 (MEM_RESERVE=0x2000, PAGE_NOACCESS=1) so Windows MUST relocate calc_engine.dll!
    a.emitHex('48b90000008001000000');          // mov rcx, 0x180000000
    a.emitHex('ba00000100');                    // mov edx, 0x10000
    a.emitHex('41b800200000');                  // mov r8d, MEM_RESERVE (0x2000)
    a.emitHex('41b901000000');                  // mov r9d, PAGE_NOACCESS (1)
    a.emitRel32('ff15', 0x2408);                // VirtualAlloc

    // LoadLibraryA("calc_engine.dll") #1
    a.emitRel32('488d0d', 0x2080);
    a.emitRel32('ff15', 0x2410);
    a.emitHex('4885c0');
    a.emitRel32('0f84', 'fail');
    a.emitHex('4889c3');                        // rbx = hMod
    a.emitRel32('488905', firstBaseRva);
    a.emitRel32('488905', activeBaseRva);

    // If mode == 3 (reload): FreeLibrary(rbx), reserve rbx via VirtualAlloc, LoadLibraryA #2 at a NEW ASLR base!
    a.emitHex('4183fc03');
    a.emitRel32('0f85', 'resolve_exports');
    a.emitHex('4889d9');
    a.emitRel32('ff15', 0x2420);                // FreeLibrary(hMod1)
    a.emitHex('4889d9');                        // rcx = old base
    a.emitHex('ba00000100');                    // edx = 0x10000
    a.emitHex('41b800200000');                  // MEM_RESERVE
    a.emitHex('41b901000000');                  // PAGE_NOACCESS
    a.emitRel32('ff15', 0x2408);                // VirtualAlloc(oldBase) -> forces LoadLibraryA #2 to pick a NEW base!
    a.emitRel32('488d0d', 0x2080);
    a.emitRel32('ff15', 0x2410);                // LoadLibraryA #2
    a.emitHex('4885c0');
    a.emitRel32('0f84', 'fail');
    a.emitHex('4889c3');                        // rbx = hMod2
    a.emitRel32('488905', activeBaseRva);

    a.label('resolve_exports');
    // If mode != 2 (uninit), call EngineInit(hostSeed)
    a.emitHex('4183fc02');
    a.emitRel32('0f84', 'call_transform');
    a.emitHex('4889d9');
    a.emitRel32('488d15', 0x20a0);              // "EngineInit"
    a.emitRel32('ff15', 0x2418);                // GetProcAddress
    a.emitHex('4885c0');
    a.emitRel32('0f84', 'fail');
    a.emitHex('b9' + seedBytes.toString('hex')); // mov ecx, hostSeed
    a.emitHex('ffd0');                          // call EngineInit

    a.label('call_transform');
    a.emitHex('4889d9');
    a.emitRel32('488d15', 0x20b8);              // "EngineTransform"
    a.emitRel32('ff15', 0x2418);                // GetProcAddress
    a.emitHex('4885c0');
    a.emitRel32('0f84', 'fail');
    a.emitHex('4989c5');                        // r13 = pEngineTransform
    a.emitRel32('488b0d', 0x3400 + 16);
    a.emitHex('4883c102');                      // rcx = tokPtrs[2] + 2 (4B input)
    a.emitRel32('488d15', hostOutBufRva);       // rdx = hostOutBuf
    a.emitHex('41ffd5');                        // call r13 (EngineTransform)
    a.label('after_host_transform');
    a.emitHex('85c0');                          // test eax, eax (0 on initialized success, -1 on uninit)
    a.emitRel32('0f85', 'uninit_exit');

    a.emitHex('31c9');
    a.emitRel32('ff15', 0x2428);                // ExitProcess(0)

    a.label('uninit_exit');
    a.emitHex('b904000000');
    a.emitRel32('ff15', 0x2428);                // ExitProcess(4) when DLL state was uninitialized!

    a.label('fail');
    a.emitHex('b901000000');
    a.emitRel32('ff15', 0x2428);                // ExitProcess(1)
  });

  return {
    binaryName: 'dll_host_runner.exe',
    image,
    sha256: sha256(image),
    hostSeed,
    firstBaseRva: '0x' + firstBaseRva.toString(16),
    activeBaseRva: '0x' + activeBaseRva.toString(16),
    hostOutBufRva: '0x' + hostOutBufRva.toString(16),
    afterHostTransformRva: '0x' + labels.get('after_host_transform').toString(16),
  };
}
