// Deterministic PE64 bytes for analysis/emulation tests. No compiler, imports,
// runtime library, or native process launch is needed; callers write only tmp copies.
export function buildPE64Fixture(version = 1) {
  if (![1, 2].includes(version)) throw new Error('fixture version must be 1 or 2');
  const image = Buffer.alloc(0x1e00);
  const base = 0x140000000n;
  const u16 = (offset, value) => image.writeUInt16LE(value, offset);
  const u32 = (offset, value) => image.writeUInt32LE(value >>> 0, offset);
  const u64 = (offset, value) => image.writeBigUInt64LE(BigInt(value), offset);
  const raw = (rva) => rva < 0x2000 ? 0x400 + rva - 0x1000 : rva < 0x3000 ? 0x800 + rva - 0x2000 : 0xe00 + rva - 0x3000;
  const text = (offset, value) => image.write(value, offset, 'ascii');
  const address = (rva) => '0x' + (base + BigInt(rva)).toString(16);
  text(0, 'MZ'); u32(0x3c, 0x80); text(0x80, 'PE\0\0');
  u16(0x84, 0x8664); u16(0x86, 3); u16(0x94, 0xf0); u16(0x96, 0x22);
  const optional = 0x98;
  u16(optional, 0x20b); image[optional + 2] = 14;
  u32(optional + 4, 0x400); u32(optional + 8, 0x1600);
  u32(optional + 16, 0x1000); u32(optional + 20, 0x1000); u64(optional + 24, base);
  u32(optional + 32, 0x1000); u32(optional + 36, 0x200);
  u16(optional + 40, 6); u16(optional + 48, 6);
  u32(optional + 56, 0x4000); u32(optional + 60, 0x400);
  u16(optional + 68, 3); u16(optional + 70, 0x100);
  u64(optional + 72, 0x100000); u64(optional + 80, 0x1000);
  u64(optional + 88, 0x100000); u64(optional + 96, 0x1000);
  u32(optional + 108, 16); u32(optional + 112, 0x2000); u32(optional + 116, 0x240);
  for (const [index, name, rva, offset, size, flags] of [
    [0, '.text', 0x1000, 0x400, 0x400, 0x60000020],
    [1, '.rdata', 0x2000, 0x800, 0x600, 0x40000040],
    [2, '.data', 0x3000, 0xe00, 0x1000, 0xc0000040],
  ]) {
    const header = optional + 0xf0 + index * 40;
    text(header, name); u32(header + 8, size); u32(header + 12, rva);
    u32(header + 16, size); u32(header + 20, offset); u32(header + 36, flags);
  }
  image.fill(0xcc, 0x400, 0x800);
  const functions = {
    add: [0x1000, '488d0411c3'],
    buffer: [0x1040, 'c6015a4889c8c3'],
    spin: [0x1080, 'ebfe'],
    fault: [0x10c0, '488b01c3'],
    constant: [0x1100, version === 1 ? 'b811000000c3' : 'b829000000c3'],
    branch: [0x1140, version === 1 ? '85c97406b801000000c3b802000000c3' : '85c9740b83f901740cb801000000c3b802000000c3b803000000c3'],
    frame: [0x11c0, '554889e54883ec2048894df8488b45f84883c4205dc3'],
    switch: [0x1200, '83f902770d48b80023004001000000ff24c8b8ffffffffc3'],
    case0: [0x1260, 'b80a000000c3'],
    case1: [0x1280, 'b814000000c3'],
    case2: [0x12a0, 'b81e000000c3'],
    xor_self: [0x12c0, '31c0c3'],
    sub_self: [0x1300, '29c0c3'],
    xor_copy: [0x1320, '89c831c8c3'],
    sub_copy: [0x1340, '89c829c8c3'],
    memoff: [0x1360, version === 1 ? '8b4104c3' : '8b4108c3'],
  };
  for (const [rva, hex] of Object.values(functions)) Buffer.from(hex, 'hex').copy(image, raw(rva));
  const symbols = [
    ...Object.entries(functions).map(([name, [rva]]) => ['ig5_fixture_' + name, rva]),
    ['_ZTVN10__cxxabiv117__class_type_infoE', 0x3000],
    ['_ZTVN10__cxxabiv120__si_class_type_infoE', 0x3040],
    ['_ZTVN10__cxxabiv121__vmi_class_type_infoE', 0x3080],
  ];
  if (symbols.length > 32) throw new Error('fixture export arrays must not overlap');
  const directory = raw(0x2000);
  u32(directory + 12, 0x3600); u32(directory + 16, 1);
  u32(directory + 20, symbols.length); u32(directory + 24, symbols.length);
  u32(directory + 28, 0x2040); u32(directory + 32, 0x20c0); u32(directory + 36, 0x2140);
  text(raw(0x3600), 'ig5-fixture.dll\0');
  let stringRva = 0x3620;
  symbols.sort((a, b) => a[0].localeCompare(b[0]));
  symbols.forEach(([name, rva], index) => {
    u32(raw(0x2040) + index * 4, rva); u32(raw(0x20c0) + index * 4, stringRva);
    u16(raw(0x2140) + index * 2, index); text(raw(stringRva), name + '\0');
    stringRva += Buffer.byteLength(name + '\0');
  });
  if (stringRva > 0x4000) throw new Error('fixture export names exceed data section');
  for (let index = 0; index < 3; index++) u64(raw(0x2300) + index * 8, base + BigInt(0x1260 + index * 0x20));
  // MSVC x64 RTTI: complete-object locator, TypeDescriptor, class hierarchy,
  // two BaseClassDescriptors, then two executable virtual slots.
  [1, 0, 0, 0x2440, 0x2480, 0x2400].forEach((value, index) => u32(raw(0x2400) + index * 4, value));
  text(raw(0x2440) + 16, '.?AVIG5Derived@@\0');
  text(raw(0x2530) + 16, '.?AVIG5Base@@\0');
  [0, 0, 2, 0x24a0].forEach((value, index) => u32(raw(0x2480) + index * 4, value));
  u32(raw(0x24a0), 0x24c0); u32(raw(0x24a0) + 4, 0x24e0);
  [0x2440, 1, 0, 0xffffffff, 0, 0].forEach((value, index) => u32(raw(0x24c0) + index * 4, value));
  [0x2530, 0, 0, 0xffffffff, 0, 0].forEach((value, index) => u32(raw(0x24e0) + index * 4, value));
  u64(raw(0x2500), base + 0x2400n); u64(raw(0x2508), base + 0x1000n); u64(raw(0x2510), base + 0x1040n);
  // Itanium ABI evidence on mapped PE data: these are byte-layout parser tests,
  // not a claim that the fixture is a Linux executable or a native C++ runtime.
  for (const runtimeTable of [0x3000, 0x3040, 0x3080]) {
    u64(raw(runtimeTable + 16), base + 0x1000n);
    u64(raw(runtimeTable + 24), base + 0x1040n);
  }
  for (const [typeRva, runtimeAddressPoint, nameRva, name] of [
    [0x30c0, 0x3010, 0x3300, '7IG5Base'],
    [0x3100, 0x3050, 0x3320, '10IG5Derived'],
    [0x3140, 0x3090, 0x3340, '8IG5Multi'],
  ]) {
    u64(raw(typeRva), base + BigInt(runtimeAddressPoint));
    u64(raw(typeRva + 8), base + BigInt(nameRva));
    text(raw(nameRva), name + '\0');
  }
  u64(raw(0x3110), base + 0x30c0n); // single public nonvirtual base
  u32(raw(0x3150), 0); u32(raw(0x3154), 2); // VMI flags and base_count
  u64(raw(0x3158), base + 0x30c0n); u64(raw(0x3160), 2);
  u64(raw(0x3168), base + 0x3100n); u64(raw(0x3170), (16 << 8) | 2);
  for (const [table, typeRva, slot0, slot1] of [
    [0x3200, 0x30c0, 0x1000, 0x1040],
    [0x3240, 0x3100, 0x11c0, 0x1000],
    [0x3280, 0x3140, 0x1040, 0x1000],
  ]) {
    u64(raw(table + 8), base + BigInt(typeRva));
    u64(raw(table + 16), base + BigInt(slot0)); u64(raw(table + 24), base + BigInt(slot1));
  }
  return {
    image, version,
    addresses: Object.fromEntries(Object.entries(functions).map(([name, [rva]]) => [name, address(rva)])),
    switchJump: address(0x120f), switchTable: address(0x2300), switchDefault: address(0x1212),
    vtable: address(0x2508), data: address(0x3000),
    itaniumTables: { class: address(0x3210), si: address(0x3250), vmi: address(0x3290) },
  };
}
