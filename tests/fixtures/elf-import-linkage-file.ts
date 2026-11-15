// ELF64 sectionless PIE: gABI ELF header, program headers, dynamic section and RELA.
// https://gabi.xinuos.com/elf/02-eheader.html
// https://gabi.xinuos.com/elf/07-pheader.html
// https://gabi.xinuos.com/elf/08-dynamic.html
export const createElfImportLinkageBytes = (): Uint8Array => {
  const bytes = new Uint8Array(1024);
  const view = new DataView(bytes.buffer);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]); // ELF64, little endian, version 1.
  view.setUint16(16, 3, true); // ET_DYN.
  view.setUint16(18, 62, true); // EM_X86_64.
  view.setUint32(20, 1, true);
  view.setBigUint64(24, 0x1100n, true);
  view.setBigUint64(32, 64n, true);
  view.setUint16(52, 64, true);
  view.setUint16(54, 56, true);
  view.setUint16(56, 3, true);
  const tags = [[3, 0x1200n], [4, 0x1260n], [5, 0x12b0n], [10, 6n], [6, 0x1280n], [11, 24n],
    [39, 48n], [23, 0x1220n], [2, 48n], [20, 7n], [30, 8n], [0, 0n]] as const;
  const segments = [
    { type: 1, flags: 7, offset: 0, size: bytes.length },
    { type: 2, flags: 6, offset: 0x300, size: tags.length * 16 },
    { type: 0x6474e552, flags: 4, offset: 0x200, size: 16 }
  ];
  segments.forEach((segment, index) => {
    const position = 64 + index * 56;
    view.setUint32(position, segment.type, true);
    view.setUint32(position + 4, segment.flags, true);
    view.setBigUint64(position + 8, BigInt(segment.offset), true);
    view.setBigUint64(position + 16, 0x1000n + BigInt(segment.offset), true);
    view.setBigUint64(position + 32, BigInt(segment.size), true);
    view.setBigUint64(position + 40, BigInt(segment.size), true);
    view.setBigUint64(position + 48, 1n, true);
  });
  // CALL 0x1120; RET. Stub: JMP [RIP+0xda] targets the slot at 0x1200.
  // Intel SDM Vol. 2, CALL/JMP encodings.
  bytes.set([0xe8, 0x1b, 0, 0, 0, 0xc3], 0x100);
  bytes.set([0xff, 0x25, 0xda, 0, 0, 0], 0x120);
  view.setBigUint64(0x220, 0x1200n, true);
  view.setBigUint64(0x228, (1n << 32n) | 7n, true); // Symbol 1, R_X86_64_JUMP_SLOT.
  // A second slot for the same import exercises sorting and missing code evidence.
  view.setBigUint64(0x238, 0x1208n, true);
  view.setBigUint64(0x240, (1n << 32n) | 7n, true);
  // System V hash: one bucket points to symbol 1; two chains terminate at STN_UNDEF.
  view.setUint32(0x260, 1, true);
  view.setUint32(0x264, 2, true);
  view.setUint32(0x268, 1, true);
  view.setUint32(0x298, 1, true); // Elf64_Sym.st_name.
  view.setUint8(0x29c, 0x12); // STB_GLOBAL | STT_FUNC; st_shndx=SHN_UNDEF.
  bytes.set(new TextEncoder().encode("\0puts\0"), 0x2b0);
  tags.forEach(([tag, value], index) => {
    view.setBigUint64(0x300 + index * 16, BigInt(tag), true);
    view.setBigUint64(0x308 + index * 16, value, true);
  });
  return bytes;
};
