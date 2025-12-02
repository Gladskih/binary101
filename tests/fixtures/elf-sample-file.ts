"use strict";

import { MockFile } from "../helpers/mock-file.js";

const encoder = new TextEncoder();

const buildElf64File = () => {
  const headerSize = 64;
  const phSize = 56;
  const shSize = 64;
  const phoff = headerSize;
  const shoff = phoff + phSize;
  const shstrOffset = shoff + shSize * 2;
  const shstrContent = encoder.encode("\0.shstrtab\0");
  const totalSize = shstrOffset + shstrContent.length;
  const bytes = new Uint8Array(totalSize).fill(0);
  const dv = new DataView(bytes.buffer);
  // e_ident
  dv.setUint32(0, 0x7f454c46, false); // ELF
  dv.setUint8(4, 2); // 64-bit
  dv.setUint8(5, 1); // little endian
  dv.setUint8(6, 1); // version
  // e_type, e_machine, e_version
  dv.setUint16(16, 2, true); // executable
  dv.setUint16(18, 0x3e, true); // x86-64
  dv.setUint32(20, 1, true);
  dv.setBigUint64(24, 0x400000n, true); // entry
  dv.setBigUint64(32, BigInt(phoff), true);
  dv.setBigUint64(40, BigInt(shoff), true);
  dv.setUint32(48, 0, true); // flags
  dv.setUint16(52, headerSize, true);
  dv.setUint16(54, phSize, true);
  dv.setUint16(56, 1, true);
  dv.setUint16(58, shSize, true);
  dv.setUint16(60, 2, true); // shnum
  dv.setUint16(62, 1, true); // shstrndx
  // Program header (single load segment)
  dv.setUint32(phoff + 0, 1, true); // PT_LOAD
  dv.setUint32(phoff + 4, 5, true); // flags R+X
  dv.setBigUint64(phoff + 8, 0n, true); // offset
  dv.setBigUint64(phoff + 16, 0x400000n, true); // vaddr
  dv.setBigUint64(phoff + 24, 0x400000n, true); // paddr
  dv.setBigUint64(phoff + 32, BigInt(totalSize), true); // filesz
  dv.setBigUint64(phoff + 40, BigInt(totalSize), true); // memsz
  dv.setBigUint64(phoff + 48, 0x1000n, true); // align
  // Section header 0 (null)
  // Section header 1 (.shstrtab)
  const sh1 = shoff + shSize;
  dv.setUint32(sh1 + 0, 1, true); // name offset in shstrtab
  dv.setUint32(sh1 + 4, 3, true); // type: STRTAB
  dv.setBigUint64(sh1 + 8, 0n, true); // flags
  dv.setBigUint64(sh1 + 16, 0n, true); // addr
  dv.setBigUint64(sh1 + 24, BigInt(shstrOffset), true); // offset
  dv.setBigUint64(sh1 + 32, BigInt(shstrContent.length), true); // size
  dv.setUint32(sh1 + 40, 0, true); // link
  dv.setUint32(sh1 + 44, 0, true); // info
  dv.setBigUint64(sh1 + 48, 1n, true); // addralign
  dv.setBigUint64(sh1 + 56, 0n, true); // entsize

  bytes.set(shstrContent, shstrOffset);
  return bytes;
};

export const createElfFile = () =>
  new MockFile(buildElf64File(), "sample.elf", "application/x-elf");
