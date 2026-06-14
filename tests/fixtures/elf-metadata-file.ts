"use strict";
import { MockFile } from "../helpers/mock-file.js";
const encoder = new TextEncoder();

const alignTo = (value: number, alignment: number): number => {
  const mask = alignment - 1;
  return (value + mask) & ~mask;
};

const buildStringTable = (names: string[]): { bytes: Uint8Array; offsets: Record<string, number> } => {
  const offsets: Record<string, number> = {};
  let text = "\0";
  for (const name of names) {
    offsets[name] = text.length;
    text += `${name}\0`;
  }
  return { bytes: encoder.encode(text), offsets };
};

export type ElfMetadataFixture = {
  file: MockFile;
  expected: {
    interpreter: string;
    needed: string[];
    soname: string;
    runpath: string;
    importSymbol: string;
    exportSymbol: string;
    buildIdHex: string;
    commentStrings: string[];
    debugLinkFileName: string;
    debugLinkCrc32: number;
  };
};

export const createElfMetadataFile = (): ElfMetadataFixture => {
  const headerSize = 64;
  const phSize = 56;
  const phnum = 5;
  const shSize = 64;
  const baseVaddr = 0x400000n;
  const entryVaddr = 0x401000n;
  const phoff = headerSize;
  let offset = phoff + phSize * phnum;

  const interpreter = "/lib64/ld-linux-x86-64.so.2";
  const interpBytes = encoder.encode(`${interpreter}\0`);
  const interpOff = offset;
  offset = alignTo(offset + interpBytes.length, 8);
  const needed = ["libc.so.6", "libm.so.6"];
  const soname = "soname.so";
  const runpath = "runpath";
  const importSymbol = "puts";
  const exportSymbol = "my_func";
  const dynstrText =
    "\0" +
    `${needed[0]}\0` +
    `${needed[1]}\0` +
    `${soname}\0` +
    `${runpath}\0` +
    `${importSymbol}\0` +
    `${exportSymbol}\0`;
  const dynstrBytes = encoder.encode(dynstrText);
  const dynstrOff = offset;
  offset = alignTo(offset + dynstrBytes.length, 8);
  const dynsymOff = offset;
  const dynsymEntrySize = 24;
  const dynsymCount = 3;
  const dynsymBytes = new Uint8Array(dynsymEntrySize * dynsymCount).fill(0);
  offset = alignTo(offset + dynsymBytes.length, 8);
  const dynamicOff = offset;
  const dynEntrySize = 16;
  const dynEntryCount = 13;
  const dynamicBytes = new Uint8Array(dynEntrySize * dynEntryCount).fill(0);
  offset = alignTo(offset + dynamicBytes.length, 8);
  const noteOff = offset;
  const buildIdBytes = new Uint8Array(20).map((_, index) => index & 0xff);
  const buildIdHex = [...buildIdBytes].map(value => value.toString(16).padStart(2, "0")).join("");
  const noteBytes = new Uint8Array(12 + 4 + buildIdBytes.length).fill(0);
  offset = alignTo(offset + noteBytes.length, 8);
  const tdataOff = offset;
  const tdataBytes = new Uint8Array([1, 2, 3, 4]);
  offset = alignTo(offset + tdataBytes.length, 8);
  const commentOff = offset;
  const commentStrings = ["GCC", "Clang"];
  const commentBytes = encoder.encode(`${commentStrings[0]}\0${commentStrings[1]}\0`);
  offset = alignTo(offset + commentBytes.length, 8);
  const debugLinkFileName = "sample.debug";
  const debugLinkCrc32 = 0x12345678;
  const debugLinkOff = offset;
  const debugNameBytes = encoder.encode(`${debugLinkFileName}\0`);
  const debugLinkSize = alignTo(debugNameBytes.length, 4) + 4;
  const debugLinkBytes = new Uint8Array(debugLinkSize).fill(0);
  debugLinkBytes.set(debugNameBytes, 0);
  new DataView(debugLinkBytes.buffer).setUint32(alignTo(debugNameBytes.length, 4), debugLinkCrc32, true);
  offset = alignTo(offset + debugLinkBytes.length, 8);
  const { bytes: shstrBytes, offsets: shNameOff } = buildStringTable([".shstrtab", ".dynstr", ".dynsym", ".dynamic", ".comment", ".gnu_debuglink", ".note.gnu.build-id", ".tdata"]);
  const shstrOff = offset;
  offset = alignTo(offset + shstrBytes.length, 8);
  const shoff = offset;
  const shnum = 9;
  const fileSize = shoff + shSize * shnum;

  const bytes = new Uint8Array(fileSize).fill(0);
  const dv = new DataView(bytes.buffer);
  // ELF header (ELF64 little-endian)
  dv.setUint32(0, 0x7f454c46, false); // ELF magic
  dv.setUint8(4, 2); // 64-bit
  dv.setUint8(5, 1); // little endian
  dv.setUint8(6, 1); // version
  dv.setUint16(0x10, 2, true); // executable
  dv.setUint16(0x12, 0x3e, true); // x86-64
  dv.setUint32(0x14, 1, true);
  dv.setBigUint64(0x18, entryVaddr, true);
  dv.setBigUint64(0x20, BigInt(phoff), true);
  dv.setBigUint64(0x28, BigInt(shoff), true);
  dv.setUint16(0x34, headerSize, true);
  dv.setUint16(0x36, phSize, true);
  dv.setUint16(0x38, phnum, true);
  dv.setUint16(0x3a, shSize, true);
  dv.setUint16(0x3c, shnum, true);
  dv.setUint16(0x3e, 1, true); // shstrndx
  const fileVaddr = (fileOffset: number): bigint => baseVaddr + BigInt(fileOffset);
  const writePh = (
    index: number,
    type: number,
    flags: number,
    fileOffset: number,
    fileSizeBytes: number,
    memSizeBytes: number,
    align: bigint
  ): void => {
    const base = phoff + index * phSize;
    dv.setUint32(base + 0, type, true);
    dv.setUint32(base + 4, flags, true);
    dv.setBigUint64(base + 8, BigInt(fileOffset), true);
    dv.setBigUint64(base + 16, fileVaddr(fileOffset), true);
    dv.setBigUint64(base + 24, fileVaddr(fileOffset), true);
    dv.setBigUint64(base + 32, BigInt(fileSizeBytes), true);
    dv.setBigUint64(base + 40, BigInt(memSizeBytes), true);
    dv.setBigUint64(base + 48, align, true);
  };
  writePh(0, 1, 5, 0, fileSize, fileSize, 0x1000n); // PT_LOAD R+X
  writePh(1, 3, 4, interpOff, interpBytes.length, interpBytes.length, 1n); // PT_INTERP R
  writePh(2, 2, 4, dynamicOff, dynamicBytes.length, dynamicBytes.length, 8n); // PT_DYNAMIC R
  writePh(3, 4, 4, noteOff, noteBytes.length, noteBytes.length, 4n); // PT_NOTE R
  writePh(4, 7, 4, tdataOff, tdataBytes.length, tdataBytes.length + 4, 8n); // PT_TLS R
  type ElfSectionHeader = {
    index: number;
    nameOff: number;
    type: number;
    flags: bigint;
    addr: bigint;
    fileOffset: number;
    size: number;
    link: number;
    info: number;
    addralign: bigint;
    entsize: bigint;
  };
  const writeSh = (section: ElfSectionHeader): void => {
    const base = shoff + section.index * shSize;
    dv.setUint32(base + 0, section.nameOff, true);
    dv.setUint32(base + 4, section.type, true);
    dv.setBigUint64(base + 8, section.flags, true);
    dv.setBigUint64(base + 16, section.addr, true);
    dv.setBigUint64(base + 24, BigInt(section.fileOffset), true);
    dv.setBigUint64(base + 32, BigInt(section.size), true);
    dv.setUint32(base + 40, section.link, true);
    dv.setUint32(base + 44, section.info, true);
    dv.setBigUint64(base + 48, section.addralign, true);
    dv.setBigUint64(base + 56, section.entsize, true);
  };
  // #0 NULL
  writeSh({
    index: 0, nameOff: 0, type: 0, flags: 0n, addr: 0n, fileOffset: 0,
    size: 0, link: 0, info: 0, addralign: 0n, entsize: 0n
  });
  // #1 .shstrtab
  writeSh({
    index: 1, nameOff: shNameOff[".shstrtab"]!, type: 3, flags: 0n, addr: 0n,
    fileOffset: shstrOff, size: shstrBytes.length, link: 0, info: 0, addralign: 1n, entsize: 0n
  });
  // #2 .dynstr
  writeSh({
    index: 2, nameOff: shNameOff[".dynstr"]!, type: 3, flags: 0x2n,
    addr: fileVaddr(dynstrOff), fileOffset: dynstrOff, size: dynstrBytes.length,
    link: 0, info: 0, addralign: 1n, entsize: 0n
  });
  // #3 .dynsym
  writeSh({
    index: 3, nameOff: shNameOff[".dynsym"]!, type: 11, flags: 0x2n,
    addr: fileVaddr(dynsymOff), fileOffset: dynsymOff, size: dynsymBytes.length,
    link: 2, info: 0, addralign: 8n, entsize: 24n
  });
  // #4 .dynamic
  writeSh({
    index: 4, nameOff: shNameOff[".dynamic"]!, type: 6, flags: 0x2n,
    addr: fileVaddr(dynamicOff), fileOffset: dynamicOff, size: dynamicBytes.length,
    link: 2, info: 0, addralign: 8n, entsize: 16n
  });
  // #5 .comment
  writeSh({
    index: 5, nameOff: shNameOff[".comment"]!, type: 1, flags: 0n, addr: 0n,
    fileOffset: commentOff, size: commentBytes.length, link: 0, info: 0, addralign: 1n, entsize: 0n
  });
  // #6 .gnu_debuglink
  writeSh({
    index: 6, nameOff: shNameOff[".gnu_debuglink"]!, type: 1, flags: 0n, addr: 0n,
    fileOffset: debugLinkOff, size: debugLinkBytes.length, link: 0, info: 0, addralign: 4n, entsize: 0n
  });
  // #7 .note.gnu.build-id
  writeSh({
    index: 7, nameOff: shNameOff[".note.gnu.build-id"]!, type: 7, flags: 0x2n,
    addr: fileVaddr(noteOff), fileOffset: noteOff, size: noteBytes.length,
    link: 0, info: 0, addralign: 4n, entsize: 0n
  });
  // #8 .tdata (TLS)
  writeSh({
    index: 8, nameOff: shNameOff[".tdata"]!, type: 1, flags: 0x403n,
    addr: fileVaddr(tdataOff), fileOffset: tdataOff, size: tdataBytes.length,
    link: 0, info: 0, addralign: 8n, entsize: 0n
  });
  // Fill .dynsym contents
  const dynsymDv = new DataView(bytes.buffer, dynsymOff, dynsymBytes.length);
  const putsOff = dynstrText.indexOf(`${importSymbol}\0`);
  const funcOff = dynstrText.indexOf(`${exportSymbol}\0`);
  // symbol #1: imported puts
  dynsymDv.setUint32(24 + 0, putsOff, true);
  dynsymDv.setUint8(24 + 4, 0x12); // GLOBAL + FUNC
  dynsymDv.setUint16(24 + 6, 0, true); // SHN_UNDEF
  // symbol #2: exported my_func
  dynsymDv.setUint32(48 + 0, funcOff, true);
  dynsymDv.setUint8(48 + 4, 0x12);
  dynsymDv.setUint16(48 + 6, 1, true);
  dynsymDv.setBigUint64(48 + 8, entryVaddr, true);
  // Fill .dynamic contents (Elf64_Dyn)
  const dynamicDv = new DataView(bytes.buffer, dynamicOff, dynamicBytes.length);
  const writeDyn = (index: number, tag: number, value: bigint): void => {
    const base = index * dynEntrySize;
    dynamicDv.setBigInt64(base + 0, BigInt(tag), true);
    dynamicDv.setBigUint64(base + 8, value, true);
  };
  writeDyn(0, 5, fileVaddr(dynstrOff)); // DT_STRTAB
  writeDyn(1, 10, BigInt(dynstrBytes.length)); // DT_STRSZ
  writeDyn(2, 1, BigInt(dynstrText.indexOf(`${needed[0]}\0`))); // DT_NEEDED libc
  writeDyn(3, 1, BigInt(dynstrText.indexOf(`${needed[1]}\0`))); // DT_NEEDED libm
  writeDyn(4, 14, BigInt(dynstrText.indexOf(`${soname}\0`))); // DT_SONAME
  writeDyn(5, 29, BigInt(dynstrText.indexOf(`${runpath}\0`))); // DT_RUNPATH
  writeDyn(6, 12, entryVaddr); // DT_INIT
  writeDyn(7, 13, 0x402000n); // DT_FINI
  writeDyn(8, 25, 0x403000n); // DT_INIT_ARRAY
  writeDyn(9, 27, 16n); // DT_INIT_ARRAYSZ
  writeDyn(10, 30, 0x1234n); // DT_FLAGS
  writeDyn(11, 0x6ffffffb, 0x5678n); // DT_FLAGS_1
  writeDyn(12, 0, 0n); // DT_NULL
  // Fill note bytes (NT_GNU_BUILD_ID)
  const noteDv = new DataView(bytes.buffer, noteOff, noteBytes.length);
  noteDv.setUint32(0, 4, true); // namesz ("GNU\0")
  noteDv.setUint32(4, buildIdBytes.length, true);
  noteDv.setUint32(8, 3, true); // NT_GNU_BUILD_ID
  bytes.set(encoder.encode("GNU\0"), noteOff + 12);
  bytes.set(buildIdBytes, noteOff + 16);
  bytes.set(interpBytes, interpOff);
  bytes.set(dynstrBytes, dynstrOff);
  bytes.set(commentBytes, commentOff);
  bytes.set(debugLinkBytes, debugLinkOff);
  bytes.set(shstrBytes, shstrOff);
  bytes.set(tdataBytes, tdataOff);
  return {
    file: new MockFile(bytes, "metadata.elf", "application/x-elf"),
    expected: {
      interpreter,
      needed,
      soname,
      runpath,
      importSymbol,
      exportSymbol,
      buildIdHex,
      commentStrings,
      debugLinkFileName,
      debugLinkCrc32
    }
  };
};
