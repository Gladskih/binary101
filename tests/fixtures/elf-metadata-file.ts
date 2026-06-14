"use strict";
import { MockFile } from "../helpers/mock-file.js";
const encoder = new TextEncoder();

const alignTo = (value: number, alignment: number): number => {
  const mask = alignment - 1;
  return (value + mask) & ~mask;
};
const buildStringTable = <Name extends string>(names: Name[]): { bytes: Uint8Array; offsets: Record<Name, number> } => {
  const offsets = {} as Record<Name, number>;
  let text = "\0";
  for (const name of names) {
    offsets[name] = text.length;
    text += `${name}\0`;
  }
  return { bytes: encoder.encode(text), offsets };
};
export type ElfMetadataFixture = {
  file: MockFile;
  expected: ElfMetadataFixtureNames;
};
type ElfMetadataFixtureNames = {
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
type ElfMetadataLayoutName = "comment" | "debugLink" | "dynamic" | "dynstr" | "dynsym" | "interp" | "note" | "shstr" | "tdata";
type ElfMetadataLayoutOffsetName = ElfMetadataLayoutName | "shoff";
type ElfMetadataSectionName = ".comment" | ".dynamic" | ".dynstr" | ".dynsym" | ".gnu_debuglink" | ".note.gnu.build-id" | ".shstrtab" | ".tdata";
type ElfMetadataFixtureLayout = {
  offsets: Record<ElfMetadataLayoutOffsetName, number>;
  bytes: Record<ElfMetadataLayoutName, Uint8Array>;
  dynstrText: string;
  sectionNameOffsets: Record<ElfMetadataSectionName, number>;
  fileSize: number;
};
type ElfProgramHeader = {
  index: number;
  type: number;
  flags: number;
  fileOffset: number;
  fileSizeBytes: number;
  memSizeBytes: number;
  align: bigint;
};
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
const createFixtureNames = (): ElfMetadataFixtureNames => {
  const buildIdBytes = new Uint8Array(20).map((_, index) => index & 0xff);
  return {
    interpreter: "/lib64/ld-linux-x86-64.so.2",
    needed: ["libc.so.6", "libm.so.6"],
    soname: "soname.so",
    runpath: "runpath",
    importSymbol: "puts",
    exportSymbol: "my_func",
    buildIdHex: [...buildIdBytes].map(value => value.toString(16).padStart(2, "0")).join(""),
    commentStrings: ["GCC", "Clang"],
    debugLinkFileName: "sample.debug",
    debugLinkCrc32: 0x12345678
  };
};
const buildDynamicStringTable = (names: ElfMetadataFixtureNames): string =>
  `\0${names.needed[0]}\0${names.needed[1]}\0${names.soname}\0` +
  `${names.runpath}\0${names.importSymbol}\0${names.exportSymbol}\0`;
const createDebugLinkBytes = (fileName: string, crc32: number): Uint8Array => {
  const debugNameBytes = encoder.encode(`${fileName}\0`);
  const debugLinkBytes = new Uint8Array(alignTo(debugNameBytes.length, 4) + 4).fill(0);
  debugLinkBytes.set(debugNameBytes, 0);
  new DataView(debugLinkBytes.buffer).setUint32(alignTo(debugNameBytes.length, 4), crc32, true);
  return debugLinkBytes;
};
const placeBytes = (
  offset: number,
  bytes: Record<ElfMetadataLayoutName, Uint8Array>,
  offsets: Record<ElfMetadataLayoutOffsetName, number>,
  name: ElfMetadataLayoutName,
  data: Uint8Array
): number => {
  bytes[name] = data;
  offsets[name] = offset;
  return alignTo(offset + data.length, 8);
};
const createElfMetadataLayout = (names: ElfMetadataFixtureNames): ElfMetadataFixtureLayout => {
  const offsets = {} as Record<ElfMetadataLayoutOffsetName, number>;
  const bytes = {} as Record<ElfMetadataLayoutName, Uint8Array>;
  let offset = 64 + 56 * 5;
  offset = placeBytes(offset, bytes, offsets, "interp", encoder.encode(`${names.interpreter}\0`));
  const dynstrText = buildDynamicStringTable(names);
  offset = placeBytes(offset, bytes, offsets, "dynstr", encoder.encode(dynstrText));
  offset = placeBytes(offset, bytes, offsets, "dynsym", new Uint8Array(24 * 3).fill(0));
  offset = placeBytes(offset, bytes, offsets, "dynamic", new Uint8Array(16 * 13).fill(0));
  offset = placeBytes(offset, bytes, offsets, "note", new Uint8Array(12 + 4 + 20).fill(0));
  offset = placeBytes(offset, bytes, offsets, "tdata", new Uint8Array([1, 2, 3, 4]));
  offset = placeBytes(
    offset,
    bytes,
    offsets,
    "comment",
    encoder.encode(`${names.commentStrings[0]}\0${names.commentStrings[1]}\0`)
  );
  offset = placeBytes(
    offset,
    bytes,
    offsets,
    "debugLink",
    createDebugLinkBytes(names.debugLinkFileName, names.debugLinkCrc32)
  );
  const sectionStrings = buildStringTable<ElfMetadataSectionName>([
    ".shstrtab", ".dynstr", ".dynsym", ".dynamic", ".comment", ".gnu_debuglink",
    ".note.gnu.build-id", ".tdata"
  ]);
  offset = placeBytes(offset, bytes, offsets, "shstr", sectionStrings.bytes);
  offsets.shoff = offset;
  return { offsets, bytes, dynstrText, sectionNameOffsets: sectionStrings.offsets, fileSize: offset + 64 * 9 };
};
const fileVaddr = (offset: number): bigint => 0x400000n + BigInt(offset);
const writeElfHeader = (dv: DataView, layout: ElfMetadataFixtureLayout): void => {
  dv.setUint32(0, 0x7f454c46, false);
  dv.setUint8(4, 2);
  dv.setUint8(5, 1);
  dv.setUint8(6, 1);
  dv.setUint16(0x10, 2, true);
  dv.setUint16(0x12, 0x3e, true);
  dv.setUint32(0x14, 1, true);
  dv.setBigUint64(0x18, 0x401000n, true);
  dv.setBigUint64(0x20, 64n, true);
  dv.setBigUint64(0x28, BigInt(layout.offsets.shoff), true);
  dv.setUint16(0x34, 64, true);
  dv.setUint16(0x36, 56, true);
  dv.setUint16(0x38, 5, true);
  dv.setUint16(0x3a, 64, true);
  dv.setUint16(0x3c, 9, true);
  dv.setUint16(0x3e, 1, true);
};
const writeProgramHeader = (dv: DataView, header: ElfProgramHeader): void => {
  const base = 64 + header.index * 56;
  dv.setUint32(base + 0, header.type, true);
  dv.setUint32(base + 4, header.flags, true);
  dv.setBigUint64(base + 8, BigInt(header.fileOffset), true);
  dv.setBigUint64(base + 16, fileVaddr(header.fileOffset), true);
  dv.setBigUint64(base + 24, fileVaddr(header.fileOffset), true);
  dv.setBigUint64(base + 32, BigInt(header.fileSizeBytes), true);
  dv.setBigUint64(base + 40, BigInt(header.memSizeBytes), true);
  dv.setBigUint64(base + 48, header.align, true);
};
const programHeader = (
  index: number,
  type: number,
  flags: number,
  fileOffset: number,
  fileSizeBytes: number,
  memSizeBytes: number,
  align: bigint
): ElfProgramHeader => ({ index, type, flags, fileOffset, fileSizeBytes, memSizeBytes, align });
const writeProgramHeaders = (dv: DataView, layout: ElfMetadataFixtureLayout): void => {
  [
    programHeader(0, 1, 5, 0, layout.fileSize, layout.fileSize, 0x1000n),
    programHeader(1, 3, 4, layout.offsets.interp, layout.bytes.interp.length, layout.bytes.interp.length, 1n),
    programHeader(2, 2, 4, layout.offsets.dynamic, layout.bytes.dynamic.length, layout.bytes.dynamic.length, 8n),
    programHeader(3, 4, 4, layout.offsets.note, layout.bytes.note.length, layout.bytes.note.length, 4n),
    programHeader(4, 7, 4, layout.offsets.tdata, layout.bytes.tdata.length, layout.bytes.tdata.length + 4, 8n)
  ].forEach(header => writeProgramHeader(dv, header));
};
const writeSectionHeader = (
  dv: DataView,
  layout: ElfMetadataFixtureLayout,
  section: ElfSectionHeader
): void => {
  const base = layout.offsets.shoff + section.index * 64;
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
const sectionHeader = (
  layout: ElfMetadataFixtureLayout,
  index: number,
  sectionName: ElfMetadataSectionName,
  type: number,
  fileOffsetName: ElfMetadataLayoutName,
  flags: bigint
): ElfSectionHeader => index === 0 ? {
  index: 0, nameOff: 0, type: 0, flags: 0n, addr: 0n, fileOffset: 0,
  size: 0, link: 0, info: 0, addralign: 0n, entsize: 0n
} : ({
  index,
  nameOff: layout.sectionNameOffsets[sectionName]!,
  type,
  flags,
  addr: flags === 0n ? 0n : fileVaddr(layout.offsets[fileOffsetName]),
  fileOffset: layout.offsets[fileOffsetName],
  size: layout.bytes[fileOffsetName].length,
  link: sectionName === ".dynsym" || sectionName === ".dynamic" ? 2 : 0,
  info: 0,
  addralign: sectionName === ".dynsym" || sectionName === ".dynamic" || sectionName === ".tdata" ? 8n : 1n,
  entsize: sectionName === ".dynsym" ? 24n : sectionName === ".dynamic" ? 16n : 0n
});
const writeSectionHeaders = (dv: DataView, layout: ElfMetadataFixtureLayout): void => {
  [
    sectionHeader(layout, 0, ".shstrtab", 0, "shstr", 0n),
    sectionHeader(layout, 1, ".shstrtab", 3, "shstr", 0n),
    sectionHeader(layout, 2, ".dynstr", 3, "dynstr", 0x2n),
    sectionHeader(layout, 3, ".dynsym", 11, "dynsym", 0x2n),
    sectionHeader(layout, 4, ".dynamic", 6, "dynamic", 0x2n),
    sectionHeader(layout, 5, ".comment", 1, "comment", 0n),
    { ...sectionHeader(layout, 6, ".gnu_debuglink", 1, "debugLink", 0n), addralign: 4n },
    { ...sectionHeader(layout, 7, ".note.gnu.build-id", 7, "note", 0x2n), addralign: 4n },
    { ...sectionHeader(layout, 8, ".tdata", 1, "tdata", 0x403n), addralign: 8n }
  ].forEach(section => writeSectionHeader(dv, layout, section));
};
const writeDynamicSymbols = (
  bytes: Uint8Array,
  layout: ElfMetadataFixtureLayout,
  names: ElfMetadataFixtureNames
): void => {
  const dv = new DataView(bytes.buffer, layout.offsets.dynsym, layout.bytes.dynsym.length);
  dv.setUint32(24, layout.dynstrText.indexOf(`${names.importSymbol}\0`), true);
  dv.setUint8(28, 0x12);
  dv.setUint16(30, 0, true);
  dv.setUint32(48, layout.dynstrText.indexOf(`${names.exportSymbol}\0`), true);
  dv.setUint8(52, 0x12);
  dv.setUint16(54, 1, true);
  dv.setBigUint64(56, 0x401000n, true);
};
const writeDynamicEntries = (
  bytes: Uint8Array,
  layout: ElfMetadataFixtureLayout,
  names: ElfMetadataFixtureNames
): void => {
  const dv = new DataView(bytes.buffer, layout.offsets.dynamic, layout.bytes.dynamic.length);
  const writeDyn = (index: number, tag: number, value: bigint): void => {
    dv.setBigInt64(index * 16, BigInt(tag), true);
    dv.setBigUint64(index * 16 + 8, value, true);
  };
  writeDyn(0, 5, fileVaddr(layout.offsets.dynstr));
  writeDyn(1, 10, BigInt(layout.bytes.dynstr.length));
  writeDyn(2, 1, BigInt(layout.dynstrText.indexOf(`${names.needed[0]}\0`)));
  writeDyn(3, 1, BigInt(layout.dynstrText.indexOf(`${names.needed[1]}\0`)));
  writeDyn(4, 14, BigInt(layout.dynstrText.indexOf(`${names.soname}\0`)));
  writeDyn(5, 29, BigInt(layout.dynstrText.indexOf(`${names.runpath}\0`)));
  writeDyn(6, 12, 0x401000n);
  writeDyn(7, 13, 0x402000n);
  writeDyn(8, 25, 0x403000n);
  writeDyn(9, 27, 16n);
  writeDyn(10, 30, 0x1234n);
  writeDyn(11, 0x6ffffffb, 0x5678n);
  writeDyn(12, 0, 0n);
};
const writePayloadSections = (bytes: Uint8Array, layout: ElfMetadataFixtureLayout): void => {
  (["interp", "dynstr", "comment", "debugLink", "shstr", "tdata"] as ElfMetadataLayoutName[])
    .forEach(name => bytes.set(layout.bytes[name], layout.offsets[name]));
  const noteDv = new DataView(bytes.buffer, layout.offsets.note, layout.bytes.note.length);
  noteDv.setUint32(0, 4, true);
  noteDv.setUint32(4, 20, true);
  noteDv.setUint32(8, 3, true);
  bytes.set(encoder.encode("GNU\0"), layout.offsets.note + 12);
  bytes.set(new Uint8Array(20).map((_, index) => index & 0xff), layout.offsets.note + 16);
};
export const createElfMetadataFile = (): ElfMetadataFixture => {
  const names = createFixtureNames();
  const layout = createElfMetadataLayout(names);
  const bytes = new Uint8Array(layout.fileSize).fill(0);
  const dataView = new DataView(bytes.buffer);
  writeElfHeader(dataView, layout);
  writeProgramHeaders(dataView, layout);
  writeSectionHeaders(dataView, layout);
  writeDynamicSymbols(bytes, layout, names);
  writeDynamicEntries(bytes, layout, names);
  writePayloadSections(bytes, layout);
  return { file: new MockFile(bytes, "metadata.elf", "application/x-elf"), expected: names };
};
