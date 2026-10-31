import { resourceRcc } from "./embedded-rcc.js";
import { resourceGResource } from "./embedded-gresource.js";

// System V ABI ELF64 header, section, symbol and Rela layouts.
// https://gabi.xinuos.com/elf/contents.html
type Section = { name: string; type: number; bytes: Uint8Array; offset: number;
  link?: number; info?: number; entrySize?: number };

const symbolTable = (rcc: Uint8Array, strings: string, type: number): Uint8Array => {
  const view = new DataView(rcc.buffer);
  const bytes = new Uint8Array(5 * 24);
  const symbols = new DataView(bytes.buffer);
  symbols.setUint32(24, 1, true);
  bytes[28] = 4; // STT_FILE; establishes the compilation unit scope.
  symbols.setUint16(30, 0xfff1, true);
  const offsets = [view.getUint32(12), view.getUint32(16), view.getUint32(8), rcc.length];
  ["qt_resource_data", "qt_resource_name", "qt_resource_struct"].forEach((name, index) => {
    const record = (index + 2) * 24;
    symbols.setUint32(record, strings.indexOf(name), true);
    bytes[record + 4] = 1; // STT_OBJECT, STB_LOCAL.
    symbols.setUint16(record + 6, 1, true);
    symbols.setBigUint64(record + 8, BigInt(offsets[index]! - 24 + (type === 1 ? 0 : 0x400080)), true);
    symbols.setBigUint64(record + 16, BigInt(offsets[index + 1]! - offsets[index]!), true);
  });
  return bytes;
};

const writeHeader = (bytes: Uint8Array, type: number, table: number, count: number): void => {
  const view = new DataView(bytes.buffer);
  bytes.set([0x7f, 69, 76, 70, 2, 1, 1]);
  view.setUint16(16, type, true);
  view.setUint16(18, 62, true); // EM_X86_64.
  view.setUint32(20, 1, true);
  view.setBigUint64(40, BigInt(table), true);
  view.setUint16(52, 64, true);
  view.setUint16(58, 64, true);
  view.setUint16(60, count, true);
  view.setUint16(62, count - 1, true);
  if (type === 1) return;
  view.setBigUint64(32, 64n, true);
  view.setUint16(54, 56, true);
  view.setUint16(56, 1, true);
  view.setUint32(64, 1, true); // PT_LOAD, file-backed, read-only.
  view.setUint32(68, 4, true);
  view.setBigUint64(80, 0x400000n, true);
  view.setBigUint64(88, 0x400000n, true);
  view.setBigUint64(96, BigInt(bytes.length), true);
  view.setBigUint64(104, BigInt(bytes.length), true);
  view.setBigUint64(112, 0x1000n, true);
};

const writeSections = (bytes: Uint8Array, sections: Section[], names: string,
  table: number, type: number): void => {
  const view = new DataView(bytes.buffer);
  sections.forEach((section, index) => {
    const offset = table + (index + 1) * 64;
    bytes.set(section.bytes, section.offset);
    view.setUint32(offset, names.indexOf(`${section.name}\0`), true);
    view.setUint32(offset + 4, section.type, true);
    view.setBigUint64(offset + 8, section.type === 1 ? 2n : 0n, true);
    view.setBigUint64(offset + 16, type === 1 ? 0n : BigInt(0x400000 + section.offset), true);
    view.setBigUint64(offset + 24, BigInt(section.offset), true);
    view.setBigUint64(offset + 32, BigInt(section.bytes.length), true);
    view.setUint32(offset + 40, section.link ?? 0, true);
    view.setUint32(offset + 44, section.info ?? 0, true);
    view.setBigUint64(offset + 48, 8n, true);
    view.setBigUint64(offset + 56, BigInt(section.entrySize ?? 0), true);
  });
};

export const resourceElf = (type: number): Uint8Array => {
  const rcc = resourceRcc(3);
  const strings = "\0qrc.cpp\0qt_resource_data\0qt_resource_name\0qt_resource_struct\0";
  const relocation = new Uint8Array(24);
  new DataView(relocation.buffer).setBigUint64(8, (2n << 32n) | 1n, true);
  const sections: Section[] = [
    { name: ".qtarrays", type: 1, bytes: rcc.slice(24), offset: 128 },
    { name: ".strtab", type: 3, bytes: new TextEncoder().encode(strings), offset: 0 },
    { name: ".symtab", type: 2, bytes: symbolTable(rcc, strings, type), offset: 0,
      link: 2, info: 5, entrySize: 24 },
    { name: ".rela.data", type: 4, bytes: relocation, offset: 0, link: 3, info: 1, entrySize: 24 }
  ];
  if (type !== 1) sections.push(
    { name: ".rodata", type: 1, bytes: Uint8Array.from([...rcc, ...resourceGResource()]), offset: 0 },
    { name: ".gresource.oracle", type: 1, bytes: resourceGResource(), offset: 0 });
  const names = `\0${sections.map(section => section.name).join("\0")}\0.shstrtab\0`;
  sections.push({ name: ".shstrtab", type: 3, bytes: new TextEncoder().encode(names), offset: 0 });
  let cursor = 128;
  for (const section of sections) {
    section.offset = cursor;
    cursor = Math.ceil((cursor + section.bytes.length) / 8) * 8;
  }
  const bytes = new Uint8Array(cursor + (sections.length + 1) * 64);
  writeHeader(bytes, type, cursor, sections.length + 1);
  writeSections(bytes, sections, names, cursor, type);
  return bytes;
};
