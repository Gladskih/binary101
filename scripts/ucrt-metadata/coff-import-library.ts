"use strict";

const ARCHIVE_MAGIC = "!<arch>\n";
const ARCHIVE_MEMBER_HEADER_SIZE = 60;
const IMPORT_OBJECT_SIGNATURE_1 = 0x0000;
const IMPORT_OBJECT_SIGNATURE_2 = 0xffff;
const IMPORT_OBJECT_HEADER_SIZE = 20;

export interface CoffImportEntry {
  module: string;
  exportName: string;
  symbolName: string;
  ordinalOrHint: number;
}

const decoder = new TextDecoder("latin1");

const assertRange = (bytes: Uint8Array, offset: number, size: number, context: string): void => {
  if (offset < 0 || size < 0 || offset + size > bytes.byteLength) {
    throw new Error(`COFF import library ${context} extends outside the archive.`);
  }
};

const readU16 = (bytes: Uint8Array, offset: number): number => {
  assertRange(bytes, offset, Uint16Array.BYTES_PER_ELEMENT, "word");
  return new DataView(bytes.buffer, bytes.byteOffset + offset, Uint16Array.BYTES_PER_ELEMENT)
    .getUint16(0, true);
};

const readU32 = (bytes: Uint8Array, offset: number): number => {
  assertRange(bytes, offset, Uint32Array.BYTES_PER_ELEMENT, "dword");
  return new DataView(bytes.buffer, bytes.byteOffset + offset, Uint32Array.BYTES_PER_ELEMENT)
    .getUint32(0, true);
};

const readAscii = (bytes: Uint8Array, offset: number, size: number): string => {
  assertRange(bytes, offset, size, "string");
  return decoder.decode(bytes.subarray(offset, offset + size));
};

const parseDecimalField = (text: string, context: string): number => {
  const trimmed = text.trim();
  const value = Number(trimmed);
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`COFF import library ${context} is not a valid decimal field.`);
  }
  return value;
};

const assertArchiveMagic = (bytes: Uint8Array): void => {
  if (readAscii(bytes, 0, ARCHIVE_MAGIC.length) !== ARCHIVE_MAGIC) {
    throw new Error("COFF import library archive magic was not found.");
  }
};

const readNullTerminatedStrings = (bytes: Uint8Array, offset: number, size: number): string[] => {
  assertRange(bytes, offset, size, "import object string table");
  const strings: string[] = [];
  let start = offset;
  const end = offset + size;
  for (let cursor = offset; cursor < end; cursor += 1) {
    if (bytes[cursor] !== 0) continue;
    strings.push(decoder.decode(bytes.subarray(start, cursor)));
    start = cursor + 1;
  }
  if (start < end) strings.push(decoder.decode(bytes.subarray(start, end)));
  return strings;
};

const readImportObject = (member: Uint8Array): CoffImportEntry | null => {
  if (member.byteLength < IMPORT_OBJECT_HEADER_SIZE) return null;
  if (
    readU16(member, 0) !== IMPORT_OBJECT_SIGNATURE_1 ||
    readU16(member, 2) !== IMPORT_OBJECT_SIGNATURE_2
  ) {
    return null;
  }
  const sizeOfData = readU32(member, 12);
  if (sizeOfData <= 0 || IMPORT_OBJECT_HEADER_SIZE + sizeOfData > member.byteLength) {
    return null;
  }
  const ordinalOrHint = readU16(member, 16);
  const strings = readNullTerminatedStrings(member, IMPORT_OBJECT_HEADER_SIZE, sizeOfData);
  const symbolName = strings[0] ?? "";
  const module = strings[1] ?? "";
  const exportName = strings[2] || symbolName;
  return symbolName && module && exportName
    ? { module, exportName, symbolName, ordinalOrHint }
    : null;
};

const uniqueEntries = (entries: CoffImportEntry[]): CoffImportEntry[] => [
  ...new Map(entries.map(entry => [`${entry.module.toLowerCase()}\u0000${entry.exportName}`, entry])).values()
];

export const readCoffImportLibraryEntries = (bytes: Uint8Array): CoffImportEntry[] => {
  assertArchiveMagic(bytes);
  const entries: CoffImportEntry[] = [];
  let offset = ARCHIVE_MAGIC.length;
  while (offset + ARCHIVE_MEMBER_HEADER_SIZE <= bytes.byteLength) {
    const headerOffset = offset;
    const size = parseDecimalField(readAscii(bytes, headerOffset + 48, 10), "member size");
    const dataOffset = headerOffset + ARCHIVE_MEMBER_HEADER_SIZE;
    assertRange(bytes, dataOffset, size, "member data");
    const importEntry = readImportObject(bytes.subarray(dataOffset, dataOffset + size));
    if (importEntry) entries.push(importEntry);
    offset = dataOffset + size + (size % 2);
  }
  return uniqueEntries(entries).sort((left, right) =>
    left.module.localeCompare(right.module) || left.exportName.localeCompare(right.exportName));
};
