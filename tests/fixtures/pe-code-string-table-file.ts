"use strict";

import { MockFile } from "../helpers/mock-file.js";

const DOS_E_LFANEW_OFFSET = 0x3c;
const PE_HEADER_OFFSET = 0x80;
const PE_SIGNATURE_SIZE = 4;
const COFF_HEADER_SIZE = 20;
const OPTIONAL_HEADER_SIZE = 240;
const SECTION_HEADER_SIZE = 40;
const NUMBER_OF_SECTIONS = 2;
const FILE_ALIGNMENT = 0x200;
const SECTION_ALIGNMENT = 0x1000;
const TEXT_RVA = 0x1000;
const RDATA_RVA = 0x4000;
const TEXT_RAW_OFFSET = 0x200;
const IMAGE_BASE = 0x140000000n;
const IMAGE_SCN_CNT_CODE = 0x00000020;
const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_READ = 0x40000000;
const MOV_RAX_IMM64_LENGTH = 10;
const ROW_COUNT = 1005;

type PeFixtureSection = {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  rawSize: number;
  rawOffset: number;
  flags: number;
};

const alignUp = (value: number, alignment: number): number =>
  Math.ceil(value / alignment) * alignment;

const writeAsciiName = (view: DataView, offset: number, name: string): void => {
  for (let index = 0; index < Math.min(8, name.length); index += 1) {
    view.setUint8(offset + index, name.charCodeAt(index));
  }
};

const writeSectionHeader = (
  view: DataView,
  offset: number,
  section: PeFixtureSection
): void => {
  writeAsciiName(view, offset, section.name);
  view.setUint32(offset + 8, section.virtualSize, true);
  view.setUint32(offset + 12, section.virtualAddress, true);
  view.setUint32(offset + 16, section.rawSize, true);
  view.setUint32(offset + 20, section.rawOffset, true);
  view.setUint32(offset + 36, section.flags, true);
};

const writePeHeaders = (
  view: DataView,
  textRawSize: number,
  rdataRawSize: number,
  rdataRawOffset: number
): void => {
  view.setUint16(0, 0x5a4d, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, PE_HEADER_OFFSET, true);
  view.setUint32(PE_HEADER_OFFSET, 0x00004550, true);
  const coffOffset = PE_HEADER_OFFSET + PE_SIGNATURE_SIZE;
  view.setUint16(coffOffset, 0x8664, true);
  view.setUint16(coffOffset + 2, NUMBER_OF_SECTIONS, true);
  view.setUint16(coffOffset + 16, OPTIONAL_HEADER_SIZE, true);
  view.setUint16(coffOffset + 18, 0x0002, true);
  writeOptionalHeader(view, coffOffset + COFF_HEADER_SIZE, textRawSize, rdataRawSize);
  const sectionOffset = coffOffset + COFF_HEADER_SIZE + OPTIONAL_HEADER_SIZE;
  writeSectionHeader(view, sectionOffset, {
    name: ".text",
    virtualSize: textRawSize,
    virtualAddress: TEXT_RVA,
    rawSize: textRawSize,
    rawOffset: TEXT_RAW_OFFSET,
    flags: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
  });
  writeSectionHeader(view, sectionOffset + SECTION_HEADER_SIZE, {
    name: ".rdata",
    virtualSize: rdataRawSize,
    virtualAddress: RDATA_RVA,
    rawSize: rdataRawSize,
    rawOffset: rdataRawOffset,
    flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
  });
};

const writeOptionalHeader = (
  view: DataView,
  offset: number,
  textRawSize: number,
  rdataRawSize: number
): void => {
  let cursor = offset;
  view.setUint16(cursor, 0x20b, true); cursor += 2;
  view.setUint8(cursor, 14); cursor += 1;
  view.setUint8(cursor, 0); cursor += 1;
  view.setUint32(cursor, textRawSize, true); cursor += 4;
  view.setUint32(cursor, rdataRawSize, true); cursor += 4;
  view.setUint32(cursor, 0, true); cursor += 4;
  view.setUint32(cursor, TEXT_RVA, true); cursor += 4;
  view.setUint32(cursor, TEXT_RVA, true); cursor += 4;
  view.setBigUint64(cursor, IMAGE_BASE, true); cursor += 8;
  view.setUint32(cursor, SECTION_ALIGNMENT, true); cursor += 4;
  view.setUint32(cursor, FILE_ALIGNMENT, true); cursor += 4;
  view.setUint16(cursor, 6, true);
  view.setUint16(cursor + 2, 0, true);
  cursor += 4;
  view.setUint16(cursor, 1, true);
  view.setUint16(cursor + 2, 0, true);
  cursor += 4;
  view.setUint16(cursor, 5, true);
  view.setUint16(cursor + 2, 1, true);
  cursor += 4;
  view.setUint32(cursor, 0, true); cursor += 4;
  view.setUint32(cursor, RDATA_RVA + rdataRawSize, true); cursor += 4;
  view.setUint32(cursor, FILE_ALIGNMENT, true); cursor += 4;
  view.setUint32(cursor, 0, true); cursor += 4;
  view.setUint16(cursor, 2, true); cursor += 2;
  view.setUint16(cursor, 0, true); cursor += 2;
  view.setBigUint64(cursor, 0x100000n, true); cursor += 8;
  view.setBigUint64(cursor, 0x1000n, true); cursor += 8;
  view.setBigUint64(cursor, 0x100000n, true); cursor += 8;
  view.setBigUint64(cursor, 0x1000n, true); cursor += 8;
  view.setUint32(cursor, 0, true); cursor += 4;
  view.setUint32(cursor, 16, true);
};

const writeCode = (bytes: Uint8Array, view: DataView, rdataRawOffset: number): void => {
  let codeOffset = TEXT_RAW_OFFSET;
  let stringOffset = 0;
  const encoder = new TextEncoder();
  for (let index = 0; index < ROW_COUNT; index += 1) {
    const stringRva = RDATA_RVA + stringOffset;
    bytes.set([0x48, 0xb8], codeOffset);
    view.setBigUint64(codeOffset + 2, IMAGE_BASE + BigInt(stringRva), true);
    const text = `value-${String(ROW_COUNT - index).padStart(4, "0")}`;
    bytes.set(encoder.encode(text), rdataRawOffset + stringOffset);
    bytes[rdataRawOffset + stringOffset + text.length] = 0;
    codeOffset += MOV_RAX_IMM64_LENGTH;
    stringOffset += text.length + 1;
  }
  bytes[codeOffset] = 0xc3;
};

export const createLargePeCodeStringReferenceFile = (): MockFile => {
  const textSize = ROW_COUNT * MOV_RAX_IMM64_LENGTH + 1;
  const textRawSize = alignUp(textSize, FILE_ALIGNMENT);
  const rdataRawOffset = TEXT_RAW_OFFSET + textRawSize;
  const rdataRawSize = alignUp(ROW_COUNT * "value-0000\0".length, FILE_ALIGNMENT);
  const bytes = new Uint8Array(rdataRawOffset + rdataRawSize);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  writePeHeaders(view, textRawSize, rdataRawSize, rdataRawOffset);
  writeCode(bytes, view, rdataRawOffset);
  return new MockFile(bytes, "large-code-strings.exe", "application/vnd.microsoft.portable-executable");
};
