"use strict";

import { createDwarf4SectionsFixture } from "./dwarf-sections-fixture.js";
import { createPeWithSectionAndIatFixture } from "./sample-files-pe.js";
import { MockFile } from "../helpers/mock-file.js";

// Independent fixture values from the Microsoft PE/COFF specification:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
const PE32 = {
  headerOffset: 0x40,
  signatureSize: 4,
  fileAlignment: 0x200,
  imageSize: 0x4000,
  coff: {
    headerSize: 20,
    sectionCountOffset: 2,
    symbolTableOffset: 8,
    symbolCountOffset: 12,
    symbolRecordSize: 18,
    dummySymbolCount: 1
  },
  optional: {
    headerSize: 224,
    entryPointOffset: 16,
    imageSizeOffset: 56,
    dataDirectoriesOffset: 96
  },
  section: {
    headerSize: 40,
    nameSize: 8,
    virtualSizeOffset: 8,
    virtualAddressOffset: 12,
    rawSizeOffset: 16,
    rawOffsetOffset: 20,
    characteristicsOffset: 36,
    firstRawFileIndex: 1,
    firstVirtualAddress: 0x1000,
    virtualAddressStride: 0x1000,
    initializedReadOnlyData: 0x42000040
  }
} as const;

const COFF_HEADER_OFFSET = PE32.headerOffset + PE32.signatureSize;
const OPTIONAL_HEADER_OFFSET = COFF_HEADER_OFFSET + PE32.coff.headerSize;
const SECTION_HEADER_OFFSET = OPTIONAL_HEADER_OFFSET + PE32.optional.headerSize;

const encodeCoffStringTable = (names: string[]): {
  bytes: Uint8Array;
  offsets: number[];
} => {
  const encoded = names.map(name => new TextEncoder().encode(`${name}\0`));
  const offsets: number[] = [];
  let size = Uint32Array.BYTES_PER_ELEMENT;
  encoded.forEach(name => {
    offsets.push(size);
    size += name.length;
  });
  const bytes = new Uint8Array(size);
  new DataView(bytes.buffer).setUint32(0, size, true);
  encoded.forEach((name, index) => bytes.set(name, offsets[index]!));
  return { bytes, offsets };
};

const writeSectionHeader = (
  view: DataView,
  index: number,
  nameOffset: number,
  virtualSize: number,
  rawOffset: number
): void => {
  const offset = SECTION_HEADER_OFFSET + index * PE32.section.headerSize;
  const name = new TextEncoder().encode(`/${nameOffset}`);
  new Uint8Array(view.buffer, offset, PE32.section.nameSize).fill(0);
  new Uint8Array(view.buffer, offset, PE32.section.nameSize).set(name);
  view.setUint32(offset + PE32.section.virtualSizeOffset, virtualSize, true);
  view.setUint32(
    offset + PE32.section.virtualAddressOffset,
    PE32.section.firstVirtualAddress + index * PE32.section.virtualAddressStride,
    true
  );
  view.setUint32(offset + PE32.section.rawSizeOffset, PE32.fileAlignment, true);
  view.setUint32(offset + PE32.section.rawOffsetOffset, rawOffset, true);
  view.setUint32(
    offset + PE32.section.characteristicsOffset,
    PE32.section.initializedReadOnlyData,
    true
  );
};

export const createPeDwarfFile = (): MockFile => {
  const dwarf = createDwarf4SectionsFixture();
  const dwarfSections = [".debug_info", ".debug_abbrev", ".debug_str"]
    .map(name => dwarf.sections.find(section => section.name === name)!);
  const stringTable = encodeCoffStringTable(dwarfSections.map(section => section.name));
  const symbolTableOffset = PE32.fileAlignment * (
    dwarfSections.length + PE32.section.firstRawFileIndex
  );
  const stringTableOffset = symbolTableOffset + PE32.coff.symbolRecordSize;
  const bytes = new Uint8Array(stringTableOffset + stringTable.bytes.length);
  bytes.set(createPeWithSectionAndIatFixture().bytes.subarray(0, PE32.fileAlignment));
  const view = new DataView(bytes.buffer);
  view.setUint16(
    COFF_HEADER_OFFSET + PE32.coff.sectionCountOffset,
    dwarfSections.length,
    true
  );
  view.setUint32(
    COFF_HEADER_OFFSET + PE32.coff.symbolTableOffset,
    symbolTableOffset,
    true
  );
  view.setUint32(
    COFF_HEADER_OFFSET + PE32.coff.symbolCountOffset,
    PE32.coff.dummySymbolCount,
    true
  );
  view.setUint32(OPTIONAL_HEADER_OFFSET + PE32.optional.entryPointOffset, 0, true);
  view.setUint32(
    OPTIONAL_HEADER_OFFSET + PE32.optional.imageSizeOffset,
    PE32.imageSize,
    true
  );
  bytes.fill(
    0,
    OPTIONAL_HEADER_OFFSET + PE32.optional.dataDirectoriesOffset,
    OPTIONAL_HEADER_OFFSET + PE32.optional.headerSize
  );
  dwarfSections.forEach((section, index) => {
    const rawOffset = PE32.fileAlignment * (index + PE32.section.firstRawFileIndex);
    writeSectionHeader(view, index, stringTable.offsets[index]!, section.size, rawOffset);
    bytes.set(
      dwarf.file.data.subarray(section.offset, section.offset + section.size),
      rawOffset
    );
  });
  bytes.set(stringTable.bytes, stringTableOffset);
  return new MockFile(bytes, "dwarf-pe.exe", "application/vnd.microsoft.portable-executable");
};
