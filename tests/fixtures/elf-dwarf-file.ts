"use strict";

import { createDwarf4SectionsFixture } from "./dwarf-sections-fixture.js";
import { createCompressedDwarfSectionsFixture } from "./dwarf-compressed-section-fixture.js";
import { MockFile } from "../helpers/mock-file.js";

// Independent fixture values from System V ABI, chapters 4 and 5:
// https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html
const ELF64 = {
  headerSize: 64,
  sectionHeaderSize: 64,
  identification: {
    magic: 0x7f454c46,
    classOffset: 4,
    dataOffset: 5,
    versionOffset: 6,
    class64: 2,
    littleEndian: 1,
    currentVersion: 1
  },
  header: {
    typeOffset: 16,
    machineOffset: 18,
    versionOffset: 20,
    sectionHeadersOffset: 40,
    headerSizeOffset: 52,
    sectionHeaderSizeOffset: 58,
    sectionCountOffset: 60,
    sectionNamesIndexOffset: 62
  },
  section: {
    nameOffset: 0,
    typeOffset: 4,
    flagsOffset: 8,
    fileOffset: 24,
    sizeOffset: 32,
    alignmentOffset: 48,
    namesIndex: 1,
    firstContentIndex: 2,
    programBitsType: 1,
    stringTableType: 3,
    compressedFlag: 0x800n
  },
  fileType: { executable: 2 },
  machine: { x86_64: 0x3e }
} as const;

const encodeStringTable = (names: string[]): {
  bytes: Uint8Array;
  offsets: number[];
} => {
  const encoded = names.map(name => new TextEncoder().encode(`${name}\0`));
  const offsets: number[] = [];
  let size = Uint8Array.BYTES_PER_ELEMENT;
  encoded.forEach(name => {
    offsets.push(size);
    size += name.length;
  });
  const bytes = new Uint8Array(size);
  encoded.forEach((name, index) => bytes.set(name, offsets[index]!));
  return { bytes, offsets };
};

const writeSection = (
  view: DataView,
  index: number,
  nameOffset: number,
  type: number,
  fileOffset: number,
  size: number,
  flags = 0n
): void => {
  const offset = ELF64.headerSize + index * ELF64.sectionHeaderSize;
  view.setUint32(offset + ELF64.section.nameOffset, nameOffset, true);
  view.setUint32(offset + ELF64.section.typeOffset, type, true);
  view.setBigUint64(offset + ELF64.section.flagsOffset, flags, true);
  view.setBigUint64(offset + ELF64.section.fileOffset, BigInt(fileOffset), true);
  view.setBigUint64(offset + ELF64.section.sizeOffset, BigInt(size), true);
  view.setBigUint64(offset + ELF64.section.alignmentOffset, 1n, true);
};

type DwarfPayloadFixture = {
  file: MockFile;
  sections: Array<{ name: string; offset: number; size: number }>;
};

const buildElfDwarfFile = (
  dwarf: DwarfPayloadFixture,
  fileName: string,
  sectionFlags: bigint
): MockFile => {
  const dwarfSections = dwarf.sections;
  const names = encodeStringTable([".shstrtab", ...dwarfSections.map(section => section.name)]);
  const sectionCount = ELF64.section.firstContentIndex + dwarfSections.length;
  const namesOffset = ELF64.headerSize + sectionCount * ELF64.sectionHeaderSize;
  const dataOffset = namesOffset + names.bytes.length;
  const fileSize = dataOffset + dwarfSections.reduce((size, section) => size + section.size, 0);
  const bytes = new Uint8Array(fileSize);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, ELF64.identification.magic, false);
  view.setUint8(ELF64.identification.classOffset, ELF64.identification.class64);
  view.setUint8(ELF64.identification.dataOffset, ELF64.identification.littleEndian);
  view.setUint8(ELF64.identification.versionOffset, ELF64.identification.currentVersion);
  view.setUint16(ELF64.header.typeOffset, ELF64.fileType.executable, true);
  view.setUint16(ELF64.header.machineOffset, ELF64.machine.x86_64, true);
  view.setUint32(ELF64.header.versionOffset, ELF64.identification.currentVersion, true);
  view.setBigUint64(ELF64.header.sectionHeadersOffset, BigInt(ELF64.headerSize), true);
  view.setUint16(ELF64.header.headerSizeOffset, ELF64.headerSize, true);
  view.setUint16(
    ELF64.header.sectionHeaderSizeOffset,
    ELF64.sectionHeaderSize,
    true
  );
  view.setUint16(ELF64.header.sectionCountOffset, sectionCount, true);
  view.setUint16(ELF64.header.sectionNamesIndexOffset, ELF64.section.namesIndex, true);
  writeSection(
    view,
    ELF64.section.namesIndex,
    names.offsets[0]!,
    ELF64.section.stringTableType,
    namesOffset,
    names.bytes.length
  );
  bytes.set(names.bytes, namesOffset);
  let cursor = dataOffset;
  dwarfSections.forEach((section, index) => {
    writeSection(
      view,
      index + ELF64.section.firstContentIndex,
      names.offsets[index + ELF64.section.namesIndex]!,
      ELF64.section.programBitsType,
      cursor,
      section.size,
      sectionFlags
    );
    bytes.set(dwarf.file.data.subarray(section.offset, section.offset + section.size), cursor);
    cursor += section.size;
  });
  return new MockFile(bytes, fileName, "application/x-elf");
};

export const createElfDwarfFile = (): MockFile => {
  const dwarf = createDwarf4SectionsFixture();
  return buildElfDwarfFile({
    file: dwarf.file,
    sections: [".debug_info", ".debug_abbrev", ".debug_str"]
      .map(name => dwarf.sections.find(section => section.name === name)!)
  }, "dwarf-elf", 0n);
};

export const createElfCompressedDwarfFile = (): MockFile => {
  const dwarf = createCompressedDwarfSectionsFixture("elf64-little-zlib");
  return buildElfDwarfFile({
    file: dwarf.file,
    sections: dwarf.candidates.map(candidate => candidate.section)
  }, "compressed-dwarf-elf", ELF64.section.compressedFlag);
};
