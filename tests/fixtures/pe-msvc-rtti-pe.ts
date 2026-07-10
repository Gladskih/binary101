"use strict";

import { COFF_SECTION_CHARACTERISTICS } from "../../analyzers/coff/layout.js";
import type { PeBaseRelocationResult } from "../../analyzers/pe/directories/reloc.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import type { PeSection, PeWindowsCore } from "../../analyzers/pe/types.js";

export const MSVC_RTTI_FIXTURE_IMAGE_BASE = 0x1_4000_0000n;
export const MSVC_RTTI_FIXTURE_TEXT_RVA = 0x1000;
export const MSVC_RTTI_FIXTURE_TEXT_SIZE = 0x200;
export const MSVC_RTTI_FIXTURE_RDATA_RVA = 0x2000;
export const MSVC_RTTI_FIXTURE_RDATA_SIZE = 0x2000;
export const MSVC_RTTI_FIXTURE_FILE_SIZE = 0x2800;

const PE_HEADER_OFFSET = 0x80;
const OPTIONAL_HEADER_SIZE = 0xf0;
const SIZE_OF_HEADERS = 0x200;
const FILE_ALIGNMENT = 0x200;
const SECTION_ALIGNMENT = 0x1000;
const TEXT_RAW_OFFSET = 0x200;
const RDATA_RAW_OFFSET = 0x400;
const RELOC_RVA = 0x4000;
const RELOC_RAW_OFFSET = 0x2400;
const RELOC_SIZE = 0x400;
const SIZE_OF_IMAGE = 0x5000;
const IMAGE_REL_BASED_DIR64 = 10;

const section = (
  name: string,
  virtualAddress: number,
  virtualSize: number,
  pointerToRawData: number,
  characteristics: number
): PeSection => ({
  name: inlinePeSectionName(name),
  virtualAddress,
  virtualSize,
  sizeOfRawData: virtualSize,
  pointerToRawData,
  characteristics
});

export const createMsvcRttiFixtureSections = (): PeSection[] => [
  section(
    ".text",
    MSVC_RTTI_FIXTURE_TEXT_RVA,
    MSVC_RTTI_FIXTURE_TEXT_SIZE,
    TEXT_RAW_OFFSET,
    COFF_SECTION_CHARACTERISTICS.CNT_CODE |
      COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE |
      COFF_SECTION_CHARACTERISTICS.MEM_READ
  ),
  section(
    ".rdata",
    MSVC_RTTI_FIXTURE_RDATA_RVA,
    MSVC_RTTI_FIXTURE_RDATA_SIZE,
    RDATA_RAW_OFFSET,
    COFF_SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA |
      COFF_SECTION_CHARACTERISTICS.MEM_READ
  ),
  section(
    ".reloc",
    RELOC_RVA,
    RELOC_SIZE,
    RELOC_RAW_OFFSET,
    COFF_SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA |
      COFF_SECTION_CHARACTERISTICS.MEM_READ
  )
];

export const msvcRttiFixtureRvaToOffset = (rva: number): number | null => {
  for (const candidate of createMsvcRttiFixtureSections()) {
    const start = candidate.virtualAddress;
    if (rva >= start && rva < start + candidate.sizeOfRawData) {
      return candidate.pointerToRawData + rva - start;
    }
  }
  return rva >= 0 && rva < SIZE_OF_HEADERS ? rva : null;
};

const writeOptionalHeader = (
  view: DataView,
  offset: number,
  magic: number,
  relocationDirectorySize: number,
  omitRelocations: boolean
): void => {
  view.setUint16(offset, magic, true);
  view.setUint32(offset + 4, MSVC_RTTI_FIXTURE_TEXT_SIZE, true);
  view.setUint32(offset + 8, MSVC_RTTI_FIXTURE_RDATA_SIZE + RELOC_SIZE, true);
  view.setUint32(offset + 16, MSVC_RTTI_FIXTURE_TEXT_RVA, true);
  view.setUint32(offset + 20, MSVC_RTTI_FIXTURE_TEXT_RVA, true);
  view.setBigUint64(offset + 24, MSVC_RTTI_FIXTURE_IMAGE_BASE, true);
  view.setUint32(offset + 32, SECTION_ALIGNMENT, true);
  view.setUint32(offset + 36, FILE_ALIGNMENT, true);
  view.setUint16(offset + 40, 6, true);
  view.setUint16(offset + 48, 6, true);
  view.setUint32(offset + 56, SIZE_OF_IMAGE, true);
  view.setUint32(offset + 60, SIZE_OF_HEADERS, true);
  view.setUint16(offset + 68, 3, true);
  view.setUint16(offset + 70, 0x0140, true);
  view.setBigUint64(offset + 72, 0x10_0000n, true);
  view.setBigUint64(offset + 80, 0x1000n, true);
  view.setBigUint64(offset + 88, 0x10_0000n, true);
  view.setBigUint64(offset + 96, 0x1000n, true);
  view.setUint32(offset + 108, 16, true);
  if (omitRelocations) return;
  view.setUint32(offset + 112 + 5 * 8, RELOC_RVA, true);
  view.setUint32(offset + 112 + 5 * 8 + 4, relocationDirectorySize, true);
};

const writeSectionHeader = (
  bytes: Uint8Array,
  view: DataView,
  offset: number,
  entry: PeSection
): void => {
  const name = new TextEncoder().encode(
    typeof entry.name === "object" && "value" in entry.name ? entry.name.value : ""
  );
  bytes.set(name.subarray(0, 8), offset);
  view.setUint32(offset + 8, entry.virtualSize, true);
  view.setUint32(offset + 12, entry.virtualAddress, true);
  view.setUint32(offset + 16, entry.sizeOfRawData, true);
  view.setUint32(offset + 20, entry.pointerToRawData, true);
  view.setUint32(offset + 36, entry.characteristics, true);
};

export const writeMsvcRttiFixtureHeaders = (
  bytes: Uint8Array,
  view: DataView,
  machine: number,
  magic: number,
  sections: PeSection[],
  relocationDirectorySize: number,
  omitRelocations: boolean
): void => {
  view.setUint16(0, 0x5a4d, true);
  view.setUint32(0x3c, PE_HEADER_OFFSET, true);
  view.setUint32(PE_HEADER_OFFSET, 0x0000_4550, true);
  const coffOffset = PE_HEADER_OFFSET + 4;
  view.setUint16(coffOffset, machine, true);
  view.setUint16(coffOffset + 2, sections.length, true);
  view.setUint16(coffOffset + 16, OPTIONAL_HEADER_SIZE, true);
  view.setUint16(coffOffset + 18, 0x0022, true);
  const optionalOffset = coffOffset + 20;
  writeOptionalHeader(view, optionalOffset, magic, relocationDirectorySize, omitRelocations);
  sections.forEach((entry, index) => writeSectionHeader(
    bytes,
    view,
    optionalOffset + OPTIONAL_HEADER_SIZE + index * 40,
    entry
  ));
};

export const writeMsvcRttiFixtureRelocations = (
  view: DataView,
  sites: Set<number>,
  tailBytes: number
): { directorySize: number; model: PeBaseRelocationResult } => {
  const pages = new Map<number, number[]>();
  for (const siteRva of sites) {
    const pageRva = siteRva & ~0xfff;
    const offsets = pages.get(pageRva) ?? [];
    offsets.push(siteRva - pageRva);
    pages.set(pageRva, offsets);
  }
  let relativeOffset = 0;
  const blocks: PeBaseRelocationResult["blocks"] = [];
  for (const [pageRva, offsets] of [...pages].sort(([left], [right]) => left - right)) {
    offsets.sort((left, right) => left - right);
    const entryOffsets = offsets.length % 2 === 0 ? offsets : [...offsets, 0];
    const blockSize = 8 + entryOffsets.length * 2;
    const blockOffset = RELOC_RAW_OFFSET + relativeOffset;
    view.setUint32(blockOffset, pageRva, true);
    view.setUint32(blockOffset + 4, blockSize, true);
    const entries = entryOffsets.map((offset, index) => ({
      type: index < offsets.length ? IMAGE_REL_BASED_DIR64 : 0,
      offset
    }));
    entries.forEach((entry, index) => view.setUint16(
      blockOffset + 8 + index * 2,
      (entry.type << 12) | entry.offset,
      true
    ));
    blocks.push({ pageRva, size: blockSize, count: entries.length, entries });
    relativeOffset += blockSize;
  }
  relativeOffset += tailBytes;
  if (relativeOffset > RELOC_SIZE) throw new Error("Synthetic .reloc is full.");
  return {
    directorySize: relativeOffset,
    model: {
      blocks,
      totalEntries: blocks.reduce((count, block) => count + block.entries.length, 0),
      ...(tailBytes
        ? { warnings: ["Base relocation directory ends with a truncated block header."] }
        : {})
    }
  };
};

export const createMsvcRttiFixtureCore = (
  machine: number,
  magic: number,
  sections: PeSection[],
  omitRelocations: boolean
): PeWindowsCore => ({
  dos: {} as PeWindowsCore["dos"],
  coff: { Machine: machine } as PeWindowsCore["coff"],
  opt: {
    Magic: magic,
    ImageBase: MSVC_RTTI_FIXTURE_IMAGE_BASE,
    SizeOfImage: SIZE_OF_IMAGE
  } as PeWindowsCore["opt"],
  dataDirs: omitRelocations ? [] : [{ name: "BASERELOC", rva: RELOC_RVA, size: RELOC_SIZE }],
  sections,
  optOff: 0,
  ddStartRel: 0,
  ddCount: 16,
  entrySection: null,
  rvaToOff: msvcRttiFixtureRvaToOffset,
  imageEnd: SIZE_OF_IMAGE,
  imageSizeMismatch: false
});

