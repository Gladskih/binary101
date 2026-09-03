"use strict";

import { COFF_SECTION_CHARACTERISTICS } from "../../analyzers/coff/layout.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_I386
} from "../../analyzers/coff/machine.js";
import type { PeBaseRelocationResult } from "../../analyzers/pe/directories/reloc.js";
import { analyzePeNativeAotMetadata } from "../../analyzers/pe/native-aot-metadata.js";
import {
  NATIVE_AOT_EMBEDDED_METADATA_SECTION,
  NATIVE_AOT_METADATA_SIGNATURE,
  NATIVE_AOT_READY_TO_RUN_SIGNATURE
} from "../../analyzers/native-aot/format.js";
import type { PeWindowsCore } from "../../analyzers/pe/types.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import { MockFile } from "./mock-file.js";

export type NativeAotHeaderLayout = "pointer-range" | "size-pointer";

export interface NativeAotMetadataFixture {
  bytes: Uint8Array;
  core: PeWindowsCore;
  embeddedMetadataRva: number;
  entrySize: number;
  headerRva: number;
  layout: NativeAotHeaderLayout;
  metadataSize: number;
  modulePointerRva: number;
  pointerSize: 4 | 8;
  relocations: PeBaseRelocationResult;
  sectionCount: number;
  view: DataView;
}

const SECTION_RVA = 0x1000;
const SECTION_SIZE = 0x1000;
const MODULE_POINTER_RVA = 0x1080;
const HEADER_RVA = 0x1100;
const RUNTIME_DATA_RVA = 0x1300;
const EMBEDDED_METADATA_RVA = 0x1400;
const METADATA_SIZE = 0x20;
const HEADER_SIZE = 16;

const writePointer = (
  view: DataView,
  offset: number,
  value: bigint,
  pointerSize: 4 | 8
): void => {
  if (pointerSize === 8) view.setBigUint64(offset, value, true);
  else view.setUint32(offset, Number(value), true);
};

const addPointerRelocation = (sites: number[], rva: number): void => {
  sites.push(rva);
};

const writeHeaderEntry = (
  fixture: WritableFixture,
  index: number,
  type: number,
  rva: number,
  size: number,
  relocationSites: number[]
): void => {
  const offset = fixture.headerRva - SECTION_RVA + HEADER_SIZE + index * fixture.entrySize;
  fixture.view.setUint32(offset, type, true);
  if (fixture.layout === "size-pointer") {
    fixture.view.setUint32(offset + 4, size, true);
    writePointer(fixture.view, offset + 8,
      fixture.coreImageBase + BigInt(rva), fixture.pointerSize);
    addPointerRelocation(relocationSites,
      fixture.headerRva + HEADER_SIZE + index * fixture.entrySize + 8);
    return;
  }
  fixture.view.setUint32(offset + 4, 1, true);
  writePointer(fixture.view, offset + 8, fixture.coreImageBase + BigInt(rva), fixture.pointerSize);
  writePointer(
    fixture.view,
    offset + 8 + fixture.pointerSize,
    fixture.coreImageBase + BigInt(rva + size),
    fixture.pointerSize
  );
  addPointerRelocation(relocationSites,
    fixture.headerRva + HEADER_SIZE + index * fixture.entrySize + 8);
  addPointerRelocation(
    relocationSites,
    fixture.headerRva + HEADER_SIZE + index * fixture.entrySize + 8 + fixture.pointerSize
  );
};

type WritableFixture = Omit<NativeAotMetadataFixture, "core" | "relocations"> & {
  coreImageBase: bigint;
};

const makeOptionalHeader = (
  fixture: WritableFixture
): PeWindowsCore["opt"] => {
  const fields = {
    LinkerMajor: 0,
    LinkerMinor: 0,
    SizeOfCode: 0,
    SizeOfInitializedData: SECTION_SIZE,
    SizeOfUninitializedData: 0,
    AddressOfEntryPoint: 0,
    BaseOfCode: 0,
    ImageBase: fixture.coreImageBase,
    SectionAlignment: 0x1000,
    FileAlignment: 0x200,
    OSVersionMajor: 0,
    OSVersionMinor: 0,
    ImageVersionMajor: 0,
    ImageVersionMinor: 0,
    SubsystemVersionMajor: 0,
    SubsystemVersionMinor: 0,
    Win32VersionValue: 0,
    SizeOfImage: 0x3000,
    SizeOfHeaders: 0,
    CheckSum: 0,
    Subsystem: 0,
    DllCharacteristics: 0,
    SizeOfStackReserve: 0n,
    SizeOfStackCommit: 0n,
    SizeOfHeapReserve: 0n,
    SizeOfHeapCommit: 0n,
    LoaderFlags: 0,
    NumberOfRvaAndSizes: 0
  };
  return fixture.pointerSize === 8
    ? { ...fields, Magic: 0x20b }
    : { ...fields, Magic: 0x10b, BaseOfData: SECTION_RVA };
};

const makeCore = (
  fixture: WritableFixture,
  machine: number
): PeWindowsCore => ({
  coff: {
    Machine: machine,
    NumberOfSections: 1,
    TimeDateStamp: 0,
    PointerToSymbolTable: 0,
    NumberOfSymbols: 0,
    SizeOfOptionalHeader: 0,
    Characteristics: 0
  },
  opt: makeOptionalHeader(fixture),
  dataDirs: [],
  dos: {} as PeWindowsCore["dos"],
  sections: [{
    name: inlinePeSectionName(".rdata"),
    virtualSize: SECTION_SIZE,
    virtualAddress: SECTION_RVA,
    sizeOfRawData: SECTION_SIZE,
    pointerToRawData: 0,
    characteristics:
      COFF_SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA |
      COFF_SECTION_CHARACTERISTICS.MEM_READ
  }],
  entrySection: null,
  rvaToOff: rva => rva >= SECTION_RVA && rva < SECTION_RVA + SECTION_SIZE
    ? rva - SECTION_RVA
    : null,
  imageEnd: SECTION_SIZE,
  imageSizeMismatch: false,
  optOff: 0,
  ddStartRel: 0,
  ddCount: 0
});

const makeRelocations = (
  sites: number[],
  pointerSize: 4 | 8
): PeBaseRelocationResult => {
  const entries = sites.map(rva => ({
      type: pointerSize === 8 ? 10 : 3,
      offset: rva - SECTION_RVA
  }));
  if (entries.length % 2 !== 0) entries.push({ type: 0, offset: 0 });
  return {
    blocks: [{
      pageRva: SECTION_RVA,
      size: 8 + entries.length * 2,
      count: entries.length,
      entries
    }],
    totalEntries: entries.length
  };
};

export const createNativeAotMetadataFixture = (
  pointerSize: 4 | 8 = 8,
  layout: NativeAotHeaderLayout = "pointer-range"
): NativeAotMetadataFixture => {
  const bytes = new Uint8Array(SECTION_SIZE);
  const view = new DataView(bytes.buffer);
  const entrySize = layout === "pointer-range" ? 8 + pointerSize * 2 : 8 + pointerSize;
  const coreImageBase = pointerSize === 8 ? 0x1_4000_0000n : 0x0040_0000n;
  const writable: WritableFixture = {
    bytes,
    coreImageBase,
    embeddedMetadataRva: EMBEDDED_METADATA_RVA,
    entrySize,
    headerRva: HEADER_RVA,
    layout,
    metadataSize: METADATA_SIZE,
    modulePointerRva: MODULE_POINTER_RVA,
    pointerSize,
    sectionCount: 2,
    view
  };
  const relocationSites = [MODULE_POINTER_RVA];
  writePointer(view, MODULE_POINTER_RVA - SECTION_RVA,
    coreImageBase + BigInt(HEADER_RVA), pointerSize);
  view.setUint32(HEADER_RVA - SECTION_RVA, NATIVE_AOT_READY_TO_RUN_SIGNATURE, true);
  view.setUint16(HEADER_RVA - SECTION_RVA + 4, 16, true);
  view.setUint16(HEADER_RVA - SECTION_RVA + 6, 0, true);
  view.setUint32(HEADER_RVA - SECTION_RVA + 8, 0, true);
  view.setUint16(HEADER_RVA - SECTION_RVA + 12, writable.sectionCount, true);
  view.setUint8(HEADER_RVA - SECTION_RVA + 14, entrySize);
  view.setUint8(HEADER_RVA - SECTION_RVA + 15, 1);
  writeHeaderEntry(writable, 0, 201, RUNTIME_DATA_RVA, 0x20, relocationSites);
  writeHeaderEntry(
    writable,
    1,
    NATIVE_AOT_EMBEDDED_METADATA_SECTION,
    EMBEDDED_METADATA_RVA,
    METADATA_SIZE,
    relocationSites
  );
  view.setUint32(EMBEDDED_METADATA_RVA - SECTION_RVA, NATIVE_AOT_METADATA_SIGNATURE, true);
  const core = makeCore(writable,
    pointerSize === 8 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386);
  return {
    ...writable,
    core,
    relocations: makeRelocations(relocationSites, pointerSize)
  };
};

export const parseNativeAotMetadataFixture = (fixture: NativeAotMetadataFixture) =>
  analyzePeNativeAotMetadata(
    new MockFile(fixture.bytes, "native-aot-metadata.bin"),
    fixture.core,
    fixture.relocations
  );

export const setNativeAotReflectionMetadata = (
  fixture: NativeAotMetadataFixture,
  metadata: Uint8Array
): void => {
  const offset = fixture.embeddedMetadataRva - SECTION_RVA;
  if (offset + metadata.byteLength > fixture.bytes.byteLength) {
    throw new Error("NativeFormat fixture does not fit in the PE section.");
  }
  fixture.bytes.set(metadata, offset);
  fixture.metadataSize = metadata.byteLength;
  const entryOffset = fixture.headerRva - SECTION_RVA + HEADER_SIZE + fixture.entrySize;
  if (fixture.layout === "size-pointer") {
    fixture.view.setUint32(entryOffset + 4, metadata.byteLength, true);
    return;
  }
  writePointer(
    fixture.view,
    entryOffset + 8 + fixture.pointerSize,
    fixture.core.opt.ImageBase + BigInt(fixture.embeddedMetadataRva + metadata.byteLength),
    fixture.pointerSize
  );
};

export const insertNativeAotPointerRangeSection = (
  fixture: NativeAotMetadataFixture,
  type: number
): void => {
  if (fixture.layout !== "pointer-range") throw new Error("Pointer-range fixture required.");
  const oldEntryOffset = fixture.headerRva - SECTION_RVA + HEADER_SIZE + fixture.entrySize;
  fixture.bytes.copyWithin(oldEntryOffset + fixture.entrySize, oldEntryOffset,
    oldEntryOffset + fixture.entrySize);
  const oldStartRva = fixture.headerRva + HEADER_SIZE + fixture.entrySize + 8;
  fixture.relocations.blocks[0]!.entries.forEach(entry => {
    if (entry.offset === oldStartRva - SECTION_RVA ||
      entry.offset === oldStartRva - SECTION_RVA + fixture.pointerSize) {
      entry.offset += fixture.entrySize;
    }
  });
  const sites: number[] = [];
  writeHeaderEntry({ ...fixture, coreImageBase: fixture.core.opt.ImageBase },
    1, type, RUNTIME_DATA_RVA, 0x10, sites);
  fixture.relocations.blocks[0]!.entries.push(...sites.map(rva => ({
    type: fixture.pointerSize === 8 ? 10 : 3,
    offset: rva - SECTION_RVA
  })));
  fixture.relocations.blocks[0]!.count += sites.length;
  fixture.relocations.blocks[0]!.size += sites.length * 2;
  fixture.relocations.totalEntries += sites.length;
  fixture.sectionCount += 1;
  fixture.view.setUint16(fixture.headerRva - SECTION_RVA + 12, fixture.sectionCount, true);
};
