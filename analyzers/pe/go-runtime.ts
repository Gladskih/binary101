"use strict";

import {
  parseGoPcHeader,
  parseGoRuntimeMetadataFromHeader,
  type PcHeader
} from "../go-runtime/parser.js";
import { SUPPORTED_GO_RUNTIME_LAYOUTS } from "../go-runtime/layouts.js";
import type { GoRuntimeAddressSpace, GoRuntimeMetadata } from "../go-runtime/types.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "./optional-header/magic.js";
import { scanFileRangeForPatterns } from "./go-runtime-scan.js";
import type { PeSection, PeWindowsCore } from "./types.js";

// Microsoft PE format, Section Flags:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
const IMAGE_SCN_MEM_EXECUTE = 0x2000_0000;

interface MappedSection {
  address: bigint;
  fileOffset: number;
  fileSize: number;
  memorySize: number;
  executable: boolean;
  writable: boolean;
}

interface ModuleDataCandidate {
  address: bigint;
  header: PcHeader;
}

const sectionMemorySize = (section: PeSection): number =>
  (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);

const toMappedSection = (section: PeSection, imageBase: bigint): MappedSection => ({
  address: imageBase + BigInt(section.virtualAddress >>> 0),
  fileOffset: section.pointerToRawData >>> 0,
  fileSize: Math.min(section.sizeOfRawData >>> 0, sectionMemorySize(section)),
  memorySize: sectionMemorySize(section),
  executable: (section.characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0,
  writable: (section.characteristics & 0x8000_0000) !== 0
});

const isMappedDataSection = (section: PeSection): boolean =>
  (section.characteristics & 0x0000_0040) !== 0 &&
  (section.characteristics & 0x4000_0000) !== 0 &&
  (section.characteristics & IMAGE_SCN_MEM_EXECUTE) === 0 &&
  (section.sizeOfRawData >>> 0) > 0 &&
  sectionMemorySize(section) > 0;

const rangeEnd = (start: bigint, size: number): bigint | null =>
  Number.isSafeInteger(size) && size >= 0 ? start + BigInt(size) : null;

const fileBackedSectionSize = (section: MappedSection): number => section.fileSize;
const memorySectionSize = (section: MappedSection): number => section.memorySize;

const containingSection = (
  sections: readonly MappedSection[],
  address: bigint,
  size: number,
  sectionSize: (section: MappedSection) => number
): MappedSection | null => {
  const end = rangeEnd(address, size);
  if (end == null) return null;
  return sections.find(section => {
    return address >= section.address && end <= section.address + BigInt(sectionSize(section));
  }) ?? null;
};

const createAddressSpace = (
  reader: FileRangeReader,
  sections: readonly MappedSection[],
  pointerSize: 4 | 8
): GoRuntimeAddressSpace => ({
  pointerSize,
  isMappedRange: (address, size) =>
    containingSection(sections, address, size, fileBackedSectionSize) != null,
  isExecutableRange: (start, end) => {
    if (end <= start || end - start > BigInt(Number.MAX_SAFE_INTEGER)) return false;
    return containingSection(
      sections,
      start,
      Number(end - start),
      memorySectionSize
    )?.executable === true;
  },
  readMapped: async (address, size) => {
    const section = containingSection(sections, address, size, fileBackedSectionSize);
    if (!section) return null;
    const relative = address - section.address;
    if (relative > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    const bytes = await reader.readBytes(section.fileOffset + Number(relative), size);
    return bytes.byteLength === size ? bytes : null;
  }
});

const littleEndianBytes = (value: number): Uint8Array => {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
};

const pointerBytes = (value: bigint, pointerSize: 4 | 8): Uint8Array => {
  const bytes = new Uint8Array(pointerSize);
  const view = new DataView(bytes.buffer);
  if (pointerSize === 8) view.setBigUint64(0, value, true);
  else view.setUint32(0, Number(value), true);
  return bytes;
};

const fileOffsetToAddress = (section: MappedSection, fileOffset: number): bigint =>
  section.address + BigInt(fileOffset - section.fileOffset);

const firstAlignedFileOffset = (section: MappedSection, alignment: 4 | 8): number => {
  const rawRemainder = Number(section.address % BigInt(alignment));
  const addressRemainder = (rawRemainder + alignment) % alignment;
  return section.fileOffset + (alignment - addressRemainder) % alignment;
};

const scanMappedSectionForPatterns = (
  file: File,
  section: MappedSection,
  patterns: readonly Uint8Array[],
  alignment: 4 | 8
): Promise<number[]> => {
  const offset = firstAlignedFileOffset(section, alignment);
  const skippedBytes = offset - section.fileOffset;
  return skippedBytes < section.fileSize
    ? scanFileRangeForPatterns(file, offset, section.fileSize - skippedBytes, patterns, alignment)
    : Promise.resolve([]);
};

const findPcHeaders = async (
  file: File,
  sections: readonly MappedSection[],
  image: GoRuntimeAddressSpace
): Promise<PcHeader[]> => {
  const patterns = SUPPORTED_GO_RUNTIME_LAYOUTS.map(layout => littleEndianBytes(layout.magic));
  const candidates: PcHeader[] = [];
  for (const section of sections.filter(candidate => !candidate.executable)) {
    const offsets = await scanMappedSectionForPatterns(file, section, patterns, image.pointerSize);
    for (const offset of offsets) {
      const address = fileOffsetToAddress(section, offset);
      if (address % BigInt(image.pointerSize) !== 0n) continue;
      const header = await parseGoPcHeader(image, address);
      if (header) candidates.push(header);
    }
  }
  return candidates;
};

const readPointer = (view: DataView, pointerSize: 4 | 8): bigint =>
  pointerSize === 8 ? view.getBigUint64(0, true) : BigInt(view.getUint32(0, true));

const findModuleDataCandidates = async (
  file: File,
  reader: FileRangeReader,
  sections: readonly MappedSection[],
  headers: PcHeader[],
  pointerSize: 4 | 8
): Promise<ModuleDataCandidate[]> => {
  const candidates: ModuleDataCandidate[] = [];
  const headersByAddress = new Map(headers.map(header => [header.address, header]));
  const patterns = headers.map(header => pointerBytes(header.address, pointerSize));
  for (const section of sections.filter(candidate => candidate.writable && !candidate.executable)) {
    const offsets = await scanMappedSectionForPatterns(file, section, patterns, pointerSize);
    for (const offset of offsets) {
      const address = fileOffsetToAddress(section, offset);
      if (address % BigInt(pointerSize) !== 0n) continue;
      const pointer = await reader.read(offset, pointerSize);
      if (pointer.byteLength !== pointerSize) continue;
      const header = headersByAddress.get(readPointer(pointer, pointerSize));
      if (header) candidates.push({ address, header });
    }
  }
  return candidates;
};

const distinctResult = (results: GoRuntimeMetadata[]): GoRuntimeMetadata | null => {
  const unique = new Map<string, GoRuntimeMetadata>();
  for (const result of results) {
    unique.set(`${result.pcHeaderAddress}:${result.moduleDataAddress}`, result);
  }
  return unique.size === 1 ? [...unique.values()][0]! : null;
};

export const analyzePeGoRuntime = async (
  file: File,
  reader: FileRangeReader,
  core: PeWindowsCore
): Promise<GoRuntimeMetadata | null> => {
  const pointerSize = core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 8 : 4;
  const mappedSections = core.sections.filter(isMappedDataSection)
    .map(section => toMappedSection(section, core.opt.ImageBase));
  const allSections = core.sections.map(section => toMappedSection(section, core.opt.ImageBase));
  if (!mappedSections.length) return null;
  const image = createAddressSpace(reader, allSections, pointerSize);
  const results: GoRuntimeMetadata[] = [];
  try {
    const headers = await findPcHeaders(file, mappedSections, image);
    const candidates = await findModuleDataCandidates(
      file,
      reader,
      mappedSections,
      headers,
      pointerSize
    );
    for (const candidate of candidates) {
      const result = await parseGoRuntimeMetadataFromHeader(
        image,
        candidate.header,
        candidate.address
      );
      if (result) results.push(result);
    }
  } catch {
    return null;
  }
  return distinctResult(results);
};
