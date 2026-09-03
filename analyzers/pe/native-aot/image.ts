"use strict";

import { COFF_SECTION_CHARACTERISTICS } from "../../coff/layout.js";
import { IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386 } from "../../coff/machine.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { NativeAotVirtualImage } from "../../native-aot/virtual-image-types.js";
import {
  IMAGE_REL_BASED_DIR64,
  type PeBaseRelocationBlock,
  type PeBaseRelocationResult
} from "../directories/reloc.js";
import { findSectionContainingRva, getMappedSectionSpan } from "../disassembly/sampling.js";
import {
  PE32_OPTIONAL_HEADER_MAGIC,
  PE32_PLUS_OPTIONAL_HEADER_MAGIC
} from "../optional-header/magic.js";
import type { PeSection, PeWindowsCore } from "../types.js";

const IMAGE_REL_BASED_HIGHLOW = 3;
const BASE_RELOCATION_PAGE_SIZE = 0x1000;
const PE_RVA_LIMIT = 0x1_0000_0000;

export interface PeNativeAotImage extends NativeAotVirtualImage {
  relocationType: number;
  preferredVaToRva: (value: bigint) => number | null;
}

export const isPeNativeAotRvaRange = (
  rva: number,
  size: number,
  sizeOfImage: number
): boolean => {
  if (!Number.isSafeInteger(rva) || rva < 0 || !Number.isSafeInteger(size) || size <= 0) {
    return false;
  }
  const end = rva + size;
  return Number.isSafeInteger(end) && end <= sizeOfImage;
};

const isReadableInitializedData = (section: PeSection): boolean =>
  (section.characteristics & COFF_SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA) !== 0 &&
  (section.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_READ) !== 0 &&
  (section.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE) === 0;

const fileBackedSize = (section: PeSection, fileSize: number): number => {
  const rawStart = section.pointerToRawData >>> 0;
  if (rawStart >= fileSize) return 0;
  return Math.min(section.sizeOfRawData >>> 0, getMappedSectionSpan(section), fileSize - rawStart);
};

const findDataSection = (
  sections: PeSection[],
  rva: number,
  size: number,
  fileSize: number
): PeSection | null => {
  const section = findSectionContainingRva(sections, rva);
  if (!section || !isReadableInitializedData(section)) return null;
  const delta = rva - (section.virtualAddress >>> 0);
  return delta >= 0 && delta + size <= fileBackedSize(section, fileSize) ? section : null;
};

const isMappedSectionRange = (sections: PeSection[], rva: number, size: number): boolean => {
  const section = findSectionContainingRva(sections, rva);
  if (!section) return false;
  const delta = rva - (section.virtualAddress >>> 0);
  return delta >= 0 && delta + size <= getMappedSectionSpan(section);
};

export const createPeNativeAotImage = (
  reader: FileRangeReader,
  core: PeWindowsCore,
  pointerSize: 4 | 8,
  relocationType: number
): PeNativeAotImage => {
  const sizeOfImage = Number.isSafeInteger(core.opt.SizeOfImage) && core.opt.SizeOfImage > 0
    ? Math.min(core.opt.SizeOfImage, PE_RVA_LIMIT)
    : 0;
  const isDataRange = (rva: number, size: number, alignment: number): boolean =>
    Number.isSafeInteger(alignment) && alignment > 0 && rva % alignment === 0 &&
    isPeNativeAotRvaRange(rva, size, sizeOfImage) &&
    findDataSection(core.sections, rva, size, reader.size) != null;
  const readData = async (
    rva: number,
    size: number,
    alignment: number
  ): Promise<DataView | null> => {
    if (!isDataRange(rva, size, alignment)) return null;
    const offset = core.rvaToOff(rva);
    if (offset == null || offset < 0 || offset + size > reader.size) return null;
    const view = await reader.read(offset, size);
    return view.byteLength === size ? view : null;
  };
  const readPointerValue = async (rva: number): Promise<bigint | null> => {
    const view = await readData(rva, pointerSize, pointerSize);
    if (!view) return null;
    return pointerSize === 8 ? view.getBigUint64(0, true) : BigInt(view.getUint32(0, true));
  };
  const preferredVaToRva = (value: bigint): number | null => {
    if (core.opt.ImageBase < 0n || value < core.opt.ImageBase) return null;
    const delta = value - core.opt.ImageBase;
    return delta < BigInt(sizeOfImage) && delta < BigInt(PE_RVA_LIMIT) ? Number(delta) : null;
  };
  const readPointerTarget = async (rva: number): Promise<number | null> => {
    const value = await readPointerValue(rva);
    return value == null ? null : preferredVaToRva(value);
  };
  return {
    pointerSize,
    relocationType,
    isDataRange,
    isMappedRange: (rva, size) =>
      isPeNativeAotRvaRange(rva, size, sizeOfImage) &&
      isMappedSectionRange(core.sections, rva, size),
    readData,
    readPointerValue,
    readPointerTarget,
    preferredVaToRva
  };
};

const isConsistentRelocationBlock = (block: PeBaseRelocationBlock): boolean =>
  Number.isSafeInteger(block.pageRva) &&
  block.pageRva >= 0 &&
  block.pageRva < PE_RVA_LIMIT &&
  block.pageRva % BASE_RELOCATION_PAGE_SIZE === 0 &&
  Number.isSafeInteger(block.size) &&
  block.size >= 8 &&
  block.size % 4 === 0 &&
  block.count === block.entries.length;

export const indexPeNativeAotPointerSites = (
  relocations: PeBaseRelocationResult | null,
  image: PeNativeAotImage
): Set<number> | null => {
  if (!relocations || relocations.warnings?.length) return null;
  if (relocations.blocks.some(block => !isConsistentRelocationBlock(block))) return null;
  const entryCount = relocations.blocks.reduce((count, block) => count + block.entries.length, 0);
  if (entryCount !== relocations.totalEntries) return null;
  const sites = new Set<number>();
  for (const block of relocations.blocks) {
    for (const entry of block.entries) {
      if (entry.type !== image.relocationType) continue;
      if (!Number.isSafeInteger(entry.offset) || entry.offset < 0 || entry.offset >= 0x1000) {
        return null;
      }
      const siteRva = block.pageRva + entry.offset;
      if (!image.isDataRange(siteRva, image.pointerSize, image.pointerSize)) continue;
      if (sites.has(siteRva)) return null;
      sites.add(siteRva);
    }
  }
  return sites.size ? sites : null;
};

export const getPeNativeAotArchitecture = (
  core: PeWindowsCore
): { pointerSize: 4 | 8; relocationType: number } | null => {
  if (core.coff.Machine === IMAGE_FILE_MACHINE_AMD64 &&
    core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC) {
    return { pointerSize: 8, relocationType: IMAGE_REL_BASED_DIR64 };
  }
  if (core.coff.Machine === IMAGE_FILE_MACHINE_I386 &&
    core.opt.Magic === PE32_OPTIONAL_HEADER_MAGIC) {
    return { pointerSize: 4, relocationType: IMAGE_REL_BASED_HIGHLOW };
  }
  return null;
};
