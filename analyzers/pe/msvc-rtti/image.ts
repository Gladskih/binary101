"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { COFF_SECTION_CHARACTERISTICS } from "../../coff/layout.js";
import {
  findSectionContainingRva,
  getMappedSectionSpan,
  isMemoryExecutableSection
} from "../disassembly/sampling.js";
import type { PeSection } from "../types.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import { IMAGE_POINTER_SIZE } from "./layout.js";

export interface MsvcRttiImage {
  availableDataSize: (rva: number, limit: number) => number;
  isDataRange: (rva: number, size: number, alignment: number) => boolean;
  isExecutableRva: (rva: number) => boolean;
  preferredVaToRva: (value: bigint) => number | null;
  readData: (rva: number, size: number, alignment: number) => Promise<DataView | null>;
  readPreferredVaRva: (rva: number) => Promise<number | null>;
}

const isRvaRange = (rva: number, size: number, sizeOfImage: number): boolean => {
  if (!Number.isSafeInteger(rva) || !Number.isSafeInteger(size) || size <= 0) return false;
  if (rva < 0 || rva >= PE_RVA_EXCLUSIVE_LIMIT) return false;
  const end = rva + size;
  return end > rva && end <= PE_RVA_EXCLUSIVE_LIMIT && end <= sizeOfImage;
};

const isReadableInitializedData = (section: PeSection): boolean =>
  (section.characteristics & COFF_SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA) !== 0 &&
  (section.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_READ) !== 0 &&
  (section.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE) === 0;

const fileBackedSize = (section: PeSection, fileSize: number): number => {
  const rawStart = section.pointerToRawData >>> 0;
  if (rawStart >= fileSize) return 0;
  return Math.min(
    section.sizeOfRawData >>> 0,
    getMappedSectionSpan(section),
    fileSize - rawStart
  );
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

const fileOffsetForRva = (section: PeSection, rva: number): number =>
  (section.pointerToRawData >>> 0) + rva - (section.virtualAddress >>> 0);

export const createMsvcRttiImage = (
  reader: FileRangeReader,
  sections: PeSection[],
  imageBase: bigint,
  sizeOfImage: number
): MsvcRttiImage => {
  const normalizedImageSize = Number.isSafeInteger(sizeOfImage) && sizeOfImage > 0
    ? Math.min(sizeOfImage, PE_RVA_EXCLUSIVE_LIMIT)
    : 0;
  const isDataRange = (rva: number, size: number, alignment: number): boolean =>
    Number.isSafeInteger(alignment) && alignment > 0 && rva % alignment === 0 &&
    isRvaRange(rva, size, normalizedImageSize) &&
    findDataSection(sections, rva, size, reader.size) != null;
  const availableDataSize = (rva: number, limit: number): number => {
    if (!Number.isSafeInteger(limit) || limit <= 0 || !isRvaRange(rva, 1, normalizedImageSize)) return 0;
    const section = findDataSection(sections, rva, 1, reader.size);
    if (!section) return 0;
    const delta = rva - (section.virtualAddress >>> 0);
    return Math.min(limit, fileBackedSize(section, reader.size) - delta, normalizedImageSize - rva);
  };
  const readData = async (rva: number, size: number, alignment: number): Promise<DataView | null> => {
    if (!isDataRange(rva, size, alignment)) return null;
    const section = findDataSection(sections, rva, size, reader.size);
    if (!section) return null;
    const view = await reader.read(fileOffsetForRva(section, rva), size);
    return view.byteLength === size ? view : null;
  };
  const preferredVaToRva = (value: bigint): number | null => {
    if (imageBase < 0n || value < imageBase) return null;
    const delta = value - imageBase;
    if (delta >= BigInt(PE_RVA_EXCLUSIVE_LIMIT) || delta >= BigInt(normalizedImageSize)) return null;
    return Number(delta);
  };
  const readPreferredVaRva = async (rva: number): Promise<number | null> => {
    const view = await readData(rva, IMAGE_POINTER_SIZE, IMAGE_POINTER_SIZE);
    return view ? preferredVaToRva(view.getBigUint64(0, true)) : null;
  };
  const isExecutableRva = (rva: number): boolean => {
    if (!isRvaRange(rva, 1, normalizedImageSize)) return false;
    const section = findSectionContainingRva(sections, rva);
    return section != null && isMemoryExecutableSection(section);
  };
  return {
    availableDataSize,
    isDataRange,
    isExecutableRva,
    preferredVaToRva,
    readData,
    readPreferredVaRva
  };
};
