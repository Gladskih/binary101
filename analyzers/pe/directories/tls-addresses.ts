"use strict";

import type { PeSection, RvaToOffset } from "../types.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";

const MAX_RVA_BIGINT = 0xffff_ffffn;

export const toTlsRvaFromVa = (virtualAddress: bigint, imageBase: bigint): number | null => {
  if (virtualAddress === 0n) return null;
  if (virtualAddress < imageBase) return null;
  const delta = virtualAddress - imageBase;
  if (delta > MAX_RVA_BIGINT) return null;
  return Number(delta);
};

export const isReadableMappedTlsVa = (
  virtualAddress: bigint,
  byteLength: number,
  imageBase: bigint,
  rvaToOff: RvaToOffset,
  fileSize: number
): boolean => {
  const rva = toTlsRvaFromVa(virtualAddress, imageBase);
  if (rva == null) return false;
  const offset = rvaToOff(rva);
  return offset != null && offset >= 0 && offset + byteLength <= fileSize;
};

const findSectionContainingRva = (sections: PeSection[], rva: number): PeSection | null => {
  const normalizedRva = rva >>> 0;
  for (const section of sections) {
    const start = section.virtualAddress >>> 0;
    const size = (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);
    if (normalizedRva >= start && normalizedRva < start + size) return section;
  }
  return null;
};

export const isTlsImageVa = (
  virtualAddress: bigint,
  byteLength: number,
  imageBase: bigint,
  sections: PeSection[]
): boolean => {
  if (!Number.isSafeInteger(byteLength) || byteLength <= 0) return false;
  const rva = toTlsRvaFromVa(virtualAddress, imageBase);
  if (rva == null || rva > PE_RVA_EXCLUSIVE_LIMIT - byteLength) return false;
  const section = findSectionContainingRva(sections, rva);
  if (!section) return false;
  const sectionStart = section.virtualAddress >>> 0;
  const sectionSize = (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);
  return rva - sectionStart <= sectionSize - byteLength;
};
