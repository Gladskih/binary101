"use strict";

import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";

const PT_LOAD = 1;
const PF_X = 0x1;
const SHF_EXECINSTR = 0x4;
const SHT_NOBITS = 8;

export type ElfExecutableRegion = {
  label: string;
  fileOffset: bigint;
  fileSize: bigint;
  vaddr: bigint;
};

const isExecutableLoadSegment = (ph: ElfProgramHeader): boolean => ph.type === PT_LOAD && (ph.flags & PF_X) !== 0;

const isExecutableSection = (sec: ElfSectionHeader): boolean => {
  if (sec.type === SHT_NOBITS) return false;
  const flags = typeof sec.flags === "bigint" ? sec.flags : BigInt(sec.flags);
  return (flags & BigInt(SHF_EXECINSTR)) !== 0n;
};

export const getElfExecutableRegions = (
  programHeaders: ElfProgramHeader[],
  sections: ElfSectionHeader[]
): ElfExecutableRegion[] => {
  const segmentRegions: ElfExecutableRegion[] = programHeaders
    .filter(isExecutableLoadSegment)
    .filter(ph => ph.filesz > 0n)
    .map(ph => ({
      label: `Segment #${ph.index} (PT_LOAD + PF_X)`,
      fileOffset: ph.offset,
      fileSize: ph.filesz,
      vaddr: ph.vaddr
    }));
  if (segmentRegions.length) return segmentRegions;

  return sections
    .filter(isExecutableSection)
    .filter(sec => sec.size > 0n)
    .map(sec => ({
      label: `Section ${sec.name ? `"${sec.name}"` : `#${sec.index}`} (SHF_EXECINSTR)`,
      fileOffset: sec.offset,
      fileSize: sec.size,
      vaddr: sec.addr
    }));
};

export const findElfRegionContainingVaddr = (
  regions: ElfExecutableRegion[],
  vaddr: bigint
): ElfExecutableRegion | null => {
  for (const region of regions) {
    if (region.fileSize <= 0n) continue;
    const end = region.vaddr + region.fileSize;
    if (vaddr >= region.vaddr && vaddr < end) return region;
  }
  return null;
};

export const computeElfImageBase = (regions: ElfExecutableRegion[]): bigint => {
  let base: bigint | null = null;
  for (const region of regions) {
    if (base == null || region.vaddr < base) base = region.vaddr;
  }
  return base ?? 0n;
};

export const computeElfExecutableSpan = (regions: ElfExecutableRegion[], imageBase: bigint): bigint => {
  let maxEnd = imageBase;
  for (const region of regions) {
    const end = region.vaddr + region.fileSize;
    if (end > maxEnd) maxEnd = end;
  }
  return maxEnd - imageBase;
};

