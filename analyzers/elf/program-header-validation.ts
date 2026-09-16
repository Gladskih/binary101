import type { ElfProgramHeader } from "./types.js";

// gABI 7.1/7.2: load sizes, alignment, ordering, and unique INTERP/PHDR entries.
// https://gabi.xinuos.com/elf/07-pheader.html
const validateLoadSegment = (header: ElfProgramHeader, issues: string[]): void => {
  if (header.filesz > header.memsz) {
    issues.push(`PT_LOAD #${header.index}: p_filesz exceeds p_memsz.`);
  }
  if (header.align <= 1n) return;
  if ((header.align & (header.align - 1n)) !== 0n) {
    issues.push(`PT_LOAD #${header.index}: p_align is not a power of two.`);
  }
  if (header.vaddr % header.align !== header.offset % header.align) {
    issues.push(`PT_LOAD #${header.index}: p_vaddr and p_offset disagree modulo p_align.`);
  }
};

const validateOrderedSegments = (
  headers: ElfProgramHeader[], loads: ElfProgramHeader[], issues: string[]
): void => {
  loads.forEach((header, index) => {
    const previous = loads[index - 1];
    if (previous && header.vaddr < previous.vaddr) {
      issues.push("PT_LOAD entries must be in ascending order of p_vaddr.");
    }
  });
  for (const [type, name] of [[3, "PT_INTERP"], [6, "PT_PHDR"]] as const) {
    const entries = headers.filter(header => header.type === type);
    if (entries.length > 1) issues.push(`${name} occurs more than once.`);
    if (loads[0] && entries.some(header => header.index > loads[0]!.index)) {
      issues.push(`${name} must precede PT_LOAD entries.`);
    }
  }
};

export const validateElfProgramHeaders = (
  headers: ElfProgramHeader[], fileSize: number, issues: string[]
): void => {
  for (const header of headers) {
    // PT_NULL fields are undefined; zero-sized segments need no file payload.
    if (header.type !== 0 && header.filesz > 0n &&
      header.offset + header.filesz > BigInt(fileSize)) {
      issues.push(`Segment #${header.index} file range is outside the file.`);
    }
    if (header.type === 1) validateLoadSegment(header, issues);
  }
  validateOrderedSegments(headers, headers.filter(header => header.type === 1), issues);
};
