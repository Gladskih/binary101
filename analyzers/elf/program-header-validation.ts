import type { ElfHeader, ElfProgramHeader } from "./types.js";
import { elfLoadMappingCovers } from "./range-coverage.js";

type ProgramTable = Pick<ElfHeader, "phoff" | "phentsize" | "phnum">;

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

const validateProgramTableSegment = (
  segment: ElfProgramHeader, table: ProgramTable, loads: ElfProgramHeader[],
  fileSize: bigint, issues: string[]
): void => {
  const size = BigInt(table.phnum) * BigInt(table.phentsize);
  const label = `PT_PHDR #${segment.index}`;
  if (segment.offset !== table.phoff) issues.push(`${label}: p_offset differs from e_phoff.`);
  if (segment.filesz !== size) issues.push(`${label}: p_filesz differs from the program header table size.`);
  if (segment.memsz !== size) issues.push(`${label}: p_memsz differs from the program header table size.`);
  if (segment.offset !== table.phoff || segment.filesz !== size || segment.memsz !== size ||
    table.phoff + size > fileSize) return;
  if (!elfLoadMappingCovers(loads, table.phoff, segment.vaddr, size)) {
    issues.push(`${label}: the program header table lacks file-backed PT_LOAD coverage at p_vaddr.`);
  }
};

export const validateElfProgramHeaders = (
  headers: ElfProgramHeader[], fileSize: number, issues: string[], table?: ProgramTable
): void => {
  const loads = headers.filter(header => header.type === 1);
  for (const header of headers) {
    // PT_NULL fields are undefined; zero-sized segments need no file payload.
    if (header.type !== 0 && header.filesz > 0n &&
      header.offset + header.filesz > BigInt(fileSize)) {
      issues.push(`Segment #${header.index} file range is outside the file.`);
    }
    if (header.type === 1) validateLoadSegment(header, issues);
  }
  validateOrderedSegments(headers, loads, issues);
  const programTable = headers.find(header => header.type === 6);
  if (programTable && table) validateProgramTableSegment(programTable, table, loads, BigInt(fileSize), issues);
};
