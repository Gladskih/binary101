"use strict";

import type { ElfProgramHeader, ElfSectionHeader, ElfTlsInfo } from "./types.js";
import { ELF_FILE_TYPE, ELF_SECTION_FLAG, ELF_SECTION_TYPE, ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { elfLoadMappingCovers } from "./range-coverage.js";

const PT_TLS = 7;
// gABI 7.7: the file image initializes the leading part of the template;
// the remaining bytes are zero-filled and may contain SHT_NOBITS sections.
// https://gabi.xinuos.com/elf/07-pheader.html#thread-local-storage
const validateTlsSections = (
  sections: ElfSectionHeader[], template: ElfProgramHeader, issues: string[]
): void => {
  if (template.filesz > template.memsz) return;
  for (const section of sections) {
    const isZeroFill = section.type === ELF_SECTION_TYPE.NOBITS;
    const start = section.addr - template.vaddr;
    const end = start + section.size;
    const fits = isZeroFill ? start >= template.filesz && end <= template.memsz :
      start >= 0n && end <= template.filesz && section.offset === template.offset + start;
    if (fits) continue;
    issues.push(isZeroFill ? `TLS section #${section.index} is outside the zero-filled PT_TLS template.` :
      `TLS section #${section.index} file range or address disagrees with the PT_TLS initialization image.`);
  }
};

const validateTlsTemplate = (
  sections: ElfSectionHeader[], segments: ElfProgramHeader[], issues: string[]
): void => {
  // glibc retains one template per shared object and ignores empty PT_TLS entries.
  // https://github.com/bminor/glibc/blob/master/elf/dl-load.c
  const templates = segments.filter(segment => segment.memsz > 0n);
  if (templates.length > 1) {
    issues.push("Multiple nonempty PT_TLS entries describe the TLS template.");
  } else if (templates[0]) {
    validateTlsSections(sections, templates[0], issues);
  } else if (sections.length && !segments.some(segment => segment.filesz > 0n)) {
    issues.push("SHF_TLS sections are present without a nonempty PT_TLS template.");
  }
};

// gABI 7.7 gives PT_TLS flags as PF_R; glibc uses p_align as a power-of-two mask.
// https://github.com/bminor/glibc/blob/master/elf/dl-load.c
const validateTlsSegment = (segment: ElfProgramHeader, loads: ElfProgramHeader[], issues: string[]): void => {
  const label = `PT_TLS #${segment.index}`;
  if (segment.filesz > segment.memsz) {
    issues.push(`${label}: p_filesz exceeds p_memsz.`);
    return;
  }
  if (!segment.memsz) return;
  if (segment.flags !== 4) issues.push(`${label}: the TLS template flags must be PF_R.`);
  if ((segment.align & (segment.align - 1n)) !== 0n) {
    issues.push(`${label}: p_align is not zero or a power of two.`);
  }
  if (loads.length && segment.filesz && !elfLoadMappingCovers(loads, segment.offset, segment.vaddr, segment.filesz)) {
    issues.push(`${label}: the initialization bytes do not map through PT_LOAD at p_vaddr.`);
  }
};

export function parseElfTlsInfo(
  programHeaders: ElfProgramHeader[], sections: ElfSectionHeader[], fileType?: number
): ElfTlsInfo | null {
  const tlsSegments = programHeaders.filter(header => header.type === PT_TLS);
  const tlsSections = sections.filter(section => section.size > 0n && (section.flags & ELF_SECTION_FLAG.TLS));
  if (!tlsSegments.length && !tlsSections.length) return null;
  const issues: string[] = [];
  const loads = programHeaders.filter(header => header.type === ELF_SEGMENT_TYPE.LOAD);
  for (const segment of tlsSegments) validateTlsSegment(segment, loads, issues);
  if (fileType === ELF_FILE_TYPE.EXEC || fileType === ELF_FILE_TYPE.DYN) {
    validateTlsTemplate(tlsSections, tlsSegments, issues);
  }
  return {
    segments: tlsSegments.map(ph => ({
      index: ph.index,
      offset: ph.offset,
      vaddr: ph.vaddr,
      filesz: ph.filesz,
      memsz: ph.memsz,
      align: ph.align
    })),
    sections: tlsSections.map(sec => ({
      index: sec.index,
      name: sec.name || "",
      addr: sec.addr,
      offset: sec.offset,
      size: sec.size,
      flags: sec.flagNames
    })),
    ...(issues.length ? { issues } : {})
  };
}

