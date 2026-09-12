"use strict";

import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import type { PeSection, RvaToOffset } from "../types.js";

type SectionMapping = { start: number; end: number; offset: number; rawSize: number };

const sectionSpan = (
  sections: SectionMapping[], rva: number, fileSize: number
): { offset: number; size: number } | null => {
  let boundary = PE_RVA_EXCLUSIVE_LIMIT;
  for (const section of sections) {
    // An earlier section can take precedence partway through a later section's range.
    if (section.start > rva) boundary = Math.min(boundary, section.start);
    if (rva < section.start || rva >= section.end) continue;
    const delta = rva - section.start;
    const offset = section.offset + delta;
    const size = Math.min(section.end - rva, section.rawSize - delta,
      fileSize - offset, boundary - rva);
    return size > 0 ? { offset, size } : null;
  }
  return null;
};

export const createRvaToOffsetMapper = (
  sections: PeSection[], fileSize: number, sizeOfHeaders: number, minimumHeaderSpan: number
): RvaToOffset => {
  // PE/COFF Section Table: VirtualSize bounds mapped data; raw padding is not virtual data.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
  const mappings = sections.map(section => ({
    start: section.virtualAddress,
    end: Math.min(PE_RVA_EXCLUSIVE_LIMIT,
      section.virtualAddress + (section.virtualSize || section.sizeOfRawData)),
    offset: section.pointerToRawData,
    rawSize: section.sizeOfRawData
  }));
  const headerSize = sizeOfHeaders >= minimumHeaderSpan ? Math.min(sizeOfHeaders, fileSize) : 0;
  const span: NonNullable<RvaToOffset["span"]> = rva => {
    if (!Number.isInteger(rva) || rva < 0 || rva >= PE_RVA_EXCLUSIVE_LIMIT) return null;
    return rva < headerSize
      ? { offset: rva, size: headerSize - rva }
      : sectionSpan(mappings, rva, fileSize);
  };
  return Object.assign((rva: number) => span(rva)?.offset ?? null, { span });
};
