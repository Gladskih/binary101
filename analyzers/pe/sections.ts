"use strict";

import type { PeSection, RvaToOffset } from "./types.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "./rva-limits.js";

const IMAGE_SECTION_HEADER_SIZE = 40;
const sectionNameDecoder = new TextDecoder("utf-8", { fatal: false });

const getMappedSectionSpan = (section: PeSection): number =>
  (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);

const createRvaToOffsetMapper = (
  sections: PeSection[],
  fileSize: number,
  sizeOfHeaders: number,
  minimumHeaderSpan: number
): RvaToOffset => {
  const spans = sections.map(section => {
    const virtualAddress = section.virtualAddress >>> 0;
    const mappedSpan = getMappedSectionSpan(section);
    const fileOffset = section.pointerToRawData >>> 0;
    const rawSize = section.sizeOfRawData >>> 0;
  return {
      vaStart: virtualAddress,
      vaEnd: Math.min(PE_RVA_EXCLUSIVE_LIMIT, virtualAddress + mappedSpan),
      fileOffset,
      rawSize
    };
  });
  return relativeVirtualAddress => {
    if (
      !Number.isInteger(relativeVirtualAddress) ||
      relativeVirtualAddress < 0 ||
      relativeVirtualAddress >= PE_RVA_EXCLUSIVE_LIMIT
    ) {
      return null;
    }
    const normalized = relativeVirtualAddress >>> 0;
    const headerSpan =
      (sizeOfHeaders >>> 0) >= (minimumHeaderSpan >>> 0)
        ? Math.max(0, Math.min(sizeOfHeaders >>> 0, fileSize >>> 0))
        : 0;
    if (normalized < headerSpan) return normalized;
    for (const span of spans) {
      if (normalized >= span.vaStart && normalized < span.vaEnd) {
        const delta = normalized - span.vaStart;
        if (delta >= span.rawSize) return null;
        return (span.fileOffset + delta) >>> 0;
      }
    }
    return null;
  };
};

const parseSectionHeaders = async (
  file: File,
  optionalHeaderOffset: number,
  sizeOfOptionalHeader: number,
  numberOfSections: number,
  sizeOfHeaders: number
): Promise<{ sections: PeSection[]; rvaToOff: RvaToOffset; sectOff: number; warnings?: string[] }> => {
  const sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const safeSectionCount = numberOfSections >>> 0;
  const sectionHeadersView = new DataView(
    await file
      .slice(
        sectionHeadersOffset,
        sectionHeadersOffset + safeSectionCount * IMAGE_SECTION_HEADER_SIZE
      )
      .arrayBuffer()
  );
  const sections: PeSection[] = [];
  const warnings: string[] = [];
  if (sectionHeadersView.byteLength < safeSectionCount * IMAGE_SECTION_HEADER_SIZE) {
    warnings.push("Section header table is truncated by end of file.");
  }
  for (let sectionIndex = 0; sectionIndex < safeSectionCount; sectionIndex += 1) {
    const baseOffset = sectionIndex * IMAGE_SECTION_HEADER_SIZE;
    if (sectionHeadersView.byteLength < baseOffset + IMAGE_SECTION_HEADER_SIZE) break;
    const nameBytes = new Uint8Array(
      sectionHeadersView.buffer,
      sectionHeadersView.byteOffset + baseOffset,
      8
    );
    const zeroIndex = nameBytes.indexOf(0);
    const name = sectionNameDecoder.decode(nameBytes.subarray(0, zeroIndex === -1 ? 8 : zeroIndex));
    const virtualSize = sectionHeadersView.getUint32(baseOffset + 8, true);
    const virtualAddress = sectionHeadersView.getUint32(baseOffset + 12, true);
    const sizeOfRawData = sectionHeadersView.getUint32(baseOffset + 16, true);
    const pointerToRawData = sectionHeadersView.getUint32(baseOffset + 20, true);
    const characteristics = sectionHeadersView.getUint32(baseOffset + 36, true);
    sections.push({
      name: name || "(unnamed)",
      virtualSize,
      virtualAddress,
      sizeOfRawData,
      pointerToRawData,
      characteristics
    });
  }
  const rvaToOff = createRvaToOffsetMapper(
    sections,
    file.size,
    sizeOfHeaders,
    sectionHeadersOffset + safeSectionCount * IMAGE_SECTION_HEADER_SIZE
  );
  return warnings.length
    ? { sections, rvaToOff, sectOff: sectionHeadersOffset, warnings }
    : { sections, rvaToOff, sectOff: sectionHeadersOffset };
};

export { parseSectionHeaders };
