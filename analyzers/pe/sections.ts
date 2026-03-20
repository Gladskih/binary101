"use strict";

import type { PeSection, RvaToOffset } from "./types.js";

const IMAGE_SECTION_HEADER_SIZE = 40;
const IMAGE_FILE_HEADER_MAX_SECTIONS = 96;

const getMappedSectionSpan = (section: PeSection): number =>
  (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);

const createRvaToOffsetMapper = (
  sections: PeSection[],
  fileSize: number,
  sizeOfHeaders: number
): RvaToOffset => {
  const spans = sections.map(section => {
    const virtualAddress = section.virtualAddress >>> 0;
    const mappedSpan = getMappedSectionSpan(section);
    const fileOffset = section.pointerToRawData >>> 0;
    const rawSize = section.sizeOfRawData >>> 0;
    return { vaStart: virtualAddress, vaEnd: (virtualAddress + mappedSpan) >>> 0, fileOffset, rawSize };
  });
  return relativeVirtualAddress => {
    const normalized = relativeVirtualAddress >>> 0;
    const headerSpan = Math.max(0, Math.min(sizeOfHeaders >>> 0, fileSize >>> 0));
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
): Promise<{ sections: PeSection[]; rvaToOff: RvaToOffset; sectOff: number }> => {
  const sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const safeSectionCount = Math.min(numberOfSections >>> 0, IMAGE_FILE_HEADER_MAX_SECTIONS);
  const sectionHeadersView = new DataView(
    await file
      .slice(
        sectionHeadersOffset,
        sectionHeadersOffset + safeSectionCount * IMAGE_SECTION_HEADER_SIZE
      )
      .arrayBuffer()
  );
  const sections: PeSection[] = [];
  for (let sectionIndex = 0; sectionIndex < safeSectionCount; sectionIndex += 1) {
    const baseOffset = sectionIndex * IMAGE_SECTION_HEADER_SIZE;
    if (sectionHeadersView.byteLength < baseOffset + IMAGE_SECTION_HEADER_SIZE) break;
    let name = "";
    for (let nameIndex = 0; nameIndex < 8; nameIndex += 1) {
      const codePoint = sectionHeadersView.getUint8(baseOffset + nameIndex);
      if (codePoint === 0) break;
      name += String.fromCharCode(codePoint);
    }
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
  const rvaToOff = createRvaToOffsetMapper(sections, file.size, sizeOfHeaders);
  return { sections, rvaToOff, sectOff: sectionHeadersOffset };
};

export { parseSectionHeaders };
