"use strict";

import type { PeSection, RvaToOffset } from "./types.js";

const createRvaToOffsetMapper = (sections: PeSection[]): RvaToOffset => {
  const spans = sections.map(section => {
    const virtualAddress = section.virtualAddress >>> 0;
    const virtualSize = Math.max(section.virtualSize >>> 0, section.sizeOfRawData >>> 0);
    const fileOffset = section.pointerToRawData >>> 0;
    return { vaStart: virtualAddress, vaEnd: (virtualAddress + virtualSize) >>> 0, fileOffset };
  });
  return relativeVirtualAddress => {
    const normalized = relativeVirtualAddress >>> 0;
    for (const span of spans) {
      if (normalized >= span.vaStart && normalized < span.vaEnd) {
        return (span.fileOffset + (normalized - span.vaStart)) >>> 0;
      }
    }
    return null;
  };
};

const parseSectionHeaders = async (
  file: File,
  optionalHeaderOffset: number,
  sizeOfOptionalHeader: number,
  numberOfSections: number
): Promise<{ sections: PeSection[]; rvaToOff: RvaToOffset; sectOff: number }> => {
  const sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const sectionHeadersView = new DataView(
    await file.slice(sectionHeadersOffset, sectionHeadersOffset + numberOfSections * 40).arrayBuffer()
  );
  const sections: PeSection[] = [];
  for (let sectionIndex = 0; sectionIndex < numberOfSections; sectionIndex += 1) {
    const baseOffset = sectionIndex * 40;
    if (sectionHeadersView.byteLength < baseOffset + 40) break;
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
  const rvaToOff = createRvaToOffsetMapper(sections);
  return { sections, rvaToOff, sectOff: sectionHeadersOffset };
};

export { parseSectionHeaders };
