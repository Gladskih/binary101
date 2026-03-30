"use strict";

import type { PeSection, RvaToOffset } from "./types.js";
import { createCoffStringTableResolver, resolveSectionName } from "./coff-string-table.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "./rva-limits.js";

const IMAGE_SECTION_HEADER_SIZE = 40;
const sectionNameDecoder = new TextDecoder("utf-8", { fatal: false });
const LONG_SECTION_NAME_REFERENCE = /^\/\d+$/;
const NON_STANDARD_IMAGE_SYMBOL_TABLE_WARNING =
  "PE image has a COFF symbol table even though Microsoft PE format says PointerToSymbolTable and NumberOfSymbols should be zero for images because COFF debugging information is deprecated.";
const NON_STANDARD_IMAGE_LONG_SECTION_NAME_WARNING =
  "PE image uses COFF string-table section names like /4 even though Microsoft PE format says executable images do not use a string table for section names and do not support section names longer than 8 characters. Any recovered name is a non-standard best-effort decode.";

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

const readSectionHeader = (
  sectionHeadersView: DataView,
  baseOffset: number,
  stringTableResolver: Awaited<ReturnType<typeof createCoffStringTableResolver>>["resolver"]
): Promise<{ rawName: string; section: PeSection; warning?: string }> => {
  const nameBytes = new Uint8Array(
    sectionHeadersView.buffer,
    sectionHeadersView.byteOffset + baseOffset,
    8
  );
  const zeroIndex = nameBytes.indexOf(0);
  const rawName = sectionNameDecoder.decode(nameBytes.subarray(0, zeroIndex === -1 ? 8 : zeroIndex));
  return resolveSectionName(rawName, stringTableResolver).then(resolvedName => ({
    rawName,
    section: {
      name: resolvedName.name,
      virtualSize: sectionHeadersView.getUint32(baseOffset + 8, true),
      virtualAddress: sectionHeadersView.getUint32(baseOffset + 12, true),
      sizeOfRawData: sectionHeadersView.getUint32(baseOffset + 16, true),
      pointerToRawData: sectionHeadersView.getUint32(baseOffset + 20, true),
      characteristics: sectionHeadersView.getUint32(baseOffset + 36, true)
    },
    ...(resolvedName.warning ? { warning: resolvedName.warning } : {})
  }));
};

const parseSectionHeaders = async (
  file: File,
  optionalHeaderOffset: number,
  sizeOfOptionalHeader: number,
  numberOfSections: number,
  sizeOfHeaders: number,
  pointerToSymbolTable = 0,
  numberOfSymbols = 0
): Promise<{ sections: PeSection[]; rvaToOff: RvaToOffset; sectOff: number; warnings?: string[] }> => {
  const sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const safeSectionCount = numberOfSections >>> 0;
  const coffStringTable = await createCoffStringTableResolver(
    file,
    pointerToSymbolTable,
    numberOfSymbols
  );
  const sectionHeadersView = new DataView(
    await file
      .slice(
        sectionHeadersOffset,
        sectionHeadersOffset + safeSectionCount * IMAGE_SECTION_HEADER_SIZE
      )
      .arrayBuffer()
  );
  const sections: PeSection[] = [];
  const warnings = coffStringTable?.warning ? [coffStringTable.warning] : [];
  let sawLongSectionNameReference = false;
  if (sectionHeadersView.byteLength < safeSectionCount * IMAGE_SECTION_HEADER_SIZE) {
    warnings.push("Section header table is truncated by end of file.");
  }
  for (let sectionIndex = 0; sectionIndex < safeSectionCount; sectionIndex += 1) {
    const baseOffset = sectionIndex * IMAGE_SECTION_HEADER_SIZE;
    if (sectionHeadersView.byteLength < baseOffset + IMAGE_SECTION_HEADER_SIZE) break;
    const { rawName, section, warning } = await readSectionHeader(
      sectionHeadersView,
      baseOffset,
      coffStringTable.resolver
    );
    sawLongSectionNameReference ||= LONG_SECTION_NAME_REFERENCE.test(rawName);
    if (warning) warnings.push(warning);
    sections.push(section);
  }
  // Microsoft PE format, "COFF File Header (Object and Image)":
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
  // PointerToSymbolTable and NumberOfSymbols should be zero for image files.
  if ((pointerToSymbolTable >>> 0) !== 0 || (numberOfSymbols >>> 0) !== 0) {
    warnings.push(NON_STANDARD_IMAGE_SYMBOL_TABLE_WARNING);
  }
  // Microsoft PE format, "Section Table (Section Headers)":
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
  // Executable images do not use a string table for section names and do not support names longer than 8 chars.
  if (sawLongSectionNameReference) {
    warnings.push(NON_STANDARD_IMAGE_LONG_SECTION_NAME_WARNING);
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
