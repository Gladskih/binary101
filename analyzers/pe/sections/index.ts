"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { parseCoffSectionHeaders } from "../../coff/section-headers.js";
import { COFF_SECTION_HEADER_BYTE_LENGTH } from "../../coff/layout.js";
import type { PeSection, RvaToOffset } from "../types.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";

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

const appendPeImageWarnings = (
  warnings: string[],
  pointerToSymbolTable: number,
  numberOfSymbols: number,
  rawNames: string[]
): void => {
  // Microsoft PE format, "COFF File Header (Object and Image)":
  // PointerToSymbolTable and NumberOfSymbols should be zero for image files.
  if ((pointerToSymbolTable >>> 0) !== 0 || (numberOfSymbols >>> 0) !== 0) {
    warnings.push(NON_STANDARD_IMAGE_SYMBOL_TABLE_WARNING);
  }
  // Microsoft PE format, "Section Table (Section Headers)":
  // Executable images do not use the COFF string table for section names.
  if (rawNames.some(rawName => LONG_SECTION_NAME_REFERENCE.test(rawName))) {
    warnings.push(NON_STANDARD_IMAGE_LONG_SECTION_NAME_WARNING);
  }
};

export const parseSectionHeaders = async (
  reader: FileRangeReader,
  optionalHeaderOffset: number,
  sizeOfOptionalHeader: number,
  numberOfSections: number,
  sizeOfHeaders: number,
  pointerToSymbolTable = 0,
  numberOfSymbols = 0
): Promise<{
  sections: PeSection[];
  rvaToOff: RvaToOffset;
  sectOff: number;
  coffStringTableSize?: number;
  warnings?: string[];
}> => {
  const parsed = await parseCoffSectionHeaders(
    reader,
    optionalHeaderOffset,
    sizeOfOptionalHeader,
    numberOfSections,
    pointerToSymbolTable,
    numberOfSymbols
  );
  const sections: PeSection[] = parsed.sections;
  const warnings = [...(parsed.warnings ?? [])];
  appendPeImageWarnings(warnings, pointerToSymbolTable, numberOfSymbols, parsed.rawNames);
  return {
    sections,
    rvaToOff: createRvaToOffsetMapper(
      sections,
      reader.size,
      sizeOfHeaders,
      parsed.sectionHeadersOffset + (numberOfSections >>> 0) * COFF_SECTION_HEADER_BYTE_LENGTH
    ),
    sectOff: parsed.sectionHeadersOffset,
    ...(parsed.coffStringTableSize != null ? { coffStringTableSize: parsed.coffStringTableSize } : {}),
    ...(warnings.length ? { warnings } : {})
  };
};
