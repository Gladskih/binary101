"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { CoffSection } from "./types.js";
import { createCoffStringTableResolver, resolveCoffSectionName } from "./section-string-table.js";
import {
  COFF_SECTION_HEADER_BYTE_LENGTH,
  COFF_SECTION_HEADER_FIELDS,
  COFF_SHORT_NAME_BYTE_LENGTH,
  readCoffField
} from "./layout.js";

const sectionNameDecoder = new TextDecoder("utf-8");

export interface CoffSectionHeaderParseResult {
  sections: CoffSection[];
  sectionHeadersOffset: number;
  coffStringTableSize?: number;
  rawNames: string[];
  warnings?: string[];
}

const readSectionHeader = async (
  sectionHeadersView: DataView,
  baseOffset: number,
  stringTableResolver: Awaited<ReturnType<typeof createCoffStringTableResolver>>["resolver"]
): Promise<{ rawName: string; section: CoffSection; warning?: string }> => {
  const nameBytes = new Uint8Array(
    sectionHeadersView.buffer,
    sectionHeadersView.byteOffset + baseOffset,
    COFF_SHORT_NAME_BYTE_LENGTH
  );
  const zeroIndex = nameBytes.indexOf(0);
  const rawName = sectionNameDecoder.decode(
    nameBytes.subarray(0, zeroIndex === -1 ? COFF_SHORT_NAME_BYTE_LENGTH : zeroIndex)
  );
  const resolvedName = await resolveCoffSectionName(rawName, stringTableResolver);
  return {
    rawName,
    section: {
      name: resolvedName.name,
      virtualSize: readCoffField(sectionHeadersView, baseOffset, COFF_SECTION_HEADER_FIELDS.VirtualSize),
      virtualAddress: readCoffField(sectionHeadersView, baseOffset, COFF_SECTION_HEADER_FIELDS.VirtualAddress),
      sizeOfRawData: readCoffField(sectionHeadersView, baseOffset, COFF_SECTION_HEADER_FIELDS.SizeOfRawData),
      pointerToRawData: readCoffField(sectionHeadersView, baseOffset, COFF_SECTION_HEADER_FIELDS.PointerToRawData),
      pointerToRelocations: readCoffField(
        sectionHeadersView,
        baseOffset,
        COFF_SECTION_HEADER_FIELDS.PointerToRelocations
      ),
      pointerToLinenumbers: readCoffField(
        sectionHeadersView,
        baseOffset,
        COFF_SECTION_HEADER_FIELDS.PointerToLinenumbers
      ),
      numberOfRelocations: readCoffField(
        sectionHeadersView,
        baseOffset,
        COFF_SECTION_HEADER_FIELDS.NumberOfRelocations
      ),
      numberOfLinenumbers: readCoffField(
        sectionHeadersView,
        baseOffset,
        COFF_SECTION_HEADER_FIELDS.NumberOfLinenumbers
      ),
      characteristics: readCoffField(sectionHeadersView, baseOffset, COFF_SECTION_HEADER_FIELDS.Characteristics)
    },
    ...(resolvedName.warning ? { warning: resolvedName.warning } : {})
  };
};

export const parseCoffSectionHeaders = async (
  reader: FileRangeReader,
  optionalHeaderOffset: number,
  sizeOfOptionalHeader: number,
  numberOfSections: number,
  pointerToSymbolTable = 0,
  numberOfSymbols = 0
): Promise<CoffSectionHeaderParseResult> => {
  const sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const safeSectionCount = numberOfSections >>> 0;
  const coffStringTable = await createCoffStringTableResolver(
    reader,
    pointerToSymbolTable,
    numberOfSymbols
  );
  const sectionHeadersView = await reader.read(
    sectionHeadersOffset,
    safeSectionCount * COFF_SECTION_HEADER_BYTE_LENGTH
  );
  const warnings = coffStringTable.warning ? [coffStringTable.warning] : [];
  if (sectionHeadersView.byteLength < safeSectionCount * COFF_SECTION_HEADER_BYTE_LENGTH) {
    warnings.push("Section header table is truncated by end of file.");
  }
  const readableSectionCount = Math.min(
    safeSectionCount,
    Math.floor(sectionHeadersView.byteLength / COFF_SECTION_HEADER_BYTE_LENGTH)
  );
  const parsedHeaders = await Promise.all(
    Array.from({ length: readableSectionCount }, (_, sectionIndex) => readSectionHeader(
      sectionHeadersView,
      sectionIndex * COFF_SECTION_HEADER_BYTE_LENGTH,
      coffStringTable.resolver
    ))
  );
  warnings.push(...parsedHeaders.flatMap(({ warning }) => warning ? [warning] : []));
  return {
    sections: parsedHeaders.map(({ section }) => section),
    sectionHeadersOffset,
    rawNames: parsedHeaders.map(({ rawName }) => rawName),
    ...(coffStringTable.readableSize != null ? { coffStringTableSize: coffStringTable.readableSize } : {}),
    ...(warnings.length ? { warnings } : {})
  };
};
