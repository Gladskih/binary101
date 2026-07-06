"use strict";

import { DEFAULT_FILE_READ_WINDOW_BYTES, type FileRangeReader } from "../file-range-reader.js";
import { coffSectionNameValue } from "./section-name.js";
import type { CoffRelocation, CoffRelocationBlock, CoffSection } from "./types.js";
import {
  COFF_RELOCATION_EXTENDED_COUNT_SENTINEL,
  COFF_RELOCATION_FIELDS,
  COFF_RELOCATION_RECORD_BYTE_LENGTH,
  COFF_SECTION_CHARACTERISTICS,
  readCoffField
} from "./layout.js";

// Internal I/O policy, not a PE/COFF format value: keep each sparse relocation
// read within FileRangeReader's measured cache window.
const RELOCATION_READ_CHUNK_RECORD_COUNT = Math.max(
  1,
  Math.floor(DEFAULT_FILE_READ_WINDOW_BYTES / COFF_RELOCATION_RECORD_BYTE_LENGTH)
);

type RelocationRecordSpan = {
  startOffset: number;
  recordCount: number;
  extendedRelocationCount?: number;
};

const addBlockWarning = (
  warnings: string[],
  addWarning: (message: string) => void,
  message: string
): void => {
  warnings.push(message);
  addWarning(message);
};

const buildRelocationBlock = (
  section: CoffSection,
  sectionIndex: number,
  offset: number,
  records: CoffRelocation[],
  warnings: string[],
  extendedRelocationCount?: number
): CoffRelocationBlock => ({
  offset,
  sectionIndex,
  sectionName: coffSectionNameValue(section.name),
  records,
  ...(extendedRelocationCount != null ? { extendedRelocationCount } : {}),
  ...(warnings.length ? { warnings } : {})
});

const parseRelocationRecord = (view: DataView, recordOffset: number, index: number): CoffRelocation => ({
  index,
  virtualAddress: readCoffField(view, recordOffset, COFF_RELOCATION_FIELDS.VirtualAddress),
  symbolTableIndex: readCoffField(view, recordOffset, COFF_RELOCATION_FIELDS.SymbolTableIndex),
  type: readCoffField(view, recordOffset, COFF_RELOCATION_FIELDS.Type)
});

const parseRelocationChunk = (view: DataView, firstRecordIndex: number): CoffRelocation[] =>
  Array.from(
    { length: Math.floor(view.byteLength / COFF_RELOCATION_RECORD_BYTE_LENGTH) },
    (_, chunkIndex) => parseRelocationRecord(
      view,
      chunkIndex * COFF_RELOCATION_RECORD_BYTE_LENGTH,
      firstRecordIndex + chunkIndex
    )
  );

const parseRelocationRecords = async (
  reader: FileRangeReader,
  startOffset: number,
  recordCount: number
): Promise<CoffRelocation[]> => {
  const chunkStarts = Array.from(
    { length: Math.ceil(recordCount / RELOCATION_READ_CHUNK_RECORD_COUNT) },
    (_, chunkIndex) => chunkIndex * RELOCATION_READ_CHUNK_RECORD_COUNT
  );
  const chunks = await chunkStarts.reduce<Promise<CoffRelocation[][]>>(async (pendingChunks, index) => {
    const parsedChunks = await pendingChunks;
    const chunkCount = Math.min(RELOCATION_READ_CHUNK_RECORD_COUNT, recordCount - index);
    const view = await reader.read(
      startOffset + index * COFF_RELOCATION_RECORD_BYTE_LENGTH,
      chunkCount * COFF_RELOCATION_RECORD_BYTE_LENGTH
    );
    return [...parsedChunks, parseRelocationChunk(view, index)];
  }, Promise.resolve([]));
  return chunks.flat();
};

const getReadableRelocationCount = (
  reader: FileRangeReader,
  startOffset: number,
  recordCount: number
): number =>
  Math.min(
    recordCount,
    Math.max(0, Math.floor((reader.size - startOffset) / COFF_RELOCATION_RECORD_BYTE_LENGTH))
  );

const readExtendedRelocationSpan = async (
  reader: FileRangeReader,
  offset: number,
  warnings: string[],
  addWarning: (message: string) => void
): Promise<RelocationRecordSpan | null> => {
  const marker = await reader.read(offset, COFF_RELOCATION_RECORD_BYTE_LENGTH);
  if (marker.byteLength < COFF_RELOCATION_RECORD_BYTE_LENGTH) {
    addBlockWarning(warnings, addWarning, "COFF extended relocation count record is truncated.");
    return null;
  }
  const extendedRelocationCount = readCoffField(marker, 0, COFF_RELOCATION_FIELDS.VirtualAddress);
  if (extendedRelocationCount === 0) {
    addBlockWarning(warnings, addWarning, "COFF extended relocation count is zero.");
  }
  return {
    startOffset: offset + COFF_RELOCATION_RECORD_BYTE_LENGTH,
    recordCount: Math.max(0, extendedRelocationCount - 1),
    extendedRelocationCount
  };
};

const getRelocationSpan = async (
  reader: FileRangeReader,
  section: CoffSection,
  offset: number,
  count: number,
  warnings: string[],
  addWarning: (message: string) => void
): Promise<RelocationRecordSpan | null> => {
  const hasExtendedFlag = (section.characteristics & COFF_SECTION_CHARACTERISTICS.LNK_NRELOC_OVFL) !== 0;
  if (!hasExtendedFlag) return { startOffset: offset, recordCount: count };
  if (count !== COFF_RELOCATION_EXTENDED_COUNT_SENTINEL) {
    addBlockWarning(
      warnings,
      addWarning,
      "COFF section has extended relocation flag without the 0xffff relocation count sentinel."
    );
    return { startOffset: offset, recordCount: count };
  }
  return readExtendedRelocationSpan(reader, offset, warnings, addWarning);
};

const parseSectionRelocations = async (
  reader: FileRangeReader,
  section: CoffSection,
  sectionIndex: number,
  addWarning: (message: string) => void
): Promise<CoffRelocationBlock | null> => {
  const count = section.numberOfRelocations ?? 0;
  const offset = section.pointerToRelocations ?? 0;
  const warnings: string[] = [];
  if (count === 0 && offset === 0) return null;
  if (count === 0) {
    addBlockWarning(warnings, addWarning, "COFF section relocation pointer is set but count is 0.");
    return buildRelocationBlock(section, sectionIndex, offset, [], warnings);
  }
  if (offset === 0) {
    addBlockWarning(warnings, addWarning, "COFF section relocation count is set but pointer is 0.");
    return buildRelocationBlock(section, sectionIndex, offset, [], warnings);
  }
  if (offset >= reader.size) {
    addBlockWarning(warnings, addWarning, "COFF relocation table starts past end of file.");
    return buildRelocationBlock(section, sectionIndex, offset, [], warnings);
  }
  const span = await getRelocationSpan(reader, section, offset, count, warnings, addWarning);
  if (!span) return buildRelocationBlock(section, sectionIndex, offset, [], warnings);
  const readableCount = getReadableRelocationCount(reader, span.startOffset, span.recordCount);
  if (readableCount < span.recordCount) {
    addBlockWarning(warnings, addWarning, "COFF relocation table is truncated.");
  }
  return buildRelocationBlock(
    section,
    sectionIndex,
    offset,
    await parseRelocationRecords(reader, span.startOffset, readableCount),
    warnings,
    span.extendedRelocationCount
  );
};

export const parseCoffRelocations = async (
  reader: FileRangeReader,
  sections: CoffSection[],
  addWarning: (message: string) => void
): Promise<CoffRelocationBlock[]> => {
  const blocks = await Promise.all(
    sections.map((section, index) => parseSectionRelocations(reader, section, index + 1, addWarning))
  );
  return blocks.filter((block): block is CoffRelocationBlock => block != null);
};
