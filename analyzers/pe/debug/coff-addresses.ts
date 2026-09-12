"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import { mappedRvaSpan } from "../rva-mapping.js";
import { createRvaRangeReader } from "../rva-range-reader.js";
import { COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH } from "../../coff/layout.js";

export type CoffTableReader = {
  reader: FileRangeReader;
  offset: number;
  toFileOffset: (offset: number) => number | null;
};

const isReaderOffset = (reader: FileRangeReader, offset: number): boolean =>
  Number.isSafeInteger(offset) && offset >= 0 && offset < reader.size;

const fileTableReader = (reader: FileRangeReader, offset: number): CoffTableReader | null =>
  isReaderOffset(reader, offset) ? {
    reader, offset,
    toFileOffset: position => isReaderOffset(reader, position) ? position : null
  } : null;

const mappedTableReader = (
  reader: FileRangeReader, rvaToOff: RvaToOffset, rva: number
): CoffTableReader | null => {
  if (!mappedRvaSpan(rvaToOff, rva, 1, reader.size)) return null;
  const window = createRvaRangeReader(reader, rvaToOff, rva, PE_RVA_EXCLUSIVE_LIMIT - rva);
  return {
    reader: window,
    offset: 0,
    toFileOffset: offset => isReaderOffset(window, offset)
      ? mappedRvaSpan(rvaToOff, rva + offset, 1, reader.size)?.offset ?? null
      : null
  };
};

export const resolveCoffTableReader = (
  reader: FileRangeReader, rvaToOff: RvaToOffset, addressOfRawDataRva: number,
  pointerToRawDataOff: number, dataSize: number, lva: number, minimumBytes: number
): CoffTableReader | null => {
  // Preserve the supported payload-relative and RVA forms of COFF LVA fields.
  // Each table has its own reader: a relative table offset must never become a file offset.
  // Classify against declared SizeOfData, so truncation cannot reinterpret a relative LVA.
  const relativeOffset = [lva, addressOfRawDataRva ? lva - addressOfRawDataRva : null]
    .find(offset => offset != null && offset >= 0 &&
      offset + Math.min(minimumBytes, 1) <= dataSize);
  if (relativeOffset != null) {
    return pointerToRawDataOff
      ? fileTableReader(reader, pointerToRawDataOff + relativeOffset)
      : mappedTableReader(reader, rvaToOff, addressOfRawDataRva + relativeOffset);
  }
  if (lva) return mappedTableReader(reader, rvaToOff, lva);
  return pointerToRawDataOff
    ? fileTableReader(reader, pointerToRawDataOff + COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH)
    : mappedTableReader(reader, rvaToOff, addressOfRawDataRva + COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH);
};
