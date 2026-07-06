"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { CoffFileHeader } from "./types.js";
import {
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_FILE_HEADER_FIELDS,
  readCoffField
} from "./layout.js";

export const readCoffFileHeaderFields = (
  headerView: DataView,
  headerOffset: number
): CoffFileHeader => ({
  Machine: readCoffField(headerView, headerOffset, COFF_FILE_HEADER_FIELDS.Machine),
  NumberOfSections: readCoffField(headerView, headerOffset, COFF_FILE_HEADER_FIELDS.NumberOfSections),
  TimeDateStamp: readCoffField(headerView, headerOffset, COFF_FILE_HEADER_FIELDS.TimeDateStamp),
  PointerToSymbolTable: readCoffField(
    headerView,
    headerOffset,
    COFF_FILE_HEADER_FIELDS.PointerToSymbolTable
  ),
  NumberOfSymbols: readCoffField(headerView, headerOffset, COFF_FILE_HEADER_FIELDS.NumberOfSymbols),
  SizeOfOptionalHeader: readCoffField(
    headerView,
    headerOffset,
    COFF_FILE_HEADER_FIELDS.SizeOfOptionalHeader
  ),
  Characteristics: readCoffField(headerView, headerOffset, COFF_FILE_HEADER_FIELDS.Characteristics)
});

export const parseCoffFileHeaderAt = async (
  reader: FileRangeReader,
  offset: number
): Promise<CoffFileHeader | null> => {
  const headerView = await reader.read(offset, COFF_FILE_HEADER_BYTE_LENGTH);
  return headerView.byteLength < COFF_FILE_HEADER_BYTE_LENGTH
    ? null
    : readCoffFileHeaderFields(headerView, 0);
};
