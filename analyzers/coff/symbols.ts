"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { COFF_STORAGE_CLASS } from "./storage-classes.js";
import { createCoffDebugStringTable } from "./debug-string-table.js";
import {
  type CoffAuxiliaryRecord,
  type CoffStringTable,
  type CoffSymbol
} from "./debug-types.js";
import {
  COFF_AUX_BEGIN_END_FUNCTION_FIELDS,
  COFF_AUX_FUNCTION_DEFINITION_FIELDS,
  COFF_AUX_SECTION_DEFINITION_FIELDS,
  COFF_AUX_WEAK_EXTERNAL_FIELDS,
  COFF_SHORT_NAME_BYTE_LENGTH,
  COFF_SYMBOL_FIELDS,
  COFF_SYMBOL_NAME_FIELDS,
  COFF_SYMBOL_RECORD_BYTE_LENGTH,
  readCoffField
} from "./layout.js";

export type CoffSymbolParseResult = {
  symbols: CoffSymbol[];
  stringTable: CoffStringTable | null;
};

const stringDecoder = new TextDecoder("utf-8");

// Microsoft PE/COFF symbol Type encodes the derived type in bits 4..5;
// derived type value 2 means function.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#type-representation
const hasFunctionType = (type: number): boolean => ((type >>> 4) & 0x3) === 2;

const asView = (bytes: Uint8Array): DataView =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

const decodeBytesToNull = (bytes: Uint8Array): string => {
  const zeroIndex = bytes.indexOf(0);
  return stringDecoder.decode(bytes.subarray(0, zeroIndex === -1 ? bytes.length : zeroIndex));
};

const resolveSymbolName = async (
  view: DataView,
  offset: number,
  stringTable: CoffStringTable | null,
  addWarning: (message: string) => void
): Promise<Pick<CoffSymbol, "name" | "nameSource" | "stringTableOffset">> => {
  if (readCoffField(view, offset, COFF_SYMBOL_NAME_FIELDS.ShortNameOrZeroes) !== 0) {
    return { name: readAsciiString(view, offset, COFF_SHORT_NAME_BYTE_LENGTH), nameSource: "short" };
  }
  const stringTableOffset = readCoffField(view, offset, COFF_SYMBOL_NAME_FIELDS.StringTableOffset);
  if (!stringTable) {
    addWarning(`COFF symbol name offset /${stringTableOffset} cannot be resolved without a string table.`);
    return { name: `/${stringTableOffset}`, nameSource: "unresolved", stringTableOffset };
  }
  const resolved = await stringTable.resolve(stringTableOffset);
  if (resolved.warning) addWarning(resolved.warning);
  return { name: resolved.value, nameSource: "string-table", stringTableOffset };
};

const parseAuxRecord = (
  symbol: Pick<CoffSymbol, "name" | "value" | "sectionNumber" | "type" | "storageClass">,
  bytes: Uint8Array
): CoffAuxiliaryRecord => {
  const view = asView(bytes);
  if (
    symbol.storageClass === COFF_STORAGE_CLASS.EXTERNAL &&
    hasFunctionType(symbol.type) &&
    symbol.sectionNumber > 0
  ) {
    return {
      kind: "function-definition",
      tagIndex: readCoffField(view, 0, COFF_AUX_FUNCTION_DEFINITION_FIELDS.TagIndex),
      totalSize: readCoffField(view, 0, COFF_AUX_FUNCTION_DEFINITION_FIELDS.TotalSize),
      pointerToLineNumber: readCoffField(view, 0, COFF_AUX_FUNCTION_DEFINITION_FIELDS.PointerToLineNumber),
      pointerToNextFunction: readCoffField(view, 0, COFF_AUX_FUNCTION_DEFINITION_FIELDS.PointerToNextFunction)
    };
  }
  if (symbol.storageClass === COFF_STORAGE_CLASS.FUNCTION && (symbol.name === ".bf" || symbol.name === ".ef")) {
    return {
      kind: "begin-end-function",
      lineNumber: readCoffField(view, 0, COFF_AUX_BEGIN_END_FUNCTION_FIELDS.LineNumber),
      pointerToNextFunction: readCoffField(view, 0, COFF_AUX_BEGIN_END_FUNCTION_FIELDS.PointerToNextFunction)
    };
  }
  if (symbol.storageClass === COFF_STORAGE_CLASS.EXTERNAL && symbol.sectionNumber === 0 && symbol.value === 0) {
    return {
      kind: "weak-external",
      tagIndex: readCoffField(view, 0, COFF_AUX_WEAK_EXTERNAL_FIELDS.TagIndex),
      characteristics: readCoffField(view, 0, COFF_AUX_WEAK_EXTERNAL_FIELDS.Characteristics)
    };
  }
  if (symbol.storageClass === COFF_STORAGE_CLASS.FILE) return { kind: "file", fileName: decodeBytesToNull(bytes) };
  if (symbol.storageClass === COFF_STORAGE_CLASS.STATIC && symbol.value === 0 && symbol.sectionNumber > 0) {
    return {
      kind: "section-definition",
      length: readCoffField(view, 0, COFF_AUX_SECTION_DEFINITION_FIELDS.Length),
      numberOfRelocations: readCoffField(view, 0, COFF_AUX_SECTION_DEFINITION_FIELDS.NumberOfRelocations),
      numberOfLineNumbers: readCoffField(view, 0, COFF_AUX_SECTION_DEFINITION_FIELDS.NumberOfLineNumbers),
      checkSum: readCoffField(view, 0, COFF_AUX_SECTION_DEFINITION_FIELDS.CheckSum),
      number: readCoffField(view, 0, COFF_AUX_SECTION_DEFINITION_FIELDS.Number),
      selection: readCoffField(view, 0, COFF_AUX_SECTION_DEFINITION_FIELDS.Selection)
    };
  }
  return { kind: "raw", bytes: [...bytes] };
};

const parseSymbol = async (
  view: DataView,
  offset: number,
  index: number,
  stringTable: CoffStringTable | null,
  addWarning: (message: string) => void
): Promise<Omit<CoffSymbol, "auxiliaryRecords">> => ({
  index,
  ...await resolveSymbolName(view, offset, stringTable, addWarning),
  value: readCoffField(view, offset, COFF_SYMBOL_FIELDS.Value),
  sectionNumber: readCoffField(view, offset, COFF_SYMBOL_FIELDS.SectionNumber),
  type: readCoffField(view, offset, COFF_SYMBOL_FIELDS.Type),
  storageClass: readCoffField(view, offset, COFF_SYMBOL_FIELDS.StorageClass),
  auxiliarySymbolCount: readCoffField(view, offset, COFF_SYMBOL_FIELDS.NumberOfAuxSymbols)
});

const parseSymbolTableBytes = async (
  reader: FileRangeReader,
  symbolTableOffset: number,
  wholeRecordBytes: number,
  stringTable: CoffStringTable | null,
  addWarning: (message: string) => void
): Promise<CoffSymbol[]> => {
  const view = await reader.read(symbolTableOffset, wholeRecordBytes);
  const recordCount = wholeRecordBytes / COFF_SYMBOL_RECORD_BYTE_LENGTH;
  // This local mutable accumulator is deliberate: on LatticeLab.exe
  // (94,947 COFF symbol records, 70,933 emitted symbols), the previous
  // immutable recursive accumulator took about 8.7 s in parseForUi by repeatedly
  // copying growing arrays; this linear pass measured about 0.21-0.28 s.
  const symbols: CoffSymbol[] = [];
  let index = 0;
  while (index < recordCount) {
    const offset = index * COFF_SYMBOL_RECORD_BYTE_LENGTH;
    const base = await parseSymbol(view, offset, index, stringTable, addWarning);
    const remainingRecords = recordCount - index - 1;
    const auxCount = Math.min(base.auxiliarySymbolCount, remainingRecords);
    const auxiliaryRecords = Array.from({ length: auxCount }, (_, auxIndex) => {
      const auxOffset = offset + (auxIndex + 1) * COFF_SYMBOL_RECORD_BYTE_LENGTH;
      return parseAuxRecord(
        base,
        new Uint8Array(view.buffer, view.byteOffset + auxOffset, COFF_SYMBOL_RECORD_BYTE_LENGTH)
      );
    });
    if (auxCount < base.auxiliarySymbolCount) {
      addWarning(`COFF symbol #${index} auxiliary records are truncated.`);
    }
    symbols[symbols.length] = { ...base, auxiliaryRecords };
    index += 1 + auxCount;
  }
  return symbols;
};

export const parseCoffSymbols = async (
  reader: FileRangeReader,
  symbolTableOffset: number,
  numberOfSymbols: number,
  addWarning: (message: string) => void
): Promise<CoffSymbolParseResult> => {
  const requestedBytes = numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  const symbolTableEnd = symbolTableOffset + requestedBytes;
  if (!Number.isSafeInteger(requestedBytes) || !Number.isSafeInteger(symbolTableEnd)) {
    addWarning("COFF symbol table size overflows JavaScript's safe integer range.");
    return { symbols: [], stringTable: null };
  }
  const availableBytes = Math.min(requestedBytes, Math.max(0, reader.size - symbolTableOffset));
  if (availableBytes < requestedBytes) addWarning("COFF symbol table is truncated.");
  const wholeRecordBytes =
    Math.floor(availableBytes / COFF_SYMBOL_RECORD_BYTE_LENGTH) * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  const stringTable = await createCoffDebugStringTable(reader, symbolTableEnd, addWarning);
  return {
    symbols: await parseSymbolTableBytes(
      reader,
      symbolTableOffset,
      wholeRecordBytes,
      stringTable,
      addWarning
    ),
    stringTable
  };
};
