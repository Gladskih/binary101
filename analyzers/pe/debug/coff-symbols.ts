"use strict";

import { readAsciiString } from "../../../binary-utils.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import { COFF_STORAGE_CLASS } from "./coff-storage-classes.js";
import { createCoffDebugStringTable } from "./coff-string-table.js";
import {
  IMAGE_SYMBOL_SIZE,
  type PeCoffAuxiliaryRecord,
  type PeCoffStringTable,
  type PeCoffSymbol
} from "./coff-types.js";

export type PeCoffSymbolParseResult = {
  symbols: PeCoffSymbol[];
  stringTable: PeCoffStringTable | null;
};

const stringDecoder = new TextDecoder("utf-8", { fatal: false });

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
  stringTable: PeCoffStringTable | null,
  addWarning: (message: string) => void
): Promise<Pick<PeCoffSymbol, "name" | "nameSource" | "stringTableOffset">> => {
  if (view.getUint32(offset, true) !== 0) {
    return { name: readAsciiString(view, offset, 8), nameSource: "short" };
  }
  const stringTableOffset = view.getUint32(offset + 4, true);
  if (!stringTable) {
    addWarning(`COFF symbol name offset /${stringTableOffset} cannot be resolved without a string table.`);
    return { name: `/${stringTableOffset}`, nameSource: "unresolved", stringTableOffset };
  }
  const resolved = await stringTable.resolve(stringTableOffset);
  if (resolved.warning) addWarning(resolved.warning);
  return { name: resolved.value, nameSource: "string-table", stringTableOffset };
};

const parseAuxRecord = (
  symbol: Pick<PeCoffSymbol, "name" | "value" | "sectionNumber" | "type" | "storageClass">,
  bytes: Uint8Array
): PeCoffAuxiliaryRecord => {
  const view = asView(bytes);
  if (
    symbol.storageClass === COFF_STORAGE_CLASS.EXTERNAL &&
    hasFunctionType(symbol.type) &&
    symbol.sectionNumber > 0
  ) {
    return {
      kind: "function-definition",
      tagIndex: view.getUint32(0, true),
      totalSize: view.getUint32(4, true),
      pointerToLineNumber: view.getUint32(8, true),
      pointerToNextFunction: view.getUint32(12, true)
    };
  }
  if (symbol.storageClass === COFF_STORAGE_CLASS.FUNCTION && (symbol.name === ".bf" || symbol.name === ".ef")) {
    return {
      kind: "begin-end-function",
      lineNumber: view.getUint16(4, true),
      pointerToNextFunction: view.getUint32(12, true)
    };
  }
  if (symbol.storageClass === COFF_STORAGE_CLASS.EXTERNAL && symbol.sectionNumber === 0 && symbol.value === 0) {
    return { kind: "weak-external", tagIndex: view.getUint32(0, true), characteristics: view.getUint32(4, true) };
  }
  if (symbol.storageClass === COFF_STORAGE_CLASS.FILE) return { kind: "file", fileName: decodeBytesToNull(bytes) };
  if (symbol.storageClass === COFF_STORAGE_CLASS.STATIC && symbol.value === 0 && symbol.sectionNumber > 0) {
    return {
      kind: "section-definition",
      length: view.getUint32(0, true),
      numberOfRelocations: view.getUint16(4, true),
      numberOfLineNumbers: view.getUint16(6, true),
      checkSum: view.getUint32(8, true),
      number: view.getUint16(12, true),
      selection: view.getUint8(14)
    };
  }
  return { kind: "raw", bytes: [...bytes] };
};

const parseSymbol = async (
  view: DataView,
  offset: number,
  index: number,
  stringTable: PeCoffStringTable | null,
  addWarning: (message: string) => void
): Promise<Omit<PeCoffSymbol, "auxiliaryRecords">> => ({
  index,
  ...await resolveSymbolName(view, offset, stringTable, addWarning),
  value: view.getUint32(offset + 8, true),
  sectionNumber: view.getInt16(offset + 12, true),
  type: view.getUint16(offset + 14, true),
  storageClass: view.getUint8(offset + 16),
  auxiliarySymbolCount: view.getUint8(offset + 17)
});

const parseSymbolTableBytes = async (
  reader: FileRangeReader,
  symbolTableOffset: number,
  wholeRecordBytes: number,
  stringTable: PeCoffStringTable | null,
  addWarning: (message: string) => void
): Promise<PeCoffSymbol[]> => {
  const view = await reader.read(symbolTableOffset, wholeRecordBytes);
  const symbols: PeCoffSymbol[] = [];
  for (let index = 0; index < wholeRecordBytes / IMAGE_SYMBOL_SIZE;) {
    const offset = index * IMAGE_SYMBOL_SIZE;
    const base = await parseSymbol(view, offset, index, stringTable, addWarning);
    const remainingRecords = wholeRecordBytes / IMAGE_SYMBOL_SIZE - index - 1;
    const auxCount = Math.min(base.auxiliarySymbolCount, remainingRecords);
    const auxiliaryRecords = Array.from({ length: auxCount }, (_, auxIndex) => {
      const auxOffset = offset + (auxIndex + 1) * IMAGE_SYMBOL_SIZE;
      return parseAuxRecord(base, new Uint8Array(view.buffer, view.byteOffset + auxOffset, IMAGE_SYMBOL_SIZE));
    });
    if (auxCount < base.auxiliarySymbolCount) {
      addWarning(`COFF symbol #${index} auxiliary records are truncated.`);
    }
    symbols.push({ ...base, auxiliaryRecords });
    index += 1 + auxCount;
  }
  return symbols;
};

export const parseCoffSymbols = async (
  reader: FileRangeReader,
  symbolTableOffset: number,
  numberOfSymbols: number,
  addWarning: (message: string) => void
): Promise<PeCoffSymbolParseResult> => {
  const requestedBytes = numberOfSymbols * IMAGE_SYMBOL_SIZE;
  if (!Number.isSafeInteger(requestedBytes) || symbolTableOffset + requestedBytes < symbolTableOffset) {
    addWarning("COFF symbol table size overflows JavaScript's safe integer range.");
    return { symbols: [], stringTable: null };
  }
  const availableBytes = Math.min(requestedBytes, Math.max(0, reader.size - symbolTableOffset));
  if (availableBytes < requestedBytes) addWarning("COFF symbol table is truncated.");
  const wholeRecordBytes = Math.floor(availableBytes / IMAGE_SYMBOL_SIZE) * IMAGE_SYMBOL_SIZE;
  const stringTableOffset = symbolTableOffset + requestedBytes;
  const stringTable = await createCoffDebugStringTable(reader, stringTableOffset, addWarning);
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
