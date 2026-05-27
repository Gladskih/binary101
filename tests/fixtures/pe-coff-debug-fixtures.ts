"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

// Microsoft PE/COFF IMAGE_SYMBOL records are fixed 18-byte entries.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
export const IMAGE_SYMBOL_SIZE = 18;
// Microsoft PE/COFF line-number records are fixed 6-byte entries.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-line-numbers-deprecated
export const IMAGE_LINENUMBER_SIZE = 6;
// Microsoft IMAGE_COFF_SYMBOLS_HEADER is eight DWORDs.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_coff_symbols_header
export const IMAGE_COFF_SYMBOLS_HEADER_SIZE = 32;
// Microsoft PE/COFF storage-class values used by the test fixtures.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#storage-class
export const TEST_COFF_STORAGE_CLASS = {
  AUTOMATIC: 1,
  EXTERNAL: 2,
  STATIC: 3,
  FUNCTION: 101,
  FILE: 103
} as const;

// Microsoft COFF line-number records store a 4-byte Type union followed by a
// 2-byte Linenumber. The first record in a function uses Linenumber 0 to point
// at the symbol-table index; later records use virtual addresses plus line numbers.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-line-numbers-deprecated
export const TEST_COFF_LINE_NUMBERS = [
  { symbolTableIndexOrVirtualAddress: 1, lineNumber: 0 },
  { symbolTableIndexOrVirtualAddress: 0x1010, lineNumber: 42 }
] as const;

export type CoffSymbolInput = {
  name: string;
  value?: number;
  sectionNumber?: number;
  type?: number;
  storageClass?: number;
  auxRecords?: Uint8Array[];
};

export const writeU16 = (bytes: Uint8Array, offset: number, value: number): void =>
  new DataView(bytes.buffer).setUint16(offset, value, true);

export const writeI16 = (bytes: Uint8Array, offset: number, value: number): void =>
  new DataView(bytes.buffer).setInt16(offset, value, true);

export const writeU32 = (bytes: Uint8Array, offset: number, value: number): void =>
  new DataView(bytes.buffer).setUint32(offset, value, true);

const createStringTable = (names: string[]): { bytes: Uint8Array; offsets: Map<string, number> } => {
  const encoder = new TextEncoder();
  const encodedNames = names.map(name => ({ name, bytes: encoder.encode(`${name}\0`) }));
  const size = 4 + encodedNames.reduce((sum, entry) => sum + entry.bytes.length, 0);
  const bytes = new Uint8Array(size);
  const offsets = new Map<string, number>();
  writeU32(bytes, 0, size);
  let cursor = 4;
  encodedNames.forEach(entry => {
    offsets.set(entry.name, cursor);
    bytes.set(entry.bytes, cursor);
    cursor += entry.bytes.length;
  });
  return { bytes, offsets };
};

const writeSymbol = (
  bytes: Uint8Array,
  offset: number,
  symbol: CoffSymbolInput,
  stringOffsets: Map<string, number>
): void => {
  if (symbol.name.length <= 8) {
    bytes.set(new TextEncoder().encode(symbol.name), offset);
  } else {
    writeU32(bytes, offset + 4, expectDefined(stringOffsets.get(symbol.name)));
  }
  writeU32(bytes, offset + 8, symbol.value ?? 0);
  writeI16(bytes, offset + 12, symbol.sectionNumber ?? 1);
  writeU16(bytes, offset + 14, symbol.type ?? 0);
  bytes[offset + 16] = symbol.storageClass ?? TEST_COFF_STORAGE_CLASS.EXTERNAL;
  bytes[offset + 17] = symbol.auxRecords?.length ?? 0;
};

export const createSymbolTable = (
  symbols: CoffSymbolInput[],
  stringNames: string[]
): { bytes: Uint8Array; recordCount: number } => {
  const stringTable = createStringTable(stringNames);
  const recordCount = symbols.reduce((sum, symbol) => sum + 1 + (symbol.auxRecords?.length ?? 0), 0);
  const bytes = new Uint8Array(recordCount * IMAGE_SYMBOL_SIZE + stringTable.bytes.length);
  let cursor = 0;
  symbols.forEach(symbol => {
    writeSymbol(bytes, cursor, symbol, stringTable.offsets);
    cursor += IMAGE_SYMBOL_SIZE;
    symbol.auxRecords?.forEach(auxRecord => {
      bytes.set(auxRecord, cursor);
      cursor += IMAGE_SYMBOL_SIZE;
    });
  });
  bytes.set(stringTable.bytes, cursor);
  return { bytes, recordCount };
};

export const createFileAuxRecord = (fileName: string): Uint8Array => {
  const bytes = new Uint8Array(IMAGE_SYMBOL_SIZE);
  bytes.set(new TextEncoder().encode(fileName));
  return bytes;
};

export const createFunctionAuxRecord = (): Uint8Array => {
  const bytes = new Uint8Array(IMAGE_SYMBOL_SIZE);
  // Microsoft auxiliary format 1: TagIndex, TotalSize, PointerToLinenumber,
  // and PointerToNextFunction are DWORDs at offsets 0, 4, 8, and 12.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-1-function-definitions
  writeU32(bytes, 0, 2);
  writeU32(bytes, 4, 0x30);
  writeU32(bytes, 8, 0x200);
  writeU32(bytes, 12, 0);
  return bytes;
};

export const createAuxRecord = (): Uint8Array => new Uint8Array(IMAGE_SYMBOL_SIZE);

export const createLineNumbers = (): Uint8Array => {
  const bytes = new Uint8Array(TEST_COFF_LINE_NUMBERS.length * IMAGE_LINENUMBER_SIZE);
  TEST_COFF_LINE_NUMBERS.forEach((record, index) => {
    const offset = index * IMAGE_LINENUMBER_SIZE;
    writeU32(bytes, offset, record.symbolTableIndexOrVirtualAddress);
    writeU16(bytes, offset + Uint32Array.BYTES_PER_ELEMENT, record.lineNumber);
  });
  return bytes;
};

export const createOffsetFile = (payload: Uint8Array): MockFile => {
  const bytes = new Uint8Array(payload.length + 1);
  bytes.set(payload, 1);
  return new MockFile(bytes);
};
