"use strict";

import {
  COFF_AUX_FUNCTION_DEFINITION_FIELDS,
  COFF_LINE_NUMBER_FIELDS,
  COFF_LINE_NUMBER_RECORD_BYTE_LENGTH,
  COFF_SHORT_NAME_BYTE_LENGTH,
  COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH,
  COFF_SYMBOL_FIELDS,
  COFF_SYMBOL_NAME_FIELDS,
  COFF_SYMBOL_RECORD_BYTE_LENGTH,
  type CoffNumericField
} from "../../analyzers/coff/layout.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { createPePlusWithSection } from "./sample-files-pe.js";

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

const writeCoffField = (
  bytes: Uint8Array,
  recordOffset: number,
  field: CoffNumericField,
  value: number
): void => {
  const view = new DataView(bytes.buffer);
  const offset = recordOffset + field.offset;
  if (field.width === "u8") {
    view.setUint8(offset, value);
    return;
  }
  if (field.width === "u16") {
    view.setUint16(offset, value, true);
    return;
  }
  if (field.width === "i16") {
    view.setInt16(offset, value, true);
    return;
  }
  view.setUint32(offset, value, true);
};

const createStringTable = (names: string[]): { bytes: Uint8Array; offsets: Map<string, number> } => {
  const encoder = new TextEncoder();
  const encodedNames = names.map(name => ({ name, bytes: encoder.encode(`${name}\0`) }));
  const size = COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH +
    encodedNames.reduce((sum, entry) => sum + entry.bytes.length, 0);
  const bytes = new Uint8Array(size);
  const offsets = new Map<string, number>();
  writeU32(bytes, 0, size);
  let cursor = COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH;
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
  if (symbol.name.length <= COFF_SHORT_NAME_BYTE_LENGTH) {
    bytes.set(new TextEncoder().encode(symbol.name), offset);
  } else {
    writeCoffField(
      bytes,
      offset,
      COFF_SYMBOL_NAME_FIELDS.StringTableOffset,
      expectDefined(stringOffsets.get(symbol.name))
    );
  }
  writeCoffField(bytes, offset, COFF_SYMBOL_FIELDS.Value, symbol.value ?? 0);
  writeCoffField(bytes, offset, COFF_SYMBOL_FIELDS.SectionNumber, symbol.sectionNumber ?? 1);
  writeCoffField(bytes, offset, COFF_SYMBOL_FIELDS.Type, symbol.type ?? 0);
  writeCoffField(
    bytes,
    offset,
    COFF_SYMBOL_FIELDS.StorageClass,
    symbol.storageClass ?? TEST_COFF_STORAGE_CLASS.EXTERNAL
  );
  writeCoffField(bytes, offset, COFF_SYMBOL_FIELDS.NumberOfAuxSymbols, symbol.auxRecords?.length ?? 0);
};

export const createSymbolTable = (
  symbols: CoffSymbolInput[],
  stringNames: string[]
): { bytes: Uint8Array; recordCount: number } => {
  const stringTable = createStringTable(stringNames);
  const recordCount = symbols.reduce((sum, symbol) => sum + 1 + (symbol.auxRecords?.length ?? 0), 0);
  const bytes = new Uint8Array(recordCount * COFF_SYMBOL_RECORD_BYTE_LENGTH + stringTable.bytes.length);
  let cursor = 0;
  symbols.forEach(symbol => {
    writeSymbol(bytes, cursor, symbol, stringTable.offsets);
    cursor += COFF_SYMBOL_RECORD_BYTE_LENGTH;
    symbol.auxRecords?.forEach(auxRecord => {
      bytes.set(auxRecord, cursor);
      cursor += COFF_SYMBOL_RECORD_BYTE_LENGTH;
    });
  });
  bytes.set(stringTable.bytes, cursor);
  return { bytes, recordCount };
};

export const createFileAuxRecord = (fileName: string): Uint8Array => {
  const bytes = new Uint8Array(COFF_SYMBOL_RECORD_BYTE_LENGTH);
  bytes.set(new TextEncoder().encode(fileName));
  return bytes;
};

export const createFunctionAuxRecord = (): Uint8Array => {
  const bytes = new Uint8Array(COFF_SYMBOL_RECORD_BYTE_LENGTH);
  writeCoffField(bytes, 0, COFF_AUX_FUNCTION_DEFINITION_FIELDS.TagIndex, 2);
  writeCoffField(bytes, 0, COFF_AUX_FUNCTION_DEFINITION_FIELDS.TotalSize, 0x30);
  writeCoffField(bytes, 0, COFF_AUX_FUNCTION_DEFINITION_FIELDS.PointerToLineNumber, 0x200);
  writeCoffField(bytes, 0, COFF_AUX_FUNCTION_DEFINITION_FIELDS.PointerToNextFunction, 0);
  return bytes;
};

export const createAuxRecord = (): Uint8Array => new Uint8Array(COFF_SYMBOL_RECORD_BYTE_LENGTH);

export const createLineNumbers = (): Uint8Array => {
  const bytes = new Uint8Array(TEST_COFF_LINE_NUMBERS.length * COFF_LINE_NUMBER_RECORD_BYTE_LENGTH);
  TEST_COFF_LINE_NUMBERS.forEach((record, index) => {
    const offset = index * COFF_LINE_NUMBER_RECORD_BYTE_LENGTH;
    writeCoffField(
      bytes,
      offset,
      COFF_LINE_NUMBER_FIELDS.SymbolTableIndexOrVirtualAddress,
      record.symbolTableIndexOrVirtualAddress
    );
    writeCoffField(bytes, offset, COFF_LINE_NUMBER_FIELDS.LineNumber, record.lineNumber);
  });
  return bytes;
};

export const createOffsetFile = (payload: Uint8Array): MockFile => {
  const bytes = new Uint8Array(payload.length + 1);
  bytes.set(payload, 1);
  return new MockFile(bytes);
};

export const createLargePeLegacyCoffSymbolFile = (symbolCount = 251): MockFile => {
  const image = createPePlusWithSection();
  const symbolTable = createSymbolTable(
    Array.from({ length: symbolCount }, (_, index) => ({ name: `sym${index}` })),
    []
  );
  const bytes = new Uint8Array(image.length + symbolTable.bytes.length);
  bytes.set(image);
  bytes.set(symbolTable.bytes, image.length);

  const peHeaderOffset = 0x40;
  const coffOffset = peHeaderOffset + Uint32Array.BYTES_PER_ELEMENT;
  const view = new DataView(bytes.buffer);
  view.setUint32(coffOffset + 8, image.length, true);
  view.setUint32(coffOffset + 12, symbolTable.recordCount, true);

  return new MockFile(
    bytes,
    "large-coff-symbols.exe",
    "application/vnd.microsoft.portable-executable"
  );
};
