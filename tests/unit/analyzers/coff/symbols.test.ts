"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  COFF_AUX_BEGIN_END_FUNCTION_FIELDS,
  COFF_AUX_FUNCTION_DEFINITION_FIELDS,
  COFF_AUX_SECTION_DEFINITION_FIELDS,
  COFF_AUX_WEAK_EXTERNAL_FIELDS,
  COFF_SHORT_NAME_BYTE_LENGTH,
  COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH,
  COFF_SYMBOL_FIELDS,
  COFF_SYMBOL_NAME_FIELDS,
  COFF_SYMBOL_RECORD_BYTE_LENGTH,
  type CoffNumericField
} from "../../../../analyzers/coff/layout.js";
import { parseCoffSymbols } from "../../../../analyzers/coff/symbols.js";
import { COFF_STORAGE_CLASS } from "../../../../analyzers/coff/storage-classes.js";
import { MockFile } from "../../../helpers/mock-file.js";

type SymbolInput = {
  name: string;
  value?: number;
  sectionNumber?: number;
  type?: number;
  storageClass: number;
  aux?: Uint8Array[];
};

const writeField = (
  view: DataView,
  recordOffset: number,
  field: CoffNumericField,
  value: number
): void => {
  const offset = recordOffset + field.offset;
  if (field.width === "u8") view.setUint8(offset, value);
  else if (field.width === "u16") view.setUint16(offset, value, true);
  else if (field.width === "i16") view.setInt16(offset, value, true);
  else view.setUint32(offset, value, true);
};

const encodeAscii = (text: string): Uint8Array =>
  Uint8Array.from([...text].map(char => char.charCodeAt(0)));

const createStringTable = (names: string[]): { bytes: Uint8Array; offsets: Map<string, number> } => {
  const encoded = names.map(name => ({ name, bytes: encodeAscii(`${name}\0`) }));
  const size = COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH +
    encoded.reduce((sum, entry) => sum + entry.bytes.length, 0);
  const bytes = new Uint8Array(size);
  new DataView(bytes.buffer).setUint32(0, size, true);
  const offsets = new Map<string, number>();
  encoded.reduce((offset, entry) => {
    offsets.set(entry.name, offset);
    bytes.set(entry.bytes, offset);
    return offset + entry.bytes.length;
  }, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  return { bytes, offsets };
};

const writeSymbol = (
  bytes: Uint8Array,
  offset: number,
  symbol: SymbolInput,
  stringOffsets: Map<string, number>
): void => {
  const view = new DataView(bytes.buffer);
  if (symbol.name.length <= COFF_SHORT_NAME_BYTE_LENGTH) {
    bytes.set(encodeAscii(symbol.name), offset);
  } else {
    writeField(view, offset, COFF_SYMBOL_NAME_FIELDS.StringTableOffset, stringOffsets.get(symbol.name) ?? 0);
  }
  writeField(view, offset, COFF_SYMBOL_FIELDS.Value, symbol.value ?? 0);
  writeField(view, offset, COFF_SYMBOL_FIELDS.SectionNumber, symbol.sectionNumber ?? 1);
  writeField(view, offset, COFF_SYMBOL_FIELDS.Type, symbol.type ?? 0);
  writeField(view, offset, COFF_SYMBOL_FIELDS.StorageClass, symbol.storageClass);
  writeField(view, offset, COFF_SYMBOL_FIELDS.NumberOfAuxSymbols, symbol.aux?.length ?? 0);
};

const createAuxRecord = (writes: Array<[CoffNumericField, number]>): Uint8Array => {
  const bytes = new Uint8Array(COFF_SYMBOL_RECORD_BYTE_LENGTH);
  const view = new DataView(bytes.buffer);
  writes.forEach(([field, value]) => writeField(view, 0, field, value));
  return bytes;
};

const createSymbolTable = (
  symbols: SymbolInput[],
  stringNames: string[] = []
): { bytes: Uint8Array; recordCount: number } => {
  const stringTable = createStringTable(stringNames);
  const recordCount = symbols.reduce((count, symbol) => count + 1 + (symbol.aux?.length ?? 0), 0);
  const bytes = new Uint8Array(recordCount * COFF_SYMBOL_RECORD_BYTE_LENGTH + stringTable.bytes.length);
  let cursor = 0;
  symbols.forEach(symbol => {
    writeSymbol(bytes, cursor, symbol, stringTable.offsets);
    cursor += COFF_SYMBOL_RECORD_BYTE_LENGTH;
    (symbol.aux ?? []).forEach(aux => {
      bytes.set(aux, cursor);
      cursor += COFF_SYMBOL_RECORD_BYTE_LENGTH;
    });
  });
  bytes.set(stringTable.bytes, cursor);
  return { bytes, recordCount };
};

void test("parseCoffSymbols decodes named auxiliary record formats", async () => {
  const fileAux = new Uint8Array(COFF_SYMBOL_RECORD_BYTE_LENGTH);
  fileAux.set(encodeAscii("main.c\0ignored"));
  const fileAuxWithoutNull = encodeAscii("abcdefghijklmnopqr");
  const functionAux = createAuxRecord([
    [COFF_AUX_FUNCTION_DEFINITION_FIELDS.TagIndex, 7],
    [COFF_AUX_FUNCTION_DEFINITION_FIELDS.TotalSize, 0x30],
    [COFF_AUX_FUNCTION_DEFINITION_FIELDS.PointerToLineNumber, 0x200],
    [COFF_AUX_FUNCTION_DEFINITION_FIELDS.PointerToNextFunction, 0x240]
  ]);
  const beginEndAux = createAuxRecord([
    [COFF_AUX_BEGIN_END_FUNCTION_FIELDS.LineNumber, 12],
    [COFF_AUX_BEGIN_END_FUNCTION_FIELDS.PointerToNextFunction, 0x300]
  ]);
  const weakAux = createAuxRecord([
    [COFF_AUX_WEAK_EXTERNAL_FIELDS.TagIndex, 3],
    [COFF_AUX_WEAK_EXTERNAL_FIELDS.Characteristics, 2]
  ]);
  const sectionAux = createAuxRecord([
    [COFF_AUX_SECTION_DEFINITION_FIELDS.Length, 0x40],
    [COFF_AUX_SECTION_DEFINITION_FIELDS.NumberOfRelocations, 5],
    [COFF_AUX_SECTION_DEFINITION_FIELDS.NumberOfLineNumbers, 6],
    [COFF_AUX_SECTION_DEFINITION_FIELDS.CheckSum, 0xabcd],
    [COFF_AUX_SECTION_DEFINITION_FIELDS.Number, 2],
    [COFF_AUX_SECTION_DEFINITION_FIELDS.Selection, 4]
  ]);
  const rawAux = Uint8Array.from({ length: COFF_SYMBOL_RECORD_BYTE_LENGTH }, (_, index) => index + 1);
  const table = createSymbolTable([
    {
      name: "long_function_name",
      sectionNumber: 1,
      type: 0x20,
      storageClass: COFF_STORAGE_CLASS.EXTERNAL,
      aux: [functionAux]
    },
    { name: ".bf", storageClass: COFF_STORAGE_CLASS.FUNCTION, aux: [beginEndAux] },
    { name: "weak", sectionNumber: 0, storageClass: COFF_STORAGE_CLASS.EXTERNAL, aux: [weakAux] },
    { name: ".file", sectionNumber: -2, storageClass: COFF_STORAGE_CLASS.FILE, aux: [fileAux] },
    { name: ".file2", sectionNumber: -2, storageClass: COFF_STORAGE_CLASS.FILE, aux: [fileAuxWithoutNull] },
    { name: ".text", storageClass: COFF_STORAGE_CLASS.STATIC, aux: [sectionAux] },
    { name: "raw", storageClass: COFF_STORAGE_CLASS.AUTOMATIC, aux: [rawAux] }
  ], ["long_function_name"]);

  const warnings: string[] = [];
  const result = await parseCoffSymbols(new MockFile(table.bytes), 0, table.recordCount, warnings.push.bind(warnings));

  assert.equal(result.symbols[0]?.name, "long_function_name");
  assert.deepEqual(result.symbols[0]?.auxiliaryRecords[0], {
    kind: "function-definition",
    tagIndex: 7,
    totalSize: 0x30,
    pointerToLineNumber: 0x200,
    pointerToNextFunction: 0x240
  });
  assert.deepEqual(result.symbols[1]?.auxiliaryRecords[0], {
    kind: "begin-end-function",
    lineNumber: 12,
    pointerToNextFunction: 0x300
  });
  assert.deepEqual(result.symbols[2]?.auxiliaryRecords[0], {
    kind: "weak-external",
    tagIndex: 3,
    characteristics: 2
  });
  assert.deepEqual(result.symbols[3]?.auxiliaryRecords[0], { kind: "file", fileName: "main.c" });
  assert.deepEqual(result.symbols[4]?.auxiliaryRecords[0], {
    kind: "file",
    fileName: "abcdefghijklmnopqr"
  });
  assert.deepEqual(result.symbols[5]?.auxiliaryRecords[0], {
    kind: "section-definition",
    length: 0x40,
    numberOfRelocations: 5,
    numberOfLineNumbers: 6,
    checkSum: 0xabcd,
    number: 2,
    selection: 4
  });
  assert.deepEqual(result.symbols[6]?.auxiliaryRecords[0], { kind: "raw", bytes: [...rawAux] });
  assert.deepEqual(warnings, []);
});

void test("parseCoffSymbols warns for truncated auxiliary records and unsafe sizes", async () => {
  const table = createSymbolTable([
    {
      name: "aux",
      storageClass: COFF_STORAGE_CLASS.EXTERNAL,
      aux: [new Uint8Array(COFF_SYMBOL_RECORD_BYTE_LENGTH)]
    }
  ]);
  const warnings: string[] = [];
  const truncated = table.bytes.slice(0, COFF_SYMBOL_RECORD_BYTE_LENGTH);
  const truncatedResult = await parseCoffSymbols(new MockFile(truncated), 0, 2, warnings.push.bind(warnings));
  const unsafeWarnings: string[] = [];
  const unsafe = await parseCoffSymbols(
    new MockFile(new Uint8Array()),
    0,
    Number.MAX_SAFE_INTEGER,
    unsafeWarnings.push.bind(unsafeWarnings)
  );
  const unsafeOffsetWarnings: string[] = [];
  const unsafeOffset = await parseCoffSymbols(
    new MockFile(new Uint8Array()),
    Number.MAX_SAFE_INTEGER,
    1,
    unsafeOffsetWarnings.push.bind(unsafeOffsetWarnings)
  );

  assert.equal(truncatedResult.symbols[0]?.auxiliaryRecords.length, 0);
  assert.match(warnings.join(" | "), /auxiliary records are truncated/i);
  assert.deepEqual(unsafe.symbols, []);
  assert.match(unsafeWarnings.join(" | "), /overflows/i);
  assert.deepEqual(unsafeOffset.symbols, []);
  assert.match(unsafeOffsetWarnings.join(" | "), /overflows/i);
});

void test("parseCoffSymbols keeps auxiliary records raw when guard fields do not match", async () => {
  const rawAux = Uint8Array.from({ length: COFF_SYMBOL_RECORD_BYTE_LENGTH }, (_, index) => 0xf0 - index);
  const table = createSymbolTable([
    {
      name: "not-func",
      sectionNumber: 1,
      type: 0,
      storageClass: COFF_STORAGE_CLASS.EXTERNAL,
      aux: [rawAux]
    },
    { name: ".lf", storageClass: COFF_STORAGE_CLASS.FUNCTION, aux: [rawAux] },
    { name: ".ef", storageClass: COFF_STORAGE_CLASS.FUNCTION, aux: [rawAux] },
    { name: "weakv", value: 1, sectionNumber: 0, storageClass: COFF_STORAGE_CLASS.EXTERNAL, aux: [rawAux] },
    {
      name: "auto-f",
      sectionNumber: 1,
      type: 0x20,
      storageClass: COFF_STORAGE_CLASS.AUTOMATIC,
      aux: [rawAux]
    },
    {
      name: "zero-f",
      value: 1,
      sectionNumber: 0,
      type: 0x20,
      storageClass: COFF_STORAGE_CLASS.EXTERNAL,
      aux: [rawAux]
    },
    { name: ".bf", storageClass: COFF_STORAGE_CLASS.AUTOMATIC, aux: [rawAux] },
    { name: ".bss", value: 1, sectionNumber: 1, storageClass: COFF_STORAGE_CLASS.STATIC, aux: [rawAux] },
    { name: ".zero", value: 0, sectionNumber: 0, storageClass: COFF_STORAGE_CLASS.STATIC, aux: [rawAux] }
  ]);

  const result = await parseCoffSymbols(new MockFile(table.bytes), 0, table.recordCount, assert.fail);

  assert.deepEqual(result.symbols[0]?.auxiliaryRecords[0], { kind: "raw", bytes: [...rawAux] });
  assert.deepEqual(result.symbols[1]?.auxiliaryRecords[0], { kind: "raw", bytes: [...rawAux] });
  assert.equal(result.symbols[2]?.auxiliaryRecords[0]?.kind, "begin-end-function");
  assert.deepEqual(result.symbols[3]?.auxiliaryRecords[0], { kind: "raw", bytes: [...rawAux] });
  assert.deepEqual(result.symbols[4]?.auxiliaryRecords[0], { kind: "raw", bytes: [...rawAux] });
  assert.deepEqual(result.symbols[5]?.auxiliaryRecords[0], { kind: "raw", bytes: [...rawAux] });
  assert.deepEqual(result.symbols[6]?.auxiliaryRecords[0], { kind: "raw", bytes: [...rawAux] });
  assert.deepEqual(result.symbols[7]?.auxiliaryRecords[0], { kind: "raw", bytes: [...rawAux] });
  assert.deepEqual(result.symbols[8]?.auxiliaryRecords[0], { kind: "raw", bytes: [...rawAux] });
});

void test("parseCoffSymbols detects truncated aux records after a later primary symbol", async () => {
  const table = createSymbolTable([
    { name: "first", storageClass: COFF_STORAGE_CLASS.EXTERNAL },
    {
      name: "second",
      storageClass: COFF_STORAGE_CLASS.EXTERNAL,
      aux: [
        new Uint8Array(COFF_SYMBOL_RECORD_BYTE_LENGTH),
        new Uint8Array(COFF_SYMBOL_RECORD_BYTE_LENGTH)
      ]
    }
  ]);
  const truncated = table.bytes.slice(0, COFF_SYMBOL_RECORD_BYTE_LENGTH * 3);
  const warnings: string[] = [];

  const result = await parseCoffSymbols(new MockFile(truncated), 0, 4, warnings.push.bind(warnings));

  assert.equal(result.symbols.length, 2);
  assert.equal(result.symbols[1]?.auxiliaryRecords.length, 1);
  assert.match(warnings.join(" | "), /symbol #1 auxiliary records are truncated/i);
});

void test("parseCoffSymbols accepts an empty symbol table without overflow warnings", async () => {
  const warnings: string[] = [];

  const result = await parseCoffSymbols(new MockFile(new Uint8Array()), 0, 0, warnings.push.bind(warnings));

  assert.deepEqual(result.symbols, []);
  assert.deepEqual(warnings, []);
});
