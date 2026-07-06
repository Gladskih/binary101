"use strict";

import assert from "node:assert/strict";
import test from "node:test";

import {
  COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH,
  COFF_DEBUG_SYMBOLS_HEADER_FIELDS,
  COFF_FILE_CHARACTERISTICS,
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_FILE_HEADER_FIELDS,
  COFF_LINE_NUMBER_FIELDS,
  COFF_LINE_NUMBER_RECORD_BYTE_LENGTH,
  COFF_RELOCATION_FIELDS,
  COFF_RELOCATION_RECORD_BYTE_LENGTH,
  COFF_SECTION_HEADER_BYTE_LENGTH,
  COFF_SECTION_HEADER_FIELDS,
  COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH,
  COFF_SYMBOL_FIELDS,
  COFF_SYMBOL_NAME_FIELDS,
  COFF_SYMBOL_RECORD_BYTE_LENGTH,
  readCoffField
} from "../../../../analyzers/coff/layout.js";

void test("COFF fixed record sizes match the Microsoft PE/COFF layouts", () => {
  // Microsoft PE/COFF: IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER, IMAGE_SYMBOL,
  // IMAGE_RELOCATION, IMAGE_LINENUMBER, and IMAGE_COFF_SYMBOLS_HEADER.
  assert.equal(COFF_FILE_HEADER_BYTE_LENGTH, 20);
  assert.equal(COFF_SECTION_HEADER_BYTE_LENGTH, 40);
  assert.equal(COFF_SYMBOL_RECORD_BYTE_LENGTH, 18);
  assert.equal(COFF_RELOCATION_RECORD_BYTE_LENGTH, 10);
  assert.equal(COFF_LINE_NUMBER_RECORD_BYTE_LENGTH, 6);
  assert.equal(COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH, 32);
  assert.equal(COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH, 4);
});

void test("COFF file characteristic bits are centralized", () => {
  assert.deepEqual(COFF_FILE_CHARACTERISTICS, {
    RELOCS_STRIPPED: 0x0001,
    EXECUTABLE_IMAGE: 0x0002,
    MACHINE_32BIT: 0x0100,
    DLL: 0x2000
  });
});

void test("COFF header field offsets are centralized in the layout table", () => {
  assert.deepEqual(COFF_FILE_HEADER_FIELDS, {
    Machine: { offset: 0, width: "u16" },
    NumberOfSections: { offset: 2, width: "u16" },
    TimeDateStamp: { offset: 4, width: "u32" },
    PointerToSymbolTable: { offset: 8, width: "u32" },
    NumberOfSymbols: { offset: 12, width: "u32" },
    SizeOfOptionalHeader: { offset: 16, width: "u16" },
    Characteristics: { offset: 18, width: "u16" }
  });
});

void test("COFF section and symbol field offsets cover parser-critical members", () => {
  assert.deepEqual(COFF_SECTION_HEADER_FIELDS.PointerToRelocations, { offset: 24, width: "u32" });
  assert.deepEqual(COFF_SECTION_HEADER_FIELDS.NumberOfRelocations, { offset: 32, width: "u16" });
  assert.deepEqual(COFF_SECTION_HEADER_FIELDS.NumberOfLinenumbers, { offset: 34, width: "u16" });
  assert.deepEqual(COFF_SYMBOL_FIELDS.SectionNumber, { offset: 12, width: "i16" });
  assert.deepEqual(COFF_SYMBOL_FIELDS.NumberOfAuxSymbols, { offset: 17, width: "u8" });
  assert.deepEqual(COFF_SYMBOL_NAME_FIELDS.StringTableOffset, { offset: 4, width: "u32" });
});

void test("COFF relocation, line-number, and debug-header offsets cover parser-critical members", () => {
  assert.deepEqual(COFF_RELOCATION_FIELDS.SymbolTableIndex, { offset: 4, width: "u32" });
  assert.deepEqual(COFF_RELOCATION_FIELDS.Type, { offset: 8, width: "u16" });
  assert.deepEqual(COFF_LINE_NUMBER_FIELDS.LineNumber, { offset: 4, width: "u16" });
  assert.deepEqual(COFF_DEBUG_SYMBOLS_HEADER_FIELDS.LvaToFirstSymbol, { offset: 4, width: "u32" });
  assert.deepEqual(COFF_DEBUG_SYMBOLS_HEADER_FIELDS.RvaToLastByteOfData, { offset: 28, width: "u32" });
});

void test("readCoffField reads little-endian unsigned and signed widths", () => {
  const bytes = new Uint8Array([0x7f, 0x34, 0x12, 0xfe, 0xff, 0x78, 0x56, 0x34, 0x12]);
  const view = new DataView(bytes.buffer);
  assert.equal(readCoffField(view, 0, { offset: 0, width: "u8" }), 0x7f);
  assert.equal(readCoffField(view, 0, { offset: 1, width: "u16" }), 0x1234);
  assert.equal(readCoffField(view, 0, { offset: 3, width: "i16" }), -2);
  assert.equal(readCoffField(view, 0, { offset: 5, width: "u32" }), 0x12345678);
});
