"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_SECTION_HEADER_BYTE_LENGTH,
  COFF_SECTION_HEADER_FIELDS,
  COFF_SHORT_NAME_BYTE_LENGTH,
  COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH,
  COFF_SYMBOL_RECORD_BYTE_LENGTH,
  type CoffNumericField
} from "../../../../analyzers/coff/layout.js";
import { parseCoffSectionHeaders } from "../../../../analyzers/coff/section-headers.js";
import { coffSectionNameOffset, coffSectionNameValue } from "../../../../analyzers/coff/section-name.js";
import { MockFile } from "../../../helpers/mock-file.js";

const FIXTURE_SYMBOL_TABLE_OFFSET = 0x80; // Arbitrary aligned fixture offset, not a COFF field size.

const writeField = (view: DataView, base: number, field: CoffNumericField, value: number): void => {
  const offset = base + field.offset;
  if (field.width === "u16") view.setUint16(offset, value, true);
  else view.setUint32(offset, value, true);
};

const writeAscii = (bytes: Uint8Array, offset: number, text: string, maxLength: number): void => {
  bytes.set(new TextEncoder().encode(text).subarray(0, maxLength), offset);
};

void test("parseCoffSectionHeaders parses section fields and long COFF names", async () => {
  const numberOfSymbols = 1;
  const stringTableOffset = FIXTURE_SYMBOL_TABLE_OFFSET + numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  const bytes = new Uint8Array(stringTableOffset + COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH + 12);
  const view = new DataView(bytes.buffer);
  writeAscii(bytes, COFF_FILE_HEADER_BYTE_LENGTH, "/4", COFF_SHORT_NAME_BYTE_LENGTH);
  writeField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.VirtualSize, 0x10);
  writeField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.VirtualAddress, 0x2000);
  writeField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.SizeOfRawData, 0x20);
  writeField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.PointerToRawData, 0x40);
  writeField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.PointerToRelocations, 0x60);
  writeField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.PointerToLinenumbers, 0x70);
  writeField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.NumberOfRelocations, 2);
  writeField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.NumberOfLinenumbers, 3);
  writeField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.Characteristics, 0x40000040);
  view.setUint32(stringTableOffset, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH + 12, true);
  writeAscii(bytes, stringTableOffset + COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH, ".debug$S\0", 12);

  const parsed = await parseCoffSectionHeaders(
    new MockFile(bytes),
    COFF_FILE_HEADER_BYTE_LENGTH,
    0,
    1,
    FIXTURE_SYMBOL_TABLE_OFFSET,
    numberOfSymbols
  );

  assert.equal(parsed.rawNames[0], "/4");
  assert.equal(parsed.coffStringTableSize, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH + 12);
  assert.equal(coffSectionNameValue(parsed.sections[0]!.name), ".debug$S");
  assert.equal(coffSectionNameOffset(parsed.sections[0]!.name), COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  assert.deepEqual(parsed.sections[0], {
    name: parsed.sections[0]!.name,
    virtualSize: 0x10,
    virtualAddress: 0x2000,
    sizeOfRawData: 0x20,
    pointerToRawData: 0x40,
    pointerToRelocations: 0x60,
    pointerToLinenumbers: 0x70,
    numberOfRelocations: 2,
    numberOfLinenumbers: 3,
    characteristics: 0x40000040
  });
});

void test("parseCoffSectionHeaders warns and stops at truncated section records", async () => {
  const bytes = new Uint8Array(COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH + 1);
  writeAscii(bytes, COFF_FILE_HEADER_BYTE_LENGTH, ".one", COFF_SHORT_NAME_BYTE_LENGTH);

  const parsed = await parseCoffSectionHeaders(new MockFile(bytes), COFF_FILE_HEADER_BYTE_LENGTH, 0, 2);

  assert.equal(parsed.sections.length, 1);
  assert.equal(parsed.coffStringTableSize, undefined);
  assert.equal("coffStringTableSize" in parsed, false);
  assert.match(parsed.warnings?.join(" | ") ?? "", /section header table is truncated/i);
});

void test("parseCoffSectionHeaders preserves full-width inline names and trims at NUL", async () => {
  const bytes = new Uint8Array(COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH * 2);
  writeAscii(bytes, COFF_FILE_HEADER_BYTE_LENGTH, "12345678", COFF_SHORT_NAME_BYTE_LENGTH);
  writeAscii(
    bytes,
    COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH,
    ".x\0junk",
    COFF_SHORT_NAME_BYTE_LENGTH
  );

  const parsed = await parseCoffSectionHeaders(new MockFile(bytes), COFF_FILE_HEADER_BYTE_LENGTH, 0, 2);

  assert.deepEqual(parsed.rawNames, ["12345678", ".x"]);
  assert.equal(coffSectionNameValue(parsed.sections[0]!.name), "12345678");
  assert.equal(coffSectionNameValue(parsed.sections[1]!.name), ".x");
});

void test("parseCoffSectionHeaders reports unresolved long section-name offsets", async () => {
  const numberOfSymbols = 1;
  const stringTableOffset = FIXTURE_SYMBOL_TABLE_OFFSET + numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  const bytes = new Uint8Array(stringTableOffset + COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  const view = new DataView(bytes.buffer);
  writeAscii(bytes, COFF_FILE_HEADER_BYTE_LENGTH, "/99", COFF_SHORT_NAME_BYTE_LENGTH);
  view.setUint32(stringTableOffset, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH, true);

  const parsed = await parseCoffSectionHeaders(
    new MockFile(bytes),
    COFF_FILE_HEADER_BYTE_LENGTH,
    0,
    1,
    FIXTURE_SYMBOL_TABLE_OFFSET,
    numberOfSymbols
  );

  assert.equal(coffSectionNameValue(parsed.sections[0]!.name), "/99");
  assert.match(parsed.warnings?.join(" | ") ?? "", /outside the COFF string table/i);
});
