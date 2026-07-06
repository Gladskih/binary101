"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  COFF_SECTION_HEADER_BYTE_LENGTH,
  COFF_SECTION_HEADER_FIELDS,
  COFF_SHORT_NAME_BYTE_LENGTH,
  COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH,
  COFF_SYMBOL_RECORD_BYTE_LENGTH,
  type CoffNumericField
} from "../../../../../analyzers/coff/layout.js";
import { parseSectionHeaders } from "../../../../../analyzers/pe/sections/index.js";
import { peSectionNameOffset, peSectionNameValue } from "../../../../../analyzers/pe/sections/name.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const DEFAULT_OPTIONAL_HEADER_OFFSET = 0x80;
// Full IMAGE_OPTIONAL_HEADER32 size used by these synthetic PE32 fixtures.
const DEFAULT_OPTIONAL_HEADER_SIZE = 0xe0;
const UTF8_SECTION_NAME_MICRO_SIGN = Uint8Array.from([0x2e, 0xc2, 0xb5]);

type SectionShape = { name: string; va: number; vs: number; rawSize: number; rawOff: number };

const writeCoffField = (
  view: DataView,
  recordOffset: number,
  field: CoffNumericField,
  value: number
): void => {
  const offset = recordOffset + field.offset;
  switch (field.width) {
    case "u8": view.setUint8(offset, value); break;
    case "u16": view.setUint16(offset, value, true); break;
    case "i16": view.setInt16(offset, value, true); break;
    case "u32": view.setUint32(offset, value, true); break;
  }
};

const createSectionTable = (sections: SectionShape[]): Uint8Array => {
  const buffer = new Uint8Array(sections.length * COFF_SECTION_HEADER_BYTE_LENGTH);
  const view = new DataView(buffer.buffer);
  sections.forEach((section, idx) => {
    const base = idx * COFF_SECTION_HEADER_BYTE_LENGTH;
    [...section.name].slice(0, COFF_SHORT_NAME_BYTE_LENGTH)
      .forEach((ch, i) => view.setUint8(base + i, ch.charCodeAt(0)));
    writeCoffField(view, base, COFF_SECTION_HEADER_FIELDS.VirtualSize, section.vs);
    writeCoffField(view, base, COFF_SECTION_HEADER_FIELDS.VirtualAddress, section.va);
    writeCoffField(view, base, COFF_SECTION_HEADER_FIELDS.SizeOfRawData, section.rawSize);
    writeCoffField(view, base, COFF_SECTION_HEADER_FIELDS.PointerToRawData, section.rawOff);
    writeCoffField(view, base, COFF_SECTION_HEADER_FIELDS.Characteristics, 0);
  });
  return buffer;
};

const createCoffStringTable = (names: string[]): { bytes: Uint8Array; offsets: number[] } => {
  const encodedNames = names.map(name => Uint8Array.from([...name, "\0"].map(ch => ch.charCodeAt(0))));
  const size = COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH +
    encodedNames.reduce((sum, entry) => sum + entry.length, 0);
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, size, true);
  const offsets: number[] = [];
  let offset = COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH;
  for (const entry of encodedNames) {
    offsets.push(offset);
    bytes.set(entry, offset);
    offset += entry.length;
  }
  return { bytes, offsets };
};

const createSectionHeadersFixture = (
  sections: SectionShape[],
  options: {
    optionalHeaderOffset?: number;
    sizeOfOptionalHeader?: number;
    pointerToSymbolTable?: number;
    numberOfSymbols?: number;
    stringTable?: Uint8Array;
    minimumFileSize?: number;
  } = {}
): {
  file: MockFile;
  numberOfSections: number;
  optionalHeaderOffset: number;
  sizeOfOptionalHeader: number;
  sectionTableOffset: number;
  pointerToSymbolTable: number;
  numberOfSymbols: number;
} => {
  const optionalHeaderOffset = options.optionalHeaderOffset ?? DEFAULT_OPTIONAL_HEADER_OFFSET;
  const sizeOfOptionalHeader = options.sizeOfOptionalHeader ?? DEFAULT_OPTIONAL_HEADER_SIZE;
  const sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const pointerToSymbolTable = options.pointerToSymbolTable ?? 0;
  const numberOfSymbols = options.numberOfSymbols ?? 0;
  const stringTableOffset =
    pointerToSymbolTable && numberOfSymbols
      ? pointerToSymbolTable + numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH
      : null;
  const sectionTable = createSectionTable(sections);
  const fileSize = Math.max(
    options.minimumFileSize ?? 0,
    sectionTableOffset + sectionTable.length,
    stringTableOffset != null && options.stringTable
      ? stringTableOffset + options.stringTable.length
      : 0
  );
  const fileBytes = new Uint8Array(fileSize);
  fileBytes.set(sectionTable, sectionTableOffset);
  if (stringTableOffset != null && options.stringTable) {
    fileBytes.set(options.stringTable, stringTableOffset);
  }
  return {
    file: new MockFile(fileBytes),
    numberOfSections: sections.length,
    optionalHeaderOffset,
    sizeOfOptionalHeader,
    sectionTableOffset,
    pointerToSymbolTable,
    numberOfSymbols
  };
};

const createSectionHeadersFixtureWithCoffSymbols = (
  sections: SectionShape[],
  stringTable?: Uint8Array
) =>
  createSectionHeadersFixture(sections, {
    pointerToSymbolTable: 0x200,
    numberOfSymbols: 1,
    ...(stringTable ? { stringTable } : {})
  });

void test("parseSectionHeaders reads section entries and maps RVAs to offsets", async () => {
  const fixture = createSectionHeadersFixture([
    { name: ".text", va: 0x1000, vs: 0x200, rawSize: 0x200, rawOff: 0x400 },
    { name: ".rdata", va: 0x2000, vs: 0x180, rawSize: 0x200, rawOff: 0x800 }
  ]);
  const { sections, rvaToOff, sectOff } = await parseSectionHeaders(
    fixture.file,
    fixture.optionalHeaderOffset,
    fixture.sizeOfOptionalHeader,
    fixture.numberOfSections,
    fixture.sectionTableOffset
  );

  assert.strictEqual(sectOff, fixture.sectionTableOffset);
  assert.strictEqual(sections.length, 2);
  const [first] = sections;
  if (!first) assert.fail("first section missing");
  assert.strictEqual(peSectionNameValue(first.name), ".text");
  assert.strictEqual(rvaToOff(0x1000), 0x400);
  assert.strictEqual(rvaToOff(0x2000 + 0x10), 0x800 + 0x10);
  assert.strictEqual(rvaToOff(0x3000), null);
});

void test("parseSectionHeaders does not map zero-filled virtual tail beyond raw section bytes", async () => {
  const fixture = createSectionHeadersFixture([
    { name: ".data", va: 0x1000, vs: 0x300, rawSize: 0x200, rawOff: 0x400 }
  ]);
  const { rvaToOff } = await parseSectionHeaders(
    fixture.file,
    fixture.optionalHeaderOffset,
    fixture.sizeOfOptionalHeader,
    fixture.numberOfSections,
    fixture.sectionTableOffset
  );

  assert.strictEqual(rvaToOff(0x1000 + 0x1ff), 0x400 + 0x1ff);
  assert.strictEqual(
    rvaToOff(0x1000 + 0x200),
    null,
    "RVA in zero-filled tail should not map to bytes from another file region"
  );
});

void test("parseSectionHeaders does not map raw-file padding beyond VirtualSize into the loaded image", async () => {
  const fixture = createSectionHeadersFixture([
    { name: ".text", va: 0x1000, vs: 0x80, rawSize: 0x200, rawOff: 0x400 }
  ]);
  const { rvaToOff } = await parseSectionHeaders(
    fixture.file,
    fixture.optionalHeaderOffset,
    fixture.sizeOfOptionalHeader,
    fixture.numberOfSections,
    fixture.sectionTableOffset
  );

  assert.strictEqual(rvaToOff(0x1000 + 0x7f), 0x400 + 0x7f);
  assert.strictEqual(
    rvaToOff(0x1000 + 0x80),
    null,
    "RVA in raw padding beyond VirtualSize should not resolve inside the image"
  );
});

void test("parseSectionHeaders does not wrap section RVAs past 0xffffffff back to low addresses", async () => {
  const fixture = createSectionHeadersFixture([
    { name: ".text", va: 0xfffffff0, vs: 0x40, rawSize: 0x40, rawOff: 0x200 }
  ]);
  const { rvaToOff } = await parseSectionHeaders(
    fixture.file,
    fixture.optionalHeaderOffset,
    fixture.sizeOfOptionalHeader,
    fixture.numberOfSections,
    fixture.sectionTableOffset
  );

  // RVAs are 32-bit values; a section near the top of the address space must clamp at 0xffffffff instead of
  // wrapping to 0x00000000 and becoming unmappable.
  assert.strictEqual(rvaToOff(0xfffffff0), 0x200);
  assert.strictEqual(rvaToOff(0xffffffff), 0x20f);
  assert.strictEqual(rvaToOff(0), null);
});

void test("parseSectionHeaders maps header RVA 0 to file offset 0 when SizeOfHeaders covers the image headers", async () => {
  const fileBytes = Uint8Array.of(0);

  const { rvaToOff } = await parseSectionHeaders(new MockFile(fileBytes), 0, 0, 0, fileBytes.length);

  // Microsoft PE format: the image headers are mapped at the image base, so the first header byte lives at RVA 0.
  assert.strictEqual(rvaToOff(0), 0);
});

void test("parseSectionHeaders decodes short section names as UTF-8", async () => {
  const table = new Uint8Array(COFF_SECTION_HEADER_BYTE_LENGTH).fill(0);
  const view = new DataView(table.buffer);
  table.set(UTF8_SECTION_NAME_MICRO_SIGN, 0);
  view.setUint32(8, 0x40, true);
  view.setUint32(12, 0x1000, true);
  view.setUint32(16, 0x40, true);
  view.setUint32(20, 0x200, true);
  const fixture = createSectionHeadersFixture([]);
  const fileBytes = new Uint8Array(fixture.sectionTableOffset + COFF_SECTION_HEADER_BYTE_LENGTH);
  fileBytes.set(table, fixture.sectionTableOffset);

  const { sections } = await parseSectionHeaders(
    new MockFile(fileBytes),
    fixture.optionalHeaderOffset,
    fixture.sizeOfOptionalHeader,
    1,
    fixture.sectionTableOffset
  );

  const [firstSection] = sections;
  if (!firstSection) assert.fail("section missing");
  assert.strictEqual(peSectionNameValue(firstSection.name), ".\u00b5");
});

void test("parseSectionHeaders resolves long section names from the COFF string table as a non-standard image recovery", async () => {
  const { bytes: stringTable, offsets } = createCoffStringTable([".debug_abbrev"]);
  const longNameOffset = offsets[0];
  if (longNameOffset == null) assert.fail("missing COFF string-table offset");
  const fixture = createSectionHeadersFixtureWithCoffSymbols(
    [{ name: `/${longNameOffset}`, va: 0x1000, vs: 0x40, rawSize: 0x40, rawOff: 0x200 }],
    stringTable
  );
  const { sections, warnings } = await parseSectionHeaders(
    fixture.file,
    fixture.optionalHeaderOffset,
    fixture.sizeOfOptionalHeader,
    fixture.numberOfSections,
    fixture.sectionTableOffset,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );

  const [firstSection] = sections;
  if (!firstSection) assert.fail("section missing");
  assert.strictEqual(peSectionNameValue(firstSection.name), ".debug_abbrev");
  assert.strictEqual(peSectionNameOffset(firstSection.name), longNameOffset);
  assert.deepStrictEqual(warnings, [
    "PE image has a COFF symbol table even though Microsoft PE format says PointerToSymbolTable and NumberOfSymbols should be zero for images because COFF debugging information is deprecated.",
    "PE image uses COFF string-table section names like /4 even though Microsoft PE format says executable images do not use a string table for section names and do not support section names longer than 8 characters. Any recovered name is a non-standard best-effort decode."
  ]);
});

void test("parseSectionHeaders keeps raw long names when the COFF string table is unavailable", async () => {
  const fixture = createSectionHeadersFixtureWithCoffSymbols([
    { name: "/4", va: 0x1000, vs: 0x40, rawSize: 0x40, rawOff: 0x200 }
  ]);
  const { sections, warnings } = await parseSectionHeaders(
    fixture.file,
    fixture.optionalHeaderOffset,
    fixture.sizeOfOptionalHeader,
    fixture.numberOfSections,
    fixture.sectionTableOffset,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );

  const [firstSection] = sections;
  if (!firstSection) assert.fail("section missing");
  assert.strictEqual(peSectionNameValue(firstSection.name), "/4");
  assert.strictEqual(peSectionNameOffset(firstSection.name), 4);
  assert.deepStrictEqual(
    warnings,
    [
      "COFF string table does not fit within the file; long section names may stay unresolved.",
      "PE image has a COFF symbol table even though Microsoft PE format says PointerToSymbolTable and NumberOfSymbols should be zero for images because COFF debugging information is deprecated.",
      "PE image uses COFF string-table section names like /4 even though Microsoft PE format says executable images do not use a string table for section names and do not support section names longer than 8 characters. Any recovered name is a non-standard best-effort decode."
    ]
  );
});
