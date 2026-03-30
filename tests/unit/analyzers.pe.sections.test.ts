"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSectionHeaders } from "../../analyzers/pe/sections.js";
import { peSectionNameOffset, peSectionNameValue } from "../../analyzers/pe/section-name.js";
import { MockFile } from "../helpers/mock-file.js";

// Microsoft PE/COFF: IMAGE_SECTION_HEADER records are 40 bytes wide.
const IMAGE_SECTION_HEADER_SIZE = 40;
// Microsoft PE/COFF: each COFF symbol-table record is 18 bytes.
const IMAGE_SYMBOL_SIZE = 18;
const DEFAULT_OPTIONAL_HEADER_OFFSET = 0x80;
// Full IMAGE_OPTIONAL_HEADER32 size used by these synthetic PE32 fixtures.
const DEFAULT_OPTIONAL_HEADER_SIZE = 0xe0;
const UTF8_SECTION_NAME_MICRO_SIGN = Uint8Array.from([0x2e, 0xc2, 0xb5]);

type SectionShape = { name: string; va: number; vs: number; rawSize: number; rawOff: number };

const createSectionTable = (sections: SectionShape[]): Uint8Array => {
  const buffer = new Uint8Array(sections.length * IMAGE_SECTION_HEADER_SIZE);
  const view = new DataView(buffer.buffer);
  sections.forEach((section, idx) => {
    const base = idx * IMAGE_SECTION_HEADER_SIZE;
    [...section.name].slice(0, 8).forEach((ch, i) => view.setUint8(base + i, ch.charCodeAt(0)));
    view.setUint32(base + 8, section.vs, true);
    view.setUint32(base + 12, section.va, true);
    view.setUint32(base + 16, section.rawSize, true);
    view.setUint32(base + 20, section.rawOff, true);
    view.setUint32(base + 36, 0, true);
  });
  return buffer;
};

const createCoffStringTable = (names: string[]): { bytes: Uint8Array; offsets: number[] } => {
  const encodedNames = names.map(name => Uint8Array.from([...name, "\0"].map(ch => ch.charCodeAt(0))));
  const size = 4 + encodedNames.reduce((sum, entry) => sum + entry.length, 0);
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, size, true);
  const offsets: number[] = [];
  let offset = 4;
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
      ? pointerToSymbolTable + numberOfSymbols * IMAGE_SYMBOL_SIZE
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
  const table = new Uint8Array(IMAGE_SECTION_HEADER_SIZE).fill(0);
  const view = new DataView(table.buffer);
  table.set(UTF8_SECTION_NAME_MICRO_SIGN, 0);
  view.setUint32(8, 0x40, true);
  view.setUint32(12, 0x1000, true);
  view.setUint32(16, 0x40, true);
  view.setUint32(20, 0x200, true);
  const fixture = createSectionHeadersFixture([]);
  const fileBytes = new Uint8Array(fixture.sectionTableOffset + IMAGE_SECTION_HEADER_SIZE);
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
