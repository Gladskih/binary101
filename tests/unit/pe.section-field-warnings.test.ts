"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeSectionFieldWarnings } from "../../analyzers/pe/layout/section-field-warnings.js";
import {
  createSection,
  createWindowsLayoutSubject,
  DEFAULT_FILE_ALIGNMENT,
  DEFAULT_SECTION_ALIGNMENT
} from "../fixtures/pe-layout-warning-subject.js";

const OBJECT_FIELD_WARNING =
  "Section .text has COFF object relocation/line-number fields set; " +
  "these fields should be zero in executable images.";

const createTextSection = () =>
  createSection(".text", DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT);
const createTextSectionWithFlags = (characteristics: number) =>
  createSection(".text", DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT, undefined, undefined, characteristics);

void test("collectPeSectionFieldWarnings reports PointerToRelocations", () => {
  const section = createTextSection();
  section.pointerToRelocations = 1;

  assert.deepStrictEqual(
    collectPeSectionFieldWarnings(createWindowsLayoutSubject(section)),
    [OBJECT_FIELD_WARNING]
  );
});

void test("collectPeSectionFieldWarnings reports PointerToLinenumbers", () => {
  const section = createTextSection();
  section.pointerToLinenumbers = 1;

  assert.deepStrictEqual(
    collectPeSectionFieldWarnings(createWindowsLayoutSubject(section)),
    [OBJECT_FIELD_WARNING]
  );
});

void test("collectPeSectionFieldWarnings reports NumberOfRelocations", () => {
  const section = createTextSection();
  section.numberOfRelocations = 1;

  assert.deepStrictEqual(
    collectPeSectionFieldWarnings(createWindowsLayoutSubject(section)),
    [OBJECT_FIELD_WARNING]
  );
});

void test("collectPeSectionFieldWarnings reports NumberOfLinenumbers", () => {
  const section = createTextSection();
  section.numberOfLinenumbers = 1;

  assert.deepStrictEqual(
    collectPeSectionFieldWarnings(createWindowsLayoutSubject(section)),
    [OBJECT_FIELD_WARNING]
  );
});

void test("collectPeSectionFieldWarnings accepts zero object relocation and line-number fields", () => {
  const section = createTextSection();
  section.pointerToRelocations = 0;
  section.pointerToLinenumbers = 0;
  section.numberOfRelocations = 0;
  section.numberOfLinenumbers = 0;

  assert.deepStrictEqual(collectPeSectionFieldWarnings(createWindowsLayoutSubject(section)), []);
});

void test("collectPeSectionFieldWarnings reports grouped section names", () => {
  const section = createSection(".text$mn", DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT);

  assert.deepStrictEqual(collectPeSectionFieldWarnings(createWindowsLayoutSubject(section)), [
    "Section name contains \"$\"; grouped section names are object-file syntax and image section names never " +
      "contain \"$\"."
  ]);
});

void test("collectPeSectionFieldWarnings accepts ordinary section names", () => {
  assert.deepStrictEqual(collectPeSectionFieldWarnings(createWindowsLayoutSubject(createTextSection())), []);
});

void test("collectPeSectionFieldWarnings reports object-only section flags", () => {
  const lnkInfo = createTextSectionWithFlags(0x00000200);
  const aligned = createTextSectionWithFlags(0x00100000);
  const typeNoPad = createTextSectionWithFlags(0x00000008);

  assert.ok(
    collectPeSectionFieldWarnings(createWindowsLayoutSubject(lnkInfo)).some(warning =>
      warning.includes("object-only section flags set: LNK_INFO")
    )
  );
  assert.ok(
    collectPeSectionFieldWarnings(createWindowsLayoutSubject(aligned)).some(warning =>
      warning.includes("object-only section flags set: ALIGN_1BYTES")
    )
  );
  assert.ok(
    collectPeSectionFieldWarnings(createWindowsLayoutSubject(typeNoPad)).some(warning =>
      warning.includes("object-only section flags set: TYPE_NO_PAD")
    )
  );
});

void test("collectPeSectionFieldWarnings accepts standard memory section flags", () => {
  const section = createTextSectionWithFlags(0x40000000 | 0x80000000 | 0x20000000);

  assert.deepStrictEqual(collectPeSectionFieldWarnings(createWindowsLayoutSubject(section)), []);
});

void test("collectPeSectionFieldWarnings reports reserved section flags", () => {
  const lowReserved = createTextSectionWithFlags(0x00000001);
  const highReserved = createTextSectionWithFlags(0x00020000);

  assert.ok(
    collectPeSectionFieldWarnings(createWindowsLayoutSubject(lowReserved)).some(warning =>
      warning.includes("reserved section flags set: RESERVED_00000001")
    )
  );
  assert.ok(
    collectPeSectionFieldWarnings(createWindowsLayoutSubject(highReserved)).some(warning =>
      warning.includes("reserved section flags set: MEM_PURGEABLE/MEM_16BIT")
    )
  );
});

void test("collectPeSectionFieldWarnings accepts standard content and memory flags", () => {
  const section = createTextSectionWithFlags(0x00000020 | 0x00000040 | 0x40000000);

  assert.deepStrictEqual(collectPeSectionFieldWarnings(createWindowsLayoutSubject(section)), []);
});
