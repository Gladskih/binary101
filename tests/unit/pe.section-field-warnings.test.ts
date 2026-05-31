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
