"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCoverage } from "../../analyzers/pe/coverage.js";

const COFF_WITHOUT_SECTIONS = {
  Machine: 0,
  NumberOfSections: 0,
  TimeDateStamp: 0,
  PointerToSymbolTable: 0,
  NumberOfSymbols: 0,
  SizeOfOptionalHeader: 0,
  Characteristics: 0
};

const COFF_WITH_ONE_SECTION = {
  ...COFF_WITHOUT_SECTIONS,
  NumberOfSections: 1
};

void test("buildCoverage does not classify SizeOfHeaders padding as overlay data", () => {
  const { overlaySize, coverage } = buildCoverage(
    0x200,
    0x40,
    COFF_WITHOUT_SECTIONS,
    0x58,
    0xe0,
    0x60,
    16,
    0x138,
    [],
    0x1000,
    0x1000
  );

  assert.strictEqual(overlaySize, 0);
  assert.ok(!coverage.some(entry => entry.label.startsWith("Overlay")));
});

void test("buildCoverage treats high-RVA section spans past 0xffffffff as an image-size mismatch", () => {
  const { imageSizeMismatch } = buildCoverage(
    0x240,
    0x40,
    COFF_WITH_ONE_SECTION,
    0x58,
    0xe0,
    0x60,
    16,
    0x138,
    [
      {
        name: ".text",
        virtualSize: 0x40,
        virtualAddress: 0xfffffff0,
        sizeOfRawData: 0x40,
        pointerToRawData: 0x200,
        characteristics: 0x60000020
      }
    ],
    0x1000,
    0x1000
  );

  assert.strictEqual(imageSizeMismatch, true);
});
