"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { computeEntrySection } from "../../analyzers/pe/core-entry.js";
import { inlinePeSectionName } from "../../analyzers/pe/section-name.js";

const SECTION_RVA = 0x1000;
const SECTION_VIRTUAL_SIZE = 0x80;
const SECTION_RAW_SIZE = 0x200;
const SECTION_POINTER_TO_RAW_DATA = 0x200;
// Microsoft PE format, section flags:
// 0x60000020 is IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ.
const TEXT_SECTION_CHARACTERISTICS = 0x60000020;
const ENTRYPOINT_IN_RAW_TAIL = SECTION_RVA + 0x1f0;
// Deliberately 16 bytes below the 32-bit RVA wrap boundary so adding the section span would overflow a u32.
const HIGH_RVA_SECTION_START = 0xfffffff0;
const HIGH_RVA_SECTION_SPAN = 0x40;
const ENTRY_SECTION_BOUNDARY_CASES = [
  { label: "section start", entryRva: SECTION_RVA, expected: { name: ".text", index: 0 } },
  {
    label: "virtual tail",
    entryRva: SECTION_RVA + SECTION_VIRTUAL_SIZE - 1,
    expected: { name: ".text", index: 0 }
  },
  { label: "raw tail", entryRva: ENTRYPOINT_IN_RAW_TAIL, expected: null },
  { label: "raw end excluded", entryRva: SECTION_RVA + SECTION_RAW_SIZE, expected: null },
  { label: "before section", entryRva: SECTION_RVA - 1, expected: null },
  { label: "after raw tail", entryRva: SECTION_RVA + SECTION_RAW_SIZE + 1, expected: null }
] as const;

void test("computeEntrySection uses the in-memory VirtualSize, not file-alignment padding", () => {
  // Microsoft PE format spec, section table:
  // VirtualSize is the section size when loaded into memory, while SizeOfRawData may be larger on disk because
  // it is rounded to FileAlignment. An AddressOfEntryPoint in the raw tail is not inside the mapped image.
  const opt = { AddressOfEntryPoint: ENTRYPOINT_IN_RAW_TAIL } as const;
  const sections = [
    {
      name: inlinePeSectionName(".text"),
      virtualSize: SECTION_VIRTUAL_SIZE,
      virtualAddress: SECTION_RVA,
      sizeOfRawData: SECTION_RAW_SIZE,
      pointerToRawData: SECTION_POINTER_TO_RAW_DATA,
      characteristics: TEXT_SECTION_CHARACTERISTICS
    }
  ];

  assert.strictEqual(computeEntrySection(opt, sections), null);
});

void test("computeEntrySection respects the mapped section boundary instead of the raw-file tail", () => {
  const sections = [
    {
      name: inlinePeSectionName(".text"),
      virtualSize: SECTION_VIRTUAL_SIZE,
      virtualAddress: SECTION_RVA,
      sizeOfRawData: SECTION_RAW_SIZE,
      pointerToRawData: SECTION_POINTER_TO_RAW_DATA,
      characteristics: TEXT_SECTION_CHARACTERISTICS
    }
  ];

  for (const boundaryCase of ENTRY_SECTION_BOUNDARY_CASES) {
    assert.deepStrictEqual(
      computeEntrySection({ AddressOfEntryPoint: boundaryCase.entryRva }, sections),
      boundaryCase.expected,
      boundaryCase.label
    );
  }
});

void test("computeEntrySection returns null for a missing entrypoint RVA", () => {
  assert.strictEqual(computeEntrySection({ AddressOfEntryPoint: 0 }, []), null);
});

void test("computeEntrySection skips sparse section slots and returns null when no section matches", () => {
  // The analyzer should remain defensive even if an upstream caller hands it a sparse array.
  const sections = [] as Array<{
    name: ReturnType<typeof inlinePeSectionName>;
    virtualSize: number;
    virtualAddress: number;
    sizeOfRawData: number;
    pointerToRawData: number;
    characteristics: number;
  }>;
  sections[1] = {
    name: inlinePeSectionName(".text"),
    virtualSize: SECTION_VIRTUAL_SIZE,
    virtualAddress: SECTION_RVA,
    sizeOfRawData: SECTION_RAW_SIZE,
    pointerToRawData: SECTION_POINTER_TO_RAW_DATA,
    characteristics: TEXT_SECTION_CHARACTERISTICS
  };

  assert.strictEqual(computeEntrySection({ AddressOfEntryPoint: 0x3000 }, sections), null);
});

void test("computeEntrySection does not wrap high-RVA section spans back to low addresses", () => {
  const sections = [
    {
      name: inlinePeSectionName(".text"),
      virtualSize: HIGH_RVA_SECTION_SPAN,
      virtualAddress: HIGH_RVA_SECTION_START,
      sizeOfRawData: HIGH_RVA_SECTION_SPAN,
      pointerToRawData: SECTION_POINTER_TO_RAW_DATA,
      characteristics: TEXT_SECTION_CHARACTERISTICS
    }
  ];

  assert.deepStrictEqual(
    computeEntrySection({ AddressOfEntryPoint: HIGH_RVA_SECTION_START }, sections),
    { name: ".text", index: 0 }
  );
});
