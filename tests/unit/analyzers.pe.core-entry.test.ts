"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { computeEntrySection } from "../../analyzers/pe/core-entry.js";

const SECTION_RVA = 0x1000;
const SECTION_VIRTUAL_SIZE = 0x80;
const SECTION_RAW_SIZE = 0x200;
const ENTRYPOINT_IN_RAW_TAIL = SECTION_RVA + 0x1f0;
const ENTRY_SECTION_BOUNDARY_CASES = [
  { label: "section start", entryRva: SECTION_RVA, expected: { name: ".text", index: 0 } },
  { label: "virtual tail", entryRva: SECTION_RVA + SECTION_VIRTUAL_SIZE - 1, expected: { name: ".text", index: 0 } },
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
      name: ".text",
      virtualSize: SECTION_VIRTUAL_SIZE,
      virtualAddress: SECTION_RVA,
      sizeOfRawData: SECTION_RAW_SIZE,
      pointerToRawData: 0x200,
      characteristics: 0x60000020
    }
  ];

  assert.strictEqual(computeEntrySection(opt, sections), null);
});

void test("computeEntrySection respects the mapped section boundary instead of the raw-file tail", () => {
  const sections = [
    {
      name: ".text",
      virtualSize: SECTION_VIRTUAL_SIZE,
      virtualAddress: SECTION_RVA,
      sizeOfRawData: SECTION_RAW_SIZE,
      pointerToRawData: 0x200,
      characteristics: 0x60000020
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
    name: string;
    virtualSize: number;
    virtualAddress: number;
    sizeOfRawData: number;
    pointerToRawData: number;
    characteristics: number;
  }>;
  sections[1] = {
    name: ".text",
    virtualSize: SECTION_VIRTUAL_SIZE,
    virtualAddress: SECTION_RVA,
    sizeOfRawData: SECTION_RAW_SIZE,
    pointerToRawData: 0x200,
    characteristics: 0x60000020
  };

  assert.strictEqual(computeEntrySection({ AddressOfEntryPoint: 0x3000 }, sections), null);
});
