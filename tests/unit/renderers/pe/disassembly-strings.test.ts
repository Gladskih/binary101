"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderInstructionSets } from "../../../../renderers/pe/disassembly.js";
import {
  PE_DISASSEMBLY_STRING_INLINE_LIMIT,
  PE_DISASSEMBLY_STRING_PAGE_SIZE
} from "../../../../renderers/pe/disassembly-strings.js";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import { IMAGE_FILE_MACHINE_AMD64 } from "../../../../analyzers/coff/machine.js";
import { inlinePeSectionName } from "../../../../analyzers/pe/sections/name.js";

const STRING_RVA = 0x3000;
const ROWS_AFTER_INLINE_LIMIT = PE_DISASSEMBLY_STRING_INLINE_LIMIT + 1;

const createPe = (overrides: Partial<PeWindowsParseResult> = {}): PeWindowsParseResult =>
  ({
    coff: { Machine: IMAGE_FILE_MACHINE_AMD64 },
    opt: { AddressOfEntryPoint: 0x1000 },
    sections: [],
    ...overrides
  }) as unknown as PeWindowsParseResult;

void test("renderInstructionSets renders code string references", () => {
  const pe = createPe({
    sections: [{
      name: inlinePeSectionName(".rdata"),
      virtualAddress: STRING_RVA,
      virtualSize: 0x80,
      sizeOfRawData: 0x80,
      pointerToRawData: 0x200,
      characteristics: 0
    }]
  });
  pe.disassembly = {
    bitness: 64,
    bytesSampled: 4,
    bytesDecoded: 4,
    instructionCount: 2,
    invalidInstructionCount: 0,
    directIatReferences: [],
    codeStringReferences: [{
      rva: STRING_RVA,
      encoding: "ascii",
      byteLength: 14,
      text: `https://<host>`,
      instructionRvas: [0x1000, 0x1010]
    }],
    apiStringReferences: [],
    issues: [],
    instructionSets: []
  };
  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");
  assert.ok(html.includes("Code-referenced strings (1)"));
  assert.ok(html.includes(".rdata"));
  assert.ok(html.includes("0x00001000, 0x00001010"));
  assert.ok(html.includes("https://&lt;host>"));
});

void test("renderInstructionSets pages large code string reference tables", () => {
  const pe = createPe({
    sections: [{
      name: inlinePeSectionName(".rdata"),
      virtualAddress: STRING_RVA,
      virtualSize: 0x8000,
      sizeOfRawData: 0x8000,
      pointerToRawData: 0x200,
      characteristics: 0
    }]
  });
  pe.disassembly = {
    bitness: 64,
    bytesSampled: 4,
    bytesDecoded: 4,
    instructionCount: 2,
    invalidInstructionCount: 0,
    directIatReferences: [],
    codeStringReferences: Array.from({ length: ROWS_AFTER_INLINE_LIMIT }, (_, index) => ({
      rva: STRING_RVA + index * 0x10,
      encoding: "ascii",
      byteLength: 12,
      text: `value-${String(ROWS_AFTER_INLINE_LIMIT - index).padStart(4, "0")}`,
      instructionRvas: [0x1000 + index]
    })),
    apiStringReferences: [],
    issues: [],
    instructionSets: []
  };
  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(html.includes(`Code-referenced strings (${ROWS_AFTER_INLINE_LIMIT})`));
  assert.ok(html.includes("data-paged-sortable-table-root"));
  assert.ok(html.includes(`Showing 1-${PE_DISASSEMBLY_STRING_PAGE_SIZE}`));
  assert.ok(html.includes("value-1001"));
  assert.ok(!html.includes("value-0001"));
});
