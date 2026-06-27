"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderInstructionSets } from "../../../../renderers/pe/disassembly.js";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import { inlinePeSectionName } from "../../../../analyzers/pe/sections/name.js";

const STRING_RVA = 0x3000;

const createPe = (overrides: Partial<PeWindowsParseResult> = {}): PeWindowsParseResult =>
  ({
    coff: { Machine: 0x8664 },
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
