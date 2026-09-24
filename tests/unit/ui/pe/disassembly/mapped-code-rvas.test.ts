"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeWindowsParseResult } from "../../../../../analyzers/pe/core/parse-result.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import { isMappedExecutablePeRva } from "../../../../../ui/pe-disassembly-mapped-code.js";

const pe = ({
  opt: { SizeOfImage: 0x4000 },
  sections: [{ name: inlinePeSectionName(".text"), virtualAddress: 0x1000,
    virtualSize: 0x2000, sizeOfRawData: 0x1000, pointerToRawData: 0x200,
    characteristics: 0x20000000 }], // IMAGE_SCN_MEM_EXECUTE.
  rvaToOff: (rva: number) => rva - 0xe00
}) as PeWindowsParseResult;

void test("isMappedExecutablePeRva accepts file-backed code and rejects virtual tails", () => {
  assert.equal(isMappedExecutablePeRva(pe, 0x2000, 0x1010), true);
  assert.equal(isMappedExecutablePeRva(pe, 0x2000, 0x2010), false);
  assert.equal(isMappedExecutablePeRva(pe, 0x2000, 0x3000), false);
  assert.equal(isMappedExecutablePeRva(pe, 0x2000, -1), false);
});
