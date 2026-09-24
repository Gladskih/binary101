"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeWindowsParseResult } from "../../../../../analyzers/pe/core/parse-result.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import { collectFunctionOverrideEntrypoints } from
  "../../../../../ui/pe-disassembly-function-override-seeds.js";

const makePe = (): PeWindowsParseResult => ({
  opt: { SizeOfImage: 0x5000 },
  sections: [{ name: inlinePeSectionName(".text"), virtualAddress: 0x1000,
    virtualSize: 0x2000, sizeOfRawData: 0x2000, pointerToRawData: 0x200,
    characteristics: 0x20000000 }], // IMAGE_SCN_MEM_EXECUTE in Windows SDK winnt.h.
  rvaToOff: (rva: number) => rva - 0xe00,
  loadcfg: { dynamicRelocations: { version: 1, dataSize: 0, entries: [{
    kind: "v1", symbol: 7n, baseRelocSize: 0, availableBytes: 0,
    fixup: { functions: [
      { originalRva: 0x1010, bddOffset: 0, overridingRvas: [0x2010, 0x2010],
        baseRelocations: [] },
      { originalRva: 0x3010, bddOffset: 0, overridingRvas: [0x4010],
        baseRelocations: [] }
    ], bddInfos: [] }
  }] } }
}) as unknown as PeWindowsParseResult;

void test("collectFunctionOverrideEntrypoints keeps only mapped executable functions", () => {
  const pe = makePe();

  const groups = collectFunctionOverrideEntrypoints(pe, 0x2000);

  assert.deepEqual(groups, [
    { source: "DVRT original function", rvas: [0x1010] },
    { source: "DVRT override function", rvas: [0x2010] }
  ]);
});

void test("collectFunctionOverrideEntrypoints rejects addresses outside file data", () => {
  const pe = makePe();

  const groups = collectFunctionOverrideEntrypoints(pe, 0x211);

  assert.deepEqual(groups, [{ source: "DVRT original function", rvas: [0x1010] }]);
});
