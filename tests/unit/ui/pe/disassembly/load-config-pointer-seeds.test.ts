import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import type { PeParseResult } from "../../../../../analyzers/pe/index.js";
import type { PeWindowsParseResult } from "../../../../../analyzers/pe/core/parse-result.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import { collectLoadConfigPointerSeeds } from
  "../../../../../ui/pe-disassembly-load-config-pointer-seeds.js";

const IMAGE_BASE = 0x400000n;

const createPe = (): PeParseResult => ({
  rvaToOff: (rva: number) => rva,
  sections: [{
    name: inlinePeSectionName(".text"), virtualAddress: 0x1000,
    virtualSize: 0x1000, sizeOfRawData: 0x1000, pointerToRawData: 0x1000,
    characteristics: 0x20000000 // Microsoft PE IMAGE_SCN_MEM_EXECUTE.
  }]
}) as unknown as PeParseResult;

void test("collectLoadConfigPointerSeeds reads RF routine and PE32 pointer slots", async () => {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(8, Number(IMAGE_BASE + 0x1100n), true);
  const reader = createFileRangeReader(new File([bytes], "rf-pe32"), 0, bytes.length);
  const loadcfg = {
    GuardRFFailureRoutine: IMAGE_BASE + 0x1200n,
    GuardRFFailureRoutineFunctionPointer: IMAGE_BASE + 8n
  } as PeWindowsParseResult["loadcfg"];

  const seeds = await collectLoadConfigPointerSeeds(reader, createPe(), IMAGE_BASE, 4, loadcfg);

  assert.deepEqual(seeds, [
    { source: "GuardRF failure routine", rvas: [0x1200] },
    { source: "GuardRF failure function", rvas: [0x1100] }
  ]);
});

void test("collectLoadConfigPointerSeeds skips invalid and truncated references", async () => {
  const bytes = new Uint8Array(16);
  const reader = createFileRangeReader(new File([bytes], "rf-truncated"), 0, bytes.length);
  const loadcfg = {
    GuardRFFailureRoutine: IMAGE_BASE + 0x3000n,
    GuardRFFailureRoutineFunctionPointer: IMAGE_BASE + 12n,
    GuardRFVerifyStackPointerFunctionPointer: IMAGE_BASE - 1n
  } as PeWindowsParseResult["loadcfg"];

  const seeds = await collectLoadConfigPointerSeeds(reader, createPe(), IMAGE_BASE, 8, loadcfg);

  assert.deepEqual(seeds, []);
  assert.deepEqual(await collectLoadConfigPointerSeeds(reader, createPe(), IMAGE_BASE, 8, null), []);
});
