"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import type { MsvcRttiImage } from "../../../../../analyzers/pe/msvc-rtti/image.js";
import { parseRelocationBackedVftable } from "../../../../../analyzers/pe/msvc-rtti/vftable.js";

const createImage = (overrides: Partial<MsvcRttiImage> = {}): MsvcRttiImage => ({
  availableDataSize: () => 8,
  isDataRange: () => true,
  isExecutableRva: () => true,
  preferredVaToRva: value => Number(value),
  readData: async () => new DataView(new ArrayBuffer(8)),
  readPreferredVaRva: async () => 0x1000,
  ...overrides
});

void test("parseRelocationBackedVftable enforces the 4096-slot hard limit", async () => {
  const locatorSlotRva = 0x2000;
  const sites = new Set<number>();
  for (let index = 1; index <= 4097; index += 1) sites.add(locatorSlotRva + index * 8);

  const parsed = await parseRelocationBackedVftable(
    createImage(),
    sites,
    locatorSlotRva,
    0x3000
  );

  assert.ok(parsed);
  assert.equal(parsed.functionTargetRvas.length, 4096);
});

void test("parseRelocationBackedVftable requires mapped data for the first slot", async () => {
  const parsed = await parseRelocationBackedVftable(
    createImage({ isDataRange: () => false }),
    new Set([0x2008]),
    0x2000,
    0x3000
  );

  assert.equal(parsed, null);
});

void test("parseRelocationBackedVftable requires a DIR64 first slot", async () => {
  const parsed = await parseRelocationBackedVftable(
    createImage(),
    new Set(),
    0x2000,
    0x3000
  );

  assert.equal(parsed, null);
});

void test("parseRelocationBackedVftable stops before an invalid preferred VA", async () => {
  let readCount = 0;
  const parsed = await parseRelocationBackedVftable(
    createImage({
      readPreferredVaRva: async () => (++readCount === 1 ? 0x1000 : null)
    }),
    new Set([0x2008, 0x2010]),
    0x2000,
    0x3000
  );

  assert.deepEqual(parsed?.functionTargetRvas, [0x1000]);
});

void test("parseRelocationBackedVftable stops before a non-executable target", async () => {
  const parsed = await parseRelocationBackedVftable(
    createImage({
      isExecutableRva: rva => rva !== 0x1010,
      readPreferredVaRva: async rva => rva === 0x2008 ? 0x1000 : 0x1010
    }),
    new Set([0x2008, 0x2010]),
    0x2000,
    0x3000
  );

  assert.deepEqual(parsed?.functionTargetRvas, [0x1000]);
});

void test("parseRelocationBackedVftable rejects RVA overflow after the locator slot", async () => {
  const parsed = await parseRelocationBackedVftable(
    createImage(),
    new Set([0xffff_ffff]),
    0xffff_fff8,
    0x3000
  );

  assert.equal(parsed, null);
});
