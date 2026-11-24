import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readCrinklerLayout, readCrinklerTinyLayout
} from "../../../../../analyzers/pe/packers/crinkler-layout.js";
import { CRINKLER_30_TINY } from "../../../../fixtures/crinkler-bytes.js";

// Header offsets are from the compact Tiny Header layout in header22_1k.asm.
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/modules/header22_1k.asm
for (const [field, offset] of [
  ["MZ", 0], ["version marker", 2], ["PE", 4], ["machine", 8], ["section count", 10],
  ["bit-test opcode", 12], ["optional size", 24], ["optional magic", 28], ["entry RVA", 44],
  ["PE offset and section alignment", 60], ["entry opcode", 100]
] as const) {
  void test(`Crinkler layout rejects an inconsistent ${field}`, () => {
    const bytes = Buffer.from(CRINKLER_30_TINY, "hex");
    bytes[offset] = (bytes[offset] ?? 0) ^ 0xff;
    assert.equal(readCrinklerLayout(bytes), null);
  });
}

void test("Crinkler layout requires the complete fixed stub prefix", () => {
  assert.equal(readCrinklerLayout(Buffer.from(CRINKLER_30_TINY, "hex").subarray(0, 64)), null);
});

void test("Tiny Header model parameters require both the boost and end-position instructions", () => {
  const bytes = Buffer.from(CRINKLER_30_TINY, "hex");
  const layout = readCrinklerLayout(bytes);
  assert.ok(layout);
  // The 3.0b fixture has mov cl,imm8 at 0xa8 and cmp di,imm16 at 0xc6.
  const badBoost = Buffer.from(bytes);
  badBoost[0xa8] = 0;
  const badSize = Buffer.from(bytes);
  badSize[0xc6] = 0;
  assert.equal(readCrinklerTinyLayout(badBoost, layout), null);
  assert.equal(readCrinklerTinyLayout(badSize, layout), null);
});
