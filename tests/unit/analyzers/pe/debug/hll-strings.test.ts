import assert from "node:assert/strict";
import { test } from "node:test";
import { readHllLength, readHllName } from "../../../../../analyzers/pe/debug/hll-strings.js";
import { hllName } from "../../../../fixtures/pe-hll.js";
import { legacyReader } from "../../../../fixtures/pe-legacy-codeview.js";

void test("HLL length prefixes preserve seven high bits and ANSI names across the byte boundary", async () => {
  assert.deepEqual(await readHllLength(legacyReader([0xff, 0xfe]), 0), { size: 32766, end: 2 });
  assert.deepEqual(await readHllName(legacyReader(hllName("X".repeat(300))), 0), { name: "X".repeat(300), end: 302 });
  assert.deepEqual(await readHllName(legacyReader([0]), 0), { name: "", end: 1 });
  await assert.rejects(readHllLength(legacyReader([128]), 0), /bounds/);
  await assert.rejects(readHllName(legacyReader([2, 65]), 0), /bounds/);
});
