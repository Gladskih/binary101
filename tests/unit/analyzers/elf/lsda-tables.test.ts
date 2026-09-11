import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfLsdaCallSites, readElfLsdaTypes } from "../../../../analyzers/elf/lsda-tables.js";
import { lsdaFixture } from "../../../fixtures/elf-lsda.js";

void test("reads call-site offsets and rejects relative encodings", async () => {
  const { result, cursorAt } = lsdaFixture([1, 2, 3, 0]);
  await readElfLsdaCallSites(cursorAt(0), 8, result);
  assert.deepEqual(result.callSites, [{ start: 1n, length: 2n, landingPad: 3n, action: 0n }]);
  result.callSiteEncoding = 0x11;
  await readElfLsdaCallSites(cursorAt(0), 8, result);
  assert.match(result.issues.join(" "), /encoding/);
});

void test("reports overlapping call sites and partial records", async () => {
  const { result, cursorAt } = lsdaFixture([1, 2, 3, 0, 2, 2, 3, 0, 1]);
  await readElfLsdaCallSites(cursorAt(0), 8, result);
  assert.match(result.issues.join(" "), /overlapping/);
  assert.match(result.issues.join(" "), /Truncated/);
});

void test("reads exception specification index lists and reverse type pointers", async () => {
  const { result, cursorAt } = lsdaFixture([0, 16, 0, 0, 1, 0]);
  result.typeEncoding = 3;
  result.actions = [{ offset: 0, typeFilter: -1n, nextOffset: 0n }];
  await readElfLsdaTypes(cursorAt, 4, 8, result);
  assert.deepEqual(result.specifications, [{ filter: -1n, typeIndices: [1n] }]);
  assert.deepEqual(result.types, [{ index: 1n, pointer: { address: 4096n, indirect: false } }]);
  assert.deepEqual(result.issues, []);
});

void test("reports missing type table, unsupported reverse encoding and excessive type indices", async () => {
  const { result, cursorAt } = lsdaFixture([0, 0, 0, 0]);
  result.actions = [{ offset: 0, typeFilter: 2n, nextOffset: 0n }];
  await readElfLsdaTypes(cursorAt, null, 8, result);
  assert.match(result.issues.join(" "), /missing/);
  result.typeEncoding = 1;
  await readElfLsdaTypes(cursorAt, 4, 8, result);
  assert.match(result.issues.join(" "), /fixed-width/);
  result.typeEncoding = 3;
  await readElfLsdaTypes(cursorAt, 4, 8, result);
  assert.match(result.issues.join(" "), /outside/);
});
