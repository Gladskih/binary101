import assert from "node:assert/strict";
import { test } from "node:test";
import { createRvaRangeReader } from "../../../../analyzers/pe/rva-range-reader.js";
import { createPeRvaFragments } from "../../../helpers/pe-rva-fragments.js";

void test("nested RVA readers use relative addresses across fragmented file data", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 2);
  const reader = createRvaRangeReader(fixture.reader, fixture.mapping, 0x1000, 4);
  assert.equal(reader.size, 4);
  assert.deepEqual([...await reader.readBytes(1, 8)], [2, 3, 4]);
  assert.equal((await reader.read(-1, 4)).byteLength, 0);
  assert.equal((await reader.read(4, 4)).byteLength, 0);
  assert.equal((await reader.read(NaN, 4)).byteLength, 0);
  assert.equal((await reader.read(0, -1)).byteLength, 0);
});

void test("nested readers never turn an overflowing base into a file address", async () => {
  const fixture = createPeRvaFragments(0, Uint8Array.of(1, 2, 3, 4), 2);
  const reader = createRvaRangeReader(fixture.reader, fixture.mapping, 0x100000000, 4);
  assert.equal(reader.size, 0);
  assert.equal((await reader.read(0, 4)).byteLength, 0);
});

void test("a nested reader cannot escape its smaller declared window", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4, 5, 6), 3);
  const reader = createRvaRangeReader(fixture.reader, fixture.mapping, 0x1001, 3);
  assert.deepEqual([...await reader.readBytes(0, 1)], [2]);
  assert.deepEqual([...await reader.readBytes(1, 8)], [3, 4]);
  assert.equal((await reader.read(-1, 1)).byteLength, 0);
  assert.equal((await reader.read(3, 1)).byteLength, 0);
  assert.equal((await reader.read(0.5, 1)).byteLength, 0);
});

void test("nested readers reject invalid lengths before clipping to their window", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 2);
  const reader = createRvaRangeReader(fixture.reader, fixture.mapping, 0x1000, 4);
  assert.equal((await reader.read(0, Infinity)).byteLength, 0);
  assert.equal((await reader.read(0, Number.MAX_SAFE_INTEGER + 1)).byteLength, 0);
  assert.equal((await reader.read(0, 4.5)).byteLength, 0);
});
