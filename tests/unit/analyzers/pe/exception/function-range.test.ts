import assert from "node:assert/strict";
import { test } from "node:test";
import { isValidFunctionRange, isMappedFunctionBegin } from "../../../../../analyzers/pe/exception/function-range.js";

void test("Implicit function lengths allow the exclusive end of the 32-bit RVA space", () => {
  assert.equal(isValidFunctionRange(0xfffffffc, 4, rva => rva - 0xfffffffc, 4), true);
});

void test("Function ranges reject a logical gap between mapped endpoints", () => {
  assert.equal(isValidFunctionRange(4, 4, rva => rva === 5 ? null : rva - 4, 4), false);
});

void test("Function ranges accept contiguous RVAs with fragmented physical storage", () => {
  assert.equal(isValidFunctionRange(4, 4, rva => rva < 6 ? rva - 4 : rva + 2, 10), true);
});

for (const [begin, length] of [[0, 4], [-1, 4], [0.5, 4], [NaN, 4], [Infinity, 4],
  [0x100000000, 4], [4, 0], [4, -1], [4, 0.5], [4, NaN], [4, Infinity], [0xfffffffc, 8]] as const) {
  void test(`Function ranges reject invalid coordinates ${begin}, ${length}`, () => {
    assert.equal(isValidFunctionRange(begin, length, rva => rva, 32), false);
  });
}

for (const mapped of [null, -1, 0.5, NaN, Infinity, 4]) {
  void test(`Function ranges reject invalid physical offset ${mapped}`, () => {
    assert.equal(isValidFunctionRange(4, 4, () => mapped, 4), false);
    assert.equal(isMappedFunctionBegin(4, () => mapped, 4), false);
  });
}

for (const begin of [0, -1, 0.5, NaN, Infinity, 0x100000000]) {
  void test(`Function starts reject invalid RVA ${begin}`, () => {
    assert.equal(isMappedFunctionBegin(begin, () => 0, 4), false);
  });
}

void test("Function starts accept physical offset zero and reject unknown mappings", () => {
  assert.equal(isMappedFunctionBegin(4, () => 0, 4), true);
  assert.equal(isValidFunctionRange(4, 4, () => null, 4), false);
});
