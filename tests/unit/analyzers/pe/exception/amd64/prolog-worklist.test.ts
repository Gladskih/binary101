import assert from "node:assert/strict";
import { test } from "node:test";
import { orderedAmd64PrologRanges } from "../../../../../../analyzers/pe/exception/amd64/prolog-worklist.js";

const ranges = (rva: number, begins: number[]) => begins.map(begin =>
  ({ begin, end: begin + 1, sourceUnwindInfoRva: rva }));

void test("merges interleaved owner lists without losing unwind provenance", () => {
  const groups = new Map([[1, ranges(1, [1, 4, 8])], [2, ranges(2, [2, 3, 7])],
    [3, ranges(3, [5, 6])]]);
  const result = [...orderedAmd64PrologRanges(groups)];
  assert.deepEqual(result.map(work => work.range.begin), [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.deepEqual(result.map(work => work.rva), [1, 2, 2, 1, 3, 3, 2, 1]);
});

void test("handles empty, repeated and unsorted ranges without mutating source order", () => {
  const entries = ranges(1, [4, 1, 1]);
  const groups = new Map([[1, entries], [2, ranges(2, [])]]);
  assert.deepEqual([...orderedAmd64PrologRanges(groups)].map(work => work.range.begin), [1, 1, 4]);
  assert.deepEqual(entries.map(range => range.begin), [4, 1, 1]);
  assert.deepEqual([...orderedAmd64PrologRanges(new Map())], []);
});

void test("maintains ordering over a wider heap and extreme validated RVA values", () => {
  const groups = new Map(Array.from({ length: 32 }, (_, index) =>
    [index, ranges(index, [index * 3 + 2, index * 3, index * 3 + 1])]));
  groups.set(33, ranges(33, [0xffffffff]));
  const result = [...orderedAmd64PrologRanges(groups)];
  assert.deepEqual(result.map(work => work.range.begin),
    [...Array.from({ length: 96 }, (_, index) => index), 0xffffffff]);
});
