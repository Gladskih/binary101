import assert from "node:assert/strict";
import { test } from "node:test";
import { createEhFunctionCoverage } from "../../../../../analyzers/pe/msvc-eh/function-coverage.js";
import { createEmptyExceptionDirectory } from "../../../../../analyzers/pe/exception/types.js";
import type { PeExceptionDirectory } from "../../../../../analyzers/pe/exception/types.js";

void test("runtime coverage merges unsorted overlapping ranges and includes end labels", () => {
  const covers = createEhFunctionCoverage({ ...createEmptyExceptionDirectory([], "amd64"),
    functionCount: 3, beginRvas: [0x1020, 0x1000, 0x1008], rangeLengths: [16, 16, 16] });
  assert.ok(covers);
  assert.equal(covers(0x1000), true);
  assert.equal(covers(0x1018), true);
  assert.equal(covers(0x1019), false);
  assert.equal(covers(0x1020), true);
  assert.equal(covers(0x1030), true);
  assert.equal(covers(0x1031), false);
  assert.equal(covers(0xfff), false);
});

void test("incomplete or contradictory runtime inventories do not authorize absence claims", () => {
  const base = { ...createEmptyExceptionDirectory([], "amd64"), functionCount: 1,
    beginRvas: [0x1000], rangeLengths: [16] };
  const missingLengths: PeExceptionDirectory = { ...base };
  delete missingLengths.rangeLengths;
  assert.equal(createEhFunctionCoverage(null), null);
  assert.equal(createEhFunctionCoverage({ ...base, invalidEntryCount: 1 }), null);
  assert.equal(createEhFunctionCoverage({ ...base, issues: ["truncated"] }), null);
  assert.equal(createEhFunctionCoverage({ ...base, rangeLengths: [] }), null);
  assert.equal(createEhFunctionCoverage(missingLengths), null);
  assert.equal(createEhFunctionCoverage({ ...base, functionCount: 2 }), null);
  assert.equal(createEhFunctionCoverage({ ...base, rangeLengths: [0] }), null);
  assert.equal(createEhFunctionCoverage({ ...base, beginRvas: [0xffffffff] }), null);
});

void test("a valid runtime range cannot hide an invalid neighboring range", () => {
  assert.equal(createEhFunctionCoverage({ ...createEmptyExceptionDirectory([], "amd64"),
    functionCount: 2, beginRvas: [0x1000, 0xffffffff], rangeLengths: [16, 16] }), null);
});

void test("a nested short range cannot hide the remaining extent of its outer owner", () => {
  const covers = createEhFunctionCoverage({ ...createEmptyExceptionDirectory([], "amd64"),
    functionCount: 2, beginRvas: [0x1000, 0x1010], rangeLengths: [0x100, 16] });
  assert.ok(covers);
  assert.equal(covers(0x1080), true);
  assert.equal(covers(0x1100), true);
});

void test("a descending pair preserves both original intervals after sorting", () => {
  const covers = createEhFunctionCoverage({ ...createEmptyExceptionDirectory([], "amd64"),
    functionCount: 2, beginRvas: [0x2000, 0x1000], rangeLengths: [32, 16] });
  assert.ok(covers);
  assert.equal(covers(0x1000), true);
  assert.equal(covers(0x1010), true);
  assert.equal(covers(0x1011), false);
  assert.equal(covers(0x2000), true);
  assert.equal(covers(0x2020), true);
  assert.equal(covers(0x2021), false);
});

void test("nearby IP lookups and backward jumps preserve interval boundaries and gaps", () => {
  const covers = createEhFunctionCoverage({ ...createEmptyExceptionDirectory([], "amd64"),
    functionCount: 2, beginRvas: [0x1000, 0x2000], rangeLengths: [16, 32] });
  assert.ok(covers);
  assert.equal(covers(0x1001), true);
  assert.equal(covers(0x1000), true);
  assert.equal(covers(0xfff), false);
  assert.equal(covers(0x1010), true);
  assert.equal(covers(0x1011), false);
  assert.equal(covers(0x2001), true);
  assert.equal(covers(0x1fff), false);
  assert.equal(covers(0x2020), true);
  assert.equal(covers(0x2021), false);
  assert.equal(covers(0x1002), true);
  assert.equal(covers(0x2002), true);
  assert.equal(covers(NaN), false);
  assert.equal(covers(Infinity), false);
});

void test("an empty complete function inventory never supplies a cached interval", () => {
  const covers = createEhFunctionCoverage({ ...createEmptyExceptionDirectory([], "amd64"), rangeLengths: [] });
  assert.ok(covers);
  assert.equal(covers(0), false);
  assert.equal(covers(0x1000), false);
  assert.equal(covers(NaN), false);
});

void test("an uncached interval includes its exact end on both forward and backward searches", () => {
  const covers = createEhFunctionCoverage({ ...createEmptyExceptionDirectory([], "amd64"),
    functionCount: 2, beginRvas: [0x1000, 0x2000], rangeLengths: [16, 32] });
  assert.ok(covers);
  assert.equal(covers(0x2020), true);
  assert.equal(covers(0x1010), true);
});
