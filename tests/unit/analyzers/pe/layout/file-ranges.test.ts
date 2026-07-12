"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { subtractFileRanges } from "../../../../../analyzers/pe/layout/file-ranges.js";

void test("subtractFileRanges splits a range around covered bytes", () => {
  assert.deepEqual(
    subtractFileRanges([{ start: 10, end: 30 }], [{ start: 15, end: 20 }]),
    [{ start: 10, end: 15 }, { start: 20, end: 30 }]
  );
});

void test("subtractFileRanges removes fully covered ranges", () => {
  assert.deepEqual(
    subtractFileRanges([{ start: 10, end: 20 }], [{ start: 0, end: 30 }]),
    []
  );
});

void test("subtractFileRanges normalizes overlapping inputs and coverage", () => {
  assert.deepEqual(
    subtractFileRanges(
      [{ start: 20, end: 40 }, { start: 10, end: 30 }],
      [{ start: 12, end: 18 }, { start: 15, end: 25 }, { start: 35, end: 50 }]
    ),
    [{ start: 10, end: 12 }, { start: 25, end: 35 }]
  );
});

void test("subtractFileRanges ignores empty and disjoint coverage", () => {
  assert.deepEqual(
    subtractFileRanges(
      [{ start: 10, end: 20 }],
      [{ start: 5, end: 5 }, { start: 25, end: 30 }]
    ),
    [{ start: 10, end: 20 }]
  );
});
