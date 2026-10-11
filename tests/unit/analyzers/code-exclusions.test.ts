import assert from "node:assert/strict";
import { test } from "node:test";
import { createCodeExclusionIndex } from "../../../analyzers/code-exclusions.js";

void test("merged half-open ranges protect interiors and crossing instructions", () => {
  const ranges = [{ start: 20n, end: 25n }, { start: 10n, end: 16n },
    { start: 15n, end: 20n }, { start: 30n, end: 31n }];
  const overlap = createCodeExclusionIndex(ranges);

  assert.equal(overlap(9n, 1), null);
  assert.equal(overlap(9n, 2), 10n);
  assert.equal(overlap(14n, 3), 14n);
  assert.equal(overlap(24n, 1), 24n);
  assert.equal(overlap(25n, 5), null);
  assert.equal(overlap(25n, 6), 30n);
  assert.equal(overlap(31n, 1), null);
  assert.deepEqual(ranges[1], { start: 10n, end: 16n });
});

void test("invalid bounds and lengths never exclude unrelated addresses", () => {
  const overlap = createCodeExclusionIndex([{ start: -1n, end: 1n }, { start: 4n, end: 4n },
    { start: 10n, end: 9n }, { start: 0n, end: 0x1_0000_0000_0000_0001n }]);

  assert.equal(overlap(0n, 10), null);
  assert.equal(overlap(1n, -1), null);
  assert.equal(overlap(1n, 0), null);
  assert.equal(overlap(1n, Number.POSITIVE_INFINITY), null);
  assert.equal(createCodeExclusionIndex()(0n, 1), null);
  const populated = createCodeExclusionIndex([{ start: 0n, end: 20n }]);
  assert.equal(populated(0n, 1), 0n);
  assert.equal(populated(10n, 0), null);
  assert.equal(populated(10n, -1), null);
  assert.equal(populated(10n, Number.NaN), null);
  assert.equal(populated(10n, Number.POSITIVE_INFINITY), null);
});

void test("multiple disjoint intervals stay sorted with duplicate and contained intervals", () => {
  const overlap = createCodeExclusionIndex([{ start: 50n, end: 60n },
    { start: 20n, end: 30n }, { start: 40n, end: 45n }, { start: 0n, end: 10n },
    { start: 20n, end: 25n }, { start: 3n, end: 8n }, { start: 50n, end: 60n }]);

  assert.equal(overlap(12n, 1), null);
  assert.equal(overlap(28n, 2), 28n);
  assert.equal(overlap(30n, 10), null);
  assert.equal(overlap(39n, 2), 40n);
  assert.equal(overlap(49n, 2), 50n);
  assert.equal(overlap(60n, 1), null);
});

void test("full-width addresses remain exact and adjacent intervals merge", () => {
  const overlap = createCodeExclusionIndex([{ start: 0xffff_ffff_ffff_fff0n,
    end: 0xffff_ffff_ffff_fff4n }, { start: 0xffff_ffff_ffff_fff4n,
    end: 0x1_0000_0000_0000_0000n }]);

  assert.equal(overlap(0xffff_ffff_ffff_fff8n, 4), 0xffff_ffff_ffff_fff8n);
});
