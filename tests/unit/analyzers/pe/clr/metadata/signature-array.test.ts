"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseArrayShape } from "../../../../../../analyzers/pe/clr/signature-array.js";
import { SignatureCursor } from "../../../../../../analyzers/pe/clr/signature-cursor.js";

// ECMA-335 II.23.2.13 ArrayShape encodes rank, sizes and signed lower bounds.
for (const [bytes, expected] of [
  [[2, 0, 0], "[rank 2; sizes (); lower bounds ()]"], [[1, 1, 3, 0], "[size 3]"], [[1, 0, 1, 4], "[2...]"],
  [[1, 1, 0, 1, 0], "[0...-1]"], [[1, 1, 3, 1, 0x7f], "[-1...1]"]
] as const) {
  void test(`array shape ${bytes.join(",")}`, () => {
    const issues: string[] = [];
    assert.equal(parseArrayShape(new SignatureCursor(Uint8Array.from(bytes), issues, "Array")), expected);
    assert.deepEqual(issues, []);
  });
}

for (const bytes of [
  [], [0], [65], [1], [1, 0], [1, 2, 0, 0, 0], [1, 0, 2, 0, 0],
  [1, 1, 0xff, 0], [1, 0, 1, 0xff], [1, 0xdf, 0xff, 0xff, 0xff]
]) {
  void test(`malformed array shape ${bytes.join(",")} returns a warning`, () => {
    const issues: string[] = [];
    assert.equal(parseArrayShape(new SignatureCursor(Uint8Array.from(bytes), issues, "Array")), null);
    assert.equal(issues.length, 1);
  });
}

void test("preserves a large rank using compact notation rather than rejecting its metadata", () => {
  const issues: string[] = [];
  assert.equal(parseArrayShape(new SignatureCursor(Uint8Array.of(65, 0, 0), issues, "Array")),
    "[rank 65; sizes (); lower bounds ()]");
  assert.deepEqual(issues, []);
});

void test("retains a large array's explicitly declared sizes and bounds", () => {
  assert.equal(parseArrayShape(new SignatureCursor(Uint8Array.of(65, 1, 3, 1, 0x7f), [], "Large")),
    "[rank 65; sizes (3); lower bounds (-1)]");
  assert.equal(parseArrayShape(new SignatureCursor(Uint8Array.of(64, 0, 0), [], "Boundary")),
    "[rank 64; sizes (); lower bounds ()]");
});

void test("distinguishes invalid rank and counts from truncation in diagnostics", () => {
  const rankIssues: string[] = [];
  const sizeIssues: string[] = [];
  const boundIssues: string[] = [];
  assert.equal(parseArrayShape(new SignatureCursor(Uint8Array.of(0, 0, 0), rankIssues, "Rank")), null);
  assert.match(rankIssues[0] ?? "", /rank is zero/);
  parseArrayShape(new SignatureCursor(Uint8Array.of(1, 2, 0, 0, 0), sizeIssues, "Sizes"));
  assert.match(sizeIssues[0] ?? "", /size count exceeds its rank/);
  parseArrayShape(new SignatureCursor(Uint8Array.of(1, 0, 2, 0, 0), boundIssues, "Bounds"));
  assert.match(boundIssues[0] ?? "", /lower-bound count exceeds its rank/);
});
