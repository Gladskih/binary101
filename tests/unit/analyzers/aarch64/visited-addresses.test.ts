import assert from "node:assert/strict";
import { test } from "node:test";
import { createAarch64VisitedTracker } from "../../../../analyzers/aarch64/visited-addresses.js";

void test("visited bitmap distinguishes every bit, page boundary and high address", () => {
  const visit = createAarch64VisitedTracker();

  assert.equal(visit(0n), "new");
  assert.equal(visit(4n), "new");
  assert.equal(visit(28n), "new");
  assert.equal(visit(32n), "new");
  assert.equal(visit(65532n), "new");
  assert.equal(visit(65536n), "new");
  assert.equal(visit(0xfffffffffffffffen - 2n), "new");
  assert.equal(visit(0n), "seen");
  assert.equal(visit(4n), "seen");
  assert.equal(visit(65532n), "seen");
  assert.equal(visit(65536n), "seen");
  assert.equal(visit(-4n), "invalid");
  assert.equal(visit(1n), "invalid");
  assert.equal(visit(1n << 64n), "invalid");
});

void test("tracking has a bounded memory budget instead of exceeding Set capacity", () => {
  const visit = createAarch64VisitedTracker(1);

  assert.equal(visit(0n), "new");
  assert.equal(visit(65532n), "new");
  assert.equal(visit(65536n), "limit");
  assert.equal(visit(0n), "seen");
  assert.equal(createAarch64VisitedTracker(NaN)(0n), "limit");
  assert.equal(createAarch64VisitedTracker(0)(0n), "limit");
});
