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

const fillFormerPageBudget = (visit: ReturnType<typeof createAarch64VisitedTracker>): void => {
  // Regression boundary: the former 32 MiB limit allowed 16384 pages of 64 KiB addresses.
  for (let index = 0; index < 16384; index++) visit(BigInt(index) * 65536n);
};

void test("tracking grows past the former page budget without forgetting visited addresses", () => {
  const visit = createAarch64VisitedTracker();
  fillFormerPageBudget(visit);

  assert.equal(visit(16384n * 65536n), "new");
  assert.equal(visit(16384n * 65536n), "seen");
  assert.equal(visit(0n), "seen");
  assert.equal(visit(16383n * 65536n), "seen");
});
