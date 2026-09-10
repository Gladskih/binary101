import assert from "node:assert/strict";
import { test } from "node:test";
import { validateElfHashTable } from "../../../../analyzers/elf/hash-validation.js";
import type { ElfHashTable } from "../../../../analyzers/elf/hash-types.js";

void test("rejects invalid GNU bloom dimensions, shift, buckets and termination", () => {
  const table: ElfHashTable = { kind: "gnu", offset: 0, symbolOffset: 2, bloomShift: 32,
    bloom: [], buckets: [1, 2, 2], chains: [2], issues: [] };
  validateElfHashTable(table);
  assert.match(table.issues.join(" "), /power of two/);
  assert.match(table.issues.join(" "), /shift/);
  assert.match(table.issues.join(" "), /outside/);
  assert.match(table.issues.join(" "), /overlaps/);
  assert.match(table.issues.join(" "), /terminated/);
});

void test("accepts empty buckets and convergent System V chains", () => {
  const table: ElfHashTable = { kind: "sysv", offset: 0, buckets: [0, 1, 1], chains: [0, 0], issues: [] };
  validateElfHashTable(table);
  assert.deepEqual(table.issues, []);
});
