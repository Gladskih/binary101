import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createElfSysvHashSymbolValidator, extendElfSysvHash, validateElfSysvHashChains
} from "../../../../analyzers/elf/sysv-hash.js";
import type { ElfHashTable } from "../../../../analyzers/elf/hash-types.js";

const sysv = (buckets: number[], chains: number[]): Extract<ElfHashTable, { kind: "sysv" }> =>
  ({ kind: "sysv", offset: 0, buckets, chains, issues: [] });

for (const [buckets, chains, warning] of [
  [[], [], "System V hash has no buckets."],
  [[2], [0, 0], "Hash symbol index 2 is outside the chain table."],
  [[1], [0, 1], "Hash chain has a cycle at symbol #1."],
  [[1, 2], [0, 3, 3, 0], "System V hash buckets 0 and 1 share the chain at symbol #3."]
] as const) {
  void test(warning, () => {
    const table = sysv([...buckets], [...chains]);

    validateElfSysvHashChains(table);

    assert.deepEqual(table.issues, [warning]);
    assert.equal(createElfSysvHashSymbolValidator([table]), undefined);
  });
}

void test("uses the gABI hash for raw bytes with high-bit folding across chunks", () => {
  const first = extendElfSysvHash(0, Uint8Array.of(0xff, 0xfe, 0xfd, 0xfc));
  const whole = extendElfSysvHash(first, Uint8Array.of(0xfb, 0xfa, 0xf9, 0xf8));

  // gABI 8.5 listing 8.2, the high nibble is XORed into bits 4–7.
  assert.equal(whole, 0x0edcca78);
});

void test("checks only symbols reached by the hash table and reports the first mismatch", () => {
  const table = sysv([1, 0], [0, 2, 0]);
  const unvisited = sysv([0], [0, 0]);
  validateElfSysvHashChains(table);
  validateElfSysvHashChains(unvisited);
  const validator = createElfSysvHashSymbolValidator([unvisited, table]);
  assert.ok(validator);

  validator.check(3, 1);
  validator.check(1, 2);
  validator.check(2, 1);
  validator.check(1, 1);

  assert.equal(validator.claims(2), true);
  assert.equal(validator.claims(3), false);
  assert.deepEqual(table.issues,
    ["System V hash bucket 0 contains dynamic symbol #2, whose name hashes to bucket 1."]);
  assert.deepEqual(unvisited.issues, []);
});

void test("uses only validated bucket ownership for the associated tables", () => {
  const first = sysv([1], [0, 0]);
  const second = sysv([2], [0, 0, 0]);
  assert.equal(createElfSysvHashSymbolValidator([first]), undefined);
  validateElfSysvHashChains(first);
  validateElfSysvHashChains(second);

  const validator = createElfSysvHashSymbolValidator([first, second]);

  assert.equal(validator?.claims(1), true);
  assert.equal(validator?.claims(2), true);
});
