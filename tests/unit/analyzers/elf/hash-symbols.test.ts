import assert from "node:assert/strict";
import { test } from "node:test";
import { validateElfHashSymbols } from "../../../../analyzers/elf/hash-symbols.js";
import type { ElfHashTable } from "../../../../analyzers/elf/hash-types.js";
import type { ElfDynamicSymbolInfo } from "../../../../analyzers/elf/types.js";

const symbols: ElfDynamicSymbolInfo = { total: 2, issues: [], importSymbols: [], exportSymbols: [
  { index: 1, name: "a", value: 1n, size: 1n, bind: 1, bindName: "GLOBAL", type: 2,
    typeName: "FUNC", visibility: 0, visibilityName: "DEFAULT", shndx: 1 }
] };
// GNU hash("a") = 5381 * 33 + 97 = 177670; bit 6 and (177670 >> 5) % 64 = 48.
const table = (): ElfHashTable => ({ kind: "gnu", offset: 0, symbolOffset: 1,
  bloomShift: 5, bloom: [(1n << 6n) | (1n << 48n)], buckets: [1], chains: [177671], issues: [] });

void test("verifies GNU symbol hashes and Bloom membership", () => {
  const hash = table();
  validateElfHashSymbols([hash], symbols, 64);
  assert.deepEqual(hash.issues, []);
});

void test("warns on incorrect stored hash and Bloom rejection", () => {
  const hash = table();
  hash.chains[0] = 1;
  validateElfHashSymbols([hash], symbols, 64);
  assert.match(hash.issues.join(" "), /does not match/);
  const bloom = table();
  assert.equal(bloom.kind, "gnu");
  Object.assign(bloom, { bloom: [0n] });
  validateElfHashSymbols([bloom], symbols, 64);
  assert.match(bloom.issues.join(" "), /reject/);
});

void test("ignores absent symbols and unhashed indices", () => {
  const hash = table();
  validateElfHashSymbols([hash], null, 64);
  validateElfHashSymbols([hash], { ...symbols,
    exportSymbols: symbols.exportSymbols.map(symbol => ({ ...symbol, index: 0 })) }, 64);
  assert.deepEqual(hash.issues, []);
});
