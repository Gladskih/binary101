import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfGnuHashSymbolValidator, ELF_GNU_HASH_SEED, extendElfGnuHash } from
  "../../../../analyzers/elf/hash-symbols.js";
import type { ElfHashTable } from "../../../../analyzers/elf/hash-types.js";

// GNU hash("a") = 5381 * 33 + 97 = 177670; bit 6 and (177670 >> 5) % 64 = 48.
const table = (fields: Partial<Extract<ElfHashTable, { kind: "gnu" }>> = {}): ElfHashTable =>
  ({ kind: "gnu", offset: 0, symbolOffset: 1, bloomShift: 5, bloom: [(1n << 6n) | (1n << 48n)],
    buckets: [1], chains: [177671], issues: [], ...fields });

const cases: [Partial<Extract<ElfHashTable, { kind: "gnu" }>>, RegExp | null][] = [
  [{}, null], [{ chains: [1] }, /does not match/], [{ bloom: [0n] }, /would reject/],
  [{ buckets: [0, 1] }, /unreachable.*bucket 0/],
  [{ buckets: [2], chains: [177671, 1] }, /unreachable.*bucket 0/]
];
for (const [fields, warning] of cases) {
  void test(`checks GNU chain fingerprint, Bloom membership and bucket start: ${warning}`, () => {
    const hash = table(fields);
    const validate = createElfGnuHashSymbolValidator([hash], 64);

    validate?.check(1, 177670);

    assert.equal(validate?.claims(1), true);
    assert.deepEqual(hash.issues.map(issue => warning?.test(issue)), warning ? [true] : []);
  });
}

void test("a matching fingerprint beyond the bucket terminator is unreachable", () => {
  const hash = table({ buckets: [1, 2], chains: [177671, 177671] });
  const validate = createElfGnuHashSymbolValidator([hash], 64);

  validate?.check(2, 177670);

  assert.match(hash.issues.join(" "), /unreachable.*bucket 0/);
  assert.equal(validate?.claims(0), false);
  assert.equal(validate?.claims(3), false);
});

void test("reaches a symbol at the end of a multi-record chain and uses the selected Bloom word", () => {
  // Hash 177734 selects Bloom word 1 and bits 6 and 50.
  const hash = table({ buckets: [1], chains: [177670, 177735],
    bloom: [0n, (1n << 6n) | (1n << 50n), 0n, 0n] });
  const validate = createElfGnuHashSymbolValidator([hash], 64);

  validate?.check(2, 177734);

  assert.deepEqual(hash.issues, []);
});

void test("reports the first contradiction of each kind without flooding the report", () => {
  const hash = table({ buckets: [0, 1], chains: [0, 1], bloom: [0n] });
  const validate = createElfGnuHashSymbolValidator([hash], 64);

  validate?.check(1, 177670);
  validate?.check(2, 177670);

  assert.deepEqual(hash.issues, [
    "GNU hash does not match dynamic symbol #1.",
    "GNU Bloom filter would reject dynamic symbol #1.",
    "Dynamic symbol #1 is unreachable from GNU hash bucket 0."
  ]);
});

void test("ignores an empty GNU hash or a structurally unreadable table", () => {
  assert.equal(createElfGnuHashSymbolValidator([table({ buckets: [0], chains: [] })], 64), undefined);
  assert.equal(createElfGnuHashSymbolValidator([table({ issues: ["truncated"] })], 64), undefined);
});

for (const count of [1, 2, 3]) {
  void test(`cross-checks GNU chain length against ${count} dynamic symbols`, () => {
    const hash = table();

    createElfGnuHashSymbolValidator([hash], 64)?.finish(count);

    assert.deepEqual(hash.issues.map(issue => /chain length.*dynamic symbol count/.test(issue)),
      count === 2 ? [] : [true]);
  });
}

void test("extends the unsigned GNU hash over literal byte values and successive chunks", () => {
  const first = extendElfGnuHash(ELF_GNU_HASH_SEED, Uint8Array.of(0xff, 0x80));
  const final = extendElfGnuHash(first, Uint8Array.of(0x41, 0x42, 0x43, 0x44));

  // Independent polynomial over the byte sequence, reduced modulo 2^32.
  assert.equal(final, 0x63e383ee);
});
