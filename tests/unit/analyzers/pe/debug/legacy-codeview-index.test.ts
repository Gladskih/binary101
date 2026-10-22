import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewNameIndex, readLegacyCodeViewAddressIndex } from "../../../../../analyzers/pe/debug/legacy-codeview-index.js";
import { legacyReader, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewHashIndex, codeViewAddressIndex } from "../../../../fixtures/pe-codeview-hash-index.js";

for (const [algorithm, width, entry] of [[2, 2, 4], [6, 2, 4], [10, 4, 8]] as const) {
  void test(`CodeView name index ${algorithm} reads each stored bucket count`, async () => {
    const warnings: string[] = [];
    const index = await readLegacyCodeViewNameIndex(legacyReader(
      codeViewHashIndex([0, 2, 1], width, entry), warnings), algorithm);

    assert.deepEqual(index, { algorithm, counts: [0, 2, 1] });
    assert.deepEqual(warnings, []);
  });
}

for (const algorithm of [4, 5, 8, 12]) {
  void test(`CodeView address index ${algorithm} reads the published section-count layout`, async () => {
    const warnings: string[] = [];
    const index = await readLegacyCodeViewAddressIndex(legacyReader(codeViewAddressIndex([0, 2, 1], algorithm),
      warnings), algorithm);

    assert.deepEqual(index, { algorithm, counts: [0, 2, 1] });
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView aligned address sort needs no WORD padding after an even section count", async () => {
  const warnings: string[] = [];
  const index = await readLegacyCodeViewAddressIndex(legacyReader(codeViewHashIndex([1, 0], 2, 4), warnings), 5);

  assert.deepEqual(index, { algorithm: 5, counts: [1, 0] });
  assert.deepEqual(warnings, []);
});

for (const read of [readLegacyCodeViewNameIndex, readLegacyCodeViewAddressIndex]) {
  void test(`CodeView absent, contradictory and unknown indexes stay explicit: ${read.name}`, async () => {
    const warnings: string[] = [];

    assert.equal(await read(legacyReader([], warnings), 0), undefined);
    assert.deepEqual(warnings, []);
    assert.deepEqual(await read(legacyReader([0], warnings), 0), { algorithm: 0 });
    assert.deepEqual(await read(legacyReader([], warnings), 99), { algorithm: 99 });
    assert.deepEqual(warnings, ["CodeView index has bytes although its algorithm is 0 (no index).",
      "CodeView index algorithm 99 is not decoded."]);
  });
}

for (const bytes of [[], [1, 0], [1, 0, 0, 0], [1, 0, 0, 0, ...legacyU32(0), 1, 0, 0]]) {
  void test(`CodeView name index counts reject a truncated header or parallel arrays: ${bytes.length}`, async () => {
    const warnings: string[] = [];
    const index = await readLegacyCodeViewNameIndex(legacyReader(bytes, warnings), 10);

    assert.deepEqual(index, { algorithm: 10 });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /^CodeView index counts: Error: CodeView subsection bounds exceeded/);
  });
}

void test("CodeView empty bucket arrays remain decoded and alignment filler is not interpreted", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await readLegacyCodeViewNameIndex(legacyReader([0, 0, 1, 0], warnings), 10),
    { algorithm: 10, counts: [] });
  assert.deepEqual(warnings, []);
});

for (const [offset, count, tail] of [[1, 0, 0], [1, 1, 9], [8, 0, 0], [8, 2, 16],
  [0, 1, 7], [0, 0xffffffff, 8]] as const) {
  void test(`CodeView index checks chain extent and alignment: ${offset}/${count}/${tail}`, async () => {
    const warnings: string[] = [];
    const index = await readLegacyCodeViewNameIndex(legacyReader([1, 0, 0, 0, ...legacyU32(offset),
      ...legacyU32(count), ...new Array<number>(tail).fill(0)], warnings), 10);

    assert.deepEqual(index, { algorithm: 10, counts: [count] });
    assert.deepEqual(warnings, ["CodeView index group 1 has a misaligned or truncated chain."]);
  });
}

void test("CodeView indexes preserve DWORD counts beyond WORD range", async () => {
  const warnings: string[] = [];
  const index = await readLegacyCodeViewNameIndex(legacyReader(codeViewHashIndex([65536]), warnings), 10);

  assert.deepEqual(index, { algorithm: 10, counts: [65536] });
  assert.deepEqual(warnings, []);
});

void test("CodeView chain validation reads the offset of each bucket separately", async () => {
  const warnings: string[] = [];
  const index = await readLegacyCodeViewNameIndex(legacyReader([2, 0, 0, 0,
    ...legacyU32(0), ...legacyU32(1), ...legacyU32(0), ...legacyU32(1),
    ...new Array<number>(9).fill(0)], warnings), 10);

  assert.deepEqual(index, { algorithm: 10, counts: [0, 1] });
  assert.deepEqual(warnings, ["CodeView index group 2 has a misaligned or truncated chain."]);
});

void test("CodeView old index counts follow cvdump's sequential chains without guessing offset origins", async () => {
  const warnings: string[] = [];
  const bytes = codeViewHashIndex([1, 2], 2, 4);
  bytes.splice(4, 8, ...legacyU32(0xffffffff), ...legacyU32(0xffffffff));

  assert.deepEqual(await readLegacyCodeViewNameIndex(legacyReader(bytes, warnings), 2),
    { algorithm: 2, counts: [1, 2] });
  assert.deepEqual(warnings, []);
});

void test("CodeView old sequential chains are bounded after all preceding groups", async () => {
  const warnings: string[] = [];
  const bytes = codeViewHashIndex([1, 2], 2, 4);

  assert.deepEqual(await readLegacyCodeViewAddressIndex(legacyReader(bytes.slice(0, -1), warnings), 4),
    { algorithm: 4, counts: [1, 2] });
  assert.deepEqual(warnings, ["CodeView index group 2 has a misaligned or truncated chain."]);
});

void test("CodeView indexes do not need to materialize chain payloads to summarize occupancy", async context => {
  const reader = legacyReader(codeViewHashIndex([65536]));
  const reads = context.mock.method(reader, "view");

  assert.deepEqual(await readLegacyCodeViewAddressIndex(reader, 12), { algorithm: 12, counts: [65536] });
  assert.deepEqual(reads.mock.calls.map(call => call.arguments), [[0, 4], [4, 8]]);
});
