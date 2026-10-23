import assert from "node:assert/strict";
import { test } from "node:test";
import { readHllSymbols } from "../../../../../analyzers/pe/debug/hll-symbols.js";
import { legacyReader, legacyPascal } from "../../../../fixtures/pe-legacy-codeview.js";
import { hllSymbol, hllName } from "../../../../fixtures/pe-hll.js";

// IBM HLL Symbol Scope Table figures 5-28; offsets relative to the kind byte.
for (const [type, prefix] of [[0, 9], [1, 20], [4, 7], [5, 9], [6, 9], [11, 6],
  [13, 4], [15, 20], [18, 3], [19, 9], [20, 5], [21, 7], [22, 3], [23, 13],
  [27, 11], [28, 13], [32, 8], [33, 11]] as const) {
  void test(`HLL symbol ${type} preserves its name at prefix ${prefix}`, async () => {
    const warnings: string[] = [];
    const data = await readHllSymbols(legacyReader(hllSymbol(type,
      [...new Array<number>(prefix - 1).fill(0), ...legacyPascal("<name>")]), warnings));
    assert.deepEqual(data, { kind: "symbols", encoding: "hll", records: [{ type, name: "<name>" }] });
    assert.deepEqual(warnings, []);
  });
}

for (const type of [25, 26, 29, 30]) {
  void test(`HLL long-name symbol ${type} preserves two-byte lengths`, async () => {
    const warnings: string[] = [];
    const prefix = new Map([[25, 3], [26, 20], [29, 20], [30, 9]]).get(type)!;
    const data = await readHllSymbols(legacyReader(hllSymbol(type,
      [...new Array<number>(prefix - 1).fill(0), ...hllName("X".repeat(300))]), warnings));
    assert.equal(data.records[0]!.name, "X".repeat(300));
    assert.deepEqual(warnings, []);
  });
}

void test("HLL map aliases, constants and compiler strings survive with distinct record kinds", async () => {
  const warnings: string[] = [];
  const data = await readHllSymbols(legacyReader([
    ...hllSymbol(24, [...legacyPascal("local"), ...legacyPascal("external")]),
    ...hllSymbol(14, [0, 2, 2, 52, 50, ...legacyPascal("constant")]),
    ...hllSymbol(64, [2, ...legacyPascal("/debug"), ...legacyPascal("compiler date"), ...new Array<number>(11).fill(0)])
  ], warnings));
  assert.deepEqual(data.records, [{ type: 24, name: "local", strings: ["external"] },
    { type: 14, name: "constant", strings: ["42"] }, { type: 64, strings: ["/debug", "compiler date"] }]);
  assert.deepEqual(warnings, []);
});

void test("HLL invalid records preserve neighbors and unknown inventory without guessing strings", async () => {
  const warnings: string[] = [];
  const data = await readHllSymbols(legacyReader([
    ...hllSymbol(255, legacyPascal("fake")), ...hllSymbol(4, [0]), ...hllSymbol(2),
    ...hllSymbol(18, [0, 2, ...legacyPascal("good")]), 128
  ], warnings));
  assert.deepEqual(data.records, [{ type: 255 }, { type: 4 }, { type: 2 }, { type: 18, name: "good" }]);
  assert.equal(warnings.length, 3);
});

for (const bytes of [[0], [1], [128], [128, 0], [10, 2], [128, 2, 2]]) {
  void test(`HLL record bounds ${bytes} are diagnosed before retaining a record`, async () => {
    const warnings: string[] = [];
    assert.deepEqual((await readHllSymbols(legacyReader(bytes, warnings))).records, []);
    assert.equal(warnings.length, 1);
  });
}

void test("HLL symbols expose trailing name bytes and bounded nameless records", async () => {
  const warnings: string[] = [];
  const data = await readHllSymbols(legacyReader([
    ...hllSymbol(18, [0, 2, ...legacyPascal("good"), 255]), ...hllSymbol(17, [0, 0, 0, 0]),
    ...hllSymbol(34, [0, 2, 0, 0, 0, 0]), ...hllSymbol(12), ...hllSymbol(16), ...hllSymbol(65)
  ], warnings));
  assert.equal(data.records.length, 6);
  assert.match(warnings[0]!, /has trailing bytes after its name/);
  assert.equal(warnings.length, 1);
});

void test("HLL unknown kind and framing failures identify the malformed data", async () => {
  const warnings: string[] = [];
  await readHllSymbols(legacyReader([...hllSymbol(255), 10, 2], warnings));
  assert.match(warnings[0]!, /Unknown HLL symbol kind 255/);
  assert.match(warnings[1]!, /Invalid HLL symbol record length/);
});
