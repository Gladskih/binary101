import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewC6Symbols } from "../../../../../analyzers/pe/debug/codeview-c6-symbols.js";
import { c6Symbol } from "../../../../fixtures/pe-codeview-c6.js";
import { legacyReader, legacyPascal } from "../../../../fixtures/pe-legacy-codeview.js";

// Microsoft's dumpsym6.cpp: the high kind bit widens offsets, not record lengths.
for (const [type, prefix] of [[0, 4], [1, 13], [2, 0], [4, 4], [5, 6], [11, 3],
  [12, 4], [13, 3], [15, 13], [17, 4], [18, 2], [22, 7], [0x80, 6], [0x81, 15],
  [0x84, 6], [0x85, 8], [0x8b, 5], [0x8c, 6], [0x8f, 15], [0x96, 7]] as const) {
  void test(`C6 symbol ${type} retains its name at the documented prefix`, async () => {
    const warnings: string[] = [];
    const value = await readCodeViewC6Symbols(legacyReader(c6Symbol(type,
      [...new Array<number>(prefix).fill(0), ...legacyPascal("<symbol>")]), warnings));

    assert.deepEqual(value.records, [{ type, name: "<symbol>" }]);
    assert.deepEqual(warnings, []);
  });
}

for (const [code, count] of [[0, 0], [3, 3], [133, 2], [134, 4], [135, 8], [136, 1],
  [137, 2], [138, 4], [139, 8]] as const) {
  void test(`C6 constant ${code} distinguishes byte counts from numeric type leaves`, async () => {
    const value = await readCodeViewC6Symbols(legacyReader(c6Symbol(14,
      [0, 2, code, ...new Array<number>(count).fill(130), ...legacyPascal("constant")])));

    assert.equal(value.records[0]?.name, "constant");
  });
}

void test("C6 symbols retain unknown and malformed records without losing following names", async () => {
  const warnings: string[] = [];
  const value = await readCodeViewC6Symbols(legacyReader([
    ...c6Symbol(4, [0]), ...c6Symbol(99, [130, 1, 65]), ...c6Symbol(14, [0, 2, 255]),
    ...c6Symbol(18, [0, 2, 1, 65, 255]), ...c6Symbol(16, [130, 2, 65, 66]),
    ...c6Symbol(18, [0, 2, ...legacyPascal("good")])
  ], warnings));

  assert.deepEqual(value.records, [{ type: 4 }, { type: 99 }, { type: 14 },
    { type: 18, name: "A" }, { type: 16 }, { type: 18, name: "good" }]);
  assert.equal(warnings.length, 4);
  assert.match(warnings.join(" | "), /bounds.*Unknown C6 symbol.*constant.*trailing/i);
});

for (const bytes of [[0], [1], [2, 2], [1, 2, 255], [2, 18, 0]]) {
  void test(`C6 symbol framing bounds ${bytes} produces warnings`, async () => {
    const warnings: string[] = [];
    await readCodeViewC6Symbols(legacyReader(bytes, warnings));

    assert.ok(warnings.length > 0);
  });
}

void test("C6 empty and nameless streams contain no invented strings", async () => {
  const warnings: string[] = [];
  await readCodeViewC6Symbols(legacyReader(c6Symbol(2), warnings));
  assert.deepEqual(warnings, []);
  assert.deepEqual(await readCodeViewC6Symbols(legacyReader([])), { kind: "symbols", encoding: "c6", records: [] });
  assert.deepEqual((await readCodeViewC6Symbols(legacyReader(c6Symbol(2)))).records, [{ type: 2 }]);
});

void test("C6 framing refuses incomplete records before interpreting their kinds", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Symbols(legacyReader([...c6Symbol(2), 10, 2], warnings));

  assert.deepEqual(data.records, [{ type: 2 }]);
  assert.match(warnings[0]!, /Invalid C6 symbol record length/);
});

void test("C6 constants do not confuse the easy type leaf with a 128-byte value", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Symbols(legacyReader(c6Symbol(14,
    [0, 2, 128, ...new Array<number>(128).fill(0), ...legacyPascal("fake")]), warnings));

  assert.deepEqual(data.records, [{ type: 14 }]);
  assert.match(warnings[0]!, /Unknown C6 constant encoding 128/);
});

void test("C6 final symbol length includes its length byte even for a nameless end record", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Symbols(legacyReader([2, 2], warnings));
  assert.deepEqual(data.records, []);
  assert.match(warnings[0]!, /Invalid C6 symbol record length/);
});

void test("C6 final symbol bounds are relative to the remaining stream after padding", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Symbols(legacyReader([
    ...c6Symbol(16, new Array<number>(20).fill(0)), 10, 2
  ], warnings));
  assert.deepEqual(data.records, [{ type: 16 }]);
  assert.match(warnings[0]!, /Invalid C6 symbol record length/);
});
