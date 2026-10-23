import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewFields as readFieldData } from "../../../../../analyzers/pe/debug/legacy-codeview-fields.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewStoredFieldNames, codeViewField, codeViewMethodField, codeViewBaseField } from "../../../../fixtures/pe-codeview-fields.js";
import { codeViewInteger } from "../../../../fixtures/pe-codeview-numeric-values.js";

const readLegacyCodeViewFields = async (reader: Parameters<typeof readFieldData>[0]) =>
  codeViewStoredFieldNames(await readFieldData(reader));

void test("CodeView enum values and data-member offsets retain exact integers and type references", async () => {
  const fields = await readFieldData(legacyReader([
    ...codeViewField(0x1502, [...legacyU16(3), ...codeViewInteger(0x800a, (1n << 64n) - 1n, 8)], "largest"),
    ...codeViewField(0x150d, [...legacyU16(1), ...legacyU32(0x74), ...legacyU16(12)], "count")
  ]));
  assert.deepEqual(fields, [
    { type: 0x1502, name: "largest", attributes: 3, value: "18446744073709551615" },
    { type: 0x150d, name: "count", attributes: 1, typeIndex: 0x74, offset: "12" }
  ]);
});

void test("CodeView base, virtual-base and method metadata retain their distinct numeric meanings", async () => {
  const fields = await readFieldData(legacyReader([
    ...codeViewBaseField(0x1400, 8), ...codeViewBaseField(0x1401, 12),
    ...codeViewMethodField(0x1511, 4, "virtualMethod"),
    ...codeViewField(0x150f, [...legacyU16(2), ...legacyU32(0x12345678)], "overloaded")
  ]));
  assert.deepEqual(fields, [
    { type: 0x1400, typeIndex: 0, attributes: 0, offset: "65536" },
    { type: 0x1401, typeIndex: 0, virtualBasePointer: 0, attributes: 0,
      offset: "65536", virtualBaseTableIndex: "8" },
    { type: 0x1511, typeIndex: 0, attributes: 19, vtableOffset: 32, name: "virtualMethod" },
    { type: 0x150f, typeIndex: 0x12345678, methodCount: 2, name: "overloaded" }
  ]);
});

void test("CodeView noninteger member values keep their name and a visible diagnostic", async () => {
  const warnings: string[] = [];
  const fields = await readFieldData(legacyReader(codeViewField(0x1502,
    [...legacyU16(3), ...legacyU16(0x8005), ...legacyU32(0)], "notInteger"), warnings));
  assert.deepEqual(fields, [{ type: 0x1502, attributes: 3, name: "notInteger" }]);
  assert.match(warnings.join(" | "), /value is not an integer encoding/);
});

void test("CodeView a method's negative virtual-table displacement stays signed", async () => {
  const fields = await readFieldData(legacyReader(codeViewField(0x1511,
    [...legacyU16(3 | 4 << 2), ...legacyU32(0x12345678), ...legacyU32(-8)], "adjusted")));
  assert.deepEqual(fields, [{ type: 0x1511, attributes: 19,
    typeIndex: 0x12345678, vtableOffset: -8, name: "adjusted" }]);
});

void test("CodeView field lists retain names and advance through real field boundaries and padding", async () => {
  const bytes = [...codeViewField(0x406, [...legacyU16(0x74), ...legacyU16(3), ...legacyU16(0)], "count"),
    ...codeViewField(0x403, [...legacyU16(0), ...legacyU16(7)], "last")];
  const warnings: string[] = [];

  const fields = await readFieldData(legacyReader(bytes, warnings));

  assert.deepEqual(fields, [
    { type: 0x406, typeIndex: 0x74, attributes: 3, offset: "0", name: "count" },
    { type: 0x403, attributes: 0, value: "7", name: "last" }
  ]);
  assert.deepEqual(warnings, []);
});

// Independent offsets from Microsoft's packed lf* structures, from the leaf tag.
for (const [type, offset] of [[0x404, 4], [0x407, 6], [0x408, 6], [0x409, 4],
  [0x1403, 8], [0x1406, 8], [0x1407, 8], [0x1408, 8], [0x140d, 8], [0x140e, 8], [0x140f, 2],
  [0x150c, 8], [0x150e, 8], [0x150f, 8], [0x1510, 8], [0x1512, 8], [0x1513, 8], [0x1514, 2]] as const) {
  void test(`CodeView field ${type} retains its stored name`, async () => {
    const warnings: string[] = [];
    const fields = await readLegacyCodeViewFields(legacyReader(
      codeViewField(type, new Array<number>(offset - 2).fill(0), "member"), warnings));

    assert.deepEqual(fields, [{ type, name: "member" }]);
    assert.deepEqual(warnings, []);
  });
}

for (const [type, offset] of [[0x403, 4], [0x406, 6], [0x1405, 8], [0x1502, 4], [0x150d, 8]] as const) {
  void test(`CodeView numeric field ${type} skips the entire numeric leaf before its name`, async () => {
    const bytes = codeViewField(type, [...new Array<number>(offset - 2).fill(0),
      ...legacyU16(0x8004), ...legacyU32(65536)], "large_offset");

    assert.deepEqual(await readLegacyCodeViewFields(legacyReader(bytes)), [{ type, name: "large_offset" }]);
  });
}

for (const type of [0x40c, 0x140b, 0x1511]) {
  for (const property of [0, 1, 2, 3, 4, 5, 6]) {
    void test(`CodeView method ${type} property ${property} distinguishes introducing virtual offsets`, async () => {
      const warnings: string[] = [];

      assert.deepEqual(await readLegacyCodeViewFields(legacyReader(codeViewMethodField(type, property, "method"), warnings)),
        [{ type, name: "method" }]);
      assert.deepEqual(warnings, []);
    });
  }
}

for (const [type, offset] of [[0x400, 6], [0x1400, 8], [0x151a, 8],
  [0x401, 8], [0x402, 8], [0x1401, 12], [0x1402, 12]] as const) {
  void test(`CodeView base class field ${type} advances through variable numeric offsets`, async () => {
    const bytes = [...codeViewBaseField(type, offset),
      ...codeViewField(0x409, [0, 0], "nested")];
    const warnings: string[] = [];

    assert.deepEqual(await readLegacyCodeViewFields(legacyReader(bytes, warnings)),
      [{ type }, { type: 0x409, name: "nested" }]);
    assert.deepEqual(warnings, []);
  });
}

for (const [type, size] of [[0x40a, 4], [0x40b, 4], [0x40d, 8], [0x1409, 8], [0x140a, 8], [0x140c, 12]] as const) {
  void test(`CodeView fixed field ${type} validates all ${size} bytes`, async () => {
    const bytes = [...legacyU16(type), ...new Array<number>(size - 2).fill(0)];
    const warnings: string[] = [];

    assert.deepEqual(await readLegacyCodeViewFields(legacyReader(bytes, warnings)), [{ type }]);
    assert.deepEqual(warnings, []);
    assert.deepEqual(await readLegacyCodeViewFields(legacyReader(bytes.slice(0, -1), warnings)), []);
    assert.match(warnings.join(" | "), /bounds/);
  });
}

void test("CodeView continuation indices retain their 16-bit and 32-bit widths", async () => {
  const fields = await readLegacyCodeViewFields(legacyReader([
    ...legacyU16(0x405), ...legacyU16(0x1003), ...legacyU16(0x1404), 0, 0, ...legacyU32(0x12345678)]));

  assert.deepEqual(fields, [{ type: 0x405, continuation: 0x1003 }, { type: 0x1404, continuation: 0x12345678 }]);
});

void test("CodeView field names preserve streamed UTF-8 and empty strings", async () => {
  const name = "A".repeat(255) + "😀";
  const warnings: string[] = [];
  const fields = await readLegacyCodeViewFields(legacyReader([
    ...codeViewField(0x150e, new Array<number>(6).fill(0), name), ...codeViewField(0x1514, [], "")], warnings));

  assert.deepEqual(fields, [{ type: 0x150e, name }, { type: 0x1514, name: "" }]);
  assert.deepEqual(warnings, []);
  assert.deepEqual(await readLegacyCodeViewFields(legacyReader([])), []);
});

void test("CodeView fields preserve a valid prefix and stop rather than guessing unknown boundaries", async () => {
  const warnings: string[] = [];
  const fields = await readLegacyCodeViewFields(legacyReader([
    ...codeViewField(0x407, [0, 0, 3, 0], "first"), ...legacyU16(0x7777), ...new Array<number>(8).fill(0)], warnings));

  assert.deepEqual(fields, [{ type: 0x407, name: "first" }]);
  assert.match(warnings.join(" | "), /Unsupported CodeView field kind/);
});

for (const bytes of [[3], [7, 4], [0x14, 0x15, 65], [0x14, 0x15, 0xff, 0]]) {
  void test(`CodeView malformed field bytes ${bytes} remain visible warnings`, async () => {
    const warnings: string[] = [];

    assert.deepEqual(await readLegacyCodeViewFields(legacyReader(bytes, warnings)), []);
    assert.match(warnings.join(" | "), /field list/);
  });
}

void test("CodeView padding must advance and fit the field list", async () => {
  const warnings: string[] = [];
  await readLegacyCodeViewFields(legacyReader([0xf0], warnings));
  await readLegacyCodeViewFields(legacyReader([0xf3, 0xf2], warnings));

  assert.match(warnings.join(" | "), /LF_PAD0/);
  assert.match(warnings.join(" | "), /bounds/);
  assert.deepEqual(await readLegacyCodeViewFields(legacyReader([0xf3, 0xf2, 0xf1])), []);
});

void test("CodeView padding uses its leading length rather than interpreting ignored bytes", async () => {
  const warnings: string[] = [];
  const fields = await readLegacyCodeViewFields(legacyReader([
    0xf3, 0, 0xff, ...codeViewField(0x407, [0x74, 0, 3, 0], "after_padding")], warnings));

  assert.deepEqual(fields, [{ type: 0x407, name: "after_padding" }]);
  assert.deepEqual(warnings, []);
});

void test("CodeView reserved field padding is diagnosed without losing the bounded name", async () => {
  const warnings: string[] = [];
  const fields = await readLegacyCodeViewFields(legacyReader(codeViewField(0x1510, [1, 0, 0, 0, 0, 0], "nested"), warnings));

  assert.deepEqual(fields, [{ type: 0x1510, name: "nested" }]);
  assert.deepEqual(warnings, ["CodeView field reserved padding is nonzero."]);
});

void test("CodeView reserved method properties are diagnosed without inventing virtual offsets", async () => {
  const warnings: string[] = [];
  const fields = await readLegacyCodeViewFields(legacyReader(codeViewField(0x1511,
    [...legacyU16(3 | 7 << 2), ...legacyU32(0)], "method"), warnings));

  assert.deepEqual(fields, [{ type: 0x1511, name: "method" }]);
  assert.deepEqual(warnings, ["CodeView method property is reserved."]);
});
