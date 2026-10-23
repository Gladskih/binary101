import assert from "node:assert/strict";
import { test } from "node:test";
import { readHllTypes } from "../../../../../analyzers/pe/debug/hll-type-records.js";
import { hllType, hllName } from "../../../../fixtures/pe-hll.js";
import { legacyReader, legacyPascal, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

const index = [131, ...legacyU16(512)];
const span = [133, ...legacyU16(16)];
const name = [130, ...legacyPascal("<Type>")];

for (const [type, qualifier, body] of [
  [0x40, 0, [...legacyU32(8), ...legacyU16(1), ...legacyU16(512), ...hllName("<Type>")]],
  [0x42, 0, [...legacyU16(512), ...hllName("<Type>")]],
  [0x45, 0, [2, 0, ...legacyU16(512), ...hllName("<Type>")]],
  [0x45, 16, [2, 0, ...legacyU16(512), ...span, ...hllName("<Type>")]],
  [0x46, 0, [2, ...legacyU16(512), ...span, ...hllName("<Type>")]],
  [0x52, 0, [...legacyU16(512), ...legacyPascal("<Type>")]],
  [0x57, 0, [...legacyU32(512), ...legacyPascal("<Type>")]],
  [0x5d, 0, [...index, ...name]], [0x78, 0, [...legacyU32(512), ...index, ...index, ...name]],
  [0x79, 0, [...legacyU32(512), ...legacyU16(1), ...index, ...index, ...name]],
  [0x7a, 0, [...index, ...name]],
  [0x7b, 0, [...index, ...index, ...span, ...span, ...name]],
  [0x6f, 0, [...legacyU16(512), ...span, ...span, ...legacyPascal("<Type>")]]] as const) {
  void test(`HLL type ${type} qualifier ${qualifier} retains its declared name`, async () => {
    const warnings: string[] = [];
    const data = await readHllTypes(legacyReader(hllType(type, qualifier, body), warnings), 0x400);
    assert.deepEqual(data.records, [{ type, name: "<Type>" }]);
    assert.deepEqual(warnings, []);
  });
}

void test("HLL types preserve class names, static linkage names, members and macro text", async () => {
  const warnings: string[] = [];
  const data = await readHllTypes(legacyReader([
    ...hllType(0x40, 2, [...legacyU32(8), ...legacyU16(1), ...legacyU16(512), ...hllName("Class"),
      ...legacyU16(1), ...legacyU16(0), ...hllName("SomClass")]),
    ...hllType(0x46, 1, [2, ...legacyU16(512), ...span, ...hllName("_static"), ...hllName("member")]),
    ...hllType(0x7f, 2, [130, ...legacyPascal("field"), ...span]),
    ...hllType(0x7f, 3, [130, ...legacyPascal("Enumerator"), ...span]),
    ...hllType(0x59, 0, [139, 5, 72, 101, 108, 108, 111]),
    ...hllType(0x61, 0, [133, 3, 0, 88, 40, 57])
  ], warnings), 0x400);
  assert.deepEqual(data.records, [{ type: 0x40, name: "Class", strings: ["SomClass"] },
    { type: 0x46, name: "member", strings: ["_static"] }, { type: 0x7f, strings: ["field"] },
    { type: 0x7f, strings: ["Enumerator"] }, { type: 0x59, strings: ["Hello"] },
    { type: 0x61, strings: ["X(9"] }]);
  assert.deepEqual(warnings, []);
});

void test("HLL unknown records and unsupported versions remain visible without guessed names", async () => {
  const warnings: string[] = [];
  const data = await readHllTypes(legacyReader([
    ...hllType(255, 0, name), ...hllType(0x5d, 0, [130])], warnings), 0x400);
  const unknown = await readHllTypes(legacyReader(hllType(0x5d, 0, [...index, ...name]), warnings), 0xff00);
  assert.deepEqual(data.records, [{ type: 255 }, { type: 0x5d }]);
  assert.deepEqual(unknown.records, []);
  assert.equal(warnings.length, 3);
});

for (const [type, qualifier, body] of [[0x41, 0, [2, 0, 2, ...span]], [0x43, 0, [2, 0, 2, 0, 2]],
  [0x48, 0, [0, 2]], [0x49, 0, [0, 2, 0, 2, 0, 2]], [0x51, 0, [0, 2, 8, 128]],
  [0x53, 0, [0, 0, 0, 0, ...index, ...index]], [0x54, 0, [0, 0, 0, 0, ...index, ...index]],
  [0x55, 0, span], [0x55, 2, []], [0x56, 1, []], [0x5c, 0, [0, ...span]], [0x5c, 16, []],
  [0x60, 0, span], [0x60, 2, []], [0x62, 0, span], [0x62, 2, []], [0x65, 0, []], [0x67, 0, []],
  [0x72, 0, []], [0x75, 0, [0, 0, 0, 0, ...index, ...index]], [0x7a, 0, index]] as const) {
  void test(`HLL name-free leaf ${type}/${qualifier} checks its complete structural body`, async () => {
    const warnings: string[] = [];
    const data = await readHllTypes(legacyReader(hllType(type, qualifier, body), warnings), 0x400);
    assert.deepEqual(data.records, [{ type }]);
    assert.deepEqual(warnings, []);
  });
}

for (const qualifier of [1, 4]) {
  void test(`HLL list ${qualifier} skips index values and argument flags without inventing text`, async () => {
    const warnings: string[] = [];
    const body = qualifier === 4 ? [0, ...index, 1, ...index] : [...index, ...index];
    const data = await readHllTypes(legacyReader(hllType(0x7f, qualifier, body), warnings), 0x400);
    assert.deepEqual(data.records, [{ type: 0x7f, strings: [] }]);
    assert.deepEqual(warnings, []);
  });
}

void test("HLL1 type linkage byte is distinct from later length headers", async () => {
  const warnings: string[] = [];
  const data = await readHllTypes(legacyReader([1, ...hllType(0x5d, 0, [...index, ...name])], warnings), 0x100);
  assert.deepEqual(data.records, [{ type: 0x5d, name: "<Type>" }]);
  assert.deepEqual(warnings, []);
});

for (const [bytes, message] of [[[0], /bounds/], [[1, 0, 0, 0], /record length/],
  [[20, 0, 0x5d, 0], /record length/], [hllType(0x7f, 255), /type 127 qualifier 255/],
  [hllType(0x59, 0, [136, 255]), /Negative HLL text size/], [hllType(0x67, 0, [0]), /trailing bytes/]] as const) {
  void test(`HLL type failure ${bytes} is diagnosed without losing its bounded prefix`, async () => {
    const warnings: string[] = [];
    await readHllTypes(legacyReader(bytes, warnings), 0x400);
    assert.match(warnings[0]!, message);
  });
}

void test("HLL text can be empty and unknown qualifiers never imply known name layouts", async () => {
  const warnings: string[] = [];
  const data = await readHllTypes(legacyReader([
    ...hllType(0x59, 0, [139, 0]), ...hllType(0x40, 128, new Array<number>(9).fill(0)),
    ...hllType(0x60, 255), ...hllType(0x40, 0, [...legacyU32(1), ...legacyU16(0), ...legacyU16(0), ...hllName("Class")])
  ], warnings), 0x400);
  assert.deepEqual(data.records, [{ type: 0x59, strings: [""] }, { type: 0x40 }, { type: 0x60 },
    { type: 0x40, name: "Class" }]);
  assert.match(warnings[0]!, /Unknown HLL type 64 qualifier 128/);
  assert.match(warnings[1]!, /Unknown HLL type 96 qualifier 255/);
});

void test("HLL diagnostic messages identify unsupported versions, kinds and framing", async () => {
  const warnings: string[] = [];
  await readHllTypes(legacyReader([], warnings), 0xff00);
  await readHllTypes(legacyReader(hllType(255, 0), warnings), 0x400);
  await readHllTypes(legacyReader([20, 0, 0x5d, 0], warnings), 0x400);
  assert.match(warnings[0]!, /Unsupported HLL type format version 65280/);
  assert.match(warnings[1]!, /Unknown HLL type 255/);
  assert.match(warnings[2]!, /Invalid HLL type record length/);
});

void test("HLL type lengths are relative to each remaining record, including V1 linkage", async () => {
  const warnings: string[] = [];
  const prefix = hllType(0x59, 0, [139, 40, ...new Array<number>(40).fill(65)]);
  const data = await readHllTypes(legacyReader([...prefix, 4, 0, 0x5d, 0], warnings), 0x400);
  assert.equal(data.records.length, 1);
  assert.match(warnings[0]!, /Invalid HLL type record length/);
  const v1 = await readHllTypes(legacyReader([1, ...hllType(0x67, 0), 1, 4, 0, 0x5d, 0], warnings), 0x100);
  assert.deepEqual(v1.records, [{ type: 0x67 }]);
  assert.equal(warnings.length, 2);
});
