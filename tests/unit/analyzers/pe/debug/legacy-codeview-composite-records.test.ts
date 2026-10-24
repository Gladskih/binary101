import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewCompositeType } from "../../../../../analyzers/pe/debug/legacy-codeview-composite-records.js";
import { legacyReader, legacyU16, legacyU32, legacyPascal } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "../../../../fixtures/pe-codeview-type-strings.js";
import { codeViewInteger } from "../../../../fixtures/pe-codeview-numeric-values.js";
import { codeViewCompositeText, codeViewInlineTypeName } from "../../../../fixtures/pe-codeview-composites.js";

// LLVM 007ca8ec1bd348000e42ada637c421cf5d28c11a TypeRecordMapping.cpp:
// *2 aggregates use uint32 properties and encoded uint64 member counts.
for (const [type, references, expected] of [
  [0x1608, [...legacyU32(0x1001), ...legacyU32(0x1002), ...legacyU32(0x1003)],
    { derivedTypes: 0x1002, vtableShape: 0x1003 }],
  [0x1609, [...legacyU32(0x1001), ...legacyU32(0x1002), ...legacyU32(0x1003)],
    { derivedTypes: 0x1002, vtableShape: 0x1003 }],
  [0x160a, legacyU32(0x1001), {}],
  [0x160b, [...legacyU32(0x1001), ...legacyU32(0x1002), ...legacyU32(0x1003)],
    { derivedTypes: 0x1002, vtableShape: 0x1003 }]
] as const) {
  void test(`CodeView extended aggregate ${type} retains its 64-bit member count and unknown property bits`, async () => {
    const warnings: string[] = [];
    const record = codeViewTextRecord(type, 4, [...legacyU32(0x80000200), ...references,
      ...codeViewInteger(0x800a, (1n << 64n) - 1n, 8), ...legacyU16(16),
      ...codeViewUtf8("Wide"), ...codeViewUtf8(".?AUWide@@")]);
    assert.deepEqual(await readCodeViewCompositeType(legacyReader(record, warnings), type), {
      type, name: "Wide", uniqueName: ".?AUWide@@", shape: { kind: "aggregate", fieldList: 0x1001,
        properties: 0x80000200, memberCount: "18446744073709551615", size: "16", ...expected }
    });
    assert.match(warnings.join(" | "), /unknown property bits/);
  });
}

void test("CodeView extended aggregate counts preserve invalid integers and diagnose noninteger encodings", async () => {
  const warnings: string[] = [];
  const header = [...legacyU32(0), ...legacyU32(0)];
  const negative = await readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x160a, 4,
    [...header, ...codeViewInteger(0x8003, -1n, 4), ...legacyU16(0), 0]), warnings), 0x160a);
  assert.equal(negative?.shape?.kind === "aggregate" && negative.shape.memberCount, "-1");
  const noninteger = await readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x160a, 4,
    [...header, ...legacyU16(0x8005), ...legacyU32(0), ...legacyU16(0), 0]), warnings), 0x160a);
  assert.deepEqual(noninteger?.shape, { kind: "aggregate", properties: 0, fieldList: 0, size: "0" });
  await readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x160a, 4,
    [...header, ...codeViewInteger(0x8018, 1n << 64n, 16), ...legacyU16(0), 0]), warnings), 0x160a);
  assert.match(warnings.join(" | "), /member count is not an integer/);
  assert.match(warnings.join(" | "), /member count is outside the uint64 range/);
  await assert.rejects(readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x160a, 4,
    [...header, ...legacyU16(0x800a), 1])), 0x160a), /bounds/);
});

for (const [value, leaf, width, warningsExpected] of [
  [-1n, 0x8003, 4, ["CodeView aggregate member count is outside the uint64 range."]],
  [0n, 0x8018, 16, []], [1n, 0x8018, 16, []], [(1n << 64n) - 1n, 0x8018, 16, []],
  [1n << 64n, 0x8018, 16, ["CodeView aggregate member count is outside the uint64 range."]]
] as const) {
  void test(`CodeView extended member-count range checks distinguish ${value} exactly`, async () => {
    const warnings: string[] = [];
    const record = await readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x160a, 4,
      [...legacyU32(0xffff), ...legacyU32(0), ...codeViewInteger(leaf, value, width),
        ...legacyU16(0), ...codeViewUtf8("Boundary"), ...codeViewUtf8(".?AUBoundary@@")]), warnings), 0x160a);
    assert.equal(record?.shape?.kind === "aggregate" && record.shape.memberCount, String(value));
    assert.deepEqual(warnings, warningsExpected);
  });
}

for (const type of [4, 5]) {
  void test(`CodeView narrow class ${type} preserves its member count and referenced lists`, async () => {
    const record = codeViewTextRecord(type, 4, [...legacyU16(4), ...legacyU16(0x1003),
      ...legacyU16(1), ...legacyU16(0x1002), ...legacyU16(0x1001), ...legacyU16(24), ...legacyPascal("Packet")]);
    assert.deepEqual(await readCodeViewCompositeType(legacyReader(record), type), { type, name: "Packet",
      shape: { kind: "aggregate", memberCount: 4, properties: 1, fieldList: 0x1003,
        derivedTypes: 0x1002, vtableShape: 0x1001, size: "24" } });
    await assert.rejects(readCodeViewCompositeType(legacyReader(record.slice(0, 13)), type), /bounds/);
  });
}

for (const [type, identity] of [[0x1004, {}], [0x1005, {}],
  [0x1504, { uniqueName: ".?AUPacket@@" }], [0x1505, { uniqueName: ".?AUPacket@@" }],
  [0x1519, { uniqueName: ".?AUPacket@@" }]] as const) {
  void test(`CodeView wide class ${type} retains exact sizes and decorated names`, async () => {
    const record = codeViewTextRecord(type, 4, [...legacyU16(0xffff), ...legacyU16(0x200),
      ...legacyU32(0xffffffff), ...legacyU32(0x12345678), ...legacyU32(0x87654321),
      ...codeViewInteger(0x800a, (1n << 64n) - 1n, 8), ...codeViewCompositeText(type, "Packet")]);
    assert.deepEqual(await readCodeViewCompositeType(legacyReader(record), type), { type, name: "Packet",
      ...identity,
      shape: { kind: "aggregate", memberCount: 0xffff, properties: 0x200, fieldList: 0xffffffff,
        derivedTypes: 0x12345678, vtableShape: 0x87654321, size: "18446744073709551615" } });
  });
}

for (const [type, bytes] of [
  [6, [...legacyU16(2), ...legacyU16(0x1001), ...legacyU16(0), ...legacyU16(8), ...legacyPascal("Choice")]],
  [0x1006, [...legacyU16(2), ...legacyU16(0), ...legacyU32(0x1001), ...legacyU16(8), ...legacyPascal("Choice")]],
  [0x1506, [...legacyU16(2), ...legacyU16(0), ...legacyU32(0x1001), ...legacyU16(8), ...codeViewUtf8("Choice")]]
] as const) {
  void test(`CodeView union ${type} has a field list and byte size without class-only references`, async () => {
    assert.deepEqual(await readCodeViewCompositeType(legacyReader(codeViewTextRecord(type, 4, bytes)), type),
      { type, name: "Choice", shape: { kind: "aggregate", memberCount: 2, properties: 0, fieldList: 0x1001, size: "8" } });
  });
}

for (const [type, bytes] of [
  [7, [...legacyU16(2), ...legacyU16(0x75), ...legacyU16(0x1001), ...legacyU16(0), ...legacyPascal("State")]],
  [0x1007, [...legacyU16(2), ...legacyU16(0), ...legacyU32(0x75), ...legacyU32(0x1001), ...legacyPascal("State")]],
  [0x1507, [...legacyU16(2), ...legacyU16(0), ...legacyU32(0x75), ...legacyU32(0x1001), ...codeViewUtf8("State")]]
] as const) {
  void test(`CodeView enum ${type} preserves its underlying type without inventing a byte size`, async () => {
    assert.deepEqual(await readCodeViewCompositeType(legacyReader(codeViewTextRecord(type, 4, bytes)), type),
      { type, name: "State", shape: { kind: "aggregate", memberCount: 2, properties: 0, fieldList: 0x1001, underlyingType: 0x75 } });
  });
}

for (const [type, bytes, shape] of [
  [3, [...legacyU16(0x74), ...legacyU16(0x75)], { kind: "array", elementType: 0x74, indexType: 0x75 }],
  [0x1003, [...legacyU32(0x74), ...legacyU32(0x75)], { kind: "array", elementType: 0x74, indexType: 0x75 }],
  [0x1503, [...legacyU32(0x74), ...legacyU32(0x75)], { kind: "array", elementType: 0x74, indexType: 0x75 }],
  [0x1516, [...legacyU32(0x74), ...legacyU32(0x75), ...legacyU32(8)],
    { kind: "array", elementType: 0x74, indexType: 0x75, stride: 8 }],
  [0x151b, [...legacyU32(0x74), ...legacyU32(3)], { kind: "vector", elementType: 0x74, count: 3 }],
  [0x151c, [...legacyU32(0x74), ...legacyU32(2), ...legacyU32(3), ...legacyU32(16), 1],
    { kind: "matrix", elementType: 0x74, rows: 2, columns: 3, majorStride: 16, attributes: 1 }]
] as const) {
  void test(`CodeView array-like type ${type} preserves dimensions, types and storage size`, async () => {
    assert.deepEqual(await readCodeViewCompositeType(legacyReader(codeViewTextRecord(type, 4,
      [...bytes, ...legacyU16(24), ...codeViewInlineTypeName(type, "Values")])), type),
    { type, name: "Values", shape: { ...shape, size: "24" } });
  });
}

void test("CodeView composite identities preserve metadata when their text is truncated or malformed", async () => {
  const warnings: string[] = [];
  const header = [...legacyU16(0), ...legacyU16(0x200), ...legacyU32(0), ...legacyU16(0)];
  assert.deepEqual(await readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x1506, 4,
    [...header, ...codeViewUtf8("Named")]), warnings), 0x1506), { type: 0x1506, name: "Named",
    shape: { kind: "aggregate", memberCount: 0, properties: 0x200, fieldList: 0, size: "0" } });
  assert.match(warnings.join(" | "), /decorated type name/);
  warnings.length = 0;
  assert.deepEqual(await readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x1506, 4,
    [...header, 0xff, 0]), warnings), 0x1506), { type: 0x1506,
    shape: { kind: "aggregate", memberCount: 0, properties: 0x200, fieldList: 0, size: "0" } });
  assert.match(warnings.join(" | "), /type record/);
});

void test("CodeView invalid composite sizes and matrix flags remain visible without guessing", async () => {
  const warnings: string[] = [];
  const header = [...legacyU32(0x74), ...legacyU32(0x75)];
  const negative = await readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x1503, 4,
    [...header, ...codeViewInteger(0x8003, -1n, 4), 0]), warnings), 0x1503);
  assert.equal(negative?.shape?.kind === "array" && negative.shape.size, "-1");
  const noninteger = await readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x1503, 4,
    [...header, ...legacyU16(0x8005), ...legacyU32(0), 0]), warnings), 0x1503);
  assert.deepEqual(noninteger?.shape, { kind: "array", elementType: 0x74, indexType: 0x75 });
  await readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x151c, 4,
    [...legacyU32(0x74), ...new Array<number>(12).fill(0), 0x80, ...legacyU16(0), 0]), warnings), 0x151c);
  assert.match(warnings.join(" | "), /negative byte size/);
  assert.match(warnings.join(" | "), /size is not an integer/);
  assert.match(warnings.join(" | "), /matrix.*unknown attribute/);
  assert.equal(await readCodeViewCompositeType(legacyReader([]), 0x7777), undefined);
  await assert.rejects(readCodeViewCompositeType(legacyReader(codeViewTextRecord(0x1503, 4, header)), 0x1503), /bounds/);
});
