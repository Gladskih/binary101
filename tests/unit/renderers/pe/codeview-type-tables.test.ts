import assert from "node:assert/strict";
import { test } from "node:test";
import { codeViewTypeRows } from "../../../../renderers/pe/codeview-type-tables.js";

void test("CodeView dimensioned arrays retain underlying types and bounds without fabricating byte sizes", () => {
  assert.deepEqual(codeViewTypeRows({ kind: "types", records: [
    { type: 0x1508, index: 0x1000, name: "Grid", shape: {
      kind: "dimensionedArray", underlyingType: 0x74, dimensionsType: 0x1001 } },
    { type: 0x209, index: 0x1001, shape: { kind: "constantDimensions", indexType: 0x74, rank: 2,
      boundKind: "lowerUpper", bounds: { kind: "integers", values: ["-1", "3", "2", "5"] } } }
  ] }), [["Dimensioned array", "Grid", "not stored", "—", "none",
    "underlying type: int32; bounds #4097: constant bounds (rank: 2)"]]);
});

void test("CodeView extended aggregate counts and unknown properties remain exact and visible", () => {
  const rows = codeViewTypeRows({ kind: "types", records: [
    { type: 0x1609, index: 0x1000, name: "Large", shape: { kind: "aggregate", fieldList: 0x1002,
      memberCount: "18446744073709551615", properties: 0x80000000, size: "262144" } },
    { type: 0x160a, index: 0x1001, name: "Invalid", shape: { kind: "aggregate", fieldList: 0x1002,
      properties: 0, size: "0" } },
    { type: 0x1203, index: 0x1002, members: [{ type: 0x150d, name: "first" }] }
  ] });
  assert.equal(rows[0]?.[3], "18446744073709551615");
  assert.equal(rows[0]?.[4], "unknown property bits 0x80000000");
  assert.equal(rows[0]?.[5], "fields: 1 record");
  assert.equal(rows[1]?.[3], "unavailable");
  assert.equal(rows[1]?.[5], "fields: 1 record");
});

void test("CodeView named types keep sizes, declaration counts and related type identities", () => {
  const rows = codeViewTypeRows({ kind: "types", records: [
    { type: 0x1505, index: 0x1000, name: "Packet", uniqueName: ".?AUPacket@@",
      shape: { kind: "aggregate", memberCount: 3, properties: 0x201, fieldList: 0x1001,
        derivedTypes: 0, vtableShape: 0, size: "18446744073709551615" } },
    { type: 0x1203, index: 0x1001, members: [] },
    { type: 0x1507, index: 0x1002, name: "State", shape: { kind: "aggregate",
      memberCount: 2, properties: 0x100, fieldList: 0, underlyingType: 0x75 } }
  ] });
  assert.deepEqual(rows, [
    ["Structure", "Packet", "18446744073709551615", "3", "packed; decorated name flag", "fields: 0 records"],
    ["Structure (decorated)", ".?AUPacket@@", "—", "—", "—", "—"],
    ["Enum", "State", "—", "2", "scoped", "underlying type: uint32"]
  ]);
});

void test("CodeView anonymous arrays retain their element and indexing types and layout", () => {
  const rows = codeViewTypeRows({ kind: "types", records: [
    { type: 0x1516, name: "", shape: { kind: "array", elementType: 0x74, indexType: 0x75, stride: 8, size: "24" } },
    { type: 0x151b, shape: { kind: "vector", elementType: 0x40, count: 3 } },
    { type: 0x151c, name: "Matrix", shape: { kind: "matrix", elementType: 0x41,
      rows: 2, columns: 3, majorStride: 32, attributes: 0x81, size: "64" } }
  ] });
  assert.deepEqual(rows, [
    ["Strided array", "(unnamed)", "24", "—", "none", "element: int32; index: uint32; stride: 8 bytes"],
    ["Vector", "(name unavailable)", "unavailable", "—", "none", "element: float32; elements: 3"],
    ["Matrix", "Matrix", "64", "—", "row-major; unknown attributes 0x80",
      "element: float64; rows: 2; columns: 3; major stride: 32 bytes"]
  ]);
});

void test("CodeView legacy names and malformed composite metadata stay visible", () => {
  assert.deepEqual(codeViewTypeRows({ kind: "types", encoding: "c6", records: [
    { type: 93, name: "Alias" }, { type: 255 },
    { type: 0x1506, shape: { kind: "aggregate", memberCount: 0, properties: 0xffff,
      fieldList: 0x2000, derivedTypes: 0x2001, vtableShape: 0x2002 } }
  ] }).map(row => row.slice(0, 4)), [
    ["Type alias", "Alias", "—", "—"], ["C6 type record 0x1506", "(name unavailable)", "unavailable", "0"]
  ]);
  const properties = codeViewTypeRows({ kind: "types", records: [
    { type: 0x1505, name: "All", shape: { kind: "aggregate", memberCount: 0, properties: 0xffff, fieldList: 0 } },
    { type: 0x151c, name: "Default", shape: { kind: "matrix", elementType: 0,
      rows: 0, columns: 0, majorStride: 0, attributes: 0 } }
  ] });
  assert.equal(properties[0]?.[4], "packed; constructors/destructors; overloaded operators; nested type; " +
    "contains nested types; assignment operator; conversion operators; forward declaration; scoped; " +
    "decorated name flag; sealed; intrinsic; HFA: other; MoCOM: interface");
  assert.equal(properties[1]?.[4], "column-major");
});

for (const [properties, text] of [[0, "none"], [0x800, "HFA: float"], [0x1000, "HFA: double"],
  [0x4000, "MoCOM: reference"], [0x8000, "MoCOM: value"]] as const) {
  void test(`CodeView aggregate properties ${properties} retain their published meanings`, () => {
    assert.equal(codeViewTypeRows({ kind: "types", records: [{ type: 0x1505, name: "Packet",
      shape: { kind: "aggregate", memberCount: 0, properties, fieldList: 0 } }] })[0]?.[4], text);
  });
}

for (const [member, count, suffix] of [
  [{ type: 0x150d, name: "field" }, 0, "; declared member count is too small"],
  [{ type: 0x150f, name: "method", methodCount: 2 }, 1, "; declared member count is too small"],
  [{ type: 0x150f, name: "method", methodCount: 2 }, 2, ""],
  [{ type: 0x150f, name: "unknown" }, 0, ""]
] as const) {
  void test(`CodeView decoded member counts distinguish overloads from raw field records: ${member.name}/${count}`, () => {
    const rows = codeViewTypeRows({ kind: "types", records: [
      { type: 0x1505, index: 0x1000, name: "Packet", shape: { kind: "aggregate",
        memberCount: count, properties: 0, fieldList: 0x1001 } },
      { type: 0x1203, index: 0x1001, members: [member] }
    ] });
    assert.equal(rows[0]?.[5], `fields: 1 record${suffix}`);
  });
}

void test("CodeView continuation statistics count each field list once and retain reference diagnostics", () => {
  const rows = codeViewTypeRows({ kind: "types", records: [
    { type: 0x1505, index: 0x1000, name: "Packet", shape: { kind: "aggregate", memberCount: 2,
      properties: 0, fieldList: 0x1001, derivedTypes: 0x2000, vtableShape: 0x2001 } },
    { type: 0x1203, index: 0x1001, members: [{ type: 0x150d, name: "first" },
      { type: 0x1404, continuation: 0x1002 }] },
    { type: 0x1203, index: 0x1002, members: [{ type: 0x150d, name: "second" },
      { type: 0x1404, continuation: 0x2002 }] }
  ] });
  assert.equal(rows[0]?.[5], "fields: 2 records in 2 lists; missing field list #8194; " +
    "derived types: unresolved type #8192; vtable shape: unresolved type #8193");
  assert.equal(codeViewTypeRows({ kind: "types", records: [{ type: 0x1505, name: "External",
    shape: { kind: "aggregate", memberCount: 0, properties: 0, fieldList: 0x1001 } },
  { type: 0x1203, index: 0x1001, members: [] }] })[0]?.[5], "fields: missing field list #4097");
  assert.equal(codeViewTypeRows({ kind: "types", records: [{ type: 0x1505, index: 0x1000,
    shape: { kind: "aggregate", memberCount: 0, properties: 0, fieldList: 0x1001 } },
  { type: 0x1203, index: 0x1001 }] })[0]?.[5], "fields: 0 records");
});

void test("CodeView unavailable overload counts remain unknown after later ordinary fields", () => {
  const rows = codeViewTypeRows({ kind: "types", records: [
    { type: 0x1505, index: 0x1000, name: "Packet", shape: { kind: "aggregate", memberCount: 0,
      properties: 0, fieldList: 0x1001 } },
    { type: 0x1203, index: 0x1001, members: [{ type: 0x150f, name: "unknown" },
      { type: 0x150d, name: "field" }] }
  ] });
  assert.equal(rows[0]?.[5], "fields: 2 records");
});

void test("CodeView imported array references cannot borrow a local element or index type", () => {
  const rows = codeViewTypeRows({ kind: "types", records: [
    { type: 0x1505, index: 0x1000, name: "Local" },
    { type: 0x1503, name: "Imported", shape: { kind: "array", elementType: 0x1000, indexType: 0x1000 } },
    { type: 0x1503, index: 0x1001, name: "LocalArray",
      shape: { kind: "array", elementType: 0x1000, indexType: 0x1000 } }
  ] });
  assert.equal(rows[1]?.[5], "element: unresolved type #4096; index: unresolved type #4096");
  assert.equal(rows[2]?.[5], "element: Local; index: Local");
});
