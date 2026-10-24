import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCodeViewC6TypeTables } from "../../../../renderers/pe/codeview-c6-type-tables.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";
import type { LegacyCodeViewTypeRecord } from "../../../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { buildLegacyCodeViewTables } from "../../../../renderers/pe/legacy-codeview-tables.js";

const c6Info = (records: LegacyCodeViewTypeRecord[]) => {
  const info = createLegacyCodeViewInfo();
  const section = info.directories[0]!.subsections.find(value => value.data?.kind === "types")!;
  section.data = { kind: "types", encoding: "c6", records };
  return info;
};

void test("C6 type tables group anonymous layouts and preserve names with their exact bit sizes", () => {
  const info = c6Info([
    { type: 120, c6: { kind: "array", bitLength: "64", elementType: 512 } },
    { type: 120, c6: { kind: "array", bitLength: "64", elementType: 513 } },
    { type: 120, name: "<Array>&amp;", c6: { kind: "array", bitLength: "128", elementType: 512, indexType: 600 } },
    { type: 123, name: "Range", c6: { kind: "scalar", bitLength: "64", base: { kind: "type", index: 601 },
      range: { base: { kind: "style", value: "125" }, lower: "-9223372036854775808", upper: "9223372036854775807" } } },
    { type: 93, name: "Alias" }
  ]);
  const tables = buildCodeViewC6TypeTables(info);

  assert.deepEqual(tables[0]?.rows, [["1", "1", "Array", "64", "index type not stored", "2"],
    ["1", "1", "Array", "128", "explicit index type", "1"],
    ["1", "1", "Scalar", "64", "referenced base type", "1"]]);
  assert.deepEqual(tables[1]?.rows, [["1", "1", "Array", "<Array>&amp;", "128", "element: type #512; index: type #600"],
    ["1", "1", "Scalar", "Range", "64",
      "type #601; representation: signed integer; range -9223372036854775808 to 9223372036854775807"]]);
  assert.deepEqual(buildLegacyCodeViewTables(info).find(value => value.key === "legacyTypeDetails"), tables[1]);
});

void test("C6 table properties distinguish bitfields, structures, pointers and calling conventions", () => {
  const tables = buildCodeViewC6TypeTables(c6Info([
    { type: 92, name: "Bits", c6: { kind: "bitfield", bitLength: "5", style: 124, position: 17 } },
    { type: 121, name: "Packed", c6: { kind: "structure", bitLength: "32", fieldCount: "1",
      typeList: 512, nameList: 513, packing: 104 } },
    { type: 121, name: "Union", c6: { kind: "structure", bitLength: "32", fieldCount: "0" } },
    { type: 122, name: "Pointer", c6: { kind: "pointer", typeIndex: 512, style: 115 } },
    { type: 122, name: "IntelPointer", c6: { kind: "pointer", typeIndex: 513 } },
    { type: 117, name: "Function", c6: { kind: "procedure", callingConvention: 149,
      parameterCount: "2", returnType: 514, argumentsType: 515 } },
    { type: 117, name: "Void", c6: { kind: "procedure", callingConvention: 99,
      parameterCount: "0", returnLeaf: 129, argumentsType: 512 } }
  ]));
  const rows = tables[1]!.rows;

  assert.equal(rows[0]?.[5], "bit position 17; unsigned integer");
  assert.equal(rows[1]?.[5], "1 fields; field types: list #512; field names: list #513; packed");
  assert.equal(rows[2]?.[5], "0 fields");
  assert.equal(rows[3]?.[5], "points to type #512; far");
  assert.equal(rows[3]?.[4], "not stored");
  assert.equal(rows[4]?.[5], "points to type #513; style not stored");
  assert.equal(rows[5]?.[5], "near fastcall; 2 parameters; arguments: type #515; returns type #514");
  assert.equal(rows[6]?.[5], "C near; 0 parameters; arguments: type #512; return marker 129");
});

void test("C6 unknown scalar, pointer, packing and convention leaves remain visible", () => {
  const tables = buildCodeViewC6TypeTables(c6Info([
    { type: 123, name: "UnknownScalar", c6: { kind: "scalar", bitLength: "16",
      base: { kind: "style", value: "18446744073709551615" } } },
    { type: 122, name: "UnknownPointer", c6: { kind: "pointer", typeIndex: 512, style: 255 } },
    { type: 92, name: "UnknownBits", c6: { kind: "bitfield", bitLength: "-1", position: 2, style: 255 } },
    { type: 121, name: "UnknownPacking", c6: { kind: "structure", bitLength: "8", fieldCount: "0", packing: 255 } },
    { type: 117, name: "UnknownCall", c6: { kind: "procedure", callingConvention: 255,
      parameterCount: "-1", returnLeaf: 127, argumentsType: 512 } }
  ]));

  assert.match(tables[1]!.rows[0]![5]!, /style leaf 18446744073709551615/);
  assert.match(tables[1]!.rows[1]![5]!, /unknown pointer style 255/);
  assert.match(tables[1]!.rows[2]![5]!, /unknown signedness leaf 255/);
  assert.match(tables[1]!.rows[3]![5]!, /unknown packing leaf 255/);
  assert.match(tables[1]!.rows[4]![5]!, /unknown calling convention 255/);
});

void test("C6 tables never reuse C7/HLL semantics and omit absent metadata", () => {
  assert.deepEqual(buildCodeViewC6TypeTables(createLegacyCodeViewInfo()), []);
  assert.deepEqual(buildCodeViewC6TypeTables(c6Info([])), []);
  const info = c6Info([{ type: 120, c6: { kind: "array", bitLength: "8", elementType: 512 } }]);
  const data = info.directories[0]!.subsections.find(value => value.data?.kind === "types")!.data;
  assert.ok(data?.kind === "types");
  data.encoding = "hll";
  assert.deepEqual(buildCodeViewC6TypeTables(info), []);
});

void test("C6 named arrays preserve an omitted index type without inventing a reference", () => {
  const tables = buildCodeViewC6TypeTables(c6Info([
    { type: 120, name: "Bytes", c6: { kind: "array", bitLength: "8", elementType: 512 } }
  ]));

  assert.deepEqual(tables[1]?.rows, [["1", "1", "Array", "Bytes", "8", "element: type #512"]]);
});
