import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCodeViewArrayBounds } from "../../../../renderers/pe/codeview-array-bounds.js";
import { codeViewInfoWithTypes } from "../../../fixtures/pe-codeview-callables.js";

void test("CodeView array bounds retain named arrays, exact integer ranges and language-specific lower bounds", () => {
  const tables = buildCodeViewArrayBounds(codeViewInfoWithTypes([
    { type: 0x1508, index: 0x1000, name: "<Grid>&amp;", shape: {
      kind: "dimensionedArray", underlyingType: 0x74, dimensionsType: 0x1001 } },
    { type: 0x209, index: 0x1001, shape: { kind: "constantDimensions", indexType: 0x74, rank: 2,
      boundKind: "lowerUpper", bounds: { kind: "integers", values: ["-1", "3", "2", "5"] } } },
    { type: 0x1207, index: 0x1002, shape: { kind: "constantDimensions", indexType: 0x77, rank: 1,
      boundKind: "upper", bounds: { kind: "integers", values: ["18446744073709551615"] } } }
  ]));
  assert.deepEqual(tables[0]?.rows, [
    ["1", "1", "<Grid>&amp; (rank: 2)", "int32", "1", "-1", "3"],
    ["1", "1", "<Grid>&amp; (rank: 2)", "int32", "2", "2", "5"],
    ["1", "1", "dimensions #4098 (rank: 1)", "uint64", "1", "(language default)", "18446744073709551615"]
  ]);
  assert.equal(tables[0]?.key, "arrayBounds");
  assert.equal(tables[0]?.title, "Array bounds");
  assert.deepEqual(tables[0]?.columns,
    ["Directory", "Module", "Array / dimensions", "Index type", "Dimension", "Lower bound", "Upper bound"]);
});

void test("CodeView variable bounds retain symbol names, void markers and unresolved references", () => {
  const tables = buildCodeViewArrayBounds(codeViewInfoWithTypes([
    { type: 0x120a, index: 0x1000, shape: { kind: "variableDimensions", indexType: 0x74, rank: 5,
      boundKind: "lowerUpper", bounds: [0x1001, 3, 0x1002, 0x1003, 0x1004, 0x1005, 0x2000] } },
    { type: 0x20c, index: 0x1001, symbols: [{ type: 3, name: "<minimum>&amp;" }] },
    { type: 0x20c, index: 0x1002, symbols: [{ type: 3 }] },
    { type: 0x20c, index: 0x1003 }, { type: 0x1505, index: 0x1004, name: "Wrong" },
    { type: 0x20c, index: 0x1005 }, { type: 0x20c, index: 0x1005 }
  ]));
  assert.deepEqual(tables[0]?.rows.map(row => row.slice(4)), [
    ["1", "<minimum>&amp;", "(unspecified)"], ["2", "Constant (unnamed)", "unavailable bound symbol"],
    ["3", "invalid bound reference: Wrong", "ambiguous type #4101"],
    ["4", "unresolved type #8192", "unavailable"]
  ]);
});

void test("CodeView shared bounds summarize ownership without multiplying a large shared dimension list", () => {
  const tables = buildCodeViewArrayBounds(codeViewInfoWithTypes([
    { type: 0x1508, index: 0x1000, name: "First", shape: {
      kind: "dimensionedArray", underlyingType: 0x74, dimensionsType: 0x1002 } },
    { type: 0x1508, index: 0x1001, shape: {
      kind: "dimensionedArray", underlyingType: 0x74, dimensionsType: 0x1002 } },
    { type: 0x1207, index: 0x1002, shape: { kind: "constantDimensions", indexType: 0x74, rank: 1,
      boundKind: "upper", bounds: { kind: "integers", values: ["7"] } } }
  ]));
  assert.deepEqual(tables[0]?.rows,
    [["1", "1", "dimensions #4098 (arrays: 2) (rank: 1)", "int32", "1", "(language default)", "7"]]);
});

void test("CodeView unavailable and truncated bounds stay visible without allocating rows for the declared rank", () => {
  const tables = buildCodeViewArrayBounds(codeViewInfoWithTypes([
    { type: 0x1208, shape: { kind: "constantDimensions", indexType: 0x74, rank: 0xffff,
      boundKind: "lowerUpper", bounds: { kind: "encoded", bytes: Uint8Array.of(1) } } },
    { type: 0x1208, index: 0x1000, shape: { kind: "constantDimensions", indexType: 0x74, rank: 1,
      boundKind: "lowerUpper", bounds: { kind: "integers", values: ["-1"] } } },
    { type: 0x1207, index: 0x1001, shape: { kind: "constantDimensions", indexType: 0x74, rank: 0,
      boundKind: "upper", bounds: { kind: "integers", values: [] } } }
  ]));
  assert.deepEqual(tables[0]?.rows, [
    ["1", "1", "dimensions #unresolved (rank: 65535)", "int32", "—", "unavailable", "unavailable"],
    ["1", "1", "dimensions #4096 (rank: 1)", "int32", "1", "-1", "unavailable"]
  ]);
});

void test("CodeView external array namespaces never borrow local owners or bound symbols", () => {
  const tables = buildCodeViewArrayBounds(codeViewInfoWithTypes([
    { type: 0x1508, shape: { kind: "dimensionedArray", underlyingType: 0x74, dimensionsType: 0x1000 } },
    { type: 0x1209, shape: { kind: "variableDimensions", indexType: 0x74, rank: 1,
      boundKind: "upper", bounds: [0x1001] } },
    { type: 0x20c, index: 0x1001, symbols: [{ type: 3, name: "Local" }] },
    { type: 0x1508, index: 0x1002, shape: { kind: "dimensionedArray", underlyingType: 0x74,
      dimensionsType: 0x2000 } }
  ]));
  assert.deepEqual(tables[0]?.rows, [["1", "1", "dimensions #unresolved (rank: 1)", "int32", "1",
    "(language default)", "unresolved type #4097"]]);
  assert.deepEqual(buildCodeViewArrayBounds({ signature: "NB09", directories: [] }), []);
});

void test("CodeView bounds tables skip incompatible and empty subsections", () => {
  assert.deepEqual(buildCodeViewArrayBounds({ signature: "NB09", directories: [{ flags: 0, subsections: [
    { type: 0x103, module: 1, offset: 0, size: 0, data: { kind: "types", encoding: "c6", records: [] } },
    { type: 0x125, module: 1, offset: 0, size: 0, data: { kind: "symbols", records: [] } }
  ] }] }), []);
});

void test("CodeView duplicate array identities cannot claim ownership of a valid bounds record", () => {
  const tables = buildCodeViewArrayBounds(codeViewInfoWithTypes([
    { type: 0x1508, index: 0x1000, name: "First", shape: {
      kind: "dimensionedArray", underlyingType: 0x74, dimensionsType: 0x1001 } },
    { type: 0x1508, index: 0x1000, name: "Second", shape: {
      kind: "dimensionedArray", underlyingType: 0x74, dimensionsType: 0x1001 } },
    { type: 0x1207, index: 0x1001, shape: { kind: "constantDimensions", indexType: 0x74, rank: 1,
      boundKind: "upper", bounds: { kind: "integers", values: ["7"] } } }
  ]));
  assert.equal(tables[0]?.rows[0]?.[2], "dimensions #4097 (rank: 1)");
});
