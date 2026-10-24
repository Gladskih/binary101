import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLegacyCodeViewConstantTables } from "../../../../renderers/pe/legacy-codeview-constant-tables.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";

void test("CodeView constant table keeps names, type indexes, exact values, and noninteger leaves readable", () => {
  const info = createLegacyCodeViewInfo();
  const section = info.directories[0]!.subsections.find(value => value.data?.kind === "symbols")!;
  section.data = { kind: "symbols", records: [
    { type: 0x1107, name: "Maximum", constant: { typeIndex: 4097,
      numeric: { leaf: 0x8018, byteLength: 18, value: "340282366920938463463374607431768211455" } } },
    { type: 0x1002, name: "Float", constant: { typeIndex: 4098,
      numeric: { leaf: 0x8007, byteLength: 12 } } },
    { type: 3, constant: { numeric: { issue: "Error: Unknown CodeView numeric leaf 36863." } } }
  ] };

  assert.deepEqual(buildLegacyCodeViewConstantTables(info), [{ key: "symbolConstants",
    title: "Stored symbol constants",
    columns: ["Directory", "Module", "Container", "Symbol kind", "Name", "Type index", "Stored value"],
    rows: [
      ["1", "1", "(top level)", "Constant", "Maximum", "4097",
        "340282366920938463463374607431768211455"],
      ["1", "1", "(top level)", "Constant", "Float", "4098",
        "Noninteger numeric leaf 32775 (12 bytes)"],
      ["1", "1", "(top level)", "Constant", "(name unavailable)", "unavailable",
        "Unavailable: Error: Unknown CodeView numeric leaf 36863."]
    ] }]);
});

void test("CodeView constant table omits files without constant records", () => {
  assert.deepEqual(buildLegacyCodeViewConstantTables(createLegacyCodeViewInfo()), []);
});

void test("CodeView constant table retains constant symbols embedded in a type record", () => {
  const info = createLegacyCodeViewInfo();
  const section = info.directories[0]!.subsections.find(value => value.data?.kind === "types")!;
  section.data = { kind: "types", records: [{ type: 0x20c, symbols: [{ type: 0x1107, name: "Bound",
    constant: { typeIndex: 4099, numeric: { byteLength: 2, value: "24" } } }] }] };

  assert.deepEqual(buildLegacyCodeViewConstantTables(info)[0]?.rows, [["1", "1", "Referenced symbol",
    "Constant", "Bound", "4099", "24"]]);
});
