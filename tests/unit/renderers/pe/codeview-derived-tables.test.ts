import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCodeViewDerivedTables } from "../../../../renderers/pe/codeview-derived-tables.js";
import { codeViewInfoWithTypes } from "../../../fixtures/pe-codeview-callables.js";

void test("CodeView derived lists retain class names and explicitly untranslated entries", () => {
  const tables = buildCodeViewDerivedTables(codeViewInfoWithTypes([
    { type: 0x1505, index: 0x1000, name: "Base", shape: { kind: "aggregate", properties: 0,
      fieldList: 0, memberCount: 0, derivedTypes: 0x1002 } },
    { type: 0x1505, index: 0x1001, name: "<Derived>&amp;" },
    { type: 0x205, index: 0x1002, shape: { kind: "derived", indices: [0x1001, 7, 0x1003] } }
  ]));
  assert.deepEqual(tables[0]?.rows, [["1", "1", "Base", "<Derived>&amp;"],
    ["1", "1", "Base", "not translated"], ["1", "1", "Base", "unresolved type #4099"]]);
  assert.equal(tables[0]?.title, "Derived type relationships");
  assert.deepEqual(tables[0]?.columns, ["Directory", "Module", "Base type", "Derived type"]);
});

void test("CodeView derived tables reject external owners and ambiguous or wrong-kind lists", () => {
  assert.deepEqual(buildCodeViewDerivedTables(codeViewInfoWithTypes([
    { type: 0x1505, shape: { kind: "aggregate", properties: 0, fieldList: 0, derivedTypes: 0x1000 } },
    { type: 0x1505, index: 0x1001, shape: { kind: "aggregate", properties: 0,
      fieldList: 0, derivedTypes: 0x1000 } },
    { type: 0x1505, index: 0x1001, name: "Duplicate owner" },
    { type: 0x1505, index: 0x1002, shape: { kind: "aggregate", properties: 0,
      fieldList: 0, derivedTypes: 0x1003 } },
    { type: 0x1204, index: 0x1003, shape: { kind: "derived", indices: [7] } },
    { type: 0x1204, index: 0x1003, shape: { kind: "derived", indices: [7] } },
    { type: 0x1204, index: 0x1000, shape: { kind: "derived", indices: [7] } },
    { type: 0x1505, index: 0x1004 }
  ])), []);
  assert.deepEqual(buildCodeViewDerivedTables({ signature: "NB09", directories: [{ flags: 0, subsections: [
    { type: 0x103, module: 1, offset: 0, size: 0, data: { kind: "types", encoding: "c6", records: [] } },
    { type: 0x125, module: 1, offset: 0, size: 0, data: { kind: "symbols", records: [] } }
  ] }] }), []);
});
