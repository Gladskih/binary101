import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCodeViewVtableTables } from "../../../../renderers/pe/codeview-vtable-tables.js";
import { codeViewInfoWithTypes } from "../../../fixtures/pe-codeview-callables.js";

void test("CodeView virtual table metadata retains table names, class ownership and unsigned pointer placement", () => {
  const tables = buildCodeViewVtableTables(codeViewInfoWithTypes([
    { type: 0x1505, index: 0x1000, name: "<Derived>&amp;" },
    { type: 0x1505, index: 0x1001, name: "Base" },
    { type: 0x151d, index: 0x1002, strings: ["Base::table", "read"],
      shape: { kind: "vtable", ownerType: 0x1001, baseTable: 0, pointerOffset: 0 } },
    { type: 0x151d, index: 0x1003, strings: ["<Derived>&amp;::table", "read", "<write>&amp;"],
      shape: { kind: "vtable", ownerType: 0x1000, baseTable: 0x1002, pointerOffset: 0xffffffff } },
    { type: 0x100d, index: 0x1004, shape: { kind: "vtablePath", indices: [0x1000, 0x1001] } }
  ]));
  assert.deepEqual(tables.find(table => table.key === "virtualTables")?.rows, [
    ["1", "1", "Base::table", "Base", "0", "(none)", "1"],
    ["1", "1", "<Derived>&amp;::table", "<Derived>&amp;", "4294967295", "Base::table", "2"]
  ]);
  assert.deepEqual(tables.find(table => table.key === "vtablePaths")?.rows,
    [["1", "1", "4100", "<Derived>&amp; → Base"]]);
  assert.deepEqual(tables.map(table => [table.title, table.columns]), [
    ["Virtual table layouts", ["Directory", "Module", "Table name", "Owner type", "Pointer offset",
      "Base table", "Stored method names"]],
    ["Paths to virtual tables", ["Directory", "Module", "Path type index", "Base classes (root to leaf)"]]
  ]);
});

void test("CodeView incomplete vtable names and unresolved bases remain explicit", () => {
  const tables = buildCodeViewVtableTables(codeViewInfoWithTypes([
    { type: 0x151d, index: 0x1000, shape: { kind: "vtable", ownerType: 0x2000,
      baseTable: 0x2001, pointerOffset: 8 } },
    { type: 0x151d, index: 0x1001, strings: [""], shape: { kind: "vtable", ownerType: 0x2000,
      baseTable: 0x1002, pointerOffset: 0 } },
    { type: 0x1505, index: 0x1002, name: "Wrong" },
    { type: 0x151d, index: 0x1003, strings: [], shape: { kind: "vtable", ownerType: 0x2000,
      baseTable: 0x1004, pointerOffset: 0 } },
    { type: 0x151d, index: 0x1004 }, { type: 0x151d, index: 0x1004 },
    { type: 0x100d, index: 0x1005, shape: { kind: "vtablePath", indices: [] } }
  ]));
  assert.deepEqual(tables.find(table => table.key === "virtualTables")?.rows, [
    ["1", "1", "(table name unavailable)", "unresolved type #8192", "8", "missing virtual table #8193", "unavailable"],
    ["1", "1", "(unnamed table)", "unresolved type #8192", "0", "type #4098 is not a virtual table", "0"],
    ["1", "1", "(table name unavailable)", "unresolved type #8192", "0", "ambiguous virtual table #4100", "0"]
  ]);
  assert.deepEqual(tables.find(table => table.key === "vtablePaths")?.rows, [["1", "1", "4101", "(empty)"]]);
});

void test("CodeView external or ambiguous vtable identities cannot borrow local class and table names", () => {
  const tables = buildCodeViewVtableTables(codeViewInfoWithTypes([
    { type: 0x1505, index: 0x1000, name: "Local" },
    { type: 0x151d, index: 0x1001, strings: ["Local::table"],
      shape: { kind: "vtable", ownerType: 0x1000, baseTable: 0, pointerOffset: 0 } },
    { type: 0x151d, strings: ["External"],
      shape: { kind: "vtable", ownerType: 0x1000, baseTable: 0x1001, pointerOffset: 0 } },
    { type: 0x100d, shape: { kind: "vtablePath", indices: [0x1000] } },
    { type: 0x100d, index: 0x1002, shape: { kind: "vtablePath", indices: [0x1000] } },
    { type: 0x100d, index: 0x1002, shape: { kind: "vtablePath", indices: [0x1000] } }
  ]));
  assert.deepEqual(tables.find(table => table.key === "virtualTables")?.rows[1],
    ["1", "1", "External", "unresolved type #4096", "0", "missing virtual table #4097", "0"]);
  assert.deepEqual(tables.find(table => table.key === "vtablePaths")?.rows,
    [["1", "1", "unresolved", "unresolved type #4096"],
      ["1", "1", "4098", "unresolved type #4096"], ["1", "1", "4098", "unresolved type #4096"]]);
});

void test("CodeView vtable metadata tables omit empty and incompatible subsections", () => {
  assert.deepEqual(buildCodeViewVtableTables({ signature: "NB09", directories: [] }), []);
  assert.deepEqual(buildCodeViewVtableTables({ signature: "NB09", directories: [{ flags: 0, subsections: [
    { type: 0x103, module: 1, offset: 0, size: 0, data: { kind: "types", encoding: "c6", records: [] } },
    { type: 0x125, module: 1, offset: 0, size: 0, data: { kind: "symbols", records: [] } }
  ] }] }), []);
});
