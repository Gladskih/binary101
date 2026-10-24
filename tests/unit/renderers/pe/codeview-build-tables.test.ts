import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCodeViewBuildTables } from "../../../../renderers/pe/codeview-build-tables.js";
import { codeViewInfoWithTypes } from "../../../fixtures/pe-codeview-callables.js";

void test("CodeView build and source rows resolve local strings and preserve external string-table identity", () => {
  const tables = buildCodeViewBuildTables(codeViewInfoWithTypes([
    { type: 0x1505, index: 0x1000, name: "Packet" },
    { type: 0x1605, index: 0x1001, strings: ["<source>&amp;.cpp"], shape: { kind: "stringId", substrings: 0 } },
    { type: 0x1605, index: 0x1002, strings: ["cl.exe"], shape: { kind: "stringId", substrings: 0 } },
    { type: 0x1605, index: 0x1003, strings: ["/c /DNAME=<value>&amp;"], shape: { kind: "stringId", substrings: 0 } },
    { type: 0x1603, index: 0x1004, shape: { kind: "buildInfo", indices: [0, 0x1002, 0x1001, 0, 0x1003] } },
    { type: 0x1606, index: 0x1005, shape: { kind: "sourceLine", typeIndex: 0x1000, source: 0x1001, line: 123 } },
    { type: 0x1607, index: 0x1006, shape: { kind: "sourceLine", typeIndex: 0x1000, source: 0x1001, line: 456, module: 2 } }
  ]));
  assert.deepEqual(tables.find(table => table.key === "buildInfo")?.rows, [
    ["1", "1", "1", "Current directory", "(none)"], ["1", "1", "1", "Build tool", "cl.exe"],
    ["1", "1", "1", "Source file", "<source>&amp;.cpp"], ["1", "1", "1", "Program database file", "(none)"],
    ["1", "1", "1", "Command arguments", "/c /DNAME=<value>&amp;"]
  ]);
  assert.deepEqual(tables.find(table => table.key === "typeSources")?.rows, [
    ["1", "1", "Packet", "<source>&amp;.cpp", "123"],
    ["1", "1", "Packet", "module 2 string-table offset #4097 (external)", "456"]
  ]);
  assert.deepEqual(tables.map(table => [table.title, table.columns]), [
    ["Build information", ["Directory", "Module", "Build", "Field", "Value"]],
    ["Type definition sources", ["Directory", "Module", "Type", "Source file", "Source line"]]
  ]);
});

void test("CodeView build rows diagnose missing, ambiguous, wrong-kind and unavailable strings", () => {
  const tables = buildCodeViewBuildTables(codeViewInfoWithTypes([
    { type: 0x1603, index: 0x1000, shape: { kind: "buildInfo",
      indices: [0x2000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005] } },
    { type: 0x1605, index: 0x1001 }, { type: 0x1605, index: 0x1001 },
    { type: 0x1505, index: 0x1002, name: "Wrong" },
    { type: 0x1605, index: 0x1003, shape: { kind: "stringId", substrings: 0 } },
    { type: 0x1605, index: 0x1004, strings: [""], shape: { kind: "stringId", substrings: 0 } },
    { type: 0x1605, index: 0x1005, strings: ["suffix"], shape: { kind: "stringId", substrings: 0x1006 } },
    { type: 0x1604, index: 0x1006, shape: { kind: "stringList", indices: [0x1004, 0x1005] } },
    { type: 0x1603, index: 0x1007, shape: { kind: "buildInfo", indices: [] } }
  ]));
  assert.deepEqual(tables.find(table => table.key === "buildInfo")?.rows.map(row => row.slice(2)), [
    ["1", "Current directory", "missing string ID #8192"], ["1", "Build tool", "ambiguous string ID #4097"],
    ["1", "Source file", "type #4098 is not a string ID"],
    ["1", "Program database file", "string ID #4099 has no stored text"],
    ["1", "Command arguments", "(empty)"],
    ["1", "Additional argument 6", "stored text: suffix; substring list #4102"], ["2", "Arguments", "(empty)"]
  ]);
  assert.deepEqual(tables.find(table => table.key === "stringComponents")?.rows, [
    ["1", "1", "4102", "1", "(empty)"],
    ["1", "1", "4102", "2", "stored text: suffix; substring list #4102"]
  ]);
  const components = tables.find(table => table.key === "stringComponents")!;
  assert.equal(components.title, "String components");
  assert.deepEqual(components.columns, ["Directory", "Module", "String list", "Component", "Stored text"]);
});

void test("CodeView external metadata identities cannot borrow local strings or classes", () => {
  const tables = buildCodeViewBuildTables(codeViewInfoWithTypes([
    { type: 0x1505, index: 0x1000, name: "Local" },
    { type: 0x1605, index: 0x1001, strings: ["local.cpp"], shape: { kind: "stringId", substrings: 0 } },
    { type: 0x1606, shape: { kind: "sourceLine", typeIndex: 0x1000, source: 0x1001, line: 0 } },
    { type: 0x1604, shape: { kind: "stringList", indices: [0x1001] } },
    { type: 0x1603, shape: { kind: "buildInfo", indices: [0x1001] } }
  ]));
  assert.deepEqual(tables.find(table => table.key === "typeSources")?.rows, [
    ["1", "1", "unresolved type #4096", "missing string ID #4097", "0"]
  ]);
  assert.deepEqual(tables.find(table => table.key === "stringComponents")?.rows,
    [["1", "1", "unresolved", "1", "missing string ID #4097"]]);
  assert.equal(tables.find(table => table.key === "buildInfo")?.rows[0]?.[4], "missing string ID #4097");
});

void test("CodeView metadata tables omit empty and incompatible encodings", () => {
  assert.deepEqual(buildCodeViewBuildTables({ signature: "NB09", directories: [] }), []);
  assert.deepEqual(buildCodeViewBuildTables({ signature: "NB09", directories: [{ flags: 0, subsections: [
    { type: 0x103, module: 1, offset: 0, size: 0,
      data: { kind: "types", encoding: "c6", records: [] } },
    { type: 0x125, module: 1, offset: 0, size: 0, data: { kind: "symbols", records: [] } }
  ] }] }), []);
});

void test("CodeView PDB type server identities retain GUID or classic signature, age and exact file names", () => {
  const tables = buildCodeViewBuildTables(codeViewInfoWithTypes([
    { type: 0x1515, strings: ["<types>&amp;.pdb"], shape: { kind: "typeServer", age: 0xffffffff,
      identity: { kind: "guid", value: "12345678-9abc-def0-1122-334455667788" } } },
    { type: 0x16, strings: [""], shape: { kind: "typeServer", age: 0,
      identity: { kind: "signature", value: 0x12345678 } } },
    { type: 0x1501, shape: { kind: "typeServer", age: 1, identity: { kind: "signature", value: 0 } } }
  ]));
  assert.deepEqual(tables.find(table => table.key === "typeServers"), {
    key: "typeServers", title: "PDB type server identities",
    columns: ["Directory", "Module", "PDB file", "Identity", "PDB age"], rows: [
      ["1", "1", "<types>&amp;.pdb", "GUID 12345678-9abc-def0-1122-334455667788", "4294967295"],
      ["1", "1", "(empty)", "Signature 0x12345678", "0"],
      ["1", "1", "(file name unavailable)", "Signature 0x00000000", "1"]
    ]
  });
});
