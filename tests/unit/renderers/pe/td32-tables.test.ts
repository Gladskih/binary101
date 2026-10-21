import assert from "node:assert/strict";
import { test } from "node:test";
import { buildTd32Tables } from "../../../../renderers/pe/td32-tables.js";
import { createTd32Info } from "../../../fixtures/pe-td32-view.js";

void test("TD32 tables preserve all names and report readable symbols, contributions and source statistics", () => {
  const tables = buildTd32Tables(createTd32Info());

  assert.deepEqual(tables.find(table => table.key === "modules")!.rows,
    [["1", "1", "<unit>.pas", "1", "1", "32"]]);
  assert.deepEqual(tables.find(table => table.key === "source")!.rows,
    [["1", "1", "source.pas", "1", "3", "2"]]);
  assert.deepEqual(tables.find(table => table.key === "symbols")!.rows,
    [["1", "1", "Global procedure", "Worker"], ["1", "1", "Compiler", "<compiler>"],
      ["1", "1", "Unrecognized symbol kind 30583", "(unresolved name #99)"],
      ["1", "1", "Public symbol", "(unnamed)"]]);
  assert.equal(tables.find(table => table.key === "names")!.rows[3]![2], "unused type name");
  assert.deepEqual(tables.find(table => table.key === "inventory")!.rows.slice(-2),
    [["1", "0", "Global types", "8", "types"], ["1", "0", "Unrecognized kind 2457", "8", "Not decoded"]]);
  assert.deepEqual(tables.find(table => table.key === "kinds")!.rows[1], ["1", "Scope end", "1"]);
  assert.deepEqual(tables.find(table => table.key === "types")!.rows, [["1", "0", "0", "Class", "unused type name"]]);
  assert.deepEqual(tables.find(table => table.key === "typekinds")!.rows,
    [["1", "0", "Class", "2"], ["1", "0", "Producer-specific type kind 52", "1"]]);
});

void test("TD32 tables retain directory generations and represent missing shared names explicitly", () => {
  const td32 = createTd32Info();
  td32.directories[0]!.subsections.shift();
  td32.directories.push(td32.directories[0]!);
  const tables = buildTd32Tables(td32);

  assert.equal(tables.find(table => table.key === "modules")!.rows[1]![0], "2");
  assert.equal(tables.find(table => table.key === "modules")!.rows[0]![2], "(unresolved name #1)");
  assert.ok(!tables.some(table => table.key === "names"));
  assert.deepEqual(buildTd32Tables({ signature: "FB09", directories: [] }), []);
});
