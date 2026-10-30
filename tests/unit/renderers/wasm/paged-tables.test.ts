import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWasm } from "../../../../analyzers/wasm/index.js";
import { getWasmPagedTableModel } from "../../../../renderers/wasm/paged-tables.js";
import { createWasmFile } from "../../../fixtures/wasm-fixtures.js";

// Expected values come from the hand-encoded core module fixture, not renderer constants.
const tableCases: [string, string[]][] = [
  ["sections", ["Type", "1", "8", "10", "14", "", "decoded"]],
  ["types", ["0", "(i32) → ()"]],
  ["imports", ["env", "log", "function", "type 0"]],
  ["exports", ["add", "function", "1"]],
  ["functions", ["1", "add", "1", "(i32, i32) → (i32)", "7", ""]],
  ["memories", ["0", "1", "2", "32", "false"]],
  ["tables", ["0", "funcref", "1..4, 32-bit"]],
  ["globals", ["0", "i32", "false", "i32.const 42; end"]],
  ["data", ["0", "active", "0", "i32.const 0; end", "140", "19",
    "48 65 6c 6c 6f 2c 20 57 65 62 41 73 73 65 6d 62 6c 79 21"]],
  ["elements", ["0", "active", "0", "i32.const 0; end", "funcref", "1"]],
  ["producers", ["processed-by", "Binary101 fixture", "1"]],
  ["features", ["+", "mutable-globals"]],
  ["tags", ["0", "0"]],
  ["code-0", ["119", "local.get", "0"]]
];

for (const [id, expected] of tableCases) void test(`provides stable rows and sortable values for ${id}`, async () => {
  const data = (await parseWasm(createWasmFile()))!;
  data.tags.push(0);
  const model = getWasmPagedTableModel(data, `wasm-${id}`)!;
  assert.ok(model.rowAt(0));
  assert.equal(model.rowAt(-1), null);
  assert.equal(model.rowAt(model.rowCount), null);
  assert.equal(model.sortValueAt(-1, 0), "");
  assert.equal(model.sortValueAt(0, 999), "");
  assert.equal(typeof model.sortValueAt(0, 0), "string");
  assert.deepEqual(model.columns.map((_, index) => model.sortValueAt(0, index)), expected);
  assert.deepEqual(model.rowAt(0)!.cells.map(cell => cell.html), expected);
  assert.equal(getWasmPagedTableModel(data, "unknown"), null);
  assert.equal(getWasmPagedTableModel(data, "wasm-code-999"), null);
  assert.match(getWasmPagedTableModel(data, "wasm-functions")!.rowAt(0)!.additionalRowsHtml!, /i32.add/);
});

void test("preserves numeric cell alignment and text escaping in sortable table models", async () => {
  const data = (await parseWasm(createWasmFile()))!;
  data.exports[0]!.name = "<img src=x onerror=alert(1)>";
  const model = getWasmPagedTableModel(data, "wasm-exports")!;
  assert.equal(model.rowAt(0)!.cells[0]!.html, "&lt;img src=x onerror=alert(1)&gt;");
  assert.equal(model.rowAt(0)!.cells[0]!.className, undefined);
  assert.equal(model.rowAt(0)!.cells[2]!.className, "wasmTable__number");
  assert.equal(model.sortValueAt(0, 0), "<img src=x onerror=alert(1)>");
  data.exports[0]!.name = "&lt;entry&gt;";
  assert.equal(model.rowAt(0)!.cells[0]!.html, "&amp;lt;entry&amp;gt;");
});

void test("handles unresolved and absent function bodies and nullable data memory", async () => {
  const data = (await parseWasm(createWasmFile()))!;
  data.code = [];
  data.functions.push({ typeIndex: 999 });
  data.data[0]!.memory = null;
  data.elements[0]!.entries = [[{ offset: 0, mnemonic: "ref.null", operands: "-16" }]];
  data.sections[0]!.id = 255;
  assert.equal(getWasmPagedTableModel(data, "wasm-sections")!.sortValueAt(0, 0), "Unknown");
  assert.match(getWasmPagedTableModel(data, "wasm-functions")!.sortValueAt(2, 3), /Unresolved/);
  assert.equal(getWasmPagedTableModel(data, "wasm-functions")!.sortValueAt(2, 1), "");
  assert.equal(getWasmPagedTableModel(data, "wasm-functions")!.rowAt(0)!.additionalRowsHtml, undefined);
  assert.equal(getWasmPagedTableModel(data, "wasm-data")!.sortValueAt(0, 2), "");
  assert.match(getWasmPagedTableModel(data, "wasm-elements")!.sortValueAt(0, 5), /ref.null/);
});

void test("renders grouped locals, complete element lists and leading-zero data bytes", async () => {
  const data = (await parseWasm(createWasmFile()))!;
  data.code[0]!.locals = [{ count: 3, type: "i32" }, { count: 2, type: "i64" }];
  data.elements[0]!.entries = [1, 2];
  data.data[0]!.preview = [0, 15, 255];
  assert.equal(getWasmPagedTableModel(data, "wasm-functions")!.sortValueAt(0, 5), "3 × i32, 2 × i64");
  assert.equal(getWasmPagedTableModel(data, "wasm-elements")!.sortValueAt(0, 5), "1; 2");
  assert.equal(getWasmPagedTableModel(data, "wasm-data")!.sortValueAt(0, 6), "00 0f ff");
  assert.equal(getWasmPagedTableModel(data, "wasm-sections")!.sortValueAt(11, 5), "name");
});

void test("renders unbounded shared memory64 without rounding bigint limits", async () => {
  const data = (await parseWasm(createWasmFile()))!;
  data.memories[0] = { min: 9007199254740993n, max: null, address64: true, shared: true };
  const row = getWasmPagedTableModel(data, "wasm-memories")!.rowAt(0)!;
  assert.deepEqual(row.cells.map(cell => cell.html), ["0", "9007199254740993", "—", "64", "true"]);
  assert.equal(row.cells[1]!.className, "wasmTable__number");
  assert.equal(row.cells[2]!.className, undefined);
});
