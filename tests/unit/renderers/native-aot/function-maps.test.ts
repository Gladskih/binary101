import assert from "node:assert/strict";
import test from "node:test";
import { getNativeAotFunctionTableModel, renderNativeAotFunctionMaps } from
  "../../../../renderers/native-aot/function-maps.js";
import { createFunctionMapModels } from "../../../helpers/native-aot-function-map-models.js";

void test("function maps render semantic tables and escape fields and warnings", () => {
  const html = renderNativeAotFunctionMaps(createFunctionMapModels());

  assert.match(html, /<table/);
  assert.match(html, /&lt;global>/);
  assert.match(html, /&lt;struct>/);
  assert.match(html, /&lt;field>/);
  assert.match(html, /0x00000300/);
  assert.match(html, /Native size/);
  assert.equal(renderNativeAotFunctionMaps(undefined), "");
});

for (const type of [310, 316, 317, 321, 322, 336]) {
  void test(`function map ${type} exposes lazy sortable rows and handles absent indices`, () => {
    const table = getNativeAotFunctionTableModel(createFunctionMapModels(), `native-aot-function-map-${type}`)!;

    assert.equal(table.rowCount, 1);
    assert.ok(table.rowAt(0));
    assert.equal(table.rowAt(1), null);
    assert.equal(table.sortValueAt?.(1, 0), "");
    assert.ok(table.sortValueAt?.(0, 0));
  });
}

void test("struct fields and dictionary methods have separate paginated tables", () => {
  const maps = createFunctionMapModels();
  const fields = getNativeAotFunctionTableModel(maps, "native-aot-function-map-316-fields")!;
  const methods = getNativeAotFunctionTableModel(maps, "native-aot-function-map-321-dictionary")!;

  assert.equal(fields.rowAt(0)?.cells[1]?.html, "&lt;field>");
  assert.equal(fields.rowAt(-1), null);
  assert.equal(methods.rowAt(0)?.cells[3]?.html, "0x00000300");
  assert.equal(methods.rowAt(1), null);
  assert.equal(getNativeAotFunctionTableModel(maps, "unrelated"), null);
  assert.equal(getNativeAotFunctionTableModel(maps, "native-aot-function-map-999"), null);
  assert.equal(getNativeAotFunctionTableModel(undefined, "native-aot-function-map-316"), null);
});

const expectedTables = [
  ["310", ["Type index", "Static base index", "Entry point RVA"], ["0", "1", "0x00000040"]],
  ["316", ["Type index", "Header", "Native size", "Marshal RVA", "Unmarshal RVA", "Cleanup RVA"],
    ["0", "0x00000005", "32", "0x00000040", "0x00000300", "-"]],
  ["316-fields", ["Type index", "Name", "Offset"], ["0", "<field>", "4"]],
  ["317", ["Type index", "Open static RVA", "Closed RVA", "Forward creation RVA"],
    ["1", "0x00000040", "-", "0x00000300"]],
  ["321", ["Type index", "Layout offset", "Class constructor RVA"], ["1", "0x00000000", "0x00000040"]],
  ["321-dictionary", ["Signature offset", "Flags", "Method token", "Entry point RVA"],
    ["0x00000008", "0x04", "0x0000000a", "0x00000300"]],
  ["322", ["Signature offset", "Layout offset", "Flags", "Type index", "Method token",
    "Generic type indices", "Entry point RVA"], ["0x00000000", "0x00000008", "0x05", "1",
    "0x0000000a", "0", "0x00000040"]],
  ["336", ["Type index", "Method token", "Generic type indices", "Entry point RVA"],
    ["1", "0x0000000a", "-", "0x00000300"]]
] as const;

for (const [suffix, labels, values] of expectedTables) {
  void test(`table ${suffix} preserves every column, formatted value and sort key`, () => {
    const table = getNativeAotFunctionTableModel(createFunctionMapModels(), `native-aot-function-map-${suffix}`)!;

    assert.deepEqual(table.columns.map(column => column.label), [...labels]);
    assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.html), values.map(value => value.replace("<", "&lt;")));
    assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.sortValue), [...values]);
    assert.deepEqual(values.map((_value, column) => table.sortValueAt?.(0, column)), [...values]);
    assert.deepEqual(table.columns.map(column => column.className),
      labels.map(label => label === "Name" ? "" : "peNumeric"));
    assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.className),
      labels.map(label => label === "Name" ? "" : "peNumeric"));
    assert.equal(table.pageSize, 100);
  });
}

void test("optional sizes and generic indices render concise placeholders", () => {
  const data = createFunctionMapModels();
  const struct = data.maps[1];
  const template = data.maps[4];
  const exact = data.maps[5];
  assert.ok(struct);
  assert.equal(struct.type, 316);
  assert.ok(template);
  assert.equal(template.type, 322);
  assert.ok(exact);
  assert.equal(exact.type, 336);
  delete struct.entries[0]!.nativeSize;
  template.entries[0]!.genericArgumentIndices = [];
  exact.entries[0]!.genericArgumentIndices = [2, 3];

  assert.equal(getNativeAotFunctionTableModel(data, "native-aot-function-map-316")?.rowAt(0)?.cells[2]?.html, "-");
  assert.equal(getNativeAotFunctionTableModel(data, "native-aot-function-map-322")?.rowAt(0)?.cells[5]?.html, "-");
  assert.equal(getNativeAotFunctionTableModel(data, "native-aot-function-map-336")!.rowAt(0)!.cells[2]!.html, "2, 3");
});

void test("empty function maps render no empty table or warning list", () => {
  const html = renderNativeAotFunctionMaps({ maps: [{ type: 316, entries: [], warnings: [] }], warnings: [] });

  assert.doesNotMatch(html, /<table|<ul/);
  assert.match(html, /<h5>Struct marshalling-stub map<\/h5>/);
});
