import assert from "node:assert/strict";
import test from "node:test";
import { getNativeAotFunctionTableModel, renderNativeAotFunctionMaps } from
  "../../../../renderers/native-aot/function-maps.js";
import { createFunctionMapModels } from "../../../helpers/native-aot-function-map-models.js";

void test("function maps explain counts without exposing raw code, metadata or dictionary address lists", () => {
  const data = createFunctionMapModels();
  const html = renderNativeAotFunctionMaps(data);
  const table = getNativeAotFunctionTableModel(data, "native-aot-function-map-310")!;

  assert.match(html, /NativeAOT runtime relationships/);
  assert.match(html, /Distinct code entry points/);
  assert.match(html, /generic code and native interop/);
  assert.match(html, /other sources may identify the same methods/);
  assert.match(html, /Counts describe each map separately; the same code may appear in several sources/);
  assert.match(html, /&lt;global>/);
  assert.match(html, /&lt;struct>/);
  assert.match(html, /&lt;field>/);
  assert.doesNotMatch(html, /RVA|0x0000|Method token|Type index|Layout offset|Stryker/);
  assert.equal(table.rowCount, 2);
  assert.deepEqual(table.rowAt(0)?.cells.slice(0, 2).map(cell => cell.html), ["Map records", "1"]);
  assert.equal(table.rowAt(1)?.cells[1]?.html, "1");
  assert.equal(table.rowAt(-1), null);
  assert.equal(renderNativeAotFunctionMaps(undefined), "");
  assert.equal(getNativeAotFunctionTableModel(undefined, "native-aot-function-map-310"), null);
  assert.equal(getNativeAotFunctionTableModel(data, "other"), null);
  assert.equal(getNativeAotFunctionTableModel(data, "native-aot-function-map-999"), null);
  assert.equal(getNativeAotFunctionTableModel(data, "native-aot-function-map-301-slots"), null);
});

void test("multiple global and per-map warnings remain separate list items", () => {
  const data = createFunctionMapModels();
  data.warnings = ["first <global>", "second global"];
  data.maps[0]!.warnings = ["first <map>", "second map"];

  const html = renderNativeAotFunctionMaps(data);

  assert.match(html, /<li>first &lt;global><\/li><li>second global<\/li>/);
  assert.match(html, /<li>first &lt;map><\/li><li>second map<\/li>/);
  assert.doesNotMatch(html, /Stryker/);
});

void test("named unmanaged fields retain useful layout details with numeric byte offsets", () => {
  const table = getNativeAotFunctionTableModel(createFunctionMapModels(), "native-aot-function-map-316-fields")!;

  assert.deepEqual(table.columns.map(column => column.label), ["Type record", "Native field", "Byte offset"]);
  assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.html), ["0", "&lt;field>", "4"]);
  assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.className), ["peNumeric", undefined, "peNumeric"]);
  assert.equal(table.columns[0]?.className, "peNumeric");
  assert.equal(table.columns[2]?.className, "peNumeric");
  assert.equal(table.rowAt(1), null);
  assert.equal(table.sortValueAt(0, 0), "0");
  assert.equal(table.sortValueAt(0, 1), "<field>");
  assert.equal(table.sortValueAt(0, 2), "4");
  assert.equal(table.sortValueAt(0, 3), "");
  assert.equal(table.sortValueAt(-1, 0), "");
});

void test("empty maps report zero counts and omit absent field details and warnings", () => {
  const html = renderNativeAotFunctionMaps({ maps: [{ type: 316, entries: [], warnings: [] }], warnings: [] });

  assert.match(html, /Map records/);
  assert.match(html, /Struct marshalling-stub map/);
  assert.doesNotMatch(html, /<ul|Native field/);
});
