import assert from "node:assert/strict";
import test from "node:test";
import { getNativeAotInvokeTableModel, renderNativeAotInvokeMap } from "../../../../renderers/native-aot/invoke-map.js";
import { parseNativeAotInvokeMap } from "../../../../analyzers/native-aot/invoke-map.js";
import { createNativeAotInvokeFixture } from "../../../helpers/native-aot-invoke-fixture.js";

void test("NativeAOT invoke table shows numeric method/stub RVAs and bounds-checks row access", async () => {
  const fixture = createNativeAotInvokeFixture();
  const map = (await parseNativeAotInvokeMap(fixture.image, fixture.sections))!;

  const table = getNativeAotInvokeTableModel(map, "native-aot-invoke-map")!;

  assert.equal(table.rowCount, 1);
  assert.deepEqual(table.columns.map(column => column.label), ["Method metadata offset", "Flags",
    "Declaring type index", "Entry point RVA", "Invoke stub RVA", "Generic type indices"]);
  assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.html),
    ["0x0000000a", "0x0022", "4", "0x00000040", "0x00000300", "3, 4"]);
  assert.ok(table.columns.every(column => column.className === "peNumeric"));
  assert.ok(table.rowAt(0)?.cells.every(cell => cell.className === "peNumeric"));
  assert.equal(table.sortValueAt(0, 3), "0x00000040");
  assert.equal(table.sortValueAt(2, 0), "");
  assert.equal(table.rowAt(2), null);
  assert.equal(getNativeAotInvokeTableModel(map, "other"), null);
  assert.equal(getNativeAotInvokeTableModel(undefined, "native-aot-invoke-map"), null);
});

void test("NativeAOT invoke table renders missing addresses and escaped warnings without empty tables", () => {
  const empty = { entries: [], warnings: ["bad <pointer>", "another warning"] };

  assert.equal(renderNativeAotInvokeMap(undefined), "");
  assert.match(renderNativeAotInvokeMap(empty), /bad &lt;pointer>/);
  assert.match(renderNativeAotInvokeMap(empty),
    /<ul class="smallNote"><li>bad &lt;pointer><\/li><li>another warning<\/li><\/ul>$/);
  assert.doesNotMatch(renderNativeAotInvokeMap(empty), /<table/);
  const entry = { flags: 0, metadataOffset: 0, declaringTypeIndex: 0,
    entrypointRva: null, invokeStubRva: null, genericArgumentIndices: [] };
  const table = getNativeAotInvokeTableModel({ entries: [entry], warnings: [] }, "native-aot-invoke-map")!;
  assert.deepEqual(table.rowAt(0)?.cells.slice(3).map(cell => cell.html), ["-", "-", "-"]);
  assert.match(renderNativeAotInvokeMap({ entries: [entry], warnings: [] }), /<table/);
});

void test("NativeAOT invoke map explains metadata offsets and shared code even when no rows exist", () => {
  const html = renderNativeAotInvokeMap({ entries: [], warnings: [] });

  assert.match(html, /^<h4>NativeAOT invoke map<\/h4><p class="smallNote">Validated method and invoke-stub /);
  assert.match(html, /addresses supply disassembly seeds/);
  assert.match(html, /Method offsets refer to retained NativeFormat metadata/);
  assert.match(html, /multiple entries may share the same native code\.<\/p>$/);
});
