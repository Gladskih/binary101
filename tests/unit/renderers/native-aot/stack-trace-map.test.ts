import assert from "node:assert/strict";
import test from "node:test";
import { getNativeAotStackTraceTableModel, renderNativeAotStackTraceMap } from
  "../../../../renderers/native-aot/stack-trace-map.js";
import { parseNativeAotStackTraceMap } from "../../../../analyzers/native-aot/stack-trace-map.js";
import { createNativeAotStackTraceFixture } from "../../../helpers/native-aot-stack-trace-fixture.js";

void test("NativeAOT stack-trace tables show numeric context updates and method roots", async () => {
  const fixture = createNativeAotStackTraceFixture();
  const map = (await parseNativeAotStackTraceMap(fixture.image, [fixture.section]))!;

  const table = getNativeAotStackTraceTableModel(map, "native-aot-stack-trace-map")!;

  assert.equal(table.rowCount, 2);
  assert.equal(table.columns.length, 6);
  assert.deepEqual(table.columns.map(column => column.label), ["Method RVA", "Command",
    "Owning type token update", "Name offset update", "Signature offset update",
    "Generic signature / arguments update"]);
  assert.ok(table.columns.every(column => column.className === "peNumeric"));
  assert.ok(table.rowAt(0)?.cells.every(cell => cell.className === "peNumeric"));
  assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.html),
    ["0x00000040", "0x1b", "0x01000020", "0x0000000a", "-", "0x00000014 / 0x0000001e"]);
  assert.deepEqual(table.rowAt(1)?.cells.map(cell => cell.html),
    ["0x00000300", "0x04", "-", "-", "0x00000028", "-"]);
  assert.equal(table.rowAt(2), null);
  assert.equal(table.sortValueAt(0, 0), "0x00000040");
  assert.equal(table.sortValueAt(3, 0), "");
  assert.equal(getNativeAotStackTraceTableModel(map, "other"), null);
  assert.equal(getNativeAotStackTraceTableModel(undefined, "native-aot-stack-trace-map"), null);
  assert.match(renderNativeAotStackTraceMap(map), /<table/);
});

void test("NativeAOT stack-trace tables display unresolved addresses and escaped warnings", () => {
  const map = { entries: [{ command: 0, methodRva: null }], warnings: ["bad <target>", "another warning"] };

  assert.equal(renderNativeAotStackTraceMap(undefined), "");
  assert.match(renderNativeAotStackTraceMap(map), /bad &lt;target>/);
  assert.match(renderNativeAotStackTraceMap(map),
    /<ul class="smallNote"><li>bad &lt;target><\/li><li>another warning<\/li><\/ul>/);
  assert.equal(getNativeAotStackTraceTableModel(map, "native-aot-stack-trace-map")!.rowAt(0)?.cells[0]?.html, "-");
  assert.doesNotMatch(renderNativeAotStackTraceMap({ entries: [], warnings: [] }), /<table/);
});

void test("NativeAOT stack-trace map explains context updates and hidden method seeds without empty tables", () => {
  const html = renderNativeAotStackTraceMap({ entries: [], warnings: [] });

  assert.match(html, /^<h4>NativeAOT stack-trace method map<\/h4><p class="smallNote">Validated method addresses /);
  assert.match(html, /supply disassembly seeds/);
  assert.match(html, /Metadata columns show context updates in stack-trace metadata/);
  assert.match(html, /unchanged fields retain the previous row's context/);
  assert.match(html, /Hidden methods can still supply seeds\.<\/p>$/);
});
