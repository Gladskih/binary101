import assert from "node:assert/strict";
import test from "node:test";
import { getNativeAotInvokeTableModel, renderNativeAotInvokeMap } from "../../../../renderers/native-aot/invoke-map.js";
import { parseNativeAotInvokeMap } from "../../../../analyzers/native-aot/invoke-map.js";
import { createNativeAotInvokeFixture } from "../../../helpers/native-aot-invoke-fixture.js";

void test("invocation summaries count shared methods and stubs without exposing pointer rows", async () => {
  const fixture = createNativeAotInvokeFixture();
  const map = (await parseNativeAotInvokeMap(fixture.image, fixture.sections))!;
  map.entries.push({ ...map.entries[0]!, entrypointRva: null, invokeStubRva: null, genericArgumentIndices: [] });
  map.entries.push({ ...map.entries[0]! });
  map.entries.push({ ...map.entries[0]!, entrypointRva: 0x400, invokeStubRva: 0x500, genericArgumentIndices: [] });

  const table = getNativeAotInvokeTableModel(map, "native-aot-invoke-map")!;

  assert.equal(table.rowCount, 4);
  assert.deepEqual([0, 1, 2, 3].map(index => table.rowAt(index)?.cells[1]?.html), ["4", "2", "2", "2"]);
  assert.deepEqual([0, 1, 2, 3].map(index => table.rowAt(index)?.cells[0]?.html), ["Reflection invocation records",
    "Distinct method bodies", "Distinct invocation stubs", "Records with generic arguments"]);
  assert.ok([0, 1, 2, 3].every(index => table.rowAt(index)!.cells[2]!.html.length > 20));
  assert.equal(getNativeAotInvokeTableModel(map, "other"), null);
  assert.equal(getNativeAotInvokeTableModel(undefined, "native-aot-invoke-map"), null);
  assert.match(renderNativeAotInvokeMap(map), /Adapters that translate reflection arguments/);
  assert.doesNotMatch(renderNativeAotInvokeMap(map), /RVA|0x0000|metadata offset/);
});

void test("missing invocation data is omitted while empty maps explain zero counts and escaped warnings", () => {
  const html = renderNativeAotInvokeMap({ entries: [], warnings: ["bad <pointer>", "another warning"] });

  assert.equal(renderNativeAotInvokeMap(undefined), "");
  assert.match(html, /bad &lt;pointer>/);
  assert.match(html, /NativeAOT reflection invocation/);
  assert.match(html, /<li>bad &lt;pointer><\/li><li>another warning<\/li>/);
  assert.doesNotMatch(html, /Stryker/);
  assert.match(renderNativeAotInvokeMap({ entries: [], warnings: [] }), /Distinct invocation stubs/);
  assert.doesNotMatch(renderNativeAotInvokeMap({ entries: [], warnings: [] }), /<ul/);
});
