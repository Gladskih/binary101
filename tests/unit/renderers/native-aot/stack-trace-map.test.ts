import assert from "node:assert/strict";
import test from "node:test";
import { getNativeAotStackTraceTableModel, renderNativeAotStackTraceMap } from
  "../../../../renderers/native-aot/stack-trace-map.js";
import { parseNativeAotStackTraceMap } from "../../../../analyzers/native-aot/stack-trace-map.js";
import { createNativeAotStackTraceFixture } from "../../../helpers/native-aot-stack-trace-fixture.js";

void test("stack-trace summaries explain reused contexts without raw offsets or addresses", async () => {
  const fixture = createNativeAotStackTraceFixture();
  const map = (await parseNativeAotStackTraceMap(fixture.image, [fixture.section]))!;
  map.entries.push({ command: 0, methodRva: null });
  map.entries.push({ ...map.entries[0]! });
  map.entries.push({ command: 0, methodRva: null });

  const table = getNativeAotStackTraceTableModel(map, "native-aot-stack-trace-map")!;

  assert.equal(table.rowCount, 5);
  assert.deepEqual([0, 1, 2, 3, 4].map(index => table.rowAt(index)?.cells[1]?.html), ["5", "2", "2", "1", "2"]);
  assert.deepEqual([0, 1, 2, 3, 4].map(index => table.rowAt(index)?.cells[0]?.html), ["Stack-trace records",
    "Distinct compiled methods", "Records with method names", "Records with signatures", "Generic signature records"]);
  assert.ok([0, 1, 2, 3, 4].every(index => table.rowAt(index)!.cells[2]!.html.length > 20));
  assert.equal(getNativeAotStackTraceTableModel(map, "other"), null);
  assert.equal(getNativeAotStackTraceTableModel(undefined, "native-aot-stack-trace-map"), null);
  assert.match(renderNativeAotStackTraceMap(map), /later records can reuse an earlier name/);
  assert.match(renderNativeAotStackTraceMap(map), /including methods hidden from stack traces/);
  assert.doesNotMatch(renderNativeAotStackTraceMap(map), /RVA|0x0000|offset update/);
});

void test("empty stack maps show meaningful zero counts and escaped warnings", () => {
  const html = renderNativeAotStackTraceMap({ entries: [], warnings: ["bad <target>", "another warning"] });

  assert.equal(renderNativeAotStackTraceMap(undefined), "");
  assert.match(html, /bad &lt;target>/);
  assert.match(html, /NativeAOT stack-trace metadata/);
  assert.match(html, /<li>bad &lt;target><\/li><li>another warning<\/li>/);
  assert.doesNotMatch(html, /Stryker/);
  assert.doesNotMatch(renderNativeAotStackTraceMap({ entries: [], warnings: [] }), /<ul/);
});
