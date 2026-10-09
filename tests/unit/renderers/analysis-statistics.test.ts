import assert from "node:assert/strict";
import test from "node:test";
import { createAnalysisStatisticsTable } from "../../../renderers/analysis-statistics.js";

void test("statistics explain escaped facts and align counts rather than labels", () => {
  const table = createAnalysisStatisticsTable("facts", [{ label: "<methods>", value: 12, description: "<explanation>" }]);

  assert.equal(table.id, "facts");
  assert.equal(table.rowCount, 1);
  assert.equal(table.pageSize, 100);
  assert.equal(table.tableClassName, "analysisStatisticsTable");
  assert.deepEqual(table.columns.map(column => column.label), ["What was found", "Count", "Why it matters"]);
  assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.html), ["&lt;methods>", "12", "&lt;explanation>"]);
  assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.className), [undefined, "peNumeric", undefined]);
  assert.equal(table.columns[1]?.className, "peNumeric");
  assert.equal(table.rowAt(-1), null);
  assert.equal(table.sortValueAt(0, 0), "<methods>");
  assert.equal(table.sortValueAt(0, 1), "12");
  assert.equal(table.sortValueAt(0, 2), "<explanation>");
  assert.equal(table.sortValueAt(0, 3), "");
  assert.equal(table.sortValueAt(-1, 0), "");
  assert.equal(createAnalysisStatisticsTable("empty", []).rowCount, 0);
});
