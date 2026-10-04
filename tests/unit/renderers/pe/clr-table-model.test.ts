"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createClrTableModel } from "../../../../renderers/pe/clr-table-model.js";

void test("exposes every row for pagination and handles invalid row or column requests", () => {
  const model = createClrTableModel("Type definitions", ["Type"], 1000,
    index => index >= 0 && index < 1000 ? [`T${index}`] : null);
  assert.equal(model.id, "pe-clr-Type%20definitions");
  assert.equal(model.rowCount, 1000);
  assert.deepEqual(model.rowAt(999), { cells: [{ html: "T999" }] });
  assert.equal(model.sortValueAt(999, 0), "T999");
  assert.equal(model.sortValueAt(999, 1), "");
  assert.equal(model.sortValueAt(1000, 0), "");
  assert.equal(model.rowAt(1000), null);
});

void test("right-aligns comparable numeric columns in both headers and cells", () => {
  const model = createClrTableModel("Parameters", ["RID", "Name"], 1, () => ["1", "value"]);
  assert.deepEqual(model.columns, [{ label: "RID", className: "peNumeric" }, { label: "Name" }]);
  assert.deepEqual(model.rowAt(0)?.cells, [{ html: "1", className: "peNumeric" }, { html: "value" }]);
});
