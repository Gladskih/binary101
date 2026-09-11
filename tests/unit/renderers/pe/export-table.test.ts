"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createExportTableModel } from "../../../../renderers/pe/export-table.js";
import { renderAutoPagedSortableTable } from "../../../../renderers/paged-sortable-table.js";

void test("export table preserves and escapes aliases and forwarders", () => {
  const model = createExportTableModel([
    { ordinal: 12, rva: 4096, names: ["Alpha<", "Beta&"], forwarder: "dll.Target<" }
  ]);

  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.html),
    ["1", "12", "Alpha&lt;<br>Beta&amp;", "0x00001000", "dll.Target&lt;"]);
  assert.deepEqual([0, 1, 2, 3, 4, 5].map(column => model.sortValueAt(0, column)),
    ["1", "12", "Alpha<\nBeta&", "4096", "dll.Target<", ""]);
  assert.equal(model.rowAt(0)?.cells[1]?.className, "peNumeric");
  assert.deepEqual(model.columns.map(column => column.label),
    ["#", "Ordinal", "Names", "RVA", "Forwarder"]);
  assert.deepEqual(model.columns.filter(column => column.className === "peNumeric")
    .map(column => column.label), ["#", "Ordinal", "RVA"]);
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.className),
    ["peNumeric", "peNumeric", undefined, "peNumeric", undefined]);
});

void test("export table handles unnamed, empty-name and non-forwarded slots", () => {
  const model = createExportTableModel([
    { ordinal: 1, rva: 0, names: [] },
    { ordinal: 2, rva: 0, names: [""], forwarder: "" }
  ]);

  assert.equal(model.rowAt(0)?.cells[2]?.html, "-");
  assert.equal(model.rowAt(1)?.cells[2]?.html, "");
  assert.equal(model.rowAt(0)?.cells[4]?.html, "-");
  assert.equal(model.rowAt(1)?.cells[4]?.html, "-");
  assert.equal(model.sortValueAt(0, 4), "");
});

void test("export table handles empty tables and out-of-range row indexes", () => {
  const model = createExportTableModel([]);

  assert.equal(model.rowCount, 0);
  assert.equal(model.rowAt(0), null);
  assert.equal(model.rowAt(-1), null);
  assert.equal(model.sortValueAt(1, 0), "");
});

void test("export table pages the DOM while retaining every entry in its model", () => {
  const model = createExportTableModel(Array.from({ length: 251 }, (_, index) => ({
    ordinal: index + 1, rva: index, names: [`export-${index}`]
  })));

  const firstPage = renderAutoPagedSortableTable(model);
  const lastPage = renderAutoPagedSortableTable(model,
    { pageIndex: 1, sortColumnIndex: null, sortDirection: null });

  assert.equal(model.rowCount, 251);
  assert.match(firstPage, /data-paged-sortable-table-id="pe-exports"/);
  assert.match(firstPage, /class="tableWrap"/);
  assert.match(firstPage, /export-249/);
  assert.doesNotMatch(firstPage, /export-250/);
  assert.match(lastPage, /export-250/);
  assert.doesNotMatch(lastPage, /export-249/);
});
