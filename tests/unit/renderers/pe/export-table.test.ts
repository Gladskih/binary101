"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createExportTableModel } from "../../../../renderers/pe/export-table.js";
import { renderAutoPagedSortableTable } from "../../../../renderers/paged-sortable-table.js";
import { parsePe, isPeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import { createPagedPeExportsFile } from "../../../fixtures/pe-export-table-file.js";

void test("export table shows complete LLVM signatures while preserving original aliases", async () => {
  const pe = await parsePe(new File([
    createPagedPeExportsFile(["??$square@H@demo@@YAHH@Z", "?f@@YAHH@Ztail"])
  ], "exports.dll"));
  assert.ok(pe && isPeWindowsParseResult(pe) && pe.exports);

  const model = createExportTableModel(pe.exports.entries);

  assert.match(model.rowAt(250)?.cells[2]?.html ?? "", /int __cdecl demo::square&lt;int>\(int\)/);
  assert.match(model.rowAt(250)?.cells[2]?.html ?? "", /\?\?\$square@H@demo@@YAHH@Z/);
  assert.match(model.rowAt(250)?.cells[2]?.html ?? "", /\?f@@YAHH@Ztail/);
  assert.doesNotMatch(model.rowAt(250)?.cells[2]?.html ?? "", /int __cdecl f\(int\)/);
  assert.equal(model.sortValueAt(250, 2), "??$square@H@demo@@YAHH@Z\n?f@@YAHH@Ztail");
});

void test("an unterminated export name is preserved without a guessed signature", async () => {
  const name = "?f@@YAHH@Z";
  // The fixture places its first name at 2300. Remove its NUL and all later file data.
  const bytes = createPagedPeExportsFile([name, "PlainAlias"]).slice(0, 2300 + name.length);

  const pe = await parsePe(new File([bytes], "truncated-exports.dll"));

  assert.ok(pe && isPeWindowsParseResult(pe) && pe.exports);
  assert.equal(createExportTableModel(pe.exports.entries).rowAt(250)?.cells[2]?.html, name);
  assert.ok(pe.exports.issues.includes("Export name string truncated."));
});

void test("a terminated alias does not hide an identical unterminated alias", async () => {
  const name = "?f@@YAHH@Z";
  // The second alias starts at 2400; leave the first terminated and truncate the second.
  const bytes = createPagedPeExportsFile([name, name]).slice(0, 2400 + name.length);

  const pe = await parsePe(new File([bytes], "truncated-alias.dll"));

  assert.ok(pe && isPeWindowsParseResult(pe) && pe.exports);
  assert.equal(createExportTableModel(pe.exports.entries).rowAt(250)?.cells[2]?.html,
    "<code>int __cdecl f(int)</code><br><code class=\"dim\">?f@@YAHH@Z</code><br>?f@@YAHH@Z");
  assert.ok(pe.exports.issues.includes("Export name string truncated."));
});

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

void test("marks an export named explicitly by a type library module", () => {
  const model = createExportTableModel([
    { ordinal: 12, rva: 4096, names: ["RunExport"] },
    { ordinal: 13, rva: 8192, names: ["Other"] }
  ], [{ ordinal: 12, library: "Lib<", module: "Module", function: "Run", entry: "RunExport" }]);
  assert.equal(model.columns.at(-1)?.label, "TYPELIB module");
  assert.match(model.rowAt(0)?.cells.at(-1)?.html ?? "", /Lib&lt; \/ Module\.Run/u);
  assert.equal(model.rowAt(1)?.cells.at(-1)?.html, "-");
  assert.equal(model.sortValueAt(0, 5), "Lib< / Module.Run");
});
