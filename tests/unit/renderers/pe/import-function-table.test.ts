"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createImportFunctionNameDecoder } from "../../../../analyzers/pe/imports/function-name.js";
import {
  PE_IMPORT_FUNCTION_PAGE_SIZE,
  createImportFunctionTableModel,
  renderImportFunctionTable
} from "../../../../renderers/pe/import-function-table.js";

void test("renderImportFunctionTable only adds paging controls above the inline limit", () => {
  const smallHtml = renderImportFunctionTable(
    [{ hint: 1, name: "Sleep" }],
    "test-import-small",
    0x2000,
    new Map(),
    4
  );

  assert.match(smallHtml, /<th>API<\/th>/);
  assert.doesNotMatch(smallHtml, /data-paged-sortable-table-root/);
  assert.doesNotMatch(smallHtml, /pagedSortableTableToolbar/);

  const largeHtml = renderImportFunctionTable(
    Array.from({ length: PE_IMPORT_FUNCTION_PAGE_SIZE + 1 }, (_, index) => ({
      hint: index,
      name: `Api${index}`
    })),
    "test-import-large",
    0x2000,
    new Map(),
    4
  );

  assert.match(largeHtml, /data-paged-sortable-table-id="test-import-large"/);
  assert.match(largeHtml, /Showing 1-250 of 251/);
  assert.match(largeHtml, /Sort by API/);
  assert.match(largeHtml, /<td[^>]*>Api249<\/td>/);
  assert.doesNotMatch(largeHtml, /<td[^>]*>Api250<\/td>/);
});

void test("import table displays demangled signatures with literal raw names and raw sorting", async () => {
  const functions = [{ hint: 1, name: "??$square@H@demo@@YAHH@Z" },
    { name: "Literal&lt;<script>" }, { ordinal: 9 }, {}];
  await createImportFunctionNameDecoder(assert.fail)(functions[0]!);

  const html = renderImportFunctionTable(functions, "cpp-imports", 0x2000, new Map(), 4);

  assert.match(html, /<code class="winapiMetadataSignature">int __cdecl demo::square&lt;int>\(int\)<\/code>/);
  assert.match(html, /<td[^>]*>\?\?\$square@H@demo@@YAHH@Z<\/td>/);
  assert.match(html, /MSVC C\+\+ \(LLVM\)/);
  assert.match(html, /Literal&amp;lt;&lt;script>/);
  assert.match(html, /ORD 9/);
  assert.doesNotMatch(html, /<script>/);
  const model = createImportFunctionTableModel(functions, "cpp-imports", 0, new Map(), 4);
  assert.equal(model.sortValueAt!(0, 2), "??$square@H@demo@@YAHH@Z");
  assert.equal(model.sortValueAt!(0, 3), "int __cdecl demo::square<int>(int)");
  assert.deepEqual(model.rowAt(2)?.cells[2], { html: "ORD 9", sortValue: "ORD 9" });
  assert.deepEqual(model.rowAt(3)?.cells[2], { html: "-", sortValue: "" });
  assert.equal(model.sortValueAt!(2, 2), "ORD 9");
  assert.equal(model.sortValueAt!(3, 2), "");
  for (const index of [1, 2, 3]) {
    assert.equal(model.rowAt(index)?.cells[3]?.html, "-");
    assert.equal(model.rowAt(index)?.cells[3]?.sortValue, "");
    assert.equal(model.sortValueAt!(index, 3), "");
  }
});
