"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  PE_IMPORT_FUNCTION_PAGE_SIZE,
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
