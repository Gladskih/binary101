"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { compareSortValues } from "../../ui/sortable-tables.js";

void test("compareSortValues sorts numeric strings numerically", () => {
  assert.ok(compareSortValues("16", "1024") < 0);
  assert.ok(compareSortValues("1024", "16") > 0);
  assert.equal(compareSortValues("16", "16"), 0);
});

void test("compareSortValues sorts text naturally when values are not numeric", () => {
  assert.ok(compareSortValues("IMPORT", "RESOURCE") < 0);
  assert.ok(compareSortValues("entry 2", "entry 10") < 0);
});
