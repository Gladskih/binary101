"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { listColumnTable } from "../../../../../../analyzers/pe/clr/metadata-list-columns.js";

void test("redirects each list index only when its pointer table has rows", () => {
  assert.equal(listColumnTable({ name: "FieldList", kind: "table", table: 4 }, new Map([[3, 1]])), 3);
  assert.equal(listColumnTable({ name: "MethodList", kind: "table", table: 6 }, new Map([[5, 1]])), 5);
  assert.equal(listColumnTable({ name: "ParamList", kind: "table", table: 8 }, new Map([[7, 1]])), 7);
  assert.equal(listColumnTable({ name: "EventList", kind: "table", table: 20 }, new Map([[19, 1]])), 19);
  assert.equal(listColumnTable({ name: "PropertyList", kind: "table", table: 23 }, new Map([[22, 1]])), 22);
  assert.equal(listColumnTable({ name: "FieldList", kind: "table", table: 4 }, new Map([[3, 0]])), 4);
  assert.equal(listColumnTable({ name: "Other", kind: "table", table: 4 }, new Map([[3, 1]])), 4);
  assert.equal(listColumnTable({ name: "Other", kind: "u8" }, new Map()), undefined);
});
