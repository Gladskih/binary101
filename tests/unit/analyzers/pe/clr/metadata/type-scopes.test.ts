"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createEnclosingTypeRoots } from "../../../../../../analyzers/pe/clr/metadata-type-scopes.js";
import { clrIndex } from "../../../../../helpers/clr-resolution-fixture.js";

void test("resolves forward and backward nested scopes and caches shared roots", () => {
  assert.deepEqual([...createEnclosingTypeRoots([clrIndex(1, 3), clrIndex(1), clrIndex(35)], 1)].sort(),
    [[1, 3], [2, 3], [3, 3]]);
  assert.equal(createEnclosingTypeRoots([], 1).size, 0);
});

for (const index of [clrIndex(1, 0), clrIndex(1, -1), clrIndex(1, 3), clrIndex(1, 1),
  { ...clrIndex(35), valid: false }]) {
  void test(`invalidates a nested chain ending at ${JSON.stringify(index)}`, () => {
    assert.equal(createEnclosingTypeRoots([clrIndex(1, 2), index], 1).get(1), null);
  });
}
