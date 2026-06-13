"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createEmptyResourceTree } from "../../analyzers/pe/resources/tree-result.js";

void test("createEmptyResourceTree preserves resource directory span metadata", async () => {
  const tree = createEmptyResourceTree(
    { name: "RESOURCE", rva: 0x1000, size: 0x40 },
    0x80,
    ["issue"]
  );

  assert.equal(tree.base, 0x80);
  assert.equal(tree.limitEnd, 0xc0);
  assert.equal(tree.dirRva, 0x1000);
  assert.equal(tree.dirSize, 0x40);
  assert.deepStrictEqual(tree.issues, ["issue"]);
  assert.deepStrictEqual(tree.top, []);
  assert.deepStrictEqual(tree.detail, []);
  assert.deepStrictEqual(tree.paths, []);
  assert.equal((await tree.view(0, 16)).byteLength, 0);
});

void test("createEmptyResourceTree uses zero as the fallback base for unmapped directories", () => {
  const tree = createEmptyResourceTree(
    { name: "RESOURCE", rva: 0x1000, size: 0x40 },
    null,
    []
  );

  assert.equal(tree.base, 0);
  assert.equal(tree.limitEnd, 0x40);
  assert.equal(tree.issues, undefined);
});
