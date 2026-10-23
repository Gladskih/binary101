import assert from "node:assert/strict";
import { test } from "node:test";
import { hllSourceRows } from "../../../../renderers/pe/hll-source-rows.js";

void test("HLL mappings distinguish source lines, listing lines, path codes and unresolved indices", () => {
  const rows = hllSourceRows({ kind: "hllSource", files: [{ index: 1, name: "<source.c>" },
    { index: 2, name: "unused.c" }], groups: [
    { file: 1, category: "Source lines", segment: 1, values: [7, 7, 8] },
    { file: 1, category: "Source lines", segment: 2, values: [8, 9] },
    { file: 0, category: "Listing lines", segment: 1, values: [50] },
    { file: 9, category: "Control-flow paths", segment: 1, values: [1, 1] }
  ] });
  assert.deepEqual(rows, [["<source.c>", "Source lines", "2", "5", "3"],
    ["Unspecified file", "Listing lines", "1", "1", "1"],
    ["Unknown file #9", "Control-flow paths", "1", "2", "1"], ["unused.c", "Source file", "0", "0", "0"]]);
  assert.deepEqual(hllSourceRows({ kind: "hllSource", files: [], groups: [] }), []);
});
