import assert from "node:assert/strict";
import { test } from "node:test";
import { codeViewMemberAttributes } from "../../../../renderers/pe/codeview-member-attributes.js";

for (const [attributes, expected] of [[0, []], [1, ["private"]], [2, ["protected"]], [3, ["public"]],
  [7, ["public", "virtual"]], [11, ["public", "static"]], [15, ["public", "friend"]],
  [19, ["public", "introducing virtual"]], [23, ["public", "pure virtual"]],
  [27, ["public", "pure introducing virtual"]]] as const) {
  void test(`CodeView member attributes ${attributes} retain access and method properties`, () => {
    assert.deepEqual(codeViewMemberAttributes(attributes), expected);
  });
}

void test("CodeView member attributes retain every flag and unknown values", () => {
  assert.deepEqual(codeViewMemberAttributes(0xffff), ["public", "unknown method property 7",
    "compiler-generated declaration", "not inheritable", "not constructible", "compiler-generated definition",
    "sealed", "unknown attribute bits 0xfc00"]);
});
