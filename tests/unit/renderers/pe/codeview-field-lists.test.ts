import assert from "node:assert/strict";
import { test } from "node:test";
import { createCodeViewFieldListResolver } from "../../../../renderers/pe/codeview-field-lists.js";
import { indexCodeViewTypes } from "../../../../renderers/pe/codeview-type-names.js";

void test("CodeView field lists follow continuations once and cache the completed traversal", () => {
  const records = [
    { type: 0x1203, index: 0x1000, members: [{ type: 0x1404, continuation: 0x1001 },
      { type: 0x1404, continuation: 0x1002 }] },
    { type: 0x204, index: 0x1001, members: [{ type: 0x405, continuation: 0x1002 }] },
    { type: 0x1203, index: 0x1002, members: [{ type: 0x150d, name: "last" }] }
  ];
  const resolve = createCodeViewFieldListResolver(indexCodeViewTypes(records));
  assert.deepEqual(resolve(0x1000), { lists: records, issues: [] });
  assert.equal(resolve(0x1000), resolve(0x1000));
});

void test("CodeView missing, ambiguous and non-field-list continuations are explicit", () => {
  const resolve = createCodeViewFieldListResolver(indexCodeViewTypes([
    { type: 0x1203, index: 0x1000, members: [{ type: 0x1404, continuation: 0x1001 },
      { type: 0x1404, continuation: 0x1002 }, { type: 0x1404, continuation: 0x1003 }] },
    { type: 0x1203, index: 0x1001, members: [] }, { type: 0x1203, index: 0x1001, members: [] },
    { type: 0x1505, index: 0x1002, name: "Class" }
  ]));
  assert.deepEqual(resolve(0x1000).issues, ["ambiguous field list #4097",
    "type #4098 is not a field list", "missing field list #4099"]);
  assert.deepEqual(resolve(0x1004), { lists: [], issues: ["missing field list #4100"] });
});

void test("CodeView cyclic field lists stop without dropping already recovered records", () => {
  const records = [
    { type: 0x1203, index: 0x1000, members: [{ type: 0x1404, continuation: 0x1001 }] },
    { type: 0x1203, index: 0x1001, members: [{ type: 0x1404, continuation: 0x1000 }] }
  ];
  assert.deepEqual(createCodeViewFieldListResolver(indexCodeViewTypes(records))(0x1000), {
    lists: records, issues: ["cyclic field-list continuation #4096"]
  });
  assert.deepEqual(createCodeViewFieldListResolver(indexCodeViewTypes([
    { type: 0x1203, index: 0x1000 }
  ]))(0x1000).lists, [{ type: 0x1203, index: 0x1000 }]);
});
