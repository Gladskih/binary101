import assert from "node:assert/strict";
import { test } from "node:test";
import { getPeDebugSectionDescriptor } from "../../../../renderers/pe/debug-section-descriptor.js";
import { createTd32Info } from "../../../fixtures/pe-td32-view.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";

void test("debug descriptor describes an absent or empty directory", () => {
  assert.deepEqual(getPeDebugSectionDescriptor(null),
    { key: "debug", title: "Debug directory", summary: "0 entries" });
  assert.deepEqual(getPeDebugSectionDescriptor({ entry: null }), getPeDebugSectionDescriptor(null));
});

void test("debug descriptor uses a singular directory entry count", () => {
  assert.equal(getPeDebugSectionDescriptor({ entry: null, entries: [createDebugViewEntry(0, 0, 128)] }).summary,
    "1 entry");
});

void test("debug descriptor exposes standalone TD32 sources without calling them directory entries", () => {
  assert.deepEqual(getPeDebugSectionDescriptor({ entry: null,
    td32Sources: [{ kind: "overlay", offset: 512, size: 32, td32: createTd32Info() }] }),
  { key: "debug", title: "Debug information", summary: "0 entries; TD32 sources: 1" });
});
