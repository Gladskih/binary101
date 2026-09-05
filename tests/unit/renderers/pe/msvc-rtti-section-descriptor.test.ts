import assert from "node:assert/strict";
import { test } from "node:test";
import { MSVC_RTTI_LAYOUT } from "../../../../analyzers/pe/msvc-rtti/layout.js";
import { getMsvcRttiSectionDescriptor } from
  "../../../../renderers/pe/msvc-rtti-section-descriptor.js";

void test("MSVC RTTI descriptor describes an empty analysis", () => {
  assert.deepEqual(getMsvcRttiSectionDescriptor({
    layout: MSVC_RTTI_LAYOUT, types: [], classHierarchies: [],
    completeObjectLocators: [], vftables: []
  }), { key: "msvc-rtti", summary: "0 types / 0 COL / 0 vftables", title: "Microsoft C++ RTTI" });
});
