"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { msvcRttiTypeNameCell } from "../../../../renderers/pe/msvc-rtti-type-name.js";

void test("type name cells handle missing descriptors", () => {
  assert.deepEqual(msvcRttiTypeNameCell(null), {
    html: "(unresolved)", sortValue: "(unresolved)"
  });
  assert.deepEqual(msvcRttiTypeNameCell(undefined), msvcRttiTypeNameCell(null));
});

void test("type name cells escape raw names and avoid duplicate fallback text", () => {
  assert.deepEqual(msvcRttiTypeNameCell({ rva: 0x2100, decoratedName: ".?AV<tag>@@" }), {
    html: "<code>.?AV&lt;tag>@@</code>", sortValue: ".?AV<tag>@@"
  });
});
