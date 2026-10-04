"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { clrTypeFullName, escapeClrTypeNamePart } from "../../../../../../analyzers/pe/clr/metadata-type-names.js";

void test("escapes reflection type punctuation without escaping namespace separators", () => {
  assert.equal(escapeClrTypeNamePart("A+B,C[D]*E&F\\G"), "A\\+B\\,C\\[D\\]\\*E\\&F\\\\G");
  assert.equal(clrTypeFullName("Demo.Namespace+", "A+B"), "Demo.Namespace\\+.A\\+B");
  assert.equal(clrTypeFullName("", "A+B"), "A\\+B");
  assert.equal(clrTypeFullName(null, "A"), "A");
  assert.equal(clrTypeFullName("Demo", null), null);
  assert.equal(clrTypeFullName("Demo", ""), null);
});
