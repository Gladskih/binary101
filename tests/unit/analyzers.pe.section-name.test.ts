"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  coffStringTablePeSectionName,
  inlinePeSectionName,
  peSectionNameOffset,
  peSectionNameValue
} from "../../analyzers/pe/sections/name.js";

void test("inlinePeSectionName stores the section text without a COFF string-table offset", () => {
  const name = inlinePeSectionName(".text");

  assert.equal(peSectionNameValue(name), ".text");
  assert.equal(peSectionNameOffset(name), null);
});

void test("coffStringTablePeSectionName stores both resolved text and source offset", () => {
  // COFF string-table entries start after the 4-byte size field.
  const name = coffStringTablePeSectionName(".debug_line", 4);

  assert.equal(peSectionNameValue(name), ".debug_line");
  assert.equal(peSectionNameOffset(name), 4);
});
