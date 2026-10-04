"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeMetadataUtf16 } from "../../../../../../analyzers/pe/clr/metadata-utf16.js";

void test("preserves UTF-16 BOM, null and unpaired surrogate code units", () => {
  const issues: string[] = [];
  assert.equal(decodeMetadataUtf16(Uint8Array.of(0xff, 0xfe, 0, 0, 0, 0xd8), issues, "String"), "\ufeff\0\ud800");
  assert.deepEqual(issues, []);
  assert.equal(decodeMetadataUtf16(new Uint8Array(), issues, "String"), "");
});

void test("warns on an incomplete UTF-16 code unit", () => {
  const issues: string[] = [];
  assert.equal(decodeMetadataUtf16(Uint8Array.of(65, 0, 7), issues, "String"), "A");
  assert.match(issues[0]!, /UTF-16/);
});
