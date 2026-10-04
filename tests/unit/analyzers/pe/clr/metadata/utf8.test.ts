"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeMetadataUtf8 } from "../../../../../../analyzers/pe/clr/metadata-utf8.js";

void test("preserves a leading BOM and every valid UTF-8 character", () => {
  const issues: string[] = [];
  assert.equal(decodeMetadataUtf8(new TextEncoder().encode("\ufefféЖ😀\0"), issues, "String"), "\ufefféЖ😀\0");
  assert.equal(decodeMetadataUtf8(new Uint8Array(), issues, "String"), "");
  assert.deepEqual(issues, []);
});

for (const bytes of [[0x80], [0xc0, 0x80], [0xe2, 0x82], [0xf0, 0x28, 0x8c, 0xbc], [0xed, 0xa0, 0x80]]) {
  void test(`rejects malformed UTF-8 ${bytes}`, () => {
    const issues: string[] = [];
    assert.equal(decodeMetadataUtf8(Uint8Array.from(bytes), issues, "String"), null);
    assert.deepEqual(issues, ["String: string is not valid UTF-8."]);
  });
}
