"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { SignatureCursor } from "../../../../../../analyzers/pe/clr/signature-cursor.js";

// ECMA-335 II.23.2 signed compression examples, including all three encoded widths.
for (const [bytes, expected] of [
  [[0x06], 3], [[0x7b], -3], [[0x01], -64], [[0x7e], 63],
  [[0x80, 0x80], 64], [[0xbf, 0xff], -1], [[0x80, 0x01], -8192],
  [[0xc0, 0x00, 0x40, 0x00], 8192], [[0xdf, 0xff, 0xff, 0xff], -1],
  [[0xc0, 0x00, 0x00, 0x01], -268435456]
] as const) {
  void test(`signed compressed integer ${bytes.join(",")} decodes to ${expected}`, () => {
    const issues: string[] = [];
    const cursor = new SignatureCursor(Uint8Array.from(bytes), issues, "Signed");
    assert.equal(cursor.readCompressedInt(), expected);
    assert.equal(cursor.remaining, 0);
    assert.deepEqual(issues, []);
  });
}

void test("cursor stops at malformed signed integers and emits one failure", () => {
  const issues: string[] = [];
  const cursor = new SignatureCursor(Uint8Array.of(0xff), issues, "Bad");
  assert.equal(cursor.peekU8(), 0xff);
  assert.equal(cursor.readCompressedInt(), null);
  assert.equal(cursor.peekU8(), null);
  assert.equal(cursor.readU8(), null);
  cursor.finish();
  assert.equal(issues.length, 1);
  assert.match(issues[0] ?? "", /compressed signed integer/);
});
