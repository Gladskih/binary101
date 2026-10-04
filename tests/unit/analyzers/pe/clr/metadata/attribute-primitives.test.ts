"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { AttributeCursor } from "../../../../../../analyzers/pe/clr/metadata-attribute-cursor.js";
import {
  isPrimitiveAttributeType, readAttributePrimitive
} from "../../../../../../analyzers/pe/clr/metadata-attribute-primitives.js";

// ECMA-335 II.23.3: signed/unsigned little-endian values, IEEE floats and SerString.
for (const [type, bytes, value] of [
  ["bool", [1], true], ["bool", [0], false], ["char", [0x41, 0], "A"],
  ["i1", [0xff], -1], ["u1", [0xff], 255], ["i2", [0xff, 0xff], -1],
  ["u2", [0xff, 0xff], 65535], ["i4", [0xff, 0xff, 0xff, 0xff], -1],
  ["u4", [0xff, 0xff, 0xff, 0xff], 4294967295],
  ["i8", [0, 0, 0, 0, 0, 0, 0, 0x80], "-9223372036854775808"],
  ["u8", [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], "0xffffffffffffffff"],
  ["r4", [0, 0, 0x28, 0x42], 42], ["r8", [0, 0, 0, 0, 0, 0, 0x45, 0x40], 42],
  ["string", [1, 0x41], "A"], ["System.Type", [1, 0x41], "A"], ["string", [0xff], null],
  ["i1", [1], 1], ["i2", [1, 0], 1], ["i4", [1, 0, 0, 0], 1],
  ["i1", [0x80], -128], ["i2", [0, 0x80], -32768], ["i4", [0, 0, 0, 0x80], -2147483648]
] as const) {
  void test(`reads attribute primitive ${type}/${JSON.stringify(value)}`, () => {
    const issues: string[] = [];
    assert.deepEqual(readAttributePrimitive(new AttributeCursor(Uint8Array.from(bytes), issues, "Primitive"), type),
      { value, complete: true });
    assert.deepEqual(issues, []);
    assert.equal(isPrimitiveAttributeType(type), true);
  });
}

for (const type of ["bool", "char", "i1", "i2", "i4", "i8", "u1", "u2", "u4", "u8", "r4", "r8", "string"]) {
  void test(`reports truncated attribute primitive ${type}`, () => {
    const issues: string[] = [];
    assert.deepEqual(readAttributePrimitive(new AttributeCursor(Uint8Array.of(), issues, "Empty"), type),
      { value: null, complete: false });
    assert.ok(issues.length > 0);
  });
}

void test("distinguishes an unsupported primitive from a null encoded value", () => {
  const cursor = new AttributeCursor(Uint8Array.of(), [], "Unsupported");
  assert.equal(readAttributePrimitive(cursor, "object"), undefined);
  assert.equal(readAttributePrimitive(cursor, "constructor"), undefined);
  assert.equal(readAttributePrimitive(cursor, null), undefined);
  assert.equal(isPrimitiveAttributeType("object"), true);
  assert.equal(isPrimitiveAttributeType("Demo.Mode"), false);
});
