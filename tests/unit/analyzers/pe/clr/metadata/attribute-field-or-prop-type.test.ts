"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { AttributeCursor } from "../../../../../../analyzers/pe/clr/metadata-attribute-cursor.js";
import { readFieldOrPropType } from "../../../../../../analyzers/pe/clr/metadata-attribute-field-or-prop-type.js";

// ECMA-335 II.23.3 defines the permitted FieldOrPropType/serialization codes.
for (const [code, type] of [
  [0x02, "bool"], [0x03, "char"], [0x04, "i1"], [0x05, "u1"], [0x06, "i2"],
  [0x07, "u2"], [0x08, "i4"], [0x09, "u4"], [0x0a, "i8"], [0x0b, "u8"],
  [0x0c, "r4"], [0x0d, "r8"], [0x0e, "string"], [0x50, "System.Type"], [0x51, "object"]
] as const) {
  void test(`reads serialized type ${type}`, () => {
    const issues: string[] = [];
    assert.equal(readFieldOrPropType(new AttributeCursor(Uint8Array.of(code), issues, "Type")), type);
    assert.deepEqual(issues, []);
  });
}

void test("reads arrays and named enums", () => {
  assert.equal(readFieldOrPropType(new AttributeCursor(Uint8Array.of(0x1d, 0x0e), [], "Array")), "string[]");
  assert.equal(readFieldOrPropType(new AttributeCursor(Uint8Array.of(0x55, 1, 0x41), [], "Enum")), "enum A");
});

for (const bytes of [[], [0xff], [0x1d], [0x1d, 0x1d], [0x55], [0x55, 0xff], [0x55, 0]]) {
  void test(`reports malformed serialized type ${bytes.join(",")}`, () => {
    const issues: string[] = [];
    assert.equal(readFieldOrPropType(new AttributeCursor(Uint8Array.from(bytes), issues, "Malformed")), null);
    assert.ok(issues.length > 0);
  });
}
