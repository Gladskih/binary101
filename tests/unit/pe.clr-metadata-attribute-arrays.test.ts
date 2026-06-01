"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCustomAttributeValue } from "../../analyzers/pe/clr/metadata-attributes.js";

const encoder = new TextEncoder();
const CUSTOM_ATTRIBUTE_PROLOG = [0x01, 0x00]; // ECMA-335 II.23.3 CustomAttrib prolog.
const ELEMENT_TYPE_STRING = 0x0e; // ECMA-335 II.23.1.16 ELEMENT_TYPE_STRING.

const serString = (text: string): number[] => {
  const bytes = [...encoder.encode(text)];
  assert.ok(bytes.length < 0x80);
  return [bytes.length, ...bytes];
};

const u32le = (value: number): number[] => [
  value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff
];

void test("decodeCustomAttributeValue decodes boxed values inside fixed object arrays", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ...serString("Regex"),
      ...u32le(1),
      ELEMENT_TYPE_STRING,
      ...serString("RegexOptions"),
      0, 0
    ),
    ["string", "object[]"],
    "StringSyntaxAttribute"
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, "Regex");
  assert.strictEqual(decoded.fixedArguments[1]?.value, "RegexOptions");
  assert.strictEqual(decoded.issues, undefined);
});
