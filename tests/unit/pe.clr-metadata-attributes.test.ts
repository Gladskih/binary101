"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCustomAttributeValue } from "../../analyzers/pe/clr/metadata-attributes.js";

const encoder = new TextEncoder();
const CUSTOM_ATTRIBUTE_PROLOG = [0x01, 0x00]; // ECMA-335 II.23.3 CustomAttrib prolog.
const PROPERTY_NAMED_ARGUMENT = 0x54; // ECMA-335 II.23.3 PROPERTY named argument tag.
const ELEMENT_TYPE_STRING = 0x0e; // ECMA-335 II.23.1.16 ELEMENT_TYPE_STRING.

const serString = (text: string): number[] => {
  const bytes = [...encoder.encode(text)];
  assert.ok(bytes.length < 0x80);
  return [bytes.length, ...bytes];
};

void test("decodeCustomAttributeValue decodes fixed string args and named properties", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ...serString(".NETCoreApp,Version=v8.0"),
      1, 0,
      PROPERTY_NAMED_ARGUMENT,
      ELEMENT_TYPE_STRING,
      ...serString("FrameworkDisplayName"),
      ...serString(".NET 8.0")
    ),
    ["string"],
    "TargetFrameworkAttribute"
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, ".NETCoreApp,Version=v8.0");
  assert.strictEqual(decoded.namedArguments[0]?.kind, "property");
  assert.strictEqual(decoded.namedArguments[0]?.name, "FrameworkDisplayName");
  assert.strictEqual(decoded.namedArguments[0]?.value, ".NET 8.0");
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue reports malformed prologs and strings", () => {
  const wrongProlog = decodeCustomAttributeValue(Uint8Array.of(0, 0, 0, 0), [], "BadAttribute");
  const malformedString = decodeCustomAttributeValue(
    Uint8Array.of(...CUSTOM_ATTRIBUTE_PROLOG, 0x81),
    ["string"],
    "BadAttribute"
  );

  assert.ok(wrongProlog.issues?.some(issue => /prolog/i.test(issue)));
  assert.ok(malformedString.issues?.some(issue => /string length/i.test(issue)));
});

void test("decodeCustomAttributeValue reports trailing partial named-argument counts", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(...CUSTOM_ATTRIBUTE_PROLOG, ...serString("value"), 0xff),
    ["string"],
    "TrailingAttribute"
  );

  assert.ok(decoded.issues?.some(issue => /partial NumNamed/i.test(issue)));
});
