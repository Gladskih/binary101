"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCustomAttributeValue } from "../../../../../../analyzers/pe/clr/metadata-attributes.js";

const encoder = new TextEncoder();
const CUSTOM_ATTRIBUTE_PROLOG = [0x01, 0x00]; // ECMA-335 II.23.3 CustomAttrib prolog.
const PROPERTY_NAMED_ARGUMENT = 0x54; // ECMA-335 II.23.3 PROPERTY named argument tag.
const ELEMENT_TYPE_STRING = 0x0e; // ECMA-335 II.23.1.16 ELEMENT_TYPE_STRING.
const ELEMENT_TYPE_I4 = 0x08; // ECMA-335 II.23.1.16 ELEMENT_TYPE_I4.
const ELEMENT_TYPE_I8 = 0x0a; // ECMA-335 II.23.1.16 ELEMENT_TYPE_I8.
const ELEMENT_TYPE_ENUM = 0x55; // ECMA-335 II.23.3 enum field/property type.

const serString = (text: string): number[] => {
  const bytes = [...encoder.encode(text)];
  assert.ok(bytes.length < 0x80);
  return [bytes.length, ...bytes];
};

const u32le = (value: number): number[] => [
  value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff
];

const u64le = (low: number, high: number): number[] => [...u32le(low), ...u32le(high)];

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

void test("decodeCustomAttributeValue decodes fixed System.Type and string array arguments", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ...serString("Microsoft.CodeAnalysis.SymbolKey"),
      ...u32le(2),
      ...serString("Declaration"),
      ...serString("Assembly"),
      0, 0
    ),
    ["System.Type", "string[]"],
    "ObjectTypeAttribute"
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, "Microsoft.CodeAnalysis.SymbolKey");
  assert.strictEqual(decoded.fixedArguments[1]?.value, "Declaration, Assembly");
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue decodes enum and boxed object arguments", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ...u32le(2),
      ELEMENT_TYPE_I4,
      ...u32le(7),
      1, 0,
      PROPERTY_NAMED_ARGUMENT,
      ELEMENT_TYPE_ENUM,
      ...serString("System.ComponentModel.EditorBrowsableState"),
      ...serString("State"),
      ...u32le(1)
    ),
    ["System.ComponentModel.EditorBrowsableState", "object"],
    "EditorBrowsableAttribute",
    new Map([["System.ComponentModel.EditorBrowsableState", "i4"]])
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, 2);
  assert.strictEqual(decoded.fixedArguments[1]?.value, 7);
  assert.strictEqual(decoded.namedArguments[0]?.type, "enum System.ComponentModel.EditorBrowsableState");
  assert.strictEqual(decoded.namedArguments[0]?.value, 1);
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue decodes boxed 64-bit object arguments", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ELEMENT_TYPE_I8,
      ...u64le(1, 0),
      ELEMENT_TYPE_I8,
      ...u64le(0xffffffff, 0x7fffffff),
      0, 0
    ),
    ["object", "object"],
    "ValidateRangeAttribute"
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, "1");
  assert.strictEqual(decoded.fixedArguments[1]?.value, "9223372036854775807");
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue decodes boxed array object arguments", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ...serString("VsMEFDgmlCategories"),
      0x1d,
      ELEMENT_TYPE_STRING,
      ...u32le(1),
      ...serString("VsMEFBuiltIn"),
      0, 0
    ),
    ["string", "object"],
    "PartMetadataAttribute"
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, "VsMEFDgmlCategories");
  assert.strictEqual(decoded.fixedArguments[1]?.value, "VsMEFBuiltIn");
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue uses resolved compact trailing fixed enum values", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(...CUSTOM_ATTRIBUTE_PROLOG, 2, 0, 0),
    ["System.Security.SecurityRuleSet"],
    "SecurityRulesAttribute",
    new Map([["System.Security.SecurityRuleSet", "u1"]])
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, 2);
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue uses resolved 64-bit named enum values", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ...u32le(1),
      3, 0,
      PROPERTY_NAMED_ARGUMENT,
      ELEMENT_TYPE_ENUM,
      ...serString("System.Diagnostics.Tracing.EventLevel"),
      ...serString("Level"),
      ...u32le(4),
      PROPERTY_NAMED_ARGUMENT,
      ELEMENT_TYPE_ENUM,
      ...serString("System.Diagnostics.Tracing.EventKeywords"),
      ...serString("Keywords"),
      ...u64le(0x18, 0),
      PROPERTY_NAMED_ARGUMENT,
      ELEMENT_TYPE_ENUM,
      ...serString("System.Diagnostics.Tracing.EventOpcode"),
      ...serString("Opcode"),
      ...u32le(1)
    ),
    ["i4"],
    "EventAttribute",
    new Map([["System.Diagnostics.Tracing.EventLevel", "i4"],
      ["System.Diagnostics.Tracing.EventKeywords", "u8"], ["System.Diagnostics.Tracing.EventOpcode", "i4"]])
  );

  assert.strictEqual(decoded.namedArguments[0]?.value, 4);
  assert.strictEqual(decoded.namedArguments[1]?.value, "0x0000000000000018");
  assert.strictEqual(decoded.namedArguments[2]?.value, 1);
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue stops malformed named argument loops after one failure", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(...CUSTOM_ATTRIBUTE_PROLOG, 0xff, 0xff),
    [],
    "MalformedNamedArgumentsAttribute"
  );

  assert.strictEqual(decoded.issues?.length, 2);
  assert.ok(decoded.issues?.some(issue => /truncated/i.test(issue)));
  assert.ok(decoded.issues?.some(issue => /named argument 1\/65535/i.test(issue)));
});

void test("decodeCustomAttributeValue stops arrays when declared elements exceed available bytes", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(...CUSTOM_ATTRIBUTE_PROLOG, ...u32le(0x12345678)),
    ["string[]"],
    "TruncatedArrayAttribute"
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, "");
  assert.ok(decoded.issues?.some(issue => /truncated after 0\/305419896 element/.test(issue)));
});

void test("decodeCustomAttributeValue stops arrays when an element is malformed", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(...CUSTOM_ATTRIBUTE_PROLOG, ...u32le(2), 0x81),
    ["string[]"],
    "MalformedArrayAttribute"
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, "");
  assert.ok(decoded.issues?.some(issue => /string length is malformed/.test(issue)));
  assert.ok(decoded.issues?.some(issue => /fixed arguments are incomplete/.test(issue)));
});

void test("reports missing mandatory NumNamed and truncated array counts", () => {
  assert.match(decodeCustomAttributeValue(Uint8Array.of(...CUSTOM_ATTRIBUTE_PROLOG), [], "No count")
    .issues?.[0] ?? "", /missing NumNamed/);
  assert.match(decodeCustomAttributeValue(Uint8Array.of(...CUSTOM_ATTRIBUTE_PROLOG), ["string[]"], "No array count")
    .issues?.[0] ?? "", /truncated/);
});

void test("rejects a named OBJECT whose serialized value is another OBJECT", () => {
  // CustomAttributeDecoder.DecodeArgument unwraps TaggedObject once, then requires a concrete type.
  const decoded = decodeCustomAttributeValue(Uint8Array.of(
    ...CUSTOM_ATTRIBUTE_PROLOG, 1, 0, PROPERTY_NAMED_ARGUMENT,
    0x51, ...serString("Value"), 0x51, ELEMENT_TYPE_I4, ...u32le(7)
  ), [], "Invalid box");
  assert.deepEqual(decoded.namedArguments, []);
  assert.match(decoded.issues?.[0] ?? "", /no concrete serialized type/);
});

void test("decodes named boxed primitives, arrays and resolved enums", () => {
  const decoded = decodeCustomAttributeValue(Uint8Array.of(
    ...CUSTOM_ATTRIBUTE_PROLOG, 3, 0,
    PROPERTY_NAMED_ARGUMENT, 0x51, ...serString("Number"), ELEMENT_TYPE_I4, ...u32le(7),
    PROPERTY_NAMED_ARGUMENT, 0x51, ...serString("Array"), 0x1d, ELEMENT_TYPE_STRING,
    ...u32le(1), ...serString("entry"),
    PROPERTY_NAMED_ARGUMENT, 0x51, ...serString("Enum"), ELEMENT_TYPE_ENUM,
    ...serString("Example.Enum"), 0xff
  ), [], "Boxes", new Map([["Example.Enum", "i1"]]));
  assert.deepEqual(decoded.namedArguments.map(argument => argument.value), [7, "entry", -1]);
  assert.equal(decoded.issues, undefined);
});

void test("reports absent blobs and unsupported fixed types", () => {
  assert.match(decodeCustomAttributeValue(null, [], "Absent").issues?.[0] ?? "", /blob is absent/);
  assert.match(decodeCustomAttributeValue(Uint8Array.of(1, 0, 0, 0), ["native int"], "Unsupported")
    .issues?.[0] ?? "", /not supported/);
});

void test("reports truncated boxed types and oversized strings", () => {
  assert.match(decodeCustomAttributeValue(Uint8Array.of(1, 0), ["object"], "Box")
    .issues?.[0] ?? "", /truncated/);
  assert.match(decodeCustomAttributeValue(Uint8Array.of(1, 0, 4, 0x41), ["string"], "String")
    .issues?.[0] ?? "", /extends past the blob/);
});

void test("rejects invalid named argument kinds", () => {
  assert.match(decodeCustomAttributeValue(Uint8Array.of(1, 0, 1, 0, 0xff), [], "Kind")
    .issues?.[0] ?? "", /not FIELD or PROPERTY/);
});
