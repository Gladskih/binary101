"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCustomAttributeValue } from "../../../../../../analyzers/pe/clr/metadata-attributes.js";

const encoder = new TextEncoder();
const CUSTOM_ATTRIBUTE_PROLOG = [0x01, 0x00]; // ECMA-335 II.23.3 CustomAttrib prolog.
const PROPERTY_NAMED_ARGUMENT = 0x54; // ECMA-335 II.23.3 PROPERTY named argument tag.
const ELEMENT_TYPE_I4 = 0x08; // ECMA-335 II.23.1.16 ELEMENT_TYPE_I4.
const ELEMENT_TYPE_OBJECT = 0x51; // ECMA-335 II.23.1.16 ELEMENT_TYPE_OBJECT.
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

void test("decodeCustomAttributeValue infers boxed fixed enum values before named count", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ELEMENT_TYPE_ENUM,
      ...serString("System.Data.SQLite.SQLiteConnectionFlags"),
      ...u64le(0x4008, 0x0c00),
      0, 0
    ),
    ["object"],
    "DefaultValueAttribute"
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, "0x00000c0000004008");
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue keeps compact enum values before named properties", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      2,
      1, 0,
      PROPERTY_NAMED_ARGUMENT,
      ELEMENT_TYPE_I4,
      ...serString("SkipVerificationInFullTrust"),
      ...u32le(1)
    ),
    ["System.Security.SecurityRuleSet"],
    "SecurityRulesAttribute"
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, 2);
  assert.strictEqual(decoded.namedArguments[0]?.kind, "property");
  assert.strictEqual(decoded.namedArguments[0]?.name, "SkipVerificationInFullTrust");
  assert.strictEqual(decoded.namedArguments[0]?.value, 1);
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue infers compact boxed named enum values", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      1, 0,
      PROPERTY_NAMED_ARGUMENT,
      ELEMENT_TYPE_OBJECT,
      ...serString("Max"),
      ELEMENT_TYPE_ENUM,
      ...serString("System.Runtime.Intrinsics.X86.FloatComparisonMode"),
      0x1f
    ),
    [],
    "ConstantExpectedAttribute"
  );

  assert.strictEqual(decoded.namedArguments[0]?.kind, "property");
  assert.strictEqual(decoded.namedArguments[0]?.name, "Max");
  assert.strictEqual(decoded.namedArguments[0]?.value, 31);
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue keeps compact named enums before more enum names", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ...u32le(131),
      2, 0,
      PROPERTY_NAMED_ARGUMENT,
      ELEMENT_TYPE_ENUM,
      ...serString("System.Diagnostics.Tracing.EventLevel"),
      ...serString("Level"),
      5,
      PROPERTY_NAMED_ARGUMENT,
      ELEMENT_TYPE_ENUM,
      ...serString("System.Diagnostics.Tracing.EventChannel"),
      ...serString("Channel"),
      12
    ),
    ["i4"],
    "EventAttribute"
  );

  assert.strictEqual(decoded.namedArguments[0]?.name, "Level");
  assert.strictEqual(decoded.namedArguments[0]?.value, 5);
  assert.strictEqual(decoded.namedArguments[1]?.name, "Channel");
  assert.strictEqual(decoded.namedArguments[1]?.value, 12);
  assert.strictEqual(decoded.issues, undefined);
});
