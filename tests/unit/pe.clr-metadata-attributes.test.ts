"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCustomAttributeValue } from "../../analyzers/pe/clr/metadata-attributes.js";
import { createCustomAttributes } from "../../analyzers/pe/clr/metadata-custom-attributes.js";
import { ClrHeapReaders } from "../../analyzers/pe/clr/metadata-heaps.js";
import { TABLE_MEMBER_REF } from "../../analyzers/pe/clr/metadata-schema.js";
import type { PeClrMemberReferenceInfo, PeClrMetadataIndex, PeClrTypeReferenceInfo } from "../../analyzers/pe/clr/types.js";

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
      ...serString("Assembly")
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
    "EditorBrowsableAttribute"
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

  assert.strictEqual(decoded.fixedArguments[0]?.value, "0x0000000000000001");
  assert.strictEqual(decoded.fixedArguments[1]?.value, "0x7fffffffffffffff");
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

void test("decodeCustomAttributeValue infers compact trailing fixed enum values", () => {
  const decoded = decodeCustomAttributeValue(
    Uint8Array.of(...CUSTOM_ATTRIBUTE_PROLOG, 2, 0, 0),
    ["System.Security.SecurityRuleSet"],
    "SecurityRulesAttribute"
  );

  assert.strictEqual(decoded.fixedArguments[0]?.value, 2);
  assert.strictEqual(decoded.issues, undefined);
});

void test("decodeCustomAttributeValue infers 64-bit named enum values from argument boundaries", () => {
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
    "EventAttribute"
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

void test("createCustomAttributes resolves constructor TypeRef parameters before decoding", () => {
  const issues: string[] = [];
  const memberRef: PeClrMemberReferenceInfo = {
    row: 1,
    name: ".ctor",
    parent: nullIndex(),
    parentName: "Microsoft.CodeAnalysis.ObjectTypeAttribute",
    signatureBlobIndex: 0,
    signature: {
      callingConvention: 0,
      parameterCount: 2,
      returnType: "void",
      parameterTypes: ["class TypeRef#1", "string[]"]
    }
  };
  const attributes = createCustomAttributes(
    [{
      Parent: nullIndex(),
      Type: { ...nullIndex(), table: "MemberRef", tableId: TABLE_MEMBER_REF, row: 1 },
      Value: 1
    }],
    createBlobHeapReaders([
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ...serString("Microsoft.CodeAnalysis.SymbolKey"),
      ...u32le(1),
      ...serString("Declaration")
    ], issues),
    {
      modules: [], assembly: null, assemblyRefs: [], typeRefs: [systemTypeRef()],
      typeDefs: [], methodDefs: [], memberRefs: [memberRef], moduleRefs: []
    }
  );

  assert.strictEqual(attributes[0]?.fixedArguments[0]?.value, "Microsoft.CodeAnalysis.SymbolKey");
  assert.strictEqual(attributes[0]?.fixedArguments[1]?.value, "Declaration");
  assert.strictEqual(attributes[0]?.issues, undefined);
});

const nullIndex = (): PeClrMetadataIndex => ({
  table: "null",
  tableId: -1,
  row: 0,
  raw: 0,
  valid: true
});

const systemTypeRef = (): PeClrTypeReferenceInfo => ({
  row: 1,
  name: "Type",
  namespace: "System",
  resolutionScope: nullIndex(),
  fullName: "System.Type"
});

const createBlobHeapReaders = (payload: number[], issues: string[]): ClrHeapReaders =>
  new ClrHeapReaders({
    strings: null,
    guid: null,
    blob: Uint8Array.of(0, payload.length, ...payload),
    userString: null
  }, issues);
