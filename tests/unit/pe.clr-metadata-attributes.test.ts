"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCustomAttributeValue } from "../../analyzers/pe/clr/metadata-attributes.js";
import { createCustomAttributes } from "../../analyzers/pe/clr/metadata-custom-attributes.js";
import { ClrHeapReaders } from "../../analyzers/pe/clr/metadata-heaps.js";
import { TABLE_MEMBER_REF } from "../../analyzers/pe/clr/metadata-schema.js";
import type {
  PeClrMemberReferenceInfo,
  PeClrMetadataIndex,
  PeClrTypeReferenceInfo
} from "../../analyzers/pe/clr/types.js";

const encoder = new TextEncoder();
const CUSTOM_ATTRIBUTE_PROLOG = [0x01, 0x00]; // ECMA-335 II.23.3 CustomAttrib prolog.
const PROPERTY_NAMED_ARGUMENT = 0x54; // ECMA-335 II.23.3 PROPERTY named argument tag.
const ELEMENT_TYPE_STRING = 0x0e; // ECMA-335 II.23.1.16 ELEMENT_TYPE_STRING.

const serString = (text: string): number[] => {
  const bytes = [...encoder.encode(text)];
  assert.ok(bytes.length < 0x80);
  return [bytes.length, ...bytes];
};

const u32le = (value: number): number[] => [
  value & 0xff,
  (value >>> 8) & 0xff,
  (value >>> 16) & 0xff,
  (value >>> 24) & 0xff
];

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
    [],
    null,
    [],
    [systemTypeRef()],
    [],
    [],
    [memberRef],
    []
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
