"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMarshallingDescriptor } from "../../../../../../analyzers/pe/clr/metadata-marshalling.js";

void test("decodes simple native types and optional fixed string size", () => {
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(7), "Marshal"), { kind: "marshal", nativeType: "I4", parameters: {} });
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x17, 0x80, 0x80), "Marshal"), {
    kind: "marshal", nativeType: "FIXEDSYSSTRING", parameters: { size: 128 }
  });
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x17), "Marshal").parameters, {});
});

void test("decodes ARRAY, FIXEDARRAY and interface extension fields in order", () => {
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x2a, 7, 2, 9, 1), "Marshal").parameters,
    { elementType: 7, sizeParameterIndex: 2, size: 9, flags: 1 });
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x1e, 9, 7), "Marshal").parameters,
    { size: 9, elementType: 7 });
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x19, 2), "Marshal").parameters, { iidParameterIndex: 2 });
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x1a, 2), "Marshal").parameters, { iidParameterIndex: 2 });
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x1c, 2), "Marshal").parameters, { iidParameterIndex: 2 });
});

void test("decodes SAFEARRAY subtype and CUSTOMMARSHALER strings", () => {
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x1d, 3, 1, 65), "Marshal").parameters,
    { variantType: 3, userDefinedType: "A" });
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x1d), "Marshal").parameters, {});
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x2c, 0, 0, 1, 65, 1, 66), "Marshal").parameters,
    { guid: "", nativeTypeName: "", marshalerType: "A", cookie: "B" });
});

void test("reports unknown, truncated and surplus encodings", () => {
  assert.ok(parseMarshallingDescriptor(new Uint8Array(), "Marshal").issues?.length);
  assert.ok(parseMarshallingDescriptor(Uint8Array.of(0x55), "Marshal").issues?.length);
  assert.ok(parseMarshallingDescriptor(Uint8Array.of(0x2c), "Marshal").issues?.length);
  assert.ok(parseMarshallingDescriptor(Uint8Array.of(0x17, 0x80), "Marshal").issues?.length);
  assert.match(parseMarshallingDescriptor(Uint8Array.of(7, 1), "Marshal").issues![0]!, /trailing/);
});

// CorNativeType in dotnet/runtime src/coreclr/inc/corhdr.h; includes legacy and modern codes.
for (const [code, name] of [
  [0, "END"], [1, "VOID"], [2, "BOOLEAN"], [3, "I1"], [4, "U1"], [5, "I2"], [6, "U2"],
  [7, "I4"], [8, "U4"], [9, "I8"], [10, "U8"], [11, "R4"], [12, "R8"], [13, "SYSCHAR"],
  [14, "VARIANT"], [15, "CURRENCY"], [16, "PTR"], [17, "DECIMAL"], [18, "DATE"], [19, "BSTR"],
  [20, "LPSTR"], [21, "LPWSTR"], [22, "LPTSTR"], [23, "FIXEDSYSSTRING"], [24, "OBJECTREF"],
  [25, "IUNKNOWN"], [26, "IDISPATCH"], [27, "STRUCT"], [28, "INTERFACE"], [29, "SAFEARRAY"],
  [30, "FIXEDARRAY"], [31, "INT"], [32, "UINT"], [33, "NESTEDSTRUCT"], [34, "BYVALSTR"],
  [35, "ANSIBSTR"], [36, "TBSTR"], [37, "VARIANTBOOL"], [38, "FUNC"], [40, "ASANY"],
  [42, "ARRAY"], [43, "LPSTRUCT"], [45, "ERROR"], [46, "IINSPECTABLE"], [47, "HSTRING"], [48, "LPUTF8STR"]
] as const) {
  void test(`recognizes native type ${name}`, () => {
    assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(code), "Marshal"),
      { kind: "marshal", nativeType: name, parameters: {} });
  });
}

void test("preserves custom marshaler identity, and diagnoses unknown or missing types precisely", () => {
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(44, 0, 0, 0, 0), "Marshal"), {
    kind: "marshal", nativeType: "CUSTOMMARSHALER",
    parameters: { guid: "", nativeTypeName: "", marshalerType: "", cookie: "" }
  });
  assert.deepEqual(parseMarshallingDescriptor(Uint8Array.of(0x55), "Marshal"), {
    kind: "marshal", nativeType: "0x55", parameters: {}, issues: ["Marshal: unsupported native type 0x55."]
  });
  assert.deepEqual(parseMarshallingDescriptor(new Uint8Array(), "Marshal"), {
    kind: "marshal", nativeType: "unknown", parameters: {}, issues: ["Marshal: blob is truncated."]
  });
});
