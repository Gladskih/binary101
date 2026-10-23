import assert from "node:assert/strict";
import { test } from "node:test";
import { createCodeViewTypeFormatter, indexCodeViewTypes } from "../../../../renderers/pe/codeview-type-names.js";

void test("CodeView primitive names retain width and pointer model", () => {
  const format = createCodeViewTypeFormatter(indexCodeViewTypes([]));
  assert.equal(format(0x74), "int32");
  assert.equal(format(0x41), "float64");
  assert.equal(format(0x674), "near64 pointer to int32");
  assert.equal(format(0x3), "void");
  assert.equal(format(0), "no type");
  assert.equal(format(0xfff), "unknown primitive #4095");
});

void test("CodeView primitive labels match the documented widths and language distinctions", () => {
  // Microsoft TYPE_ENUM_e in cvinfo.h; these spellings deliberately retain width
  // rather than guessing the source language's platform-dependent int or long.
  const expected: [number, string][] = [
    [0x01, "absolute symbol"], [0x02, "segment"], [0x04, "currency64"],
    [0x05, "near BASIC string"], [0x06, "far BASIC string"], [0x07, "not translated"], [0x08, "HRESULT"],
    [0x10, "signed char"], [0x11, "short16"], [0x12, "long32"], [0x13, "long64"], [0x14, "long128"],
    [0x20, "unsigned char"], [0x21, "unsigned short16"], [0x22, "unsigned long32"],
    [0x23, "unsigned long64"], [0x24, "unsigned long128"],
    [0x30, "bool8"], [0x31, "bool16"], [0x32, "bool32"], [0x33, "bool64"],
    [0x40, "float32"], [0x41, "float64"], [0x42, "float80"], [0x43, "float128"], [0x44, "float48"],
    [0x45, "partial float32"], [0x46, "float16"], [0x50, "complex32"], [0x51, "complex64"],
    [0x52, "complex80"], [0x53, "complex128"], [0x60, "bit"], [0x61, "Pascal CHAR"],
    [0x62, "bool32 (true = all bits set)"], [0x68, "int8"], [0x69, "uint8"],
    [0x70, "char"], [0x71, "wchar_t"], [0x72, "int16"], [0x73, "uint16"],
    [0x74, "int32"], [0x75, "uint32"], [0x76, "int64"], [0x77, "uint64"],
    [0x78, "int128"], [0x79, "uint128"], [0x7a, "char16"], [0x7b, "char32"]
  ];
  const format = createCodeViewTypeFormatter(indexCodeViewTypes([]));
  assert.deepEqual(expected.map(([index]) => format(index)), expected.map(([, name]) => name));
  assert.deepEqual([0x174, 0x274, 0x374, 0x474, 0x574, 0x674, 0x774].map(format), [
    "near16 pointer to int32", "far16 pointer to int32", "huge16 pointer to int32",
    "near32 pointer to int32", "far32 pointer to int32", "near64 pointer to int32", "near128 pointer to int32"
  ]);
});

void test("CodeView based pointer model labels distinguish the stored union arm", () => {
  const format = createCodeViewTypeFormatter(indexCodeViewTypes(Array.from({ length: 13 }, (_, model) => ({
    type: 0x1002, index: 0x1000 + model, shape: { kind: "pointer", typeIndex: 0x74, attributes: model }
  }))));
  assert.deepEqual(Array.from({ length: 13 }, (_, model) => format(0x1000 + model)), [
    "pointer (near16) to int32", "pointer (far16) to int32", "pointer (huge16) to int32",
    "pointer (segment-based) to int32", "pointer (value-based) to int32", "pointer (segment-value-based) to int32",
    "pointer (address-based) to int32", "pointer (segment-address-based) to int32", "pointer (type-based) to int32",
    "pointer (self-based) to int32", "pointer (near32) to int32", "pointer (far32) to int32", "pointer (near64) to int32"
  ]);
});

void test("CodeView type names follow local modifiers and pointer references", () => {
  const format = createCodeViewTypeFormatter(indexCodeViewTypes([
    { type: 0x1505, index: 0x1000, name: "Packet" },
    { type: 0x1001, index: 0x1001, shape: { kind: "modifier", attributes: 1, typeIndex: 0x1000 } },
    { type: 0x1002, index: 0x1002, shape: { kind: "pointer", attributes: 0x2a, typeIndex: 0x1001 } },
    { type: 0x1002, index: 0x1003, shape: { kind: "pointer", attributes: 0x4c,
      typeIndex: 0x74, classType: 0x1000, representation: 1 } },
    { type: 0x1001, index: 0x1004, shape: { kind: "modifier", attributes: 8, typeIndex: 0x41 } },
    { type: 0x1001, index: 0x1005, shape: { kind: "modifier", attributes: 7, typeIndex: 0x74 } }
  ]));
  assert.equal(format(0x1002), "lvalue reference (near32) to const Packet");
  assert.equal(format(0x1003), "data-member pointer of Packet (near64) to int32");
  assert.equal(format(0x1004), "unknown modifier bits 0x8 float64");
  assert.equal(format(0x1005), "const volatile unaligned int32");
});

void test("CodeView cycles, missing and duplicate indices stay explicit", () => {
  const format = createCodeViewTypeFormatter(indexCodeViewTypes([
    { type: 0x1001, index: 0x1000, shape: { kind: "modifier", attributes: 2, typeIndex: 0x1000 } },
    { type: 0x1505, index: 0x1001, name: "First" },
    { type: 0x1505, index: 0x1001, name: "Second" },
    { type: 0x7777, index: 0x1002 },
    { type: 0x1505, name: "No inferred index" }
  ]));
  assert.equal(format(0x1000), "volatile recursive type #4096");
  assert.equal(format(0x1001), "ambiguous type #4097");
  assert.equal(format(0x1002), "Type record 0x7777 #4098");
  assert.equal(format(0x1003), "unresolved type #4099");
});

void test("CodeView aliases retain their name or follow their stored reference", () => {
  const format = createCodeViewTypeFormatter(indexCodeViewTypes([
    { type: 0x150a, index: 0x1000, name: "Count", shape: { kind: "alias", typeIndex: 0x74 } },
    { type: 0x150a, index: 0x1001, shape: { kind: "alias", typeIndex: 0x41 } }
  ]));
  assert.equal(format(0x1000), "Count");
  assert.equal(format(0x1001), "float64");
});

void test("CodeView pointer qualifiers, unsupported modes and unnamed types stay readable", () => {
  const format = createCodeViewTypeFormatter(indexCodeViewTypes([
    { type: 0x1002, index: 0x1000, shape: { kind: "pointer", typeIndex: 0x40, attributes: 0x1e00 } },
    { type: 0x1002, index: 0x1001, shape: { kind: "pointer", typeIndex: 0x74, attributes: 0xff } },
    { type: 0x1505, index: 0x1002, name: "" },
    { type: 0x1001, index: 0x1003, shape: { kind: "modifier", typeIndex: 0x41, attributes: 0 } },
    { type: 0x1002, index: 0x1004, shape: { kind: "pointer", typeIndex: 0x74, attributes: 0x60, classType: 0x2000 } },
    { type: 0x1002, index: 0x1005, shape: { kind: "pointer", typeIndex: 0x74, attributes: 0x8c } }
  ]));
  assert.equal(format(0x1000), "volatile const unaligned restrict pointer (near16) to float32");
  assert.equal(format(0x1001), "unknown pointer mode 7 (unknown model 31) to int32");
  assert.equal(format(0x1002), "(unnamed type)");
  assert.equal(format(0x1003), "float64");
  assert.equal(format(0x1004), "member-function pointer of type #8192 (near16) to int32");
  assert.equal(format(0x1005), "rvalue reference (near64) to int32");
  assert.equal(format(0x1005), "rvalue reference (near64) to int32");
  assert.equal(format(-1), "invalid type index -1");
  assert.equal(format(Infinity), "invalid type index Infinity");
  assert.equal(format(0x874), "unknown primitive #2164");
});
