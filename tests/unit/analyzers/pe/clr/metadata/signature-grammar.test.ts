"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMemberRefSignature, parseMethodSignature } from "../../../../../../analyzers/pe/clr/metadata-signatures.js";
import { SignatureCursor } from "../../../../../../analyzers/pe/clr/signature-cursor.js";
import { parseFieldSignatureCore } from "../../../../../../analyzers/pe/clr/signature-grammar.js";

// ECMA-335 II.23.1.16 / II.23.2: test oracles encode the specified element values directly.
for (const [bytes, expected] of [
  [[0x0f, 1], "void*"], [[0x10, 8], "i4&"], [[0x45, 8], "i4 pinned"],
  [[0x11, 4], "valuetype TypeDef#1"], [[0x12, 5], "class TypeRef#1"],
  [[0x13, 0], "var 0"], [[0x1e, 1], "mvar 1"],
  [[0x15, 0x12, 5, 2, 8, 0x0e], "class TypeRef#1<i4, string>"],
  [[0x1b, 0, 1, 8, 0x0e], "fnptr (string) -> i4"]
] as const) {
  void test(`compound type ${expected}`, () => {
    const signature = parseMethodSignature(Uint8Array.of(0, 0, ...bytes), "Type");
    assert.equal(signature?.returnType, expected);
    assert.equal(signature?.issues, undefined);
  });
}

for (const bytes of [
  [0x11], [0x11, 0], [0x1f], [0x1f, 5], [0x1e], [0x15, 8],
  [0x15, 0x12, 0], [0x15, 0x12, 5], [0x15, 0x12, 5, 0],
  [0x15, 0x12, 5, 1, 0xff], [0x1b, 6], [0x14, 8, 0]
]) {
  void test(`malformed compound type ${bytes.join(",")}`, () => {
    const signature = parseMethodSignature(Uint8Array.of(0, 0, ...bytes), "Type");
    assert.equal(signature?.returnType, null);
    assert.ok(signature?.issues?.length);
  });
}

void test("generic method headers preserve arity and accept explicit instance signatures", () => {
  const signature = parseMethodSignature(Uint8Array.of(0x70, 2, 1, 1, 0x1e, 1), "Generic");
  assert.equal(signature?.genericParameterCount, 2);
  assert.deepEqual(signature?.parameterTypes, ["mvar 1"]);
  assert.equal(signature?.issues, undefined);
  assert.match(parseMethodSignature(Uint8Array.of(0x10, 0xff), "Generic")?.issues?.[0] ?? "", /compressed/);
});

void test("null blobs remain absent and FIELD parsing rejects a method header", () => {
  assert.equal(parseMethodSignature(null, "Absent"), undefined);
  assert.equal(parseMemberRefSignature(null, "Absent"), undefined);
  const issues: string[] = [];
  assert.equal(parseFieldSignatureCore(new SignatureCursor(Uint8Array.of(0), issues, "Field")), null);
  assert.match(issues[0] ?? "", /FIELD/);
});

void test("truncated parameters retain decoded parameters and stop after the first failure", () => {
  const signature = parseMethodSignature(Uint8Array.of(0, 1, 1, 0x0f), "Truncated");
  assert.deepEqual(signature?.parameterTypes, []);
  assert.equal(signature?.issues?.length, 1);
});

for (const [code, name] of [
  [0x01, "void"], [0x02, "bool"], [0x03, "char"], [0x04, "i1"], [0x05, "u1"], [0x06, "i2"],
  [0x07, "u2"], [0x08, "i4"], [0x09, "u4"], [0x0a, "i8"], [0x0b, "u8"], [0x0c, "r4"],
  [0x0d, "r8"], [0x0e, "string"], [0x16, "typedref"], [0x18, "native int"],
  [0x19, "native uint"], [0x1c, "object"]
] as const) {
  void test(`decodes primitive ${name}`, () => {
    assert.equal(parseMethodSignature(Uint8Array.of(0, 0, code), "Primitive")?.returnType, name);
  });
}

void test("separate parameter types do not accumulate recursive depth", () => {
  const signature = parseMethodSignature(Uint8Array.of(0, 70, 1, ...new Array<number>(70).fill(8)), "Many");
  assert.equal(signature?.parameterTypes.length, 70);
  assert.equal(signature?.issues, undefined);
});

void test("enforces the nesting budget exactly at the recursive boundary", () => {
  assert.equal(parseMethodSignature(Uint8Array.of(0, 0, ...new Array<number>(63).fill(0x0f), 8), "Limit")?.issues,
    undefined);
  assert.match(parseMethodSignature(Uint8Array.of(0, 0, ...new Array<number>(64).fill(0x0f), 8), "Limit")
    ?.issues?.[0] ?? "", /nesting limit \(64\)/);
});

void test("decodes generic value types and CoreCLR native vararg signatures", () => {
  assert.equal(parseMethodSignature(Uint8Array.of(0, 0, 0x15, 0x11, 4, 1, 8), "Generic")?.returnType,
    "valuetype TypeDef#1<i4>");
  assert.equal(parseMethodSignature(Uint8Array.of(0x0b, 1, 1, 0x41, 8), "Native vararg")?.sentinelIndex, 0);
});

void test("accepts TypeSpec handles in modifiers and reports unsupported element codes precisely", () => {
  assert.equal(parseMemberRefSignature(Uint8Array.of(6, 0x1f, 6, 8), "Modifier")?.returnType,
    "i4 modreq TypeSpec#1");
  assert.match(parseMethodSignature(Uint8Array.of(0, 0, 0x21), "Internal")?.issues?.[0] ?? "",
    /unsupported element type 0x21/);
  assert.match(parseMethodSignature(Uint8Array.of(0, 0, 0x15, 8), "Generic")?.issues?.[0] ?? "",
    /requires class or valuetype/);
  assert.match(parseMethodSignature(Uint8Array.of(0, 0, 0x15, 0x12, 5, 0), "Generic")?.issues?.[0] ?? "",
    /no type arguments/);
});
