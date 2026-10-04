"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseFieldSignature, parseMemberRefSignature, parseMethodSignature
} from "../../../../../../analyzers/pe/clr/metadata-signatures.js";

const DEFAULT_CALLING_CONVENTION = 0x00; // ECMA-335 II.23.2.1 DEFAULT method signature.
const HASTHIS_CALLING_CONVENTION = 0x20; // ECMA-335 II.23.2.1 HASTHIS method signature flag.
const ELEMENT_TYPE_VOID = 0x01; // ECMA-335 II.23.1.16 ELEMENT_TYPE_VOID.
const ELEMENT_TYPE_I4 = 0x08; // ECMA-335 II.23.1.16 ELEMENT_TYPE_I4.
const ELEMENT_TYPE_STRING = 0x0e; // ECMA-335 II.23.1.16 ELEMENT_TYPE_STRING.
const ELEMENT_TYPE_SZARRAY = 0x1d; // ECMA-335 II.23.1.16 ELEMENT_TYPE_SZARRAY.
const FIELD_CALLING_CONVENTION = 0x06; // ECMA-335 II.23.2.4 FIELD signature.

void test("parseMethodSignature decodes normal parameters and return types", () => {
  const signature = parseMethodSignature(
    Uint8Array.of(HASTHIS_CALLING_CONVENTION, 1, ELEMENT_TYPE_VOID, ELEMENT_TYPE_STRING),
    "MemberRef.Signature"
  );

  assert.strictEqual(signature?.callingConvention, HASTHIS_CALLING_CONVENTION);
  assert.strictEqual(signature?.returnType, "void");
  assert.deepStrictEqual(signature?.parameterTypes, ["string"]);
  assert.strictEqual(signature?.issues, undefined);
});

void test("parseMethodSignature decodes array element types", () => {
  const signature = parseMethodSignature(
    Uint8Array.of(DEFAULT_CALLING_CONVENTION, 1, ELEMENT_TYPE_SZARRAY, ELEMENT_TYPE_I4, ELEMENT_TYPE_STRING),
    "MethodDef.Signature"
  );

  assert.strictEqual(signature?.returnType, "i4[]");
  assert.deepStrictEqual(signature?.parameterTypes, ["string"]);
});

void test("parseMethodSignature reports truncated and malformed signatures", () => {
  const empty = parseMethodSignature(Uint8Array.of(), "Empty.Signature");
  const malformedCompressedInt = parseMethodSignature(
    Uint8Array.of(DEFAULT_CALLING_CONVENTION, 0x81),
    "Bad.Signature"
  );

  assert.ok(empty?.issues?.some(issue => /truncated/i.test(issue)));
  assert.ok(malformedCompressedInt?.issues?.some(issue => /compressed integer/i.test(issue)));
});

void test("parseMemberRefSignature decodes field signatures without treating field type as parameter count", () => {
  const signature = parseMemberRefSignature(
    Uint8Array.of(FIELD_CALLING_CONVENTION, ELEMENT_TYPE_STRING),
    "MemberRef.Signature"
  );

  assert.strictEqual(signature?.callingConvention, FIELD_CALLING_CONVENTION);
  assert.strictEqual(signature?.returnType, "string");
  assert.deepStrictEqual(signature?.parameterTypes, []);
  assert.strictEqual(signature?.issues, undefined);
});

// ECMA-335 II.23.1.16: CMOD_REQD=0x1f, CMOD_OPT=0x20 (0x21 is INTERNAL).
void test("decodes required and optional modifiers with their specified element codes", () => {
  const signature = parseMemberRefSignature(
    Uint8Array.of(0x06, 0x1f, 0x05, 0x20, 0x09, 0x08), "Modified field"
  );
  assert.equal(signature?.returnType, "i4 modopt TypeRef#2 modreq TypeRef#1");
  assert.equal(signature?.issues, undefined);
});

// ECMA-335 II.23.2.13: ARRAY carries rank, sizes and *signed* lower bounds.
void test("preserves rectangular array sizes and signed lower bounds", () => {
  const signature = parseMethodSignature(
    Uint8Array.of(0, 0, 0x14, 0x08, 2, 2, 3, 4, 2, 0x7f, 0), "Array"
  );
  assert.equal(signature?.returnType, "i4[-1...1,0...3]");
  assert.equal(signature?.issues, undefined);
});

void test("distinguishes a rank-one ARRAY from a vector", () => {
  assert.equal(parseMethodSignature(Uint8Array.of(0, 0, 0x14, 0x08, 1, 0, 0), "Array")?.returnType, "i4[*]");
});

void test("keeps the vararg sentinel position", () => {
  // ECMA-335 II.23.2.2: SENTINEL=0x41 separates fixed and optional parameters.
  const signature = parseMemberRefSignature(Uint8Array.of(5, 2, 1, 8, 0x41, 0x0e), "Vararg");
  assert.equal(signature?.sentinelIndex, 1);
  assert.deepEqual(signature?.parameterTypes, ["i4", "string"]);
  assert.equal(signature?.issues, undefined);
});

void test("bounds extreme parameter counts without allocating an array", () => {
  // ECMA-335 II.23.2: maximum compressed unsigned integer is 0x1fffffff.
  const signature = parseMethodSignature(Uint8Array.of(0, 0xdf, 0xff, 0xff, 0xff, 1), "Huge");
  assert.deepEqual(signature?.parameterTypes, []);
  assert.match(signature?.issues?.[0] ?? "", /count exceeds/);
});

void test("decodes deeply nested signatures without an artificial depth limit", () => {
  const depth = 20000;
  const signature = parseMethodSignature(Uint8Array.of(0, 0, ...new Array<number>(depth).fill(0x0f), 8), "Deep");
  assert.equal(signature?.returnType, `i4${"*".repeat(depth)}`);
  assert.equal(signature?.issues, undefined);
});

void test("does not manufacture a type when a pointer is truncated", () => {
  const signature = parseMethodSignature(Uint8Array.of(0, 0, 0x0f), "Pointer");
  assert.equal(signature?.returnType, null);
  assert.match(signature?.issues?.[0] ?? "", /truncated/);
});

void test("reports unsupported INTERNAL element types and trailing bytes", () => {
  // ECMA-335 II.23.1.16: INTERNAL=0x21 is runtime-specific, not an optional modifier.
  assert.match(parseMethodSignature(Uint8Array.of(0, 0, 0x21), "Internal")?.issues?.[0] ?? "", /unsupported/);
  assert.match(parseMethodSignature(Uint8Array.of(0, 0, 1, 8), "Trailing")?.issues?.[0] ?? "", /trailing/);
});

void test("reports invalid headers, sentinel placement and reserved tokens", () => {
  assert.match(parseMethodSignature(Uint8Array.of(6, 8), "Header")?.issues?.[0] ?? "", /calling convention/);
  assert.match(parseMethodSignature(Uint8Array.of(0x40, 0, 1), "Header")?.issues?.[0] ?? "", /EXPLICITTHIS/);
  assert.match(parseMethodSignature(Uint8Array.of(0, 1, 1, 0x41, 8), "Sentinel")?.issues?.[0] ?? "", /sentinel/);
  assert.match(parseMethodSignature(Uint8Array.of(5, 2, 1, 0x41, 8, 0x41, 8), "Sentinel")?.issues?.[0] ?? "", /duplicate/);
  assert.match(parseMethodSignature(Uint8Array.of(0, 0, 0x12, 7), "Token")?.issues?.[0] ?? "", /invalid TypeDef/);
});

void test("requires FIELD in Field table signatures", () => {
  assert.equal(parseFieldSignature(null, "Absent"), undefined);
  assert.equal(parseFieldSignature(Uint8Array.of(6, 8), "Field")?.returnType, "i4");
  assert.match(parseFieldSignature(Uint8Array.of(0, 0, 1), "Field")?.issues?.[0] ?? "", /FIELD/);
});
