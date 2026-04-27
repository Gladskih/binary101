"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMethodSignature } from "../../analyzers/pe/clr/metadata-signatures.js";

const DEFAULT_CALLING_CONVENTION = 0x00; // ECMA-335 II.23.2.1 DEFAULT method signature.
const HASTHIS_CALLING_CONVENTION = 0x20; // ECMA-335 II.23.2.1 HASTHIS method signature flag.
const ELEMENT_TYPE_VOID = 0x01; // ECMA-335 II.23.1.16 ELEMENT_TYPE_VOID.
const ELEMENT_TYPE_I4 = 0x08; // ECMA-335 II.23.1.16 ELEMENT_TYPE_I4.
const ELEMENT_TYPE_STRING = 0x0e; // ECMA-335 II.23.1.16 ELEMENT_TYPE_STRING.
const ELEMENT_TYPE_SZARRAY = 0x1d; // ECMA-335 II.23.1.16 ELEMENT_TYPE_SZARRAY.

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
