"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMethodSignature, parseFieldSignature } from "../../../../../../analyzers/pe/clr/metadata-signatures.js";

void test("preserves a function pointer's calling convention and vararg sentinel", () => {
  // ECMA-335 II.23.2: FNPTR, VARARG, ParamCount=2, VOID, I4, SENTINEL, STRING.
  const signature = parseFieldSignature(Uint8Array.of(6, 0x1b, 5, 2, 1, 8, 0x41, 0x0e), "Function pointer");
  assert.equal(signature?.returnType, "fnptr [cc=0x5] (i4, ..., string) -> void");
  assert.equal(signature?.issues, undefined);
});

void test("preserves function pointer generic arity and instance flags", () => {
  const signature = parseFieldSignature(Uint8Array.of(6, 0x1b, 0x30, 2, 1, 1, 0x1e, 0), "Function pointer");
  assert.equal(signature?.returnType, "fnptr [cc=0x30; generic=2] (mvar 0) -> void");
  assert.equal(signature?.issues, undefined);
});

void test("accepts deeply nested function pointers and generic types", () => {
  const depth = 12000;
  const blob = Uint8Array.of(0, 0, ...Array.from({ length: depth }, () => [0x1b, 0, 0]).flat(), 1);
  const signature = parseMethodSignature(blob, "Deep function pointer");
  assert.equal(signature?.returnType, `${"fnptr () -> ".repeat(depth)}void`);
  assert.equal(signature?.issues, undefined);
});
