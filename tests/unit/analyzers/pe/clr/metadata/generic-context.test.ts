"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveAttributeGenericParameters }
  from "../../../../../../analyzers/pe/clr/metadata-generic-context.js";

const owner = () => ({ table: "TypeSpec", tableId: 0x1b, row: 1, raw: 1, valid: true });

void test("substitutes VAR with the declared constructor TypeSpec arguments", () => {
  assert.deepEqual(resolveAttributeGenericParameters(["var 0", "var 1[]", "i4", null, "mvar 0", "var 2"],
    owner(), new Map([[1, { type: "class TypeDef#1<string, i4>" }]])),
  ["string", "i4[]", "i4", null, "mvar 0", "var 2"]);
});

void test("keeps nested generic, array and function pointer commas inside their argument", () => {
  assert.deepEqual(resolveAttributeGenericParameters(["var 0", "var 1", "var 2"], owner(), new Map([[1, {
    type: "class TypeRef#1<class TypeDef#2<i4, string>, i4[rank 3; sizes (1, 2); lower bounds ()], fnptr (i4, string) -> void>"
  }]])), ["class TypeDef#2<i4, string>", "i4[rank 3; sizes (1, 2); lower bounds ()]", "fnptr (i4, string) -> void"]);
});

void test("leaves unavailable and malformed generic contexts unresolved", () => {
  const types = ["var 0"];
  assert.equal(resolveAttributeGenericParameters(types, undefined, undefined), types);
  assert.equal(resolveAttributeGenericParameters(types, { ...owner(), valid: false }, undefined), types);
  assert.equal(resolveAttributeGenericParameters(types, { ...owner(), tableId: 2 }, undefined), types);
  assert.deepEqual(resolveAttributeGenericParameters(types, owner(), undefined), types);
  assert.deepEqual(resolveAttributeGenericParameters(types, owner(), new Map([[1, { type: null }]])), types);
  assert.deepEqual(resolveAttributeGenericParameters(types, owner(), new Map([[1, { type: "i4" }]])), types);
  assert.deepEqual(resolveAttributeGenericParameters(types, owner(), new Map([[1, {
    type: "class TypeDef#1<i4>", issues: ["truncated"]
  }]])), types);
});

void test("does not interpret a function pointer return arrow as a generic delimiter", () => {
  assert.deepEqual(resolveAttributeGenericParameters(["var 0", "var 1"], owner(), new Map([[1, {
    type: "class TypeDef#1<fnptr (i4) -> string, i4>"
  }]])), ["fnptr (i4) -> string", "i4"]);
});
