"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createEnumUnderlyingTypes } from "../../../../../../analyzers/pe/clr/metadata-enums.js";
import type {
  PeClrFieldInfo, PeClrTypeDefinitionInfo, PeClrTypeReferenceInfo
} from "../../../../../../analyzers/pe/clr/types.js";

const baseReference = (): PeClrTypeReferenceInfo => ({
  row: 1, name: "Enum", namespace: "System", fullName: "System.Enum",
  resolutionScope: { table: "AssemblyRef", tableId: 35, row: 1, raw: 6, valid: true }
});

const definition = (): PeClrTypeDefinitionInfo => ({
  row: 1, name: "Mode", namespace: "Demo", fullName: "Demo.Mode", flags: 0,
  extends: { table: "TypeRef", tableId: 1, row: 1, raw: 5, valid: true },
  fieldStart: 1, fieldEnd: 1, methodStart: 1, methodEnd: null
});

const underlyingField = (type = "u1"): PeClrFieldInfo => ({
  row: 1, name: "value__", flags: 0, signatureBlobIndex: 1,
  signature: { callingConvention: 6, parameterCount: 0, returnType: type, parameterTypes: [] }
});

void test("resolves enum widths from their validated value__ field", () => {
  assert.deepEqual([...createEnumUnderlyingTypes([definition()], [baseReference()], [underlyingField()])],
    [["Demo.Mode", "u1"]]);
  assert.deepEqual([...createEnumUnderlyingTypes([definition()], [baseReference()], [underlyingField("i8")])],
    [["Demo.Mode", "i8"]]);
});

for (const field of [
  { ...underlyingField(), name: "other" }, { ...underlyingField(), flags: 0x10 },
  { row: 1, name: "value__", flags: 0, signatureBlobIndex: 0 }, underlyingField("string"),
  { ...underlyingField(), signature: { ...underlyingField().signature!, issues: ["truncated"] } },
  underlyingField("xi4"), underlyingField("i4x")
]) {
  void test(`rejects invalid enum field ${field.name}/${field.flags}/${field.signature?.returnType}`, () => {
    assert.equal(createEnumUnderlyingTypes([definition()], [baseReference()], [field]).size, 0);
  });
}

for (const type of [
  { ...definition(), fullName: null }, { ...definition(), fieldStart: 0 },
  { ...definition(), fieldEnd: null }, { ...definition(), fieldEnd: 2 },
  { ...definition(), extends: { ...definition().extends, valid: false } },
  { ...definition(), extends: { ...definition().extends, row: 0 } },
  { ...definition(), extends: { ...definition().extends, row: 2 } },
  { ...definition(), extends: { ...definition().extends, tableId: 27 } }
]) {
  void test(`rejects incomplete enum definition ${JSON.stringify(type)}`, () => {
    assert.equal(createEnumUnderlyingTypes([type], [baseReference()], [underlyingField()]).size, 0);
  });
}

void test("handles local base types and rejects multiple instance fields", () => {
  const localBase = { ...definition(), row: 2, fullName: "System.Enum", fieldEnd: null };
  const derived = { ...definition(), extends: { ...definition().extends, tableId: 2, row: 2 } };
  assert.equal(createEnumUnderlyingTypes([derived, localBase], [], [underlyingField()]).get("Demo.Mode"), "u1");
  assert.equal(createEnumUnderlyingTypes([derived], [], [underlyingField()]).size, 0);
  assert.equal(createEnumUnderlyingTypes([{ ...definition(), fieldEnd: 2 }], [baseReference()],
    [underlyingField(), underlyingField()]).size, 0);
});

void test("reads only fields in the enum's declared list range", () => {
  const unrelated = { ...underlyingField(), row: 1, name: "Unrelated" };
  assert.equal(createEnumUnderlyingTypes([{ ...definition(), fieldStart: 2, fieldEnd: 2 }], [baseReference()],
    [unrelated, { ...underlyingField(), row: 2 }]).get("Demo.Mode"), "u1");
});

void test("does not interpret another table as a local enum base", () => {
  const fakeBase = { ...definition(), fullName: "System.Enum" };
  const bad = { ...definition(), extends: { ...definition().extends, tableId: 27 } };
  assert.equal(createEnumUnderlyingTypes([fakeBase, bad], [], [underlyingField()]).size, 0);
});
