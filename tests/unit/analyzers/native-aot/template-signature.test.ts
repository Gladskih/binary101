import assert from "node:assert/strict";
import test from "node:test";
import { readTemplateMethodSignature } from "../../../../analyzers/native-aot/template-signature.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";
import { createLegacyLayoutCursor } from "../../../helpers/native-layout-legacy-fixture.js";

void test("legacy template signatures retain method names and USG flags without inventing metadata tokens", () => {
  const cursor = createLegacyLayoutCursor(Uint8Array.of(26, 0, 12, 2, 77, 6, 2, 44, 0));

  assert.deepEqual(readTemplateMethodSignature(cursor, new Map()),
    { flags: 13, declaringTypeIndex: 0, methodName: "M", methodSignatureOffset: 8,
      genericArgumentIndices: [1], entrypointIndex: 0 });
  assert.equal(cursor.offset, 8);
});

void test("template signatures separate their function index from external type indices", () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(10, 0, 12, 20, 2, 44));

  assert.deepEqual(readTemplateMethodSignature(fixture.cursor, new Map()),
    { flags: 5, entrypointIndex: 0, declaringTypeIndex: 0, methodToken: 10,
      genericArgumentIndices: [1] });
  assert.equal(fixture.cursor.offset, 6);
});
void test("non-generic template signatures leave following data unread", () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 12, 20, 4, 44));

  assert.deepEqual(readTemplateMethodSignature(fixture.cursor, new Map()),
    { flags: 0, declaringTypeIndex: 0, methodToken: 10, genericArgumentIndices: [], entrypointIndex: null });
  assert.equal(fixture.cursor.offset, 3);
});
