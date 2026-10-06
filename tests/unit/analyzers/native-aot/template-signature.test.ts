import assert from "node:assert/strict";
import test from "node:test";
import { readTemplateMethodSignature } from "../../../../analyzers/native-aot/template-signature.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

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
