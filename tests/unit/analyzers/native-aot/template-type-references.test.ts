import assert from "node:assert/strict";
import test from "node:test";
import { readTemplateTypeReference } from "../../../../analyzers/native-aot/template-type-references.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("template type lookbacks preserve caller position and reuse decoded references", () => {
  const { cursor } = createFunctionEntryFixture(Uint8Array.of(44, 0, 0, 0, 66));
  cursor.offset = 4;
  const cache = new Map<number, number>();

  assert.equal(readTemplateTypeReference(cursor, cache), 1);
  assert.equal(cursor.offset, 5);
  cursor.offset = 4;
  assert.equal(readTemplateTypeReference(cursor, cache), 1);
  assert.deepEqual([...cache.entries()], [[4, 1], [0, 1]]);
});

void test("template type references reject unsupported, forward and truncated encodings", () => {
  assert.throws(() => readTemplateTypeReference(createFunctionEntryFixture(Uint8Array.of(8)).cursor,
    new Map()), /non-external/);
  assert.throws(() => readTemplateTypeReference(createFunctionEntryFixture(Uint8Array.of(2)).cursor,
    new Map()), /lookback/);
  assert.throws(() => readTemplateTypeReference(createFunctionEntryFixture(Uint8Array.of(15)).cursor,
    new Map()), /outside/);
});

void test("template type caches avoid following lookbacks again", context => {
  const { cursor } = createFunctionEntryFixture(Uint8Array.of(44, 0, 0, 0, 66));
  const unsigned = context.mock.method(cursor.reader, "unsigned");
  const cache = new Map<number, number>();
  cursor.offset = 4;

  assert.equal(readTemplateTypeReference(cursor, cache), 1);
  assert.equal(unsigned.mock.callCount(), 2);
  cursor.offset = 4;
  assert.equal(readTemplateTypeReference(cursor, cache), 1);
  assert.equal(unsigned.mock.callCount(), 3);
});

void test("noncanonical template lookbacks cannot refer to their own field or forward data", () => {
  assert.throws(() => readTemplateTypeReference(createFunctionEntryFixture(
    Uint8Array.of(15, 1, 0, 0, 0)).cursor, new Map()), /out of bounds or cyclic/);
  assert.throws(() => readTemplateTypeReference(createFunctionEntryFixture(
    Uint8Array.of(15, 33, 0, 0, 0)).cursor, new Map()), /out of bounds or cyclic/);
});
