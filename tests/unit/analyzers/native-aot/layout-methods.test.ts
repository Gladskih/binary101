import assert from "node:assert/strict";
import test from "node:test";
import { readLayoutMethod } from "../../../../analyzers/native-aot/layout-methods.js";
import { NativeLayoutTypeReader } from "../../../../analyzers/native-aot/layout-type.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("dictionary method signatures skip generic variable and nested owner types", () => {
  const { cursor } = createFunctionEntryFixture(Uint8Array.of(10, 2, 38, 12, 8, 20, 2, 8));

  assert.deepEqual(readLayoutMethod(cursor, new NativeLayoutTypeReader()),
    { signatureOffset: 0, flags: 5, methodToken: 10, entrypointIndex: 1 });
  assert.equal(cursor.offset, cursor.reader.size);
});

void test("dictionary method signatures reject unknown flags and truncated fields", () => {
  assert.throws(() => readLayoutMethod(createFunctionEntryFixture(Uint8Array.of(16)).cursor,
    new NativeLayoutTypeReader()), /flags/);
  assert.throws(() => readLayoutMethod(createFunctionEntryFixture(Uint8Array.of(8)).cursor,
    new NativeLayoutTypeReader()), /outside/);
});

void test("method signatures without optional fields consume only their owner and token", () => {
  const { cursor } = createFunctionEntryFixture(Uint8Array.of(0, 12, 20));

  assert.deepEqual(readLayoutMethod(cursor, new NativeLayoutTypeReader()),
    { signatureOffset: 0, flags: 0, methodToken: 10, entrypointIndex: null });
});
