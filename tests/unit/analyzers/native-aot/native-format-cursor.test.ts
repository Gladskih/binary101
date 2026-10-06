import assert from "node:assert/strict";
import test from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatCursor } from "../../../../analyzers/native-aot/native-format-cursor.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("NativeFormat cursor reads fields once and retains the following offset", () => {
  const cursor = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(4, 6, 8, 2, 65)), 0);

  assert.deepEqual(cursor.indices(), [3, 4]);
  assert.equal(cursor.string(), "A");
  assert.equal(cursor.offset, 5);
  assert.equal(cursor.fork(1).unsigned(), 3);
});
void test("NativeFormat cursors reject huge counts, truncated scalars and invalid UTF-8", () => {
  assert.throws(() => createFunctionEntryFixture(Uint8Array.of(4, 0)).cursor.indices(), /remaining/);
  assert.throws(() => createFunctionEntryFixture(Uint8Array.of(15)).cursor.unsigned(), /outside/);
  assert.throws(() => createFunctionEntryFixture(Uint8Array.of(2, 255)).cursor.string(), /encoded data/);
});
