import assert from "node:assert/strict";
import test from "node:test";
import { NativeLayoutTypeReader } from "../../../../analyzers/native-aot/layout-type.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("NativeLayout skips nested types without a depth cap", () => {
  const bytes = new Uint8Array(10002).fill(36);
  bytes[10000] = 12;
  const { cursor } = createFunctionEntryFixture(bytes);

  new NativeLayoutTypeReader().skip(cursor);

  assert.equal(cursor.offset, 10001);
});

void test("NativeLayout skips instantiations, arrays and function pointer types", () => {
  // Instantiation(2 args): External, MDArray(rank2, Variable, bounds, lower bounds),
  // FunctionPointer(default convention, one parameter, BuiltIn return, External parameter).
  const { cursor } = createFunctionEntryFixture(Uint8Array.of(
    70, 12, 84, 8, 2, 6, 2, 0, 22, 0, 2, 10, 12));

  new NativeLayoutTypeReader().skip(cursor);

  assert.equal(cursor.offset, cursor.reader.size);
});

void test("NativeLayout rejects cyclic, truncated and unknown types", () => {
  const types = new NativeLayoutTypeReader();

  assert.throws(() => types.skip(createFunctionEntryFixture(Uint8Array.of(36)).cursor), /outside/);
  assert.throws(() => types.skip(createFunctionEntryFixture(Uint8Array.of(0)).cursor), /unknown/);
  assert.throws(() => types.skip(createFunctionEntryFixture(Uint8Array.of(36, 2)).cursor), /lookback/);
});

void test("NativeLayout reuses lookback type graphs and rejects links into containing types", () => {
  const { cursor } = createFunctionEntryFixture(Uint8Array.of(38, 12, 8, 0, 66));
  const types = new NativeLayoutTypeReader();

  types.skip(cursor);
  assert.equal(cursor.offset, 3);
  cursor.offset = 4;
  types.skip(cursor);
  assert.equal(cursor.offset, 5);
  assert.throws(() => types.skip(createFunctionEntryFixture(Uint8Array.of(36, 36, 2)).cursor), /cyclic/);
});

void test("cached type graphs are decoded once and remain scoped to their reader", context => {
  const { cursor } = createFunctionEntryFixture(Uint8Array.of(38, 12, 8, 0, 66));
  const unsigned = context.mock.method(cursor.reader, "unsigned");
  const types = new NativeLayoutTypeReader();

  types.skip(cursor);
  assert.equal(unsigned.mock.callCount(), 3);
  cursor.offset = 0;
  types.skip(cursor);
  assert.equal(unsigned.mock.callCount(), 3);
  cursor.offset = 4;
  types.skip(cursor);
  assert.equal(unsigned.mock.callCount(), 4);
  types.skip(createFunctionEntryFixture(Uint8Array.of(12)).cursor);
});

void test("NativeLayout rejects noncanonical lookbacks that reach their own field or its suffix", () => {
  const types = new NativeLayoutTypeReader();

  assert.throws(() => types.skip(createFunctionEntryFixture(Uint8Array.of(15, 1, 0, 0, 0)).cursor), /prefix/);
  assert.throws(() => types.skip(createFunctionEntryFixture(Uint8Array.of(15, 33, 0, 0, 0)).cursor), /prefix/);
});

void test("NativeLayout instantiation counts are bounded by bytes after the type field", () => {
  const { cursor } = createFunctionEntryFixture(Uint8Array.of(0, 102, 12));
  cursor.offset = 1;

  assert.throws(() => new NativeLayoutTypeReader().skip(cursor), /nested types are outside/);
});
