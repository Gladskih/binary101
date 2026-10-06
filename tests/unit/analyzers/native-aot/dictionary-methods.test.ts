import assert from "node:assert/strict";
import test from "node:test";
import { readDictionaryMethods } from "../../../../analyzers/native-aot/dictionary-methods.js";
import { NativeLayoutTypeReader } from "../../../../analyzers/native-aot/layout-type.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("dictionary cells yield only explicit method function indices", () => {
  // Three inline cells: type handle, Method(has pointer), static data(kind).
  const { cursor, issues } = createFunctionEntryFixture(Uint8Array.of(6, 2, 12, 26, 8, 2, 12, 20, 10, 12, 0));

  assert.deepEqual(readDictionaryMethods(cursor, new NativeLayoutTypeReader(), issues),
    [{ signatureOffset: 4, flags: 4, methodToken: 10, entrypointIndex: 1 }]);
  assert.equal(issues.size, 0);
});

void test("unknown dictionary cells preserve the preceding method", () => {
  const { cursor, issues } = createFunctionEntryFixture(Uint8Array.of(4, 26, 8, 0, 12, 20, 0));

  assert.equal(readDictionaryMethods(cursor, new NativeLayoutTypeReader(), issues).length, 1);
  assert.match([...issues][0]!, /unknown/);
});

void test("constrained method cells decode both type and method payloads", () => {
  const { cursor, issues } = createFunctionEntryFixture(Uint8Array.of(
    6, 64, 12, 8, 2, 66, 12, 8, 2, 68, 8, 8, 0, 12, 20));

  assert.deepEqual(readDictionaryMethods(cursor, new NativeLayoutTypeReader(), issues),
    [{ signatureOffset: 11, flags: 4, methodToken: 10, entrypointIndex: 0 }]);
  assert.equal(issues.size, 0);
});

void test("NotYetSupported marker cells warn and do not hide following method cells", () => {
  // 0xee requires a two-byte NativeFormat integer; marker is encoded independently of production.
  const { cursor, issues } = createFunctionEntryFixture(Uint8Array.of(4, 185, 3, 0, 26, 0, 12, 20));

  assert.equal(readDictionaryMethods(cursor, new NativeLayoutTypeReader(), issues).length, 1);
  assert.match([...issues][0]!, /NotYetSupported/);
});

void test("dictionary decoding exposes untyped reader failures", context => {
  const { cursor, issues } = createFunctionEntryFixture(Uint8Array.of(2));
  context.mock.method(cursor, "count", () => { throw "untyped failure"; });

  assert.deepEqual(readDictionaryMethods(cursor, new NativeLayoutTypeReader(), issues), []);
  assert.deepEqual([...issues], ["NativeLayout dictionary read failed."]);
});
