import assert from "node:assert/strict";
import test from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { readNativeFormatScalar, isNativeFormatCollection, nativeFormatCollectionScalar } from
  "../../../../analyzers/native-aot/native-format-scalars.js";
import { nativeFormatWideBytes, nativeFormatFloatBytes } from "../../../helpers/native-format-constant-fixture.js";

for (const [encoding, bytes, expected] of [
  ["byte", [255], 255], ["unsigned", [84], 42], ["signed", [254], -1],
  ["int64", nativeFormatWideBytes(-9223372036854775808n), "-9223372036854775808"],
  ["uint64", nativeFormatWideBytes(18446744073709551615n), "18446744073709551615"],
  ["float32", nativeFormatFloatBytes(-1.5, 4), -1.5], ["float64", nativeFormatFloatBytes(Math.PI, 8), Math.PI]
] as const) {
  void test(`NativeFormat ${encoding} follows its upstream primitive encoding`, () => {
    const reader = new NativeFormatReader(Uint8Array.from(bytes));

    assert.deepEqual(readNativeFormatScalar(reader, encoding, 0), { value: expected, nextOffset: bytes.length });
    assert.throws(() => readNativeFormatScalar(reader, encoding, -1), /outside/);
    assert.throws(() => readNativeFormatScalar(reader, encoding, reader.size), /outside/);
  });
}

void test("scalar dispatch rejects unknown encodings and identifies collection element encodings", () => {
  const reader = new NativeFormatReader(new Uint8Array());

  assert.throws(() => readNativeFormatScalar(reader, "missing", 0), /Unknown/);
  assert.throws(() => readNativeFormatScalar(reader, "constructor", 0), /Unknown/);
  assert.throws(() => readNativeFormatScalar(reader, "toString", 0), /Unknown/);
  assert.equal(isNativeFormatCollection("array:uint64"), true);
  assert.equal(isNativeFormatCollection("values"), true);
  assert.equal(isNativeFormatCollection("unsigned"), false);
  assert.equal(nativeFormatCollectionScalar("array:int64"), "int64");
  assert.equal(nativeFormatCollectionScalar("signeds"), "signed");
});
