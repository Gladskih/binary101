import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeArrayReader } from "../../../../analyzers/native-aot/native-array.js";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { createNativeArrayWideIndexFixture, createNativeArrayTwoBlockFixture } from
  "../../../helpers/native-array-fixture.js";

// Independent NativeArray encoding oracle: count<<2 | indexWidth; block index;
// compressed tree node (leafIndex<<2), then arbitrary nonempty payload.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/NativeArray.cs
void test("reads a sparse block and rejects indices outside the declared count", () => {
  const array = new NativeArrayReader(Uint8Array.of(16, 1, 16, 42));

  assert.equal(array.count, 2);
  assert.equal(array.at(0), null);
  assert.equal(array.at(1), null);
  assert.equal(array.at(-1), null);
  assert.equal(array.at(2), null);
  assert.equal(array.at(NaN), null);
});

void test("reads the special leaf at a matching index", () => {
  const array = new NativeArrayReader(Uint8Array.of(16, 1, 8, 42));

  assert.equal(array.at(1), 3);
});

void test("rejects truncated headers, indices, nodes and payload offsets", () => {
  assert.throws(() => new NativeArrayReader(new Uint8Array()), /outside/);
  assert.throws(() => new NativeArrayReader(Uint8Array.of(16)), /index.*truncated/);
  assert.throws(() => new NativeArrayReader(Uint8Array.of(8, 100)).at(0), /outside/);
  assert.throws(() => new NativeArrayReader(Uint8Array.of(8, 1, 0)).at(0), /outside/);
});

void test("walks left and right branches and caches shared nodes", context => {
  const array = new NativeArrayReader(Uint8Array.of(16, 1, 2, 2, 2, 22, 42, 99));
  const reads = context.mock.method(NativeFormatReader.prototype, "unsigned");

  assert.equal(array.at(0), 6);
  assert.equal(array.at(1), 7);
  assert.equal(array.at(0), 6);
  assert.equal(reads.mock.calls.length, 4);
});

void test("does not treat a missing right branch as a matching special leaf", () => {
  const array = new NativeArrayReader(Uint8Array.of(72, 1, 2, 0, 42));

  assert.equal(array.at(8), null);
});

for (const [header, width] of [[10, 2], [12, 4], [14, 4]] as const) {
  void test(`decodes index width ${width} from NativeArray header ${header}`, () => {
    const array = new NativeArrayReader(createNativeArrayWideIndexFixture(header, width));

    assert.equal(array.at(0), 258);
  });
}

void test("caches node decoding failures within the array", context => {
  const array = new NativeArrayReader(Uint8Array.of(16, 1, 0xff));
  const reads = context.mock.method(NativeFormatReader.prototype, "unsigned");

  assert.throws(() => array.at(0), /compressed/);
  assert.throws(() => array.at(1), /compressed/);
  assert.equal(reads.mock.calls.length, 1);
});

void test("indexes later blocks with their actual two- and four-byte widths", () => {
  const twoByte = new NativeArrayReader(createNativeArrayTwoBlockFixture(2));
  const fourByte = new NativeArrayReader(createNativeArrayTwoBlockFixture(4));

  assert.equal(twoByte.at(16), 262);
  assert.equal(fourByte.at(16), 70002);
  assert.throws(() => new NativeArrayReader(Uint8Array.of(138, 0, 0, 0)), /index.*truncated/);
  assert.throws(() => new NativeArrayReader(Uint8Array.of(140, 0, 0, 0, 0, 0, 0, 0)),
    /index.*truncated/);
  assert.equal(new NativeArrayReader(Uint8Array.of(8, 1, 4, 42)).at(0), null);
});
