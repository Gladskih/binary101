import { nativeFormatFixtureKinds as kinds, nativeFormatIntegerBytes, nativeFormatShortUnsigned,
  nativeFormatSampleInteger } from "../../../helpers/native-format-wire-fixture.js";
import assert from "node:assert/strict";
import test from "node:test";
import { readNativeFormatConstantNode as read } from "../../../../analyzers/native-aot/native-format-constant-nodes.js";
import { nativeFormatConstantFixture as fixture, nativeFormatWideBytes, nativeFormatFloatBytes,
  createNativeFormatDependentConstantFixture } from
  "../../../helpers/native-format-constant-fixture.js";

// Integral boundary values follow the CLR primitive widths: unsigned max = 2^N - 1,
// signed min = -2^(N-1). Negative short values use DecodeSigned's sign-extended form.
// https://ecma-international.org/publications-and-standards/standards/ecma-335/ (I.12.1.2)
// Int64/UInt64 wire payloads follow NativePrimitiveDecoder.DecodeUnsignedLong;
// 2^53+1 specifically checks that values beyond JS's exact integer range stay strings.
for (const [kind, type, bytes, expected] of [
  [kinds.boolean, "bool", [2], true], // Noncanonical true: any nonzero byte is true.
  [kinds.byte, "byte", [2 ** 8 - 1], 2 ** 8 - 1],
  [kinds.char, "char", nativeFormatIntegerBytes("a".charCodeAt(0)), "a"],
  [kinds.double, "double", nativeFormatFloatBytes(Math.PI, Float64Array.BYTES_PER_ELEMENT), Math.PI],
  [kinds.int16, "short", nativeFormatIntegerBytes(-1), -1],
  [kinds.int32, "int", nativeFormatIntegerBytes(nativeFormatSampleInteger), nativeFormatSampleInteger],
  [kinds.int64, "long", nativeFormatWideBytes(-(2n ** 63n)), String(-(2n ** 63n))],
  [kinds.sbyte, "sbyte", [2 ** 7], -(2 ** 7)],
  [kinds.single, "float", nativeFormatFloatBytes(-0, Float32Array.BYTES_PER_ELEMENT), -0],
  [kinds.uint16, "ushort", nativeFormatIntegerBytes(2 ** 16 - 1), 2 ** 16 - 1],
  [kinds.uint32, "uint", nativeFormatIntegerBytes(2 ** 32 - 1), 2 ** 32 - 1],
  [kinds.uint64, "ulong", nativeFormatWideBytes(2n ** 64n - 1n), String(2n ** 64n - 1n)]
] as const) {
  void test(`constant kind ${kind} retains its ${type} value`, () => {
    const data = fixture(kind, [...bytes]);
    const node = read(data.store, data.signatures, data.handle);

    assert.deepEqual(node.dependencies, []);
    assert.deepEqual(node.format([]), { type, value: expected });
    assert.equal(data.warnings.size, 0);
  });
}

for (const [kind, type, bytes, expected] of [
  [kinds.booleanArray, "bool", [1], true],
  [kinds.byteArray, "byte", [2 ** 8 - 1], 2 ** 8 - 1],
  [kinds.charArray, "char", nativeFormatIntegerBytes("a".charCodeAt(0)), "a"],
  [kinds.doubleArray, "double", nativeFormatFloatBytes(Infinity, Float64Array.BYTES_PER_ELEMENT), Infinity],
  [kinds.int16Array, "short", nativeFormatIntegerBytes(-1), -1],
  [kinds.int32Array, "int", nativeFormatIntegerBytes(nativeFormatSampleInteger), nativeFormatSampleInteger],
  [kinds.int64Array, "long", nativeFormatWideBytes(2n ** 53n + 1n), String(2n ** 53n + 1n)],
  [kinds.sbyteArray, "sbyte", [2 ** 8 - 1], -1],
  [kinds.singleArray, "float", nativeFormatFloatBytes(NaN, Float32Array.BYTES_PER_ELEMENT), NaN],
  [kinds.uint16Array, "ushort", nativeFormatIntegerBytes(nativeFormatSampleInteger), nativeFormatSampleInteger],
  [kinds.uint32Array, "uint", nativeFormatIntegerBytes(nativeFormatSampleInteger), nativeFormatSampleInteger],
  [kinds.uint64Array, "ulong", nativeFormatWideBytes(2n ** 64n - 1n), String(2n ** 64n - 1n)]
] as const) {
  void test(`constant array kind ${kind} retains typed ${type} elements`, () => {
    const data = fixture(kind, [nativeFormatShortUnsigned(1), ...bytes]);

    assert.deepEqual(read(data.store, data.signatures, data.handle).format([]),
      { type: `${type}[]`, value: [{ type, value: expected }] });
    assert.equal(data.warnings.size, 0);
  });
}

void test("reference and string constants retain null, empty text and UTF-8", () => {
  const nullData = fixture(kinds.reference, []);
  const encoded = new TextEncoder().encode("é");
  const text = fixture(kinds.string, [...nativeFormatIntegerBytes(encoded.length), ...encoded]);

  assert.deepEqual(read(nullData.store, nullData.signatures, nullData.handle).format([]), { type: "object", value: null });
  assert.deepEqual(read(text.store, text.signatures, text.handle).format([]), { type: "string", value: "é" });
  assert.deepEqual(fixture(kinds.string, [0]).constants.value({ type: kinds.string, offset: 1 }), { type: "string", value: "" });
});

void test("narrow integer constants reject out-of-range encodings and truncated payloads", () => {
  const character = fixture(kinds.char, nativeFormatIntegerBytes(2 ** 16));
  const short = fixture(kinds.int16, nativeFormatIntegerBytes(2 ** 15));
  const truncated = fixture(kinds.double, [0]);
  const unsupported = fixture(kinds.byReference, [0]);

  assert.throws(() => read(character.store, character.signatures, character.handle), /exceeds/);
  assert.throws(() => read(short.store, short.signatures, short.handle), /exceeds/);
  assert.throws(() => read(truncated.store, truncated.signatures, truncated.handle), /outside/);
  assert.throws(() => read(unsupported.store, unsupported.signatures, unsupported.handle), /Unsupported/);
});
void test("truncated floating arrays retain complete elements and warn about the unreadable suffix", () => {
  // Declares two Float64 elements but supplies only one complete value and one byte.
  const data = fixture(kinds.doubleArray, [nativeFormatShortUnsigned(2),
    ...nativeFormatFloatBytes(1.5, Float64Array.BYTES_PER_ELEMENT), 0]);

  assert.deepEqual(data.constants.value(data.handle), { type: "double[]", value: [{ type: "double", value: 1.5 }] });
  assert.match([...data.warnings].join(" "), /outside/);
});

void test("string arrays reject non-string payload kinds instead of mislabelling numeric values", () => {
  const data = createNativeFormatDependentConstantFixture(kinds.stringArray, kinds.int32,
    nativeFormatIntegerBytes(nativeFormatSampleInteger));

  assert.throws(() => read(data.store, data.signatures, data.handle), /non-string/);
});
void test("enum constants reject non-integral payloads and propagate damaged underlying values", () => {
  const boolean = createNativeFormatDependentConstantFixture(kinds.enum, kinds.boolean, [1]);
  const damaged = createNativeFormatDependentConstantFixture(kinds.enum, kinds.double, [1]);

  assert.equal(boolean.constants.value(boolean.handle).type, "<invalid>");
  assert.match([...boolean.warnings].join(" "), /non-integral/);
  assert.equal(damaged.constants.value(damaged.handle).type, "<invalid>");
  assert.match([...damaged.warnings].join(" "), /outside/);
});

for (const expected of [-(2 ** 15), 2 ** 15 - 1]) {
  void test(`Int16 constant accepts boundary ${expected}`, () => {
    // NativePrimitiveDecoder signed long form: low 4 prefix bits, then a signed Int32 payload.
    const data = fixture(kinds.int16, nativeFormatIntegerBytes(expected));

    assert.deepEqual(data.constants.value(data.handle), { type: "short", value: expected });
    assert.equal(data.warnings.size, 0);
  });
}

void test("signed bytes keep positive values below the sign bit and booleans accept any nonzero byte", () => {
  const positive = fixture(kinds.sbyte, [2 ** 7 - 1]);
  const boolean = fixture(kinds.boolean, [2]);

  assert.deepEqual(positive.constants.value(positive.handle), { type: "sbyte", value: 2 ** 7 - 1 });
  assert.deepEqual(boolean.constants.value(boolean.handle), { type: "bool", value: true });
});
