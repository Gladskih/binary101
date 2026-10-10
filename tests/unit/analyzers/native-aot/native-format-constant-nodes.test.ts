import assert from "node:assert/strict";
import test from "node:test";
import { readNativeFormatConstantNode as read } from "../../../../analyzers/native-aot/native-format-constant-nodes.js";
import { nativeFormatConstantFixture as fixture, nativeFormatWideBytes, nativeFormatFloatBytes } from
  "../../../helpers/native-format-constant-fixture.js";

// HandleType IDs and payloads come from NativeFormatReaderGen.cs, not the production schema.
for (const [kind, type, bytes, expected] of [
  [0x04, "bool", [2], true], [0x06, "byte", [255], 255], [0x08, "char", [194], "a"],
  [0x0a, "double", nativeFormatFloatBytes(Math.PI, 8), Math.PI], [0x0f, "short", [254], -1],
  [0x11, "int", [84], 42], [0x13, "long", nativeFormatWideBytes(-9223372036854775808n), "-9223372036854775808"],
  [0x16, "sbyte", [128], -128], [0x18, "float", nativeFormatFloatBytes(-0, 4), -0],
  [0x1c, "ushort", [0x0f, 255, 255, 0, 0], 65535], [0x1e, "uint", [0x0f, 255, 255, 255, 255], 4294967295],
  [0x20, "ulong", nativeFormatWideBytes(18446744073709551615n), "18446744073709551615"]
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
  [0x03, "bool", [1], true], [0x05, "byte", [255], 255], [0x07, "char", [194], "a"],
  [0x09, "double", nativeFormatFloatBytes(Infinity, 8), Infinity], [0x0e, "short", [254], -1],
  [0x10, "int", [84], 42], [0x12, "long", nativeFormatWideBytes(9007199254740993n), "9007199254740993"],
  [0x15, "sbyte", [255], -1], [0x17, "float", nativeFormatFloatBytes(NaN, 4), NaN],
  [0x1b, "ushort", [84], 42], [0x1d, "uint", [84], 42],
  [0x1f, "ulong", nativeFormatWideBytes(18446744073709551615n), "18446744073709551615"]
] as const) {
  void test(`constant array kind ${kind} retains typed ${type} elements`, () => {
    const data = fixture(kind, [2, ...bytes]);

    assert.deepEqual(read(data.store, data.signatures, data.handle).format([]),
      { type: `${type}[]`, value: [{ type, value: expected }] });
    assert.equal(data.warnings.size, 0);
  });
}

void test("reference and string constants retain null, empty text and UTF-8", () => {
  const nullData = fixture(0x14, []);
  const text = fixture(0x1a, [4, 195, 169]);

  assert.deepEqual(read(nullData.store, nullData.signatures, nullData.handle).format([]), { type: "object", value: null });
  assert.deepEqual(read(text.store, text.signatures, text.handle).format([]), { type: "string", value: "é" });
  assert.deepEqual(fixture(0x1a, [0]).constants.value({ type: 0x1a, offset: 1 }), { type: "string", value: "" });
});

void test("narrow integer constants reject out-of-range encodings and truncated payloads", () => {
  const character = fixture(0x08, [0x0f, 0, 0, 1, 0]);
  const short = fixture(0x0f, [0x0f, 0, 128, 0, 0]);
  const truncated = fixture(0x0a, [0]);
  const unsupported = fixture(0x02, [0]);

  assert.throws(() => read(character.store, character.signatures, character.handle), /exceeds/);
  assert.throws(() => read(short.store, short.signatures, short.handle), /exceeds/);
  assert.throws(() => read(truncated.store, truncated.signatures, truncated.handle), /outside/);
  assert.throws(() => read(unsupported.store, unsupported.signatures, unsupported.handle), /Unsupported/);
});
void test("truncated floating arrays retain complete elements and warn about the unreadable suffix", () => {
  const data = fixture(0x09, [4, ...nativeFormatFloatBytes(1.5, 8), 0]);

  assert.deepEqual(data.constants.value(data.handle), { type: "double[]", value: [{ type: "double", value: 1.5 }] });
  assert.match([...data.warnings].join(" "), /outside/);
});

void test("string arrays reject non-string payload kinds instead of mislabelling numeric values", () => {
  // Generic Int32 handle at offset 7: (7 << 7) | 0x11.
  const data = fixture(0x19, [2, 15, 145, 3, 0, 0, 84]);

  assert.throws(() => read(data.store, data.signatures, data.handle), /non-string/);
});
void test("enum constants reject non-integral payloads and propagate damaged underlying values", () => {
  // EnumValue: value is a Boolean record at offset 8, followed by a nil enum type handle.
  const boolean = fixture(0x0c, [15, 4, 4, 0, 0, 0, 0, 1]);
  // EnumValue: value is a truncated Double record at offset 8.
  const damaged = fixture(0x0c, [15, 10, 4, 0, 0, 0, 0, 1]);

  assert.equal(boolean.constants.value(boolean.handle).type, "<invalid>");
  assert.match([...boolean.warnings].join(" "), /non-integral/);
  assert.equal(damaged.constants.value(damaged.handle).type, "<invalid>");
  assert.match([...damaged.warnings].join(" "), /outside/);
});

for (const [bytes, expected] of [[[0, 128, 255, 255], -32768], [[255, 127, 0, 0], 32767]] as const) {
  void test(`Int16 constant accepts boundary ${expected}`, () => {
    // NativePrimitiveDecoder signed long form: low 4 prefix bits, then a signed Int32 payload.
    const data = fixture(0x0f, [15, ...bytes]);

    assert.deepEqual(data.constants.value(data.handle), { type: "short", value: expected });
    assert.equal(data.warnings.size, 0);
  });
}

void test("signed bytes keep positive values below the sign bit and booleans accept any nonzero byte", () => {
  const positive = fixture(0x16, [127]);
  const boolean = fixture(0x04, [2]);

  assert.deepEqual(positive.constants.value(positive.handle), { type: "sbyte", value: 127 });
  assert.deepEqual(boolean.constants.value(boolean.handle), { type: "bool", value: true });
});
