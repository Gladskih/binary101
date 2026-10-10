"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  NativeFormatError,
  NativeFormatReader
} from "../../../../analyzers/native-aot/native-format-reader.js";

// Generated HandleType values, independently mirrored from the runtime reader headers.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
const handleType = {
  constantString: 0x1a, fieldDefinition: 0x23, methodDefinition: 0x28,
  namespaceDefinition: 0x2f, scopeDefinition: 0x38, typeDefinition: 0x3a, typeReference: 0x3d
} as const;

void test("NativeFormatReader sign-extends each compressed width and respects view offsets", () => {
  // DecodeSigned sign-extends the final byte at each width; the leading zero is view padding.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.Primitives.cs
  const reader = new NativeFormatReader(Uint8Array.of(0,
    0xfe, // one-byte signed -1
    0xfd, 0xff, // two-byte signed -1
    0xfb, 0xff, 0xff, // three-byte signed -1
    0xf7, 0xff, 0xff, 0xff, // four-byte signed -1
    0x0f, 0xff, 0xff, 0xff, 0xff, // five-byte signed -1
    0x0f, 0, 0, 0, 0x80).subarray(1)); // five-byte Int32.MinValue

  assert.deepEqual(reader.signed(0), { value: -1, nextOffset: 1 });
  assert.deepEqual(reader.signed(1), { value: -1, nextOffset: 3 });
  assert.deepEqual(reader.signed(3), { value: -1, nextOffset: 6 });
  assert.deepEqual(reader.signed(6), { value: -1, nextOffset: 10 });
  assert.deepEqual(reader.signed(10), { value: -1, nextOffset: 15 });
  assert.deepEqual(reader.signed(15), { value: -2147483648, nextOffset: 20 });
  assert.deepEqual(reader.uint8(0), { value: 254, nextOffset: 1 });
  assert.throws(() => reader.uint8(reader.size), /range/i);
  assert.throws(() => reader.uint8(reader.size), NativeFormatError);
  assert.throws(() => reader.uint8(0.5), NativeFormatError);
  assert.throws(() => reader.uint8(Number.NaN), NativeFormatError);
  assert.throws(() => reader.signed(reader.size), /range/i);
});

void test("NativeFormatReader decodes all unsigned integer widths", () => {
  // DecodeUnsigned: low tag bits select widths 1-5; payloads below decode to the assertions below.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.Primitives.cs
  const reader = new NativeFormatReader(Uint8Array.from([
    0x02, // 1 byte: 1
    0x8d, 0x04, // 2 bytes: 0x123
    0x2b, 0x1a, 0x09, // 3 bytes: 0x12345
    0x77, 0x56, 0x34, 0x12, // 4 bytes: 0x1234567
    0x0f, 0x78, 0x56, 0x34, 0x12 // 5 bytes: 0x12345678
  ]));

  assert.deepEqual(reader.unsigned(0), { nextOffset: 1, value: 1 });
  assert.deepEqual(reader.unsigned(1), { nextOffset: 3, value: 0x123 });
  assert.deepEqual(reader.unsigned(3), { nextOffset: 6, value: 0x12345 });
  assert.deepEqual(reader.unsigned(6), { nextOffset: 10, value: 0x1234567 });
  assert.deepEqual(reader.unsigned(10), { nextOffset: 15, value: 0x12345678 });
});

void test("NativeFormatReader distinguishes typed and polymorphic handles", () => {
  // 0x0a encodes a typed offset 5; 0xbd,0x14 encodes polymorphic (offset 10, type 0x2f).
  // MdBinaryReader uses seven low tag bits in .NET 10.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/MdBinaryReader.cs
  const bytes = new Uint8Array(16);
  bytes.set([0x0a, 0xbd, 0x14], 0);
  const reader = new NativeFormatReader(bytes);

  assert.deepEqual(reader.handle(0, [handleType.namespaceDefinition]).value,
    { type: handleType.namespaceDefinition, offset: 5 });
  assert.deepEqual(reader.handle(1, [handleType.namespaceDefinition, handleType.scopeDefinition]).value,
    { type: handleType.namespaceDefinition, offset: 10 });
  assert.throws(() => reader.handle(1, [handleType.scopeDefinition, handleType.typeDefinition]), NativeFormatError);
  assert.throws(() => reader.handle(1, [handleType.scopeDefinition, handleType.typeDefinition]),
    new RegExp(`Unexpected handle type ${handleType.namespaceDefinition}`));
});

void test("NativeFormatReader separates typed-handle tag bits from its record offset", () => {
  // TypeDefinitionHandle(int): (0x3a << 25) | 7 means type-definition tag 0x3a, offset 7.
  // The five-byte unsigned prefix 0x0f is followed by the little-endian token bytes.
  const bytes = new Uint8Array(16);
  bytes.set([0x0f, 7, 0, 0, 0x74]); // (0x3a << 25) | 7, encoded with DecodeUnsigned.
  const reader = new NativeFormatReader(bytes);

  assert.deepEqual(reader.handle(0, [handleType.typeDefinition]), {
    nextOffset: 5, value: { type: handleType.typeDefinition, offset: 7 }
  });
  assert.throws(() => reader.handle(0, [handleType.namespaceDefinition]),
    new RegExp(`Unexpected typed handle type ${handleType.typeDefinition}`));
});

void test("NativeFormatReader bounds-checks integers, collections, handles, and UTF-8", () => {
  const invalidInteger = new NativeFormatReader(Uint8Array.of(0x1f)); // Reserved invalid compressed-int tag.
  const truncatedInteger = new NativeFormatReader(Uint8Array.of(0x01)); // Two-byte form, second byte absent.
  const outsideHandle = new NativeFormatReader(Uint8Array.of(0x20)); // Typed offset 16 in one byte of data.
  const invalidString = new NativeFormatReader(Uint8Array.of(0, 0x02, 0xff)); // Length 1, invalid UTF-8.

  assert.throws(() => invalidInteger.unsigned(0), /compressed integer/i);
  assert.throws(() => truncatedInteger.unsigned(0), /range/i);
  assert.throws(() => outsideHandle.handle(0, [handleType.namespaceDefinition]), /outside/i);
  assert.throws(() => invalidString.string({ type: handleType.constantString, offset: 1 }), /UTF-8/i);
  assert.throws(() => outsideHandle.handles(0, [handleType.namespaceDefinition]), /range/i);
  assert.throws(() => outsideHandle.bytes(0), /range/i);
});

void test("NativeFormatReader reads bounded primitive and collection values", () => {
  const reader = new NativeFormatReader(Uint8Array.from([
    0x78, 0x56, 0x34, 0x12,
    0x02, 0x0c, // One handle at typed offset 6.
    0x04, 0xaa, 0xbb // Byte blob length 2, followed by its contents.
  ]));

  assert.equal(reader.size, 9);
  assert.equal(reader.uint32(0), 0x12345678);
  assert.deepEqual(reader.handles(4, [handleType.namespaceDefinition]), {
    nextOffset: 6,
    value: [{ type: handleType.namespaceDefinition, offset: 6 }]
  });
  assert.deepEqual(reader.bytes(6), {
    nextOffset: 9,
    value: Uint8Array.of(0xaa, 0xbb)
  });
});

void test("NativeFormatReader handles boundaries, nil values, and invalid ranges", () => {
  const equalBoundaryHandle = new NativeFormatReader(Uint8Array.of(0x04, 0)); // Typed offset == size (2).
  const nilReader = new NativeFormatReader(Uint8Array.of(0x02, 0x41)); // String handle offset zero is nil.
  const truncatedBytes = new NativeFormatReader(Uint8Array.of(0x04, 0xaa)); // Length 2, only one byte follows.

  assert.throws(() => equalBoundaryHandle.handle(0, [handleType.namespaceDefinition]), /outside/i);
  assert.deepEqual(new NativeFormatReader(Uint8Array.of(0)).handles(0, [handleType.namespaceDefinition]), {
    nextOffset: 1,
    value: []
  });
  assert.deepEqual(new NativeFormatReader(Uint8Array.of(0x02, 0)).handles(0, [handleType.namespaceDefinition]), {
    nextOffset: 2,
    value: []
  });
  assert.equal(nilReader.string({ type: handleType.constantString, offset: 0 }), "");
  assert.throws(() => truncatedBytes.bytes(0), /range/i);
  assert.throws(() => nilReader.uint32(0), NativeFormatError);
  assert.throws(() => nilReader.unsigned(-1), /range/i);
  assert.throws(() => nilReader.unsigned(Number.NaN), /range/i);
});

void test("NativeFormatReader rejects every truncated compressed integer width", () => {
  const truncatedThreeByte = new NativeFormatReader(Uint8Array.of(0x03, 0));
  const truncatedFourByte = new NativeFormatReader(Uint8Array.of(0x07, 0, 0));

  assert.throws(() => truncatedThreeByte.unsigned(0), NativeFormatError);
  assert.throws(() => truncatedFourByte.unsigned(0), NativeFormatError);
});

void test("NativeFormatReader rejects impossible counts before inspecting any handle", context => {
  // Five-byte form carries the full UInt32 after the 0x0f prefix; this count exceeds remaining bytes.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.Primitives.cs
  const reader = new NativeFormatReader(Uint8Array.from([0x0f, 0xff, 0xff, 0xff, 0xff, 0]));
  const handleReads = context.mock.method(reader, "handle");

  assert.throws(() => reader.handles(0, [handleType.fieldDefinition]), /outside the metadata/);
  assert.equal(handleReads.mock.callCount(), 0);
});

void test("NativeFormatReader derives the collection bound from actual remaining bytes", () => {
  const reader = new NativeFormatReader(Uint8Array.from([4, 0, 0]));

  assert.deepEqual(reader.collectionCount(0), { value: 2, nextOffset: 1 });
  assert.deepEqual(reader.handles(0, [handleType.fieldDefinition]), { value: [], nextOffset: 3 });
  assert.throws(() => new NativeFormatReader(Uint8Array.from([6, 0, 0])).collectionCount(0), /range/i);
});

void test("NativeFormatReader measures string extents in UTF-8 bytes", () => {
  const encoded = new TextEncoder().encode("é🙂");
  // UTF-8 text is 6 bytes; its one-byte NativeFormat length value 6 is stored as 6 << 1.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.Primitives.cs
  const bytes = Uint8Array.from([0, encoded.length << 1, ...encoded]);
  const reader = new NativeFormatReader(bytes);

  assert.deepEqual(reader.bytes(1).value, encoded);
  assert.equal(reader.string({ type: handleType.constantString, offset: 1 }), "é🙂");
  assert.throws(() => new NativeFormatReader(bytes.subarray(0, -1))
    .string({ type: handleType.constantString, offset: 1 }), /outside the metadata/);
});

void test("NativeFormatReader reuses shared strings and UTF-8 failures", context => {
  const reader = new NativeFormatReader(Uint8Array.from([0, 2, 65, 2, 0xff]));
  const decode = context.mock.method(TextDecoder.prototype, "decode");

  assert.equal(reader.string({ type: handleType.constantString, offset: 1 }), "A");
  assert.equal(reader.string({ type: handleType.constantString, offset: 1 }), "A");
  assert.throws(() => reader.string({ type: handleType.constantString, offset: 3 }), /UTF-8/i);
  assert.throws(() => reader.string({ type: handleType.constantString, offset: 3 }), /UTF-8/i);
  assert.equal(decode.mock.callCount(), 2);
});

void test("NativeFormatReader caches empty strings and bounds failures", context => {
  const reader = new NativeFormatReader(Uint8Array.from([0, 0, 4]));
  const reads = context.mock.method(reader, "bytes");

  assert.equal(reader.string({ type: handleType.constantString, offset: 1 }), "");
  assert.equal(reader.string({ type: handleType.constantString, offset: 1 }), "");
  assert.throws(() => reader.string({ type: handleType.constantString, offset: 2 }), /outside the metadata/);
  assert.throws(() => reader.string({ type: handleType.constantString, offset: 2 }), /outside the metadata/);
  assert.equal(reads.mock.callCount(), 2);
});
void test("64-bit integers accept short forms and reject invalid or truncated wide prefixes", () => {
  const reader = new NativeFormatReader(Uint8Array.of(254, 84, 63, 31));

  assert.deepEqual(reader.signed64(0), { value: "-1", nextOffset: 1 });
  assert.deepEqual(reader.unsigned64(0), { value: "127", nextOffset: 1 });
  assert.deepEqual(reader.signed64(1), { value: "42", nextOffset: 2 });
  assert.throws(() => reader.unsigned64(2), /Invalid compressed 64-bit/);
  assert.throws(() => reader.signed64(2), /Invalid compressed 64-bit/);
  assert.throws(() => reader.unsigned64(3), /outside/);
  assert.throws(() => reader.signed64(3), /outside/);
  assert.throws(() => reader.float32(1), /outside/);
  assert.throws(() => reader.float64(0), /outside/);
});
void test("metadata handles select the .NET 9 or .NET 10 wire layout explicitly", () => {
  // MdBinaryReader: .NET 9 generic handle = (offset << 8) | kind; .NET 10 uses 7 tag bits.
  // https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/MdBinaryReader.cs
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/MdBinaryReader.cs
  const legacy = new NativeFormatReader(Uint8Array.of(15, 61, 1, 0, 0, 0, 0, 0), "dotnet9");
  const modern = new NativeFormatReader(Uint8Array.of(15, 61, 1, 0, 0, 0, 0, 0), "dotnet10");
  // Generated .NET 9 typed handle: (ConstantString handle type 0x1a << 24) | offset 8.
  // https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs
  const tagged = new NativeFormatReader(Uint8Array.of(15, 8, 0, 0, 26, 0, 0, 0, 0), "dotnet9");

  assert.deepEqual(legacy.handle(0, [handleType.typeDefinition, handleType.typeReference]).value,
    { type: handleType.typeReference, offset: 1 });
  assert.deepEqual(modern.handle(0, [handleType.typeDefinition, handleType.typeReference]).value,
    { type: handleType.typeReference, offset: 2 });
  assert.deepEqual(tagged.handle(0, [handleType.constantString]).value,
    { type: handleType.constantString, offset: 8 });
  assert.throws(() => tagged.handle(0, [handleType.methodDefinition]), /Unexpected typed/);
});
