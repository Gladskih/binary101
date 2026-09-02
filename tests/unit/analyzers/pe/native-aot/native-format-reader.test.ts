"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  NativeFormatError,
  NativeFormatReader
} from "../../../../../analyzers/pe/native-aot/native-format-reader.js";

void test("NativeFormatReader decodes all unsigned integer widths", () => {
  // NativePrimitiveDecoder.DecodeUnsigned in dotnet/runtime defines these five encodings.
  const reader = new NativeFormatReader(Uint8Array.from([
    0x02,
    0x8d, 0x04,
    0x2b, 0x1a, 0x09,
    0x77, 0x56, 0x34, 0x12,
    0x0f, 0x78, 0x56, 0x34, 0x12
  ]));

  assert.deepEqual(reader.unsigned(0), { nextOffset: 1, value: 1 });
  assert.deepEqual(reader.unsigned(1), { nextOffset: 3, value: 0x123 });
  assert.deepEqual(reader.unsigned(3), { nextOffset: 6, value: 0x12345 });
  assert.deepEqual(reader.unsigned(6), { nextOffset: 10, value: 0x1234567 });
  assert.deepEqual(reader.unsigned(10), { nextOffset: 15, value: 0x12345678 });
});

void test("NativeFormatReader distinguishes typed and polymorphic handles", () => {
  // Typed handles encode only their offset; polymorphic Handle encodes type in the low seven bits.
  const bytes = new Uint8Array(16);
  bytes.set([0x0a, 0xbd, 0x14], 0);
  const reader = new NativeFormatReader(bytes);

  assert.deepEqual(reader.handle(0, [0x2f]).value, { type: 0x2f, offset: 5 });
  assert.deepEqual(reader.handle(1, [0x2f, 0x38]).value, { type: 0x2f, offset: 10 });
  assert.throws(() => reader.handle(1, [0x38, 0x3a]), NativeFormatError);
  assert.throws(() => reader.handle(1, [0x38, 0x3a]), /Unexpected handle type 47/);
});

void test("NativeFormatReader bounds-checks integers, collections, handles, and UTF-8", () => {
  const invalidInteger = new NativeFormatReader(Uint8Array.of(0x1f));
  const truncatedInteger = new NativeFormatReader(Uint8Array.of(0x01));
  const outsideHandle = new NativeFormatReader(Uint8Array.of(0x20));
  const invalidString = new NativeFormatReader(Uint8Array.of(0, 0x02, 0xff));

  assert.throws(() => invalidInteger.unsigned(0), /compressed integer/i);
  assert.throws(() => truncatedInteger.unsigned(0), /range/i);
  assert.throws(() => outsideHandle.handle(0, [0x2f]), /outside/i);
  assert.throws(() => invalidString.string({ type: 0x1a, offset: 1 }), /UTF-8/i);
  assert.throws(() => outsideHandle.handles(0, [0x2f], 1), /safety limit/i);
  assert.throws(() => outsideHandle.bytes(0, 1), /safety limit/i);
});

void test("NativeFormatReader reads bounded primitive and collection values", () => {
  const reader = new NativeFormatReader(Uint8Array.from([
    0x78, 0x56, 0x34, 0x12,
    0x02, 0x0c,
    0x04, 0xaa, 0xbb
  ]));

  assert.equal(reader.size, 9);
  assert.equal(reader.uint32(0), 0x12345678);
  assert.deepEqual(reader.handles(4, [0x2f], 1), {
    nextOffset: 6,
    value: [{ type: 0x2f, offset: 6 }]
  });
  assert.deepEqual(reader.bytes(6, 2), {
    nextOffset: 9,
    value: Uint8Array.of(0xaa, 0xbb)
  });
});

void test("NativeFormatReader handles boundaries, nil values, and invalid ranges", () => {
  const equalBoundaryHandle = new NativeFormatReader(Uint8Array.of(0x04, 0));
  const nilReader = new NativeFormatReader(Uint8Array.of(0x02, 0x41));
  const truncatedBytes = new NativeFormatReader(Uint8Array.of(0x04, 0xaa));

  assert.throws(() => equalBoundaryHandle.handle(0, [0x2f]), /outside/i);
  assert.deepEqual(new NativeFormatReader(Uint8Array.of(0)).handles(0, [0x2f], 0), {
    nextOffset: 1,
    value: []
  });
  assert.deepEqual(new NativeFormatReader(Uint8Array.of(0x02, 0)).handles(0, [0x2f], 1), {
    nextOffset: 2,
    value: []
  });
  assert.equal(nilReader.string({ type: 0x1a, offset: 0 }), "");
  assert.throws(() => truncatedBytes.bytes(0, 2), /range/i);
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
