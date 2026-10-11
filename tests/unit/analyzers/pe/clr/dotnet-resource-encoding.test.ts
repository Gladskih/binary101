"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readSevenBitEncodedInt, readBinaryString, readUtf16Name
} from "../../../../../analyzers/pe/clr/dotnet-resource-encoding.js";

void test("seven-bit integers accept the full signed Int32 range", () => {
  const negative = readSevenBitEncodedInt(Uint8Array.of(255, 255, 255, 255, 15), 0);
  const positive = readSevenBitEncodedInt(Uint8Array.of(255, 255, 255, 255, 7), 0);

  assert.deepStrictEqual(negative, { value: -1, next: 5 });
  assert.deepStrictEqual(positive, { value: 2147483647, next: 5 });
});

const invalidIntegers = [
  { bytes: [128], offset: 0 },
  { bytes: [255, 255, 255, 255, 16], offset: 0 },
  { bytes: [128, 128, 128, 128, 128, 0], offset: 0 },
  { bytes: [1], offset: -1 },
  { bytes: [1], offset: 0.5 },
  { bytes: [1], offset: Number.MAX_SAFE_INTEGER }
];

for (const [index, item] of invalidIntegers.entries()) {
  void test(`invalid seven-bit integer ${index} is rejected`, () => {
    assert.strictEqual(readSevenBitEncodedInt(Uint8Array.from(item.bytes), item.offset), null);
  });
}

void test("binary strings decode empty and Unicode strings", () => {
  const unicode = new TextEncoder().encode("Привет");

  assert.deepStrictEqual(readBinaryString(Uint8Array.of(0), 0), { value: "", next: 1 });
  assert.deepStrictEqual(readBinaryString(Uint8Array.of(unicode.length, ...unicode), 0),
    { value: "Привет", next: unicode.length + 1 });
});

void test("embedded strings and resource names preserve a leading U+FEFF character", () => {
  assert.deepStrictEqual(readBinaryString(Uint8Array.of(4, 239, 187, 191, 65), 0),
    { value: "\uFEFFA", next: 5 });
  assert.deepStrictEqual(readUtf16Name(Uint8Array.of(4, 255, 254, 65, 0, 0, 0, 0, 0), 0, 9),
    { value: "\uFEFFA", dataOffsetPosition: 5 });
});

for (const bytes of [[128], [255, 255, 255, 255, 15], [2, 65], [1, 255]]) {
  void test(`invalid binary string ${bytes.join("-")} is rejected`, () => {
    assert.strictEqual(readBinaryString(Uint8Array.from(bytes), 0), null);
  });
}

void test("UTF-16 names are bounded independently of the enclosing payload", () => {
  const bytes = Uint8Array.of(2, 65, 0, 0, 0, 0, 0, 1);

  assert.deepStrictEqual(readUtf16Name(bytes, 0, 7), { value: "A", dataOffsetPosition: 3 });
  assert.strictEqual(readUtf16Name(bytes, 0, 6), null);
  assert.strictEqual(readUtf16Name(bytes, 0, bytes.length + 1), null);
  assert.strictEqual(readUtf16Name(bytes, 0, -1), null);
});

void test("UTF-16 names reject invalid surrogate pairs and odd byte counts", () => {
  // D800 is an unpaired high surrogate.
  assert.strictEqual(readUtf16Name(Uint8Array.of(2, 0, 216, 0, 0, 0, 0), 0, 7), null);
  assert.strictEqual(readUtf16Name(Uint8Array.of(1, 65, 0, 0, 0, 0), 0, 6), null);
});
