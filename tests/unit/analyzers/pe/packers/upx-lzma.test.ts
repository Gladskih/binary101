"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { upxAdler32 } from "../../../../../analyzers/pe/packers/upx-adler32.js";
import { decompressUpxLzma } from "../../../../../analyzers/pe/packers/upx-lzma.js";

const UNPACKED_BYTES = 24_955;
const UNPACKED_ADLER32 = 4_254_996_567;
const PACKED = Uint8Array.from(Buffer.from(
  "GgMAKqJYpQZrW5qaYo4ncMUJMo9sZrUxVukK6/uMHUfOOlCgtiYH5eVhnvPXUqcgSsrSXGW98E1E" +
  "75mGL0CRZW3NPdOoWONXUdUOMJ4JsAW31JubS8jsG2HJ/pqTqLtmuVM+UKA5ARlOsH3Ia5yu7pUt" +
  "I632uxdapEgcLCuCZMjnvsmF7u5Ge5OBNJq7fG6uEgJmdRs7o3RfucdplgaVretLwnH2TgDbhzLu" +
  "AGWBBW7rTkpcSzvjV8S0rNedZedKAD+F1PP144NwkM54edjWps4ksAA=",
  "base64"
));

void test("decompressUpxLzma decodes UPX two-byte LZMA properties", async () => {
  const unpacked = await decompressUpxLzma(PACKED, UNPACKED_BYTES, 9);

  assert.equal(unpacked.byteLength, UNPACKED_BYTES);
  assert.equal(upxAdler32(unpacked), UNPACKED_ADLER32);
});

void test("decompressUpxLzma rejects invalid redundant properties", async () => {
  const packed = PACKED.slice();
  packed[0] = (packed[0] ?? 0) ^ 8;

  await assert.rejects(decompressUpxLzma(packed, UNPACKED_BYTES, 9), /redundancy/);
});

void test("decompressUpxLzma rejects truncated streams", async () => {
  await assert.rejects(decompressUpxLzma(PACKED.subarray(0, 2), UNPACKED_BYTES, 9), /truncated/);
});

for (const firstTwoBytes of [[7, 3], [0x1a, 0x50], [0x48, 9]] as const) {
  void test(`decompressUpxLzma rejects invalid properties ${firstTwoBytes.join(",")}`, async () => {
    const packed = PACKED.slice();
    packed.set(firstTwoBytes);

    await assert.rejects(decompressUpxLzma(packed, UNPACKED_BYTES, 9), /properties are invalid/);
  });
}

for (const level of [1, 5, 10]) {
  void test(`decompressUpxLzma reconstructs the level ${level} dictionary`, async () => {
    assert.equal((await decompressUpxLzma(PACKED, UNPACKED_BYTES, level)).byteLength, UNPACKED_BYTES);
  });
}

void test("decompressUpxLzma rejects dictionaries beyond the browser decoder limit", async () => {
  await assert.rejects(decompressUpxLzma(PACKED, 100_000_000, 10), /browser decoder limit/);
});

void test("decompressUpxLzma rejects unconsumed trailing input", async () => {
  const packed = new Uint8Array(PACKED.byteLength + 1);
  packed.set(PACKED);

  await assert.rejects(decompressUpxLzma(packed, UNPACKED_BYTES, 9), /unconsumed/);
});

void test("decompressUpxLzma rejects mismatched output sizes", async () => {
  await assert.rejects(
    decompressUpxLzma(PACKED.subarray(0, PACKED.byteLength - 2), UNPACKED_BYTES, 9),
    /output size/
  );
});
