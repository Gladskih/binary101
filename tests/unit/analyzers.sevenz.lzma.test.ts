"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { SEVENZIP_LZMA_PROPERTY_BYTES } from "../../analyzers/sevenz/method-ids.js";
import { decompressLzmaWithProperties } from "../../analyzers/sevenz/lzma.js";

const DECODED_TEXT = "DATA";
const DECODED_TEXT_BYTES = BigInt(DECODED_TEXT.length);
const TOO_LARGE_UNPACK_SIZE = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
// 7z LZMA coder properties for lc=3, lp=0, pb=2 and a 64 KiB dictionary.
// https://www.7-zip.org/sdk.html
const LZMA_PROPERTIES = [0x5d, 0x00, 0x00, 0x01, 0x00];
const TRUNCATED_LZMA_PROPERTIES = LZMA_PROPERTIES.slice(0, SEVENZIP_LZMA_PROPERTY_BYTES - 1);
// Raw LZMA stream fixture that decodes to "DATA"; the lzma_alone wrapper is
// built from separate 7z properties by the production module under test.
const PACKED_DATA = Uint8Array.from([
  0x00, 0x22, 0x10, 0x46, 0xcd, 0x69, 0xa5, 0x3c, 0x7f, 0xff, 0xfa, 0x6f, 0xe0, 0x00
]);

void test("decompressLzmaWithProperties decodes raw 7z LZMA streams", async () => {
  const decoded = await decompressLzmaWithProperties(LZMA_PROPERTIES, PACKED_DATA, DECODED_TEXT_BYTES);

  assert.deepEqual(decoded, new TextEncoder().encode(DECODED_TEXT));
});

void test("decompressLzmaWithProperties rejects invalid property sizes", async () => {
  await assert.rejects(
    decompressLzmaWithProperties(TRUNCATED_LZMA_PROPERTIES, PACKED_DATA, DECODED_TEXT_BYTES),
    /properties must be exactly 5 bytes/
  );
});

void test("decompressLzmaWithProperties rejects unsafe unpack sizes", async () => {
  await assert.rejects(
    decompressLzmaWithProperties(LZMA_PROPERTIES, PACKED_DATA, TOO_LARGE_UNPACK_SIZE),
    /unpack size exceeds supported range/
  );
});
