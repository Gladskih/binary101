import assert from "node:assert/strict";
import { test } from "node:test";
import { decompressZipLzma } from "../../../../analyzers/zip/lzma.js";
import { lzmaData, lzmaProperties } from "../../../fixtures/lzma.js";
import { createZipEntry } from "../../../fixtures/ui-zip-actions-fixtures.js";
import { lzmaZipFile } from "../../../fixtures/lzma-zip-file.js";
import { parseZip } from "../../../../analyzers/zip/index.js";

const packed = (): Uint8Array => Uint8Array.of(9, 4, 5, 0, ...lzmaProperties, ...lzmaData);
const entry = () => createZipEntry({ compressionMethod: 14, flags: 2,
  uncompressedSize: 4, crc32: 0x9b661ed7 }); // CRC-32 of ASCII DATA, independently zipfile-verified.

void test("ZIP LZMA decodes and verifies a marked stream", async () => {
  assert.deepEqual(await decompressZipLzma(packed(), entry()), new TextEncoder().encode("DATA"));
});

void test("ZIP LZMA decodes a real empty entry", async () => {
  const file = new File([lzmaZipFile()], "lzma.zip");
  const parsed = await parseZip(file);
  const empty = parsed?.centralDirectory?.entries[1];
  assert.ok(empty);
  assert.equal(empty.uncompressedSize, 0);
  const bytes = new Uint8Array(await file.slice(empty.dataOffset, empty.dataEnd!).arrayBuffer());

  assert.deepEqual(await decompressZipLzma(bytes, empty), new Uint8Array());
});

// Independent liblzma lzma_raw_buffer_encode, LZMA_FILTER_LZMA1EXT,
// preset 6, dict_size=65536, ext_flags=0 (no EOPM), input ASCII DATA.
// https://github.com/tukaani-project/xz/blob/master/src/liblzma/api/lzma/lzma12.h
const markerless = (): Uint8Array => Uint8Array.of(9, 4, 5, 0, ...lzmaProperties,
  ...Buffer.from("00221046cd5d741460", "hex"));

void test("ZIP LZMA decodes known-size streams without an end marker", async () => {
  assert.deepEqual(await decompressZipLzma(markerless(), { ...entry(), flags: 0 }),
    new TextEncoder().encode("DATA"));
});

void test("ZIP LZMA requires the end marker when general-purpose bit 1 is set", async () => {
  await assert.rejects(decompressZipLzma(markerless(), entry()), /declared end marker/);
});

void test("ZIP LZMA rejects an end marker when general-purpose bit 1 is clear", async () => {
  await assert.rejects(decompressZipLzma(packed(), { ...entry(), flags: 0 }), /undeclared end marker/);
});

void test("ZIP LZMA honors the byte offset of a view and bigint output sizes", async () => {
  const bytes = Uint8Array.of(255, ...packed(), 255);

  assert.deepEqual(await decompressZipLzma(bytes.subarray(1, -1),
    { ...entry(), uncompressedSize: 4n }), new TextEncoder().encode("DATA"));
});

void test("ZIP LZMA rejects invalid coder properties", async () => {
  const bytes = packed();
  bytes[4] = 255;

  await assert.rejects(decompressZipLzma(bytes, entry()), /SDK error/);
});

for (const length of [0, 1, 3, 4, 8]) {
  void test(`ZIP LZMA rejects a truncated properties header of ${length} bytes`, async () => {
    await assert.rejects(decompressZipLzma(packed().subarray(0, length), entry()), /header.*truncated/);
  });
}

void test("ZIP LZMA rejects unsupported property lengths", async () => {
  const bytes = packed();
  bytes[2] = 4;

  await assert.rejects(decompressZipLzma(bytes, entry()), /properties.*size/);
});

void test("ZIP LZMA rejects truncated compressed data", async () => {
  await assert.rejects(decompressZipLzma(packed().subarray(0, 11), entry()), /SDK error/);
});

void test("ZIP LZMA distinguishes a complete properties header from missing compressed data",
  async () => {
    await assert.rejects(decompressZipLzma(packed().subarray(0, 9), entry()), /SDK error/);
  });

void test("ZIP LZMA rejects trailing compressed data", async () => {
  await assert.rejects(decompressZipLzma(Uint8Array.of(...packed(), 42), entry()), /unconsumed/);
});

void test("ZIP LZMA rejects an incorrect CRC", async () => {
  await assert.rejects(decompressZipLzma(packed(), { ...entry(), crc32: 0 }), /CRC/);
});

void test("ZIP LZMA rejects an incorrect output size", async () => {
  await assert.rejects(decompressZipLzma(packed(), { ...entry(), uncompressedSize: 3 }), /SDK error/);
});

for (const uncompressedSize of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY,
  Number.MAX_SAFE_INTEGER + 1]) {
  void test(`ZIP LZMA rejects unsupported output size ${uncompressedSize}`, async () => {
    await assert.rejects(decompressZipLzma(packed(), { ...entry(), uncompressedSize }),
      /^Error: ZIP LZMA output size is invalid\.$/);
  });
}

for (const uncompressedSize of [-1n, 0x1_0000_0000n]) {
  void test(`ZIP LZMA rejects unsupported bigint output size ${uncompressedSize}`, async () => {
    await assert.rejects(decompressZipLzma(packed(), { ...entry(), uncompressedSize }),
      /LZMA unpack size/);
  });
}
