"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseBmp } from "../../analyzers/bmp/index.js";
import {
  createBmp16BitBitfieldsFile,
  createBmp8BitPaletteFile,
  createBmpCoreHeaderFile,
  createBmpFile,
  createBmpOs2InfoHeader2File,
  createBmpV5EmbeddedProfileFile,
  createBmpV5LinkedProfileFile,
  createBmpV5SrgbFile,
  createBmpWithPixelOffsetPastEof,
  createTruncatedBmpFile
} from "../fixtures/bmp-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parseBmp returns null for non-BMP files", async () => {
  const file = new MockFile(new Uint8Array([0x00, 0x00, 0x00]), "not.bmp", "application/octet-stream");
  const result = await parseBmp(file);
  assert.strictEqual(result, null);
});

void test("parseBmp parses BITMAPINFOHEADER 24-bit BMP layout", async () => {
  const bmp = expectDefined(await parseBmp(createBmpFile()));
  assert.strictEqual(bmp.isBmp, true);
  assert.strictEqual(bmp.dibHeader.width, 1);
  assert.strictEqual(bmp.dibHeader.height, 1);
  assert.strictEqual(bmp.dibHeader.bitsPerPixel, 24);
  assert.strictEqual(bmp.fileHeader.pixelArrayOffset, 54);
  assert.strictEqual(expectDefined(bmp.pixelArray).rowStride, 4);
  assert.deepStrictEqual(bmp.issues, []);
});

void test("parseBmp parses BITMAPCOREHEADER variant", async () => {
  const bmp = expectDefined(await parseBmp(createBmpCoreHeaderFile()));
  assert.strictEqual(bmp.dibHeader.headerSize, 12);
  assert.strictEqual(bmp.dibHeader.width, 1);
  assert.strictEqual(bmp.dibHeader.height, 1);
  assert.strictEqual(bmp.dibHeader.bitsPerPixel, 24);
  assert.strictEqual(bmp.fileHeader.pixelArrayOffset, 26);
});

void test("parseBmp parses BITMAPINFOHEADER2 (OS/2 2.x) without misreading extra fields as masks", async () => {
  const bmp = expectDefined(await parseBmp(createBmpOs2InfoHeader2File()));
  assert.strictEqual(bmp.dibHeader.headerSize, 64);
  assert.strictEqual(bmp.dibHeader.headerKind, "BITMAPINFOHEADER2");
  assert.strictEqual(bmp.dibHeader.width, 1);
  assert.strictEqual(bmp.dibHeader.height, 1);
  assert.strictEqual(bmp.dibHeader.bitsPerPixel, 24);
  assert.strictEqual(bmp.dibHeader.masks, null);
});

void test("parseBmp parses palette metadata for indexed BMPs", async () => {
  const bmp = expectDefined(await parseBmp(createBmp8BitPaletteFile()));
  assert.strictEqual(bmp.dibHeader.bitsPerPixel, 8);
  assert.ok(bmp.palette);
  assert.strictEqual(bmp.palette.expectedEntries, 4);
  assert.strictEqual(bmp.palette.entrySize, 4);
  assert.strictEqual(bmp.palette.truncated, false);
  assert.strictEqual(bmp.fileHeader.pixelArrayOffset, 70);
});

void test("parseBmp parses BITFIELDS masks", async () => {
  const bmp = expectDefined(await parseBmp(createBmp16BitBitfieldsFile()));
  assert.strictEqual(bmp.dibHeader.compression, 3);
  assert.ok(bmp.dibHeader.masks);
  assert.strictEqual(bmp.dibHeader.masks.red?.mask, 0x0000f800);
  assert.strictEqual(bmp.dibHeader.masks.green?.mask, 0x000007e0);
  assert.strictEqual(bmp.dibHeader.masks.blue?.mask, 0x0000001f);
});

void test("parseBmp reports truncated BMP headers instead of throwing", async () => {
  const bmp = expectDefined(await parseBmp(createTruncatedBmpFile()));
  assert.ok(bmp.issues.some(issue => issue.toLowerCase().includes("truncated")));
});

void test("parseBmp reports pixel array offsets past EOF", async () => {
  const bmp = expectDefined(await parseBmp(createBmpWithPixelOffsetPastEof()));
  assert.ok(bmp.issues.some(issue => issue.toLowerCase().includes("pixel array")));
});

void test("parseBmp parses BITMAPV5HEADER color space metadata", async () => {
  const bmp = expectDefined(await parseBmp(createBmpV5SrgbFile()));
  const dib = (bmp as unknown as { dibHeader: Record<string, unknown> }).dibHeader;
  assert.strictEqual(dib["headerSize"], 124);
  assert.strictEqual(dib["colorSpaceType"], 0x73524742);
  assert.strictEqual(dib["intent"], 4);
});

void test("parseBmp decodes PROFILE_LINKED filenames in BITMAPV5HEADER", async () => {
  const bmp = expectDefined(await parseBmp(createBmpV5LinkedProfileFile()));
  const dib = (bmp as unknown as { dibHeader: Record<string, unknown> }).dibHeader;
  const profile = dib["profile"] as { fileName?: string } | null;
  assert.ok(profile);
  assert.strictEqual(profile?.fileName, "sRGB.icc");
});

void test("parseBmp detects embedded ICC profile signatures for PROFILE_EMBEDDED", async () => {
  const bmp = expectDefined(await parseBmp(createBmpV5EmbeddedProfileFile()));
  assert.ok(bmp.dibHeader.profile);
  assert.strictEqual(bmp.dibHeader.profile.kind, "embedded");
  assert.strictEqual(bmp.dibHeader.profile.embedded?.signature, "acsp");
});
