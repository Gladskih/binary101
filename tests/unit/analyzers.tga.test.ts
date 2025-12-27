"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseTga } from "../../analyzers/tga/index.js";
import { createTgaFile } from "../fixtures/image-sample-files.js";
import {
  createTgaColorMappedFile,
  createTgaV2WithExtensionAndDeveloperArea,
  createTgaWithBinaryImageId
} from "../fixtures/tga-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parseTga returns null when the file is not a likely TGA candidate", async () => {
  const bytes = new Uint8Array(18);
  const file = new MockFile(bytes, "data.bin", "application/octet-stream");
  assert.equal(await parseTga(file), null);
});

void test("parseTga parses a minimal uncompressed TGA file", async () => {
  const tga = expectDefined(await parseTga(createTgaFile()));
  assert.strictEqual(tga.isTga, true);
  assert.strictEqual(tga.version, "1.0");
  assert.strictEqual(tga.header.imageType, 2);
  assert.strictEqual(tga.header.width, 1);
  assert.strictEqual(tga.header.height, 1);
  assert.strictEqual(tga.header.pixelDepth, 24);
  assert.strictEqual(tga.imageData.offset, 18);
  assert.strictEqual(tga.imageData.truncated, false);
});

void test("parseTga parses v2.0 footer signature, extension area, and developer tags", async () => {
  const tga = expectDefined(await parseTga(createTgaV2WithExtensionAndDeveloperArea()));
  assert.strictEqual(tga.version, "2.0");
  assert.ok(tga.footer?.present);
  assert.strictEqual(tga.footer?.signature, "TRUEVISION-XFILE.\\0");
  assert.ok(tga.extensionArea);
  assert.strictEqual(tga.extensionArea.authorName, "Unit Test");
  assert.ok(tga.extensionArea.timestamp);
  assert.ok(tga.developerDirectory);
  assert.strictEqual(tga.developerDirectory.tagCount, 1);
  assert.strictEqual(tga.developerDirectory.tags[0]?.tagNumber, 42);
});

void test("parseTga parses color-mapped images and palette metadata", async () => {
  const tga = expectDefined(await parseTga(createTgaColorMappedFile()));
  assert.strictEqual(tga.header.imageType, 1);
  assert.ok(tga.colorMap);
  assert.strictEqual(tga.colorMap.expectedBytes, 6);
  assert.strictEqual(tga.imageData.offset, 24);
  assert.strictEqual(tga.imageData.truncated, false);
});

void test("parseTga keeps binary Image ID fields as a hex preview", async () => {
  const tga = expectDefined(await parseTga(createTgaWithBinaryImageId()));
  assert.ok(tga.imageId);
  assert.strictEqual(tga.imageId.text, null);
  assert.ok(tga.imageId.previewHex);
});
