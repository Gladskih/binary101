"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePng } from "../../analyzers/png/index.js";
import {
  createPngFile,
  createPngWithIhdr
} from "../fixtures/sample-files.mjs";
import {
  createInvalidPngSignature,
  createPngMissingIend,
  createTruncatedPngChunk
} from "../fixtures/png-fixtures.mjs";
import { createPngWithManyChunks } from "../fixtures/png-large-chunk.mjs";

test("parsePng rejects invalid signature", async () => {
  const result = await parsePng(createInvalidPngSignature());
  assert.strictEqual(result, null);
});

test("parsePng catches missing IEND and invalid IHDR length", async () => {
  const png = await parsePng(createPngMissingIend());
  assert.ok(png);
  assert.ok(png.issues.some(issue => issue.includes("IHDR length")));
  assert.ok(png.issues.some(issue => issue.includes("IEND chunk missing")));
});

test("parsePng detects truncated chunk", async () => {
  const png = await parsePng(createTruncatedPngChunk());
  assert.ok(png);
  assert.ok(png.issues.some(issue => issue.includes("truncated")));
});

test("parsePng parses small images and chunk metadata", async () => {
  const png = await parsePng(createPngFile());
  assert.ok(png);
  assert.strictEqual(png.ihdr.width, 1);
  assert.strictEqual(png.chunkCount > 0, true);
});

test("parsePng parses IHDR for 2x2 image and reports palette/alpha", async () => {
  const png = await parsePng(createPngWithIhdr());
  assert.ok(png.ihdr);
  assert.strictEqual(png.ihdr.width, 2);
  assert.strictEqual(png.hasTransparency, false);
});

test("parsePng stops after many chunks with warning", async () => {
  const png = await parsePng(createPngWithManyChunks());
  assert.ok(png.issues.some(issue => issue.toLowerCase().includes("truncated")));
});
