"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGif } from "../../analyzers/gif/index.js";
import { createGifFile } from "../fixtures/sample-files.js";
import { createGifWithBadTrailer, createGifWithTruncatedExtension } from "../fixtures/gif-fixtures.js";

void test("parseGif rejects missing trailer", async () => {
  const gif = await parseGif(createGifWithBadTrailer());
  assert.ok(gif);
  assert.strictEqual(gif.hasTrailer, false);
});

void test("parseGif warns on truncated extension blocks", async () => {
  const gif = await parseGif(createGifWithTruncatedExtension());
  assert.ok(gif);
  assert.ok(gif.warnings.length > 0);
});

void test("parseGif parses minimal valid GIF", async () => {
  const gif = await parseGif(createGifFile());
  assert.ok(gif.frames.length >= 0);
});