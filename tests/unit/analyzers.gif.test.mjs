"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGif } from "../../dist/analyzers/gif/index.js";
import { createGifFile } from "../fixtures/sample-files.mjs";
import { createGifWithBadTrailer, createGifWithTruncatedExtension } from "../fixtures/gif-fixtures.mjs";

test("parseGif rejects missing trailer", async () => {
  const gif = await parseGif(createGifWithBadTrailer());
  assert.ok(gif);
  assert.strictEqual(gif.hasTrailer, false);
});

test("parseGif warns on truncated extension blocks", async () => {
  const gif = await parseGif(createGifWithTruncatedExtension());
  assert.ok(gif);
  assert.ok(gif.warnings.length > 0);
});

test("parseGif parses minimal valid GIF", async () => {
  const gif = await parseGif(createGifFile());
  assert.ok(gif.frames.length >= 0);
});
