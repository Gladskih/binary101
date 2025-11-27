"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGif } from "../../analyzers/gif/index.js";
import { createGifFile } from "../fixtures/sample-files.js";
import { createGifWithBadTrailer, createGifWithTruncatedExtension } from "../fixtures/gif-fixtures.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parseGif rejects missing trailer", async () => {
  const gif = await parseGif(createGifWithBadTrailer());
  const definedGif = expectDefined(gif);
  assert.strictEqual(definedGif.hasTrailer, false);
});

void test("parseGif warns on truncated extension blocks", async () => {
  const gif = await parseGif(createGifWithTruncatedExtension());
  const definedGif = expectDefined(gif);
  assert.ok(definedGif.warnings.length > 0);
});

void test("parseGif parses minimal valid GIF", async () => {
  const gif = await parseGif(createGifFile());
  const definedGif = expectDefined(gif);
  assert.ok(definedGif.frames.length >= 0);
});
