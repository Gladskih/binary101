"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFlac } from "../../analyzers/flac/index.js";
import { renderFlac } from "../../renderers/flac/index.js";
import { createFlacFile } from "../fixtures/flac-fixtures.js";

void test("renderFlac renders summary, block table and comments", async () => {
  const parsed = await parseFlac(createFlacFile());
  const html = renderFlac(parsed);
  assert.match(html, /FLAC audio/);
  assert.match(html, /Sample rate/);
  assert.match(html, /Vorbis comments/);
  assert.match(html, /Seek table/);
  assert.match(html, /Pictures/);
});

void test("renderFlac shows warnings when present", () => {
  const html = renderFlac({
    isFlac: true,
    streamInfo: null,
    blocks: [],
    audioDataOffset: null,
    audioDataBytes: null,
    warnings: ["Metadata missing"]
  });
  assert.match(html, /Warnings/);
  assert.match(html, /Metadata missing/);
});
