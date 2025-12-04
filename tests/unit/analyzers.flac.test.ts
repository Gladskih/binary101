"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFlac } from "../../analyzers/flac/index.js";
import { createFlacFile, createTruncatedFlacFile } from "../fixtures/flac-fixtures.js";

void test("parseFlac parses stream info, metadata blocks and audio size", async () => {
  const flac = await parseFlac(createFlacFile());
  assert.ok(flac);
  assert.strictEqual(flac.streamInfo?.sampleRate, 44100);
  assert.strictEqual(flac.streamInfo?.channels, 2);
  assert.strictEqual(flac.streamInfo?.bitsPerSample, 16);
  assert.strictEqual(flac.audioDataBytes, 4);
  assert.strictEqual(flac.blocks.length, 4);
  const vorbis = flac.blocks.find(block => block.type === "VORBIS_COMMENT");
  assert.ok(vorbis);
  assert.deepStrictEqual(flac.warnings, []);
});

void test("parseFlac reports truncated metadata blocks", async () => {
  const flac = await parseFlac(createTruncatedFlacFile());
  assert.ok(flac);
  assert.strictEqual(flac.streamInfo, null);
  assert.ok(flac.warnings.length >= 1);
  assert.ok(flac.audioDataOffset !== null);
});
