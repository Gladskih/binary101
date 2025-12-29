"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMkv } from "../../analyzers/mkv/index.js";
import { createMkvFile } from "../fixtures/mkv-base-fixtures.js";
import { createWebmFile } from "../fixtures/webm-base-fixtures.js";

void test("parseMkv parses Matroska EBML containers", async () => {
  const parsed = await parseMkv(createMkvFile());
  assert.ok(parsed);
  assert.strictEqual(parsed.docType, "matroska");
  assert.strictEqual(parsed.isWebm, false);
  assert.strictEqual(parsed.isMatroska, true);
  assert.ok(parsed.segment?.tracks.length);
});

void test("parseMkv returns null for WebM docType", async () => {
  const parsed = await parseMkv(createWebmFile());
  assert.strictEqual(parsed, null);
});

