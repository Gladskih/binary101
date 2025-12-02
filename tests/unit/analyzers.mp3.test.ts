"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMp3 } from "../../analyzers/mp3/index.js";
import { createMp3File } from "../fixtures/audio-sample-files.js";
import { createMp3WithGarbageFrame, createMp3WithOnlyId3v2 } from "../fixtures/mp3-fixtures.js";

void test("parseMp3 rejects files with only ID3 and no frames", async () => {
  const mp3 = await parseMp3(createMp3WithOnlyId3v2());
  assert.strictEqual(mp3.isMp3, false);
  assert.ok(mp3.reason.toLowerCase().includes("no valid mpeg frame"));
});

void test("parseMp3 warns when scanning garbage", async () => {
  const mp3 = await parseMp3(createMp3WithGarbageFrame());
  assert.strictEqual(mp3.isMp3, true);
  assert.ok((mp3.warnings || []).length > 0);
});

void test("parseMp3 parses valid minimal MPEG stream", async () => {
  const mp3 = await parseMp3(createMp3File());
  assert.strictEqual(mp3.isMp3, true);
  assert.ok(mp3.mpeg.firstFrame);
});
