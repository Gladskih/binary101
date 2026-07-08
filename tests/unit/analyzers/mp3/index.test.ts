"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMp3, probeMp3 } from "../../../../analyzers/mp3/index.js";
import { createMp3File } from "../../../fixtures/audio-sample-files.js";
import { createMp3WithGarbageFrame, createMp3WithOnlyId3v2 } from "../../../fixtures/mp3-fixtures.js";

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

void test("probeMp3 accepts consecutive MPEG frames at the file start", async () => {
  const bytes = new Uint8Array(await createMp3File().arrayBuffer());

  assert.equal(probeMp3(new DataView(bytes.buffer)), true);
});

void test("probeMp3 rejects coincidental MPEG frames after unrelated binary data", async () => {
  const frames = new Uint8Array(await createMp3File().arrayBuffer());
  const bytes = new Uint8Array(32 + frames.length);
  bytes.set(frames, 32);

  assert.equal(probeMp3(new DataView(bytes.buffer)), false);
});

void test("probeMp3 validates ID3v2 headers", () => {
  const valid = Uint8Array.from([0x49, 0x44, 0x33, 3, 0, 0, 0, 0, 0, 0]);
  const invalidVersion = valid.slice();
  const invalidSize = valid.slice();
  invalidVersion[3] = 0xff;
  invalidSize[9] = 0x80;

  assert.equal(probeMp3(new DataView(valid.buffer)), true);
  assert.equal(probeMp3(new DataView(invalidVersion.buffer)), false);
  assert.equal(probeMp3(new DataView(invalidSize.buffer)), false);
});
