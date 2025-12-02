"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMp4, buildMp4Label } from "../../analyzers/mp4/index.js";
import { parseForUi } from "../../analyzers/index.js";
import { createMp4File } from "../fixtures/sample-files.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseMp4 reads movie header and tracks", async () => {
  const file = createMp4File();
  const parsed = await parseMp4(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.movieHeader?.timescale, 1000);
  assert.strictEqual(parsed.tracks.length, 2);
  const video = parsed.tracks.find(track => track.kind === "video");
  const audio = parsed.tracks.find(track => track.kind === "audio");
  assert.ok(video);
  assert.ok(audio);
  assert.strictEqual(video?.width, 320);
  assert.strictEqual(video?.height, 180);
  assert.strictEqual(video?.sampleCount, 2);
  assert.strictEqual(audio?.sampleCount, 2);
  assert.strictEqual(parsed.fastStart, true);
});

void test("buildMp4Label includes track summary", async () => {
  const parsed = await parseMp4(createMp4File());
  const label = buildMp4Label(parsed);
  assert.ok(label);
  assert.match(label ?? "", /MP4/);
  assert.match(label ?? "", /video:/);
});

void test("parseMp4 reports missing movie data", async () => {
  const minimal = new MockFile(new Uint8Array(createMp4File().data.slice(0, 24)), "truncated.mp4", "video/mp4");
  const parsed = await parseMp4(minimal);
  assert.ok(parsed);
  assert.ok(parsed.warnings.length >= 1);
  assert.strictEqual(parsed.tracks.length, 0);
});

void test("parseForUi routes MP4 files", async () => {
  const result = await parseForUi(createMp4File());
  assert.strictEqual(result.analyzer, "mp4");
  assert.ok(result.parsed.tracks.length >= 2);
});
