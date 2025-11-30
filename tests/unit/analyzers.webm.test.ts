"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWebm, buildWebmLabel } from "../../analyzers/webm/index.js";
import { createWebmFile, createWebmWithAttachments } from "../fixtures/sample-files.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseWebm reads EBML header, info and tracks", async () => {
  const parsed = await parseWebm(createWebmFile());
  assert.ok(parsed);
  assert.strictEqual(parsed.docType, "webm");
  assert.ok(parsed.segment);
  assert.ok(parsed.segment?.info);
  assert.ok(parsed.segment?.tracks.length >= 2);
  const info = parsed.segment?.info;
  assert.ok(info?.durationSeconds && info.durationSeconds > 1 && info.durationSeconds < 3);
  const videoTrack = parsed.segment?.tracks.find(track => track.trackType === 1);
  assert.ok(videoTrack);
  assert.strictEqual(videoTrack?.trackTypeLabel, "Video");
  assert.strictEqual(videoTrack?.flagDefault, true);
  assert.strictEqual(videoTrack?.flagEnabled, true);
  assert.ok(videoTrack?.defaultDurationFps && videoTrack.defaultDurationFps > 10);
  assert.ok(videoTrack?.video?.pixelCrop);
  assert.strictEqual(videoTrack?.video?.pixelCrop?.bottom, 2);
  const audioTrack = parsed.segment?.tracks.find(track => track.trackType === 2);
  assert.ok(audioTrack);
  assert.strictEqual(audioTrack?.language, "und");
  assert.strictEqual(audioTrack?.languageDefaulted, true);
  const label = buildWebmLabel(parsed);
  assert.ok(label);
  assert.match(label as string, /WebM/);
  assert.match(label as string, /video/);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("cues")));
});

void test("parseWebm reports issues for truncated data", async () => {
  const full = createWebmFile();
  const truncated = new MockFile(full.data.slice(0, full.data.length - 8), "trunc.webm", "video/webm");
  const parsed = await parseWebm(truncated);
  assert.ok(parsed);
  assert.ok(parsed.issues.length >= 1);
});

void test("parseWebm warns on Matroska-only elements in WebM", async () => {
  const parsed = await parseWebm(createWebmWithAttachments());
  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("attachments")));
});
