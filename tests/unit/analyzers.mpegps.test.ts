"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseMpegPs } from "../../analyzers/mpegps/index.js";
import { createMpegPsFile } from "../fixtures/mpegps-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseMpegPs parses pack headers, system headers, and PES packets", async () => {
  const file = createMpegPsFile();
  const parsed = await parseMpegPs(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.isMpegProgramStream, true);
  assert.strictEqual(parsed.fileSize, file.size);

  assert.strictEqual(parsed.packHeaders.totalCount, 2);
  assert.strictEqual(parsed.packHeaders.mpeg2Count, 2);
  assert.strictEqual(parsed.systemHeaders.totalCount, 1);
  assert.strictEqual(parsed.pes.totalPackets, 3);
  assert.strictEqual(parsed.pes.streams.length, 2);

  const video = parsed.pes.streams.find(s => s.streamId === 0xe0);
  assert.ok(video);
  assert.strictEqual(video.kind, "video");
  assert.strictEqual(video.packetCount, 2);
  assert.strictEqual(video.pts.count, 2);
  assert.strictEqual(video.pts.durationSeconds, 1);
});

void test("parseMpegPs returns null for non-MPEG-PS signatures", async () => {
  const file = new MockFile(new Uint8Array([0x00, 0x00, 0x01, 0xbb]), "not-ps.bin", "application/octet-stream");
  const parsed = await parseMpegPs(file);
  assert.equal(parsed, null);
});

void test("parseMpegPs reports truncation when the pack header is incomplete", async () => {
  const bytes = new Uint8Array([0x00, 0x00, 0x01, 0xba, 0x44, 0x00]);
  const file = new MockFile(bytes, "truncated.mpg", "video/mpeg");
  const parsed = await parseMpegPs(file);
  assert.ok(parsed);
  assert.ok(parsed.issues.length >= 1);
});

