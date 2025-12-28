"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseMpegPs } from "../../analyzers/mpegps/index.js";
import { createMpegPsChunkBoundaryFile, createMpegPsFile } from "../fixtures/mpegps-fixtures.js";
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

void test("parseMpegPs parses Program Stream Map packets", async () => {
  const packHeader = new Uint8Array([
    0x00, 0x00, 0x01, 0xba, 0x44, 0x00, 0x04, 0x00, 0x04, 0x01, 0x00, 0x00, 0x03, 0xf8
  ]);
  const psmPayload = new Uint8Array([
    0x81, 0x01, 0x00, 0x00, 0x00, 0x04, 0x1b, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
  const psm = new Uint8Array(6 + psmPayload.length);
  psm.set(new Uint8Array([0x00, 0x00, 0x01, 0xbc, 0x00, psmPayload.length]), 0);
  psm.set(psmPayload, 6);
  const endCode = new Uint8Array([0x00, 0x00, 0x01, 0xb9]);

  const bytes = new Uint8Array(packHeader.length + psm.length + endCode.length);
  bytes.set(packHeader, 0);
  bytes.set(psm, packHeader.length);
  bytes.set(endCode, packHeader.length + psm.length);

  const file = new MockFile(bytes, "psm.mpg", "video/mpeg");
  const parsed = await parseMpegPs(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.programStreamMaps.totalCount, 1);
  assert.ok(parsed.programStreamMaps.firstMap);
  assert.strictEqual(parsed.programStreamMaps.firstMap.entries.length, 1);
  assert.strictEqual(parsed.programStreamMaps.streamTypes.length, 1);
  const firstStreamType = parsed.programStreamMaps.streamTypes[0];
  assert.ok(firstStreamType);
  assert.strictEqual(firstStreamType.streamType, 0x1b);
  assert.strictEqual(firstStreamType.count, 1);
});

void test("parseMpegPs parses MPEG-1 pack headers and stuffing bytes", async () => {
  const packHeader = new Uint8Array([
    0x00, 0x00, 0x01, 0xba, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
  const stuffing = new Uint8Array([0xff, 0xff]);
  const endCode = new Uint8Array([0x00, 0x00, 0x01, 0xb9]);

  const bytes = new Uint8Array(packHeader.length + stuffing.length + endCode.length);
  bytes.set(packHeader, 0);
  bytes.set(stuffing, packHeader.length);
  bytes.set(endCode, packHeader.length + stuffing.length);

  const file = new MockFile(bytes, "mpeg1-pack.mpg", "video/mpeg");
  const parsed = await parseMpegPs(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.packHeaders.totalCount, 1);
  assert.strictEqual(parsed.packHeaders.mpeg1Count, 1);
  assert.strictEqual(parsed.packHeaders.stuffingBytesTotal, 2);
  assert.strictEqual(parsed.programEndCodeOffset, packHeader.length + stuffing.length);
  assert.strictEqual(parsed.issues.length, 0);
});

void test("parseMpegPs reports invalid pack header formats and continues scanning", async () => {
  const bytes = new Uint8Array(18);
  bytes.set(new Uint8Array([0x00, 0x00, 0x01, 0xba, 0x00]), 0);
  bytes.set(new Uint8Array([0x00, 0x00, 0x01, 0xb9]), 14);
  const file = new MockFile(bytes, "invalid-pack.mpg", "video/mpeg");
  const parsed = await parseMpegPs(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.packHeaders.totalCount, 1);
  assert.strictEqual(parsed.packHeaders.invalidCount, 1);
  assert.strictEqual(parsed.programEndCodeOffset, 14);
  assert.ok(parsed.issues.some(issue => issue.includes("Unknown pack header format byte")));
});

void test("parseMpegPs handles PES packets with length 0 by resyncing to the next start code", async () => {
  const packHeader = new Uint8Array([
    0x00, 0x00, 0x01, 0xba, 0x44, 0x00, 0x04, 0x00, 0x04, 0x01, 0x00, 0x00, 0x03, 0xf8
  ]);
  const pesZeroLength = new Uint8Array([0x00, 0x00, 0x01, 0xe0, 0x00, 0x00]);
  const endCode = new Uint8Array([0x00, 0x00, 0x01, 0xb9]);

  const bytes = new Uint8Array(packHeader.length + pesZeroLength.length + endCode.length);
  bytes.set(packHeader, 0);
  bytes.set(pesZeroLength, packHeader.length);
  bytes.set(endCode, packHeader.length + pesZeroLength.length);

  const file = new MockFile(bytes, "pes-zero.mpg", "video/mpeg");
  const parsed = await parseMpegPs(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.pes.totalPackets, 1);
  assert.strictEqual(parsed.pes.streams.length, 1);
  const stream = parsed.pes.streams[0];
  assert.ok(stream);
  assert.strictEqual(stream.streamId, 0xe0);
  assert.strictEqual(stream.packetLengthZeroCount, 1);
});

void test("parseMpegPs handles pack headers across chunk boundaries", async () => {
  const file = createMpegPsChunkBoundaryFile();
  const parsed = await parseMpegPs(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.packHeaders.totalCount, 3);
  assert.strictEqual(parsed.packHeaders.mpeg2Count, 3);
  assert.strictEqual(parsed.packHeaders.invalidCount, 0);
  assert.strictEqual(parsed.programEndCodeOffset != null, true);
  assert.strictEqual(parsed.issues.some(issue => issue.includes("Truncated MPEG-2 pack header")), false);
  assert.strictEqual(parsed.issues.some(issue => issue.includes("Unknown pack header format byte")), false);
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
