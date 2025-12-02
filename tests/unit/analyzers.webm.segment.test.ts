"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSegment } from "../../analyzers/webm/segment.js";
import { readElementAt } from "../../analyzers/webm/ebml.js";
import { createWebmFile } from "../fixtures/webm-base-fixtures.js";
import { createWebmWithAttachments } from "../fixtures/webm-attachments-fixtures.js";
import { createWebmWithCues } from "../fixtures/webm-cues-fixtures.js";
import { createWebmWithInvalidCodecs } from "../fixtures/webm-invalid-codecs-fixtures.js";

const parseTracksFromFixture = async () => {
  const file = createWebmFile();
  const issues: string[] = [];
  const ebmlHeader = await readElementAt(file, 0, issues);
  assert.ok(ebmlHeader);
  assert.notStrictEqual(ebmlHeader?.size, null);
  const segOffset = ebmlHeader!.dataOffset + (ebmlHeader!.size as number);
  const segmentHeader = await readElementAt(file, segOffset, issues);
  assert.ok(segmentHeader);
  const segment = await parseSegment(file, segmentHeader, issues, "webm");
  return { tracks: segment.tracks, issues, segment };
};

void test("parseSegment wires track flags and pixel crop", async () => {
  const { tracks, issues } = await parseTracksFromFixture();
  const video = tracks.find(track => track.trackType === 1);
  assert.ok(video);
  assert.strictEqual(video?.flagDefault, true);
  assert.strictEqual(video?.flagEnabled, true);
  assert.ok(video?.video?.pixelCrop?.top === 1);
  assert.ok(issues.some(msg => msg.toLowerCase().includes("cues")));
});

void test("parseSegment defaults missing language to und", async () => {
  const { tracks } = await parseTracksFromFixture();
  const audio = tracks.find(track => track.trackType === 2);
  assert.ok(audio);
  assert.strictEqual(audio?.language, "und");
  assert.strictEqual(audio?.languageDefaulted, true);
});

void test("parseSegment parses cue points when present", async () => {
  const file = createWebmWithCues();
  const issues: string[] = [];
  const ebmlHeader = await readElementAt(file, 0, issues);
  assert.ok(ebmlHeader);
  assert.notStrictEqual(ebmlHeader?.size, null);
  const segOffset = ebmlHeader!.dataOffset + (ebmlHeader!.size as number);
  const segmentHeader = await readElementAt(file, segOffset, issues);
  assert.ok(segmentHeader);
  const segment = await parseSegment(file, segmentHeader, issues, "webm");
  assert.ok(segment.cues);
  assert.strictEqual(segment.clusterCount, 1);
  assert.ok(segment.firstClusterOffset && segment.firstClusterOffset > 0);
  assert.strictEqual(segment.blockCount, 2);
  assert.strictEqual(segment.keyframeCount, 1);
  assert.strictEqual(segment.cues?.cuePoints.length, 2);
  const first = segment.cues?.cuePoints[0];
  const second = segment.cues?.cuePoints[1];
  assert.strictEqual(first?.timecode, 0);
  assert.strictEqual(first?.timecodeSeconds, 0);
  assert.strictEqual(second?.timecodeSeconds, 1);
  const position = first?.positions[0];
  assert.strictEqual(position?.track, 1);
  const clusterOffset = segment.scannedElements.find(element => element.id === 0x1f43b675)?.offset;
  assert.ok(clusterOffset != null);
  const relativeClusterOffset = clusterOffset! - segment.dataOffset;
  assert.strictEqual(position?.clusterPosition, relativeClusterOffset);
  assert.ok(!issues.some(msg => msg.toLowerCase().includes("cues element not found")));
});

void test("parseSegment warns on attachments in strict WebM", async () => {
  const file = createWebmWithAttachments();
  const issues: string[] = [];
  const ebmlHeader = await readElementAt(file, 0, issues);
  assert.ok(ebmlHeader);
  assert.notStrictEqual(ebmlHeader?.size, null);
  const segOffset = ebmlHeader!.dataOffset + (ebmlHeader!.size as number);
  const segmentHeader = await readElementAt(file, segOffset, issues);
  assert.ok(segmentHeader);
  const segment = await parseSegment(file, segmentHeader, issues, "webm");
  assert.ok(segment);
  assert.ok(issues.some(msg => msg.toLowerCase().includes("attachments")));
});

void test("parseSegment flags invalid WebM codec IDs", async () => {
  const file = createWebmWithInvalidCodecs();
  const issues: string[] = [];
  const ebmlHeader = await readElementAt(file, 0, issues);
  assert.ok(ebmlHeader);
  assert.notStrictEqual(ebmlHeader?.size, null);
  const segOffset = ebmlHeader!.dataOffset + (ebmlHeader!.size as number);
  const segmentHeader = await readElementAt(file, segOffset, issues);
  assert.ok(segmentHeader);
  const segment = await parseSegment(file, segmentHeader, issues, "webm");
  const video = segment.tracks.find(track => track.trackType === 1);
  const audio = segment.tracks.find(track => track.trackType === 2);
  assert.strictEqual(video?.codecIdValidForWebm, false);
  assert.strictEqual(audio?.codecIdValidForWebm, false);
  assert.ok(issues.some(msg => msg.includes("V_MS/VFW/FOURCC")));
  assert.ok(issues.some(msg => msg.includes("A_MPEG/L3")));
});
