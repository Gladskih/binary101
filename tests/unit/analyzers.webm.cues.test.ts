"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCues } from "../../analyzers/webm/cues.js";
import { CUES_ID } from "../../analyzers/webm/constants.js";
import { readElementAt, readElementHeader } from "../../analyzers/webm/ebml.js";
import { createWebmWithCues } from "../fixtures/sample-files.js";

void test("parseCues reads cue points and offsets", async () => {
  const file = createWebmWithCues();
  const issues: string[] = [];
  const ebmlHeader = await readElementAt(file, 0, issues);
  assert.ok(ebmlHeader);
  assert.notStrictEqual(ebmlHeader?.size, null);
  const segmentOffset = ebmlHeader!.dataOffset + (ebmlHeader!.size as number);
  const segmentHeader = await readElementAt(file, segmentOffset, issues);
  assert.ok(segmentHeader);

  const scanLength = 1024;
  const segmentView = new DataView(
    await file.slice(segmentHeader!.dataOffset, segmentHeader!.dataOffset + scanLength).arrayBuffer()
  );
  const seekHead = readElementHeader(segmentView, 0, segmentHeader!.dataOffset, issues);
  assert.ok(seekHead);
  const infoOffset = seekHead!.headerSize + (seekHead!.size as number);
  const infoHeader = readElementHeader(segmentView, infoOffset, segmentHeader!.dataOffset + infoOffset, issues);
  assert.ok(infoHeader);
  const tracksOffset = infoOffset + infoHeader!.headerSize + (infoHeader!.size as number);
  const tracksHeader = readElementHeader(
    segmentView,
    tracksOffset,
    segmentHeader!.dataOffset + tracksOffset,
    issues
  );
  assert.ok(tracksHeader);
  const cuesOffset = tracksOffset + tracksHeader!.headerSize + (tracksHeader!.size as number);
  const cuesHeader = readElementHeader(segmentView, cuesOffset, segmentHeader!.dataOffset + cuesOffset, issues);
  assert.ok(cuesHeader);
  assert.strictEqual(cuesHeader?.id, CUES_ID);

  const cues = await parseCues(file, cuesHeader!, issues, 1000000);
  assert.strictEqual(cues.cuePoints.length, 2);
  const [first, second] = cues.cuePoints;
  assert.strictEqual(first.timecode, 0);
  assert.strictEqual(first.timecodeSeconds, 0);
  assert.strictEqual(second.timecodeSeconds, 1);
  const position = first.positions[0];
  assert.strictEqual(position.track, 1);
  assert.strictEqual(position.clusterPosition, 297);
  assert.strictEqual(cues.truncated, false);
});
