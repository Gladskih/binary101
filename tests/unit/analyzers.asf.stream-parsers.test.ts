"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFileProperties, parseStreamProperties } from "../../analyzers/asf/stream-parsers.js";
import { parseObjectList } from "../../analyzers/asf/shared.js";
import { ASF_FILE_PROPERTIES_GUID, ASF_STREAM_PROPERTIES_GUID } from "../../analyzers/asf/constants.js";
import { createSampleAsfFile } from "../fixtures/asf-fixtures.js";
import type { AsfAudioFormat, AsfVideoFormat } from "../../analyzers/asf/types.js";

void test("parseFileProperties reads header values", async () => {
  const file = createSampleAsfFile();
  const view = new DataView(await file.arrayBuffer());
  const issues: string[] = [];
  const headerSize = view.getUint32(16, true);
  const children = parseObjectList(view, 30, headerSize, issues, "Header");
  const fileProps = children.objects.find(obj => obj.guid === ASF_FILE_PROPERTIES_GUID);
  assert.ok(fileProps);
  const parsed = parseFileProperties(view, (fileProps?.offset ?? 0) + 24, (fileProps?.size ?? 0) - 24, issues);
  assert.ok(parsed);
  assert.strictEqual(parsed?.seekable, true);
  assert.strictEqual(parsed?.broadcast, false);
  assert.strictEqual(parsed?.maxBitrate, 640000);
  assert.ok((parsed?.creationDate || "").includes("2024"));
});

void test("parseStreamProperties reports audio and video streams", async () => {
  const file = createSampleAsfFile();
  const view = new DataView(await file.arrayBuffer());
  const headerSize = view.getUint32(16, true);
  const issues: string[] = [];
  const children = parseObjectList(view, 30, headerSize, issues, "Header");
  const streams = children.objects.filter(obj => obj.guid === ASF_STREAM_PROPERTIES_GUID);
  assert.strictEqual(streams.length, 2);
  const audioObj = streams[0];
  const videoObj = streams[1];
  assert.ok(audioObj && videoObj);
  const audio = parseStreamProperties(view, audioObj.offset + 24, (audioObj.size ?? 0) - 24, issues);
  assert.ok(audio);
  assert.strictEqual(audio?.streamNumber, 1);
  assert.strictEqual(audio?.typeSpecific?.kind, "audio");
  if (audio?.typeSpecific?.kind === "audio") {
    const audioFmt: AsfAudioFormat = audio.typeSpecific;
    assert.strictEqual(audioFmt.sampleRate, 44100);
  }
  const video = parseStreamProperties(view, videoObj.offset + 24, (videoObj.size ?? 0) - 24, issues);
  assert.ok(video);
  assert.strictEqual(video?.streamNumber, 2);
  assert.strictEqual(video?.typeSpecific?.kind, "video");
  if (video?.typeSpecific?.kind === "video") {
    const videoFmt: AsfVideoFormat = video.typeSpecific;
    assert.strictEqual(videoFmt.width, 640);
  }
});

void test("parseStreamProperties returns null for truncated payloads", () => {
  const dv = new DataView(new Uint8Array(10).buffer);
  const issues: string[] = [];
  const parsed = parseStreamProperties(dv, 0, 10, issues);
  assert.strictEqual(parsed, null);
  assert.ok(issues.some(issue => issue.toLowerCase().includes("too small")));
});

void test("parseFileProperties returns null for small payloads", () => {
  const dv = new DataView(new Uint8Array(10).buffer);
  const issues: string[] = [];
  const parsed = parseFileProperties(dv, 0, 10, issues);
  assert.strictEqual(parsed, null);
  assert.ok(issues.some(issue => issue.toLowerCase().includes("too small")));
});
