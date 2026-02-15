"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderTracks } from "../../renderers/webm/tracks-view.js";
import type { WebmTrack } from "../../analyzers/webm/types.js";

const baseTrack = (): WebmTrack => ({
  trackNumber: 1,
  trackUid: 1,
  trackType: 1,
  trackTypeLabel: "Video",
  name: null,
  language: "und",
  codecId: "V_VP8",
  codecName: null,
  defaultDuration: null,
  defaultDurationFps: null,
  codecPrivateSize: null,
  codecPrivateVorbis: null,
  flagEnabled: null,
  flagDefault: null,
  flagForced: null,
  flagLacing: null,
  video: null,
  audio: null
});

void test("renderTracks shows Pixel/Display/SAR and bitstream frame-size summary", () => {
  const track = baseTrack();
  track.video = {
    pixelWidth: 632,
    pixelHeight: 388,
    displayWidth: 690,
    displayHeight: 388,
    stereoMode: null,
    alphaMode: null
  };
  track.defaultDurationFps = 30;
  track.language = "eng";
  track.name = "Phone recording";
  track.bitstreamFrameStats = {
    trackNumber: 1,
    blockCount: 3,
    keyframeCount: 3,
    parsedFrameCount: 3,
    uniqueSizes: [
      { width: 632, height: 388, count: 1 },
      { width: 640, height: 360, count: 1 },
      { width: 704, height: 396, count: 1 }
    ],
    minWidth: 632,
    maxWidth: 704,
    minHeight: 360,
    maxHeight: 396,
    mismatchWithTrackEntryCount: 2,
    allBlocksAreKeyframes: true
  };
  const html = renderTracks([track]);
  assert.match(html, /Pixel 632 x 388/);
  assert.match(html, /Display 690 x 388/);
  assert.match(html, /SAR 345:316/);
  assert.match(html, /Bitstream sizes 3 unique/);
  assert.match(html, /TrackEntry mismatch in 2\/3/);
  assert.match(html, /All blocks marked keyframe/);
  assert.match(html, /30 fps/);
  assert.match(html, /lang: eng/);
  assert.match(html, /title: Phone recording/);
});

void test("renderTracks renders unknown codec and codec private Vorbis details", () => {
  const track = baseTrack();
  track.trackType = 2;
  track.trackTypeLabel = "Audio";
  track.codecId = "A_CUSTOM";
  track.codecIdValidForWebm = false;
  track.audio = {
    samplingFrequency: 48000,
    outputSamplingFrequency: null,
    channels: 2,
    bitDepth: 16
  };
  track.codecPrivateSize = 60;
  track.codecPrivateVorbis = {
    headerPacketLengths: [10, 20, 30],
    vendor: "unit-test",
    truncated: true
  };
  const html = renderTracks([track]);
  assert.match(html, /A_CUSTOM/);
  assert.match(html, /48000 Hz/);
  assert.match(html, /2 channel\(s\)/);
  assert.match(html, /16-bit/);
  assert.match(html, /packets 10\/20\/30 B/);
  assert.match(html, /vendor &quot;unit-test&quot;/);
  assert.match(html, /truncated/);
});

void test("renderTracks returns fallback text for empty input", () => {
  assert.match(renderTracks(null), /No tracks parsed/);
});

