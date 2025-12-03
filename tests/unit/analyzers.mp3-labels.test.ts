"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildMp3Label, isShortMp3WithoutSecond, isValidatedMp3 } from "../../analyzers/mp3-labels.js";
import type { MpegFrameHeader, Mp3SuccessResult } from "../../analyzers/mp3/types.js";

const makeFrame = (overrides: Partial<MpegFrameHeader> = {}): MpegFrameHeader => ({
  offset: 0,
  rawHeader: 0xfffbaa00,
  versionBits: 3,
  versionLabel: "MPEG Version 1",
  layerBits: 1,
  layerLabel: "Layer III",
  hasCrc: false,
  bitrateKbps: 128,
  sampleRate: 44100,
  padding: false,
  privateBit: false,
  channelModeBits: 0,
  channelMode: "Stereo",
  modeExtension: null,
  copyright: false,
  original: true,
  emphasis: null,
  frameLengthBytes: 417,
  samplesPerFrame: 1152,
  ...overrides
});

const mkMp3 = (overrides: Partial<Mp3SuccessResult> = {}): Mp3SuccessResult => ({
  isMp3: true,
  mimeGuess: "audio/mpeg",
  summary: {
    hasId3v2: false,
    hasId3v1: false,
    hasApeTag: false,
    hasLyrics3: false,
    audioDataOffset: 0,
    durationSeconds: null,
    bitrateKbps: null,
    channelMode: null,
    sampleRateHz: null,
    mpegVersion: null,
    layer: null,
    isVbr: false,
    warnings: []
  },
  id3v2: null,
  id3v1: null,
  apeTag: null,
  lyrics3: null,
  mpeg: {
    firstFrame: makeFrame(),
    secondFrameValidated: true,
    nonAudioBytes: 0
  },
  vbr: null,
  durationSeconds: null,
  bitrateKbps: null,
  audioDataBytes: 0,
  warnings: [],
  ...overrides
});

void test("buildMp3Label assembles friendly label for validated streams", () => {
  const mp3 = mkMp3();
  assert.strictEqual(buildMp3Label(mp3), "MPEG Version 1, Layer III, 128 kbps, 44100 Hz, Stereo");
});

void test("isValidatedMp3 and isShortMp3WithoutSecond gate partial parses", () => {
  const validated = mkMp3();
  assert.strictEqual(isValidatedMp3(validated), true);

  const shortMp3 = mkMp3({
    mpeg: { firstFrame: makeFrame(), secondFrameValidated: false, nonAudioBytes: 0 },
    warnings: ["MPEG frames cannot be validated (file too small)"]
  });
  assert.strictEqual(isShortMp3WithoutSecond(shortMp3), true);

  const invalidMpeg: Mp3SuccessResult["mpeg"] = {
    firstFrame: null as unknown as MpegFrameHeader,
    secondFrameValidated: false,
    nonAudioBytes: 0
  };
  const invalid = mkMp3({ mpeg: invalidMpeg });
  assert.strictEqual(isValidatedMp3(invalid), false);
  assert.strictEqual(isShortMp3WithoutSecond(invalid), false);
});
