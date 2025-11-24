"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  estimateDuration,
  findFirstFrame,
  parseFrameHeader,
  parseVbrHeader,
  validateNextFrame
} from "../../dist/analyzers/mp3/mpeg.js";

const makeHeaderValue = ({
  versionBits = 0x3,
  layerBits = 0x1,
  bitrateIndex = 0x9,
  sampleRateIndex = 0x0,
  padding = 0,
  channelModeBits = 0x0
} = {}) => {
  let value = 0xffe00000; // sync word
  value |= versionBits << 19;
  value |= layerBits << 17;
  value |= 0x1 << 16; // no CRC
  value |= bitrateIndex << 12;
  value |= sampleRateIndex << 10;
  value |= (padding ? 1 : 0) << 9;
  value |= channelModeBits << 6;
  return value >>> 0;
};

const writeHeader = (array, offset, headerValue) => {
  const view = new DataView(array.buffer);
  view.setUint32(offset, headerValue, false);
};

test("parseFrameHeader rejects invalid headers and decodes basics", () => {
  const tooShort = new DataView(new Uint8Array([0xff]).buffer);
  assert.strictEqual(parseFrameHeader(tooShort, 0), null);

  const reservedVersion = new Uint8Array(4);
  writeHeader(reservedVersion, 0, makeHeaderValue({ versionBits: 0x1 }));
  assert.strictEqual(parseFrameHeader(new DataView(reservedVersion.buffer), 0), null);

  const badBitrate = new Uint8Array(4);
  writeHeader(badBitrate, 0, makeHeaderValue({ bitrateIndex: 0xf }));
  assert.strictEqual(parseFrameHeader(new DataView(badBitrate.buffer), 0), null);

  const validBytes = new Uint8Array(4);
  writeHeader(validBytes, 0, makeHeaderValue({ padding: 1, channelModeBits: 0x2 }));
  const parsed = parseFrameHeader(new DataView(validBytes.buffer), 0);
  assert.ok(parsed);
  assert.strictEqual(parsed.padding, true);
  assert.strictEqual(parsed.channelMode, "Dual channel");
});

test("findFirstFrame flags unusually distant headers", () => {
  const data = new Uint8Array(41000).fill(0);
  writeHeader(data, 40000, makeHeaderValue({ padding: 1 }));
  const issues = [];
  const frame = findFirstFrame(new DataView(data.buffer), 0, issues);
  assert.ok(frame);
  assert.ok(issues.some(msg => msg.includes("unusually far")), "expected distance warning");
});

test("validateNextFrame reports truncated, invalid, and mismatched frames", () => {
  const headerValue = makeHeaderValue({ bitrateIndex: 0x9, sampleRateIndex: 0x0 });
  const shortData = new Uint8Array(100).fill(0);
  writeHeader(shortData, 0, headerValue);
  const shortFrame = parseFrameHeader(new DataView(shortData.buffer), 0);
  const shortIssues = [];
  assert.strictEqual(validateNextFrame(new DataView(shortData.buffer), shortFrame, shortIssues), false);
  assert.ok(shortIssues.some(msg => msg.includes("too small")));

  const frameLength = shortFrame.frameLengthBytes || 0;
  const invalidSecond = new Uint8Array(frameLength + 8).fill(0);
  writeHeader(invalidSecond, 0, headerValue);
  const issues = [];
  const parsedFrame = parseFrameHeader(new DataView(invalidSecond.buffer), 0);
  assert.strictEqual(validateNextFrame(new DataView(invalidSecond.buffer), parsedFrame, issues), false);
  assert.ok(issues.some(msg => msg.includes("invalid")));

  const mismatch = new Uint8Array((parsedFrame.frameLengthBytes || 0) * 2 + 8).fill(0);
  writeHeader(mismatch, 0, headerValue);
  const mismatchView = new DataView(mismatch.buffer);
  writeHeader(
    mismatch,
    parsedFrame.frameLengthBytes || 0,
    makeHeaderValue({ versionBits: 0x2, layerBits: 0x2 })
  );
  const mismatchIssues = [];
  const mismatchFrame = parseFrameHeader(mismatchView, 0);
  assert.strictEqual(validateNextFrame(mismatchView, mismatchFrame, mismatchIssues), false);
  assert.ok(mismatchIssues.some(msg => msg.includes("disagree")));
});

test("parseVbrHeader detects Xing/Info and VBRI markers", () => {
  const headerValue = makeHeaderValue({ channelModeBits: 0x0 });
  const data = new Uint8Array(200).fill(0);
  writeHeader(data, 0, headerValue);
  const dv = new DataView(data.buffer);
  const frame = parseFrameHeader(dv, 0);
  const start = 4 + 32; // side info for MPEG1 stereo
  const flags = 0x3; // frames + bytes
  data.set([0x58, 0x69, 0x6e, 0x67], start); // "Xing"
  dv.setUint32(start + 4, flags, false);
  dv.setUint32(start + 8, 123, false);
  dv.setUint32(start + 12, 456, false);
  const xing = parseVbrHeader(dv, frame);
  assert.ok(xing);
  assert.strictEqual(xing.frames, 123);
  assert.strictEqual(xing.bytes, 456);
  assert.strictEqual(xing.vbrDetected, true);

  const vbriData = new Uint8Array(80).fill(0);
  writeHeader(vbriData, 0, headerValue);
  vbriData.set([0x56, 0x42, 0x52, 0x49], 36); // VBRI at 4 + 32
  const vbriView = new DataView(vbriData.buffer);
  vbriView.setUint16(36 + 8, 99, false); // quality
  vbriView.setUint32(36 + 10, 1000, false); // bytes
  vbriView.setUint32(36 + 14, 77, false); // frames
  const vbriFrame = parseFrameHeader(vbriView, 0);
  const vbri = parseVbrHeader(vbriView, vbriFrame);
  assert.ok(vbri);
  assert.strictEqual(vbri.type, "VBRI");
  assert.strictEqual(vbri.frames, 77);
  assert.strictEqual(vbri.bytes, 1000);
});

test("estimateDuration chooses best available information", () => {
  const baseFrame = {
    samplesPerFrame: 1152,
    sampleRate: 44100,
    bitrateKbps: 128
  };

  const vbrFrames = { frames: 100, bytes: null, vbrDetected: true };
  const issues = [];
  const framesDuration = estimateDuration(baseFrame, vbrFrames, 0, issues);
  assert.strictEqual(framesDuration, (100 * 1152) / 44100);

  const vbrBytes = { frames: null, bytes: 44100, vbrDetected: true };
  const bytesDuration = estimateDuration(baseFrame, vbrBytes, 0, issues);
  assert.strictEqual(bytesDuration, (44100 * 8) / (128000));

  const audioDuration = estimateDuration(baseFrame, null, 5000, issues);
  assert.ok(audioDuration > 0);

  const missing = estimateDuration(null, null, -1, issues);
  assert.strictEqual(missing, null);
  assert.ok(issues.some(msg => msg.includes("could not be estimated")));
});
