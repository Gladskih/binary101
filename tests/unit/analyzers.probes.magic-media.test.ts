"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { mediaProbes } from "../../analyzers/probes/magic-media.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);
const run = (bytes: ArrayLike<number>): string | null => mediaProbes.map(p => p(dvFrom(bytes))).find(Boolean) || null;

void test("detects audio and video containers", () => {
  assert.strictEqual(run([0x66, 0x4c, 0x61, 0x43]), "FLAC audio");
  assert.strictEqual(run([0x4f, 0x67, 0x67, 0x53]), "Ogg container (Vorbis/Opus/FLAC)");
  const wav = [..."RIFF"].map(c => c.charCodeAt(0)).concat([0, 0, 0, 0], ..."WAVE".split("").map(c => c.charCodeAt(0)));
  assert.strictEqual(run(wav), "WAVE audio (RIFF)");
  const avi = [..."RIFF"].map(c => c.charCodeAt(0)).concat([0, 0, 0, 0], ..."AVI ".split("").map(c => c.charCodeAt(0)));
  assert.strictEqual(run(avi), "AVI/DivX video (RIFF)");
});

void test("detects ISO-BMFF and MPEG transport streams", () => {
  const isobmff = new Uint8Array(12);
  const dv = new DataView(isobmff.buffer);
  dv.setUint32(4, 0x66747970, false);
  dv.setUint32(8, 0x68656963, false);
  assert.strictEqual(run(isobmff), "HEIF/HEIC image (ISO-BMFF)");

  const ts = new Uint8Array(188 * 3).fill(0);
  ts[0] = 0x47;
  ts[188] = 0x47;
  ts[376] = 0x47;
  assert.strictEqual(run(ts), "MPEG Transport Stream (TS)");
});

void test("does not misclassify UTF-16 BOM as MP3", () => {
  assert.strictEqual(run([0xff, 0xfe]), null);
});
