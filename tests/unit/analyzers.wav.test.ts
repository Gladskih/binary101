"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWav } from "../../analyzers/wav/index.js";
import { buildRiffFile, createWavFile } from "../fixtures/riff-sample-files.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parseWav extracts PCM format details", async () => {
  const wav = expectDefined(await parseWav(createWavFile()));
  assert.strictEqual(wav.format?.audioFormat, 1);
  assert.strictEqual(wav.format?.channels, 1);
  assert.strictEqual(wav.format?.sampleRate, 8000);
  assert.strictEqual(wav.format?.bitsPerSample, 8);
  assert.ok(wav.data);
  assert.strictEqual(wav.data?.size, 5);
  assert.ok(wav.data?.durationSeconds);
});

void test("parseWav returns null for non-WAVE RIFF files", async () => {
  const riff = buildRiffFile("TEST", [], "test.riff", "application/octet-stream");
  const wav = await parseWav(riff);
  assert.strictEqual(wav, null);
});

void test("parseWav reports missing fmt chunk", async () => {
  const riff = buildRiffFile(
    "WAVE",
    [{ id: "data", data: new Uint8Array([0x00, 0x01]) }],
    "nofmt.wav",
    "audio/wav"
  );
  const wav = expectDefined(await parseWav(riff));
  assert.ok(wav.issues.some(issue => issue.toLowerCase().includes("missing fmt")));
});
