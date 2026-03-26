"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addHeuristicResourcePreview } from "../../analyzers/pe/resources-preview-sniff.js";
import { createPngFile } from "../fixtures/image-sample-files.js";
import { createAniFile, createWavFile } from "../fixtures/riff-sample-files.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("addHeuristicResourcePreview recognizes inline PNG payloads", async () => {
  const result = await addHeuristicResourcePreview(createPngFile().data, 0);

  assert.strictEqual(result?.preview?.previewKind, "image");
  assert.strictEqual(result?.preview?.previewMime, "image/png");
  assert.match(expectDefined(result?.preview?.previewDataUrl), /^data:image\/png;base64,/);
});

void test("addHeuristicResourcePreview recognizes WAV payloads as audio", async () => {
  const result = await addHeuristicResourcePreview(createWavFile().data, 0);

  assert.strictEqual(result?.preview?.previewKind, "audio");
  assert.strictEqual(result?.preview?.previewMime, "audio/wav");
  assert.match(expectDefined(result?.preview?.previewDataUrl), /^data:audio\/wav;base64,/);
});

void test("addHeuristicResourcePreview recognizes JSON-like text payloads", async () => {
  const result = await addHeuristicResourcePreview(new TextEncoder().encode("{\"ok\":true}\n"), 0);

  assert.strictEqual(result?.preview?.previewKind, "text");
  assert.strictEqual(result?.preview?.textPreview, "{\"ok\":true}\n");
  assert.deepEqual(result?.preview?.previewFields, [{ label: "Detected", value: "JSON/Text (heuristic)" }]);
});

void test("addHeuristicResourcePreview recognizes ANI payloads and exposes summary fields", async () => {
  const result = await addHeuristicResourcePreview(createAniFile().data, 0);

  assert.strictEqual(result?.preview?.previewKind, "summary");
  assert.ok((result?.preview?.previewFields || []).some(field => field.label === "Frames" && field.value === "2"));
});
