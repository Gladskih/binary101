"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addHeuristicResourcePreview } from "../../../../../../analyzers/pe/resources/preview/sniff.js";
import { createPngFile } from "../../../../../fixtures/image-sample-files.js";
import { createAniFile, createWavFile } from "../../../../../fixtures/riff-sample-files.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

const createIcoPayload = (): Uint8Array => {
  const png = createPngFile().data;
  const ico = new Uint8Array(22 + png.length);
  const view = new DataView(ico.buffer);
  view.setUint16(2, 1, true);
  view.setUint16(4, 1, true);
  view.setUint8(6, 1);
  view.setUint8(7, 1);
  view.setUint16(10, 1, true);
  view.setUint32(14, png.length, true);
  view.setUint32(18, 22, true);
  ico.set(png, 22);
  return ico;
};

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

void test("addHeuristicResourcePreview recognizes ICO payloads", async () => {
  const result = await addHeuristicResourcePreview(createIcoPayload(), 0);

  assert.strictEqual(result?.preview?.previewKind, "image");
  assert.strictEqual(result?.preview?.previewMime, "image/x-icon");
  assert.match(expectDefined(result?.preview?.previewDataUrl), /^data:image\/x-icon;base64,/);
  assert.deepEqual(result?.preview?.previewFields, [{ label: "Detected", value: "ICO (heuristic)" }]);
});

void test("addHeuristicResourcePreview rejects truncated ICO payloads", async () => {
  const result = await addHeuristicResourcePreview(createIcoPayload().subarray(0, 21), 0);

  assert.strictEqual(result, null);
});

void test("addHeuristicResourcePreview recognizes JSON-like text payloads", async () => {
  const result = await addHeuristicResourcePreview(new TextEncoder().encode("{\"ok\":true}\n"), 0);

  assert.strictEqual(result?.preview?.previewKind, "text");
  assert.strictEqual(result?.preview?.textPreview, "{\"ok\":true}\n");
  assert.deepEqual(result?.preview?.previewFields, [{ label: "Detected", value: "JSON/Text (heuristic)" }]);
});

void test("addHeuristicResourcePreview recognizes INF-like sectioned text before JSON arrays", async () => {
  const text = "[Version]\nSignature=\"$CHICAGO$\"\n";
  const result = await addHeuristicResourcePreview(new TextEncoder().encode(text), 0);

  assert.strictEqual(result?.preview?.previewKind, "text");
  assert.strictEqual(result?.preview?.textPreview, text);
  assert.deepEqual(result?.preview?.previewFields, [{ label: "Detected", value: "INI/Text (heuristic)" }]);
});

void test("addHeuristicResourcePreview recognizes ANI payloads and exposes summary fields", async () => {
  const result = await addHeuristicResourcePreview(createAniFile().data, 0);

  assert.strictEqual(result?.preview?.previewKind, "summary");
  assert.ok((result?.preview?.previewFields || []).some(field => field.label === "Frames" && field.value === "2"));
});
