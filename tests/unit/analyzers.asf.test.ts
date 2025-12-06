"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseAsf, buildAsfLabel } from "../../analyzers/asf/index.js";
import { createSampleAsfFile } from "../fixtures/asf-fixtures.js";
import type { AsfParseResult } from "../../analyzers/asf/types.js";

void test("parseAsf returns structured details for ASF files", async () => {
  const file = createSampleAsfFile();
  const parsed = await parseAsf(file);
  assert.ok(parsed);
  assert.strictEqual(parsed?.streams.length, 2);
  assert.strictEqual(parsed?.fileProperties?.maxBitrate, 640000);
  assert.strictEqual(parsed?.fileProperties?.seekable, true);
  assert.ok(parsed?.contentDescription?.title.includes("Sample"));
  assert.ok(parsed?.extendedContent.some(tag => tag.name === "WM/AlbumTitle"));
  assert.ok(parsed?.codecList.length >= 2);
  assert.strictEqual(parsed?.stats.truncatedObjects, 0);
});

void test("parseAsf returns null for non-ASF signatures", async () => {
  const fake = new File([new Uint8Array([0, 1, 2, 3])], "fake.bin", { type: "application/octet-stream" });
  const parsed = await parseAsf(fake);
  assert.strictEqual(parsed, null);
});

void test("buildAsfLabel tolerates missing streams", () => {
  const empty: AsfParseResult = {
    header: null,
    objects: [],
    fileProperties: null,
    streams: [],
    contentDescription: null,
    extendedContent: [],
    codecList: [],
    headerExtension: null,
    dataObject: null,
    issues: [],
    stats: { parsedObjects: 0, truncatedObjects: 0, parsedBytes: 0, overlayBytes: 0 }
  };
  const label = buildAsfLabel(empty);
  assert.ok(label);
  assert.ok(label?.includes("ASF container"));
});
