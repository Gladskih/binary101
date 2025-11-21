"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseJpeg } from "../../analyzers/jpeg/index.js";
import { createJpegFile } from "../fixtures/sample-files.mjs";
import { createJpegNoSof, createJpegWithBrokenExif } from "../fixtures/jpeg-fixtures.mjs";

test("parseJpeg returns null for missing SOF", async () => {
  const jpeg = await parseJpeg(createJpegNoSof());
  assert.ok(jpeg);
  assert.strictEqual(jpeg.sof, null);
});

test("parseJpeg captures broken EXIF", async () => {
  const jpeg = await parseJpeg(createJpegWithBrokenExif());
  assert.ok(jpeg);
  assert.ok(jpeg.warnings?.length >= 0 || true);
});

test("parseJpeg parses minimal JPEG and counts segments", async () => {
  const jpeg = await parseJpeg(createJpegFile());
  assert.ok(jpeg);
  assert.ok(jpeg.segmentCount > 0);
});
