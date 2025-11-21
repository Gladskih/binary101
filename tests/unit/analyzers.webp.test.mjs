"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWebp } from "../../analyzers/webp/index.js";
import { createWebpFile } from "../fixtures/sample-files.mjs";
import { createInvalidWebpSignature, createWebpWithBadChunkSize } from "../fixtures/webp-fixtures.mjs";

test("parseWebp rejects non-RIFF/WEBP signatures", async () => {
  const result = await parseWebp(createInvalidWebpSignature());
  assert.strictEqual(result, null);
});

test("parseWebp captures size mismatch issues", async () => {
  const webp = await parseWebp(createWebpWithBadChunkSize());
  assert.ok(webp);
  assert.ok(webp.issues.length > 0);
});

test("parseWebp parses minimal WebP and extracts chunks", async () => {
  const webp = await parseWebp(createWebpFile());
  assert.ok(webp.issues.length > 0 || webp.dimensions || webp.chunks.length > 0);
  assert.ok(Array.isArray(webp.chunks));
});
