"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { detectBinaryType, parseForUi } from "../../analyzers/index.js";
import { createTgaFile } from "../fixtures/image-sample-files.js";
import { createTgaV2WithExtensionAndDeveloperArea } from "../fixtures/tga-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";

void test("detectBinaryType labels TGA files by extension", async () => {
  const detection = await detectBinaryType(createTgaFile());
  assert.match(detection, /^TGA image/);
  assert.match(detection, /1x1/);
});

void test("detectBinaryType labels TGA v2.0 files by footer signature (even when renamed)", async () => {
  const file = createTgaV2WithExtensionAndDeveloperArea();
  const renamed = new MockFile(file.data, "renamed.bin", "application/octet-stream");
  const detection = await detectBinaryType(renamed);
  assert.match(detection, /^TGA image/);
});

void test("parseForUi parses TGA files by extension", async () => {
  const result = await parseForUi(createTgaFile());
  assert.strictEqual(result.analyzer, "tga");
  assert.ok(result.parsed);
});

void test("parseForUi parses TGA v2.0 files by footer signature", async () => {
  const file = createTgaV2WithExtensionAndDeveloperArea();
  const renamed = new MockFile(file.data, "renamed.bin", "application/octet-stream");
  const result = await parseForUi(renamed);
  assert.strictEqual(result.analyzer, "tga");
  assert.ok(result.parsed);
  assert.strictEqual(result.parsed.version, "2.0");
});

