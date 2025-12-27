"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { imageProbes } from "../../analyzers/probes/magic-images.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);
const run = (bytes: ArrayLike<number>): string | null => imageProbes.map(p => p(dvFrom(bytes))).find(Boolean) || null;

void test("detects PNG, JPEG, ICO and TIFF signatures", () => {
  assert.strictEqual(run([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), "PNG image");
  const jfif = [0xff, 0xd8, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00];
  assert.strictEqual(run(jfif), "JPEG image (JFIF)");
  const ico = [
    0x00,
    0x00,
    0x01,
    0x00,
    0x01,
    0x00,
    0x01,
    0x01,
    0x00,
    0x00,
    0x01,
    0x00,
    0x20,
    0x00,
    0x04,
    0x00,
    0x00,
    0x00,
    0x16,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00
  ];
  assert.strictEqual(run(ico), "ICO/CUR icon image");
  assert.strictEqual(run([0x49, 0x49, 0x2a, 0x00]), "TIFF image");
});

void test("detects GIF variants and animated cursors", () => {
  assert.strictEqual(run([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]), "GIF image");
  assert.strictEqual(
    run([0x52, 0x49, 0x46, 0x46, 0x24, 0x00, 0x00, 0x00, 0x41, 0x43, 0x4f, 0x4e]),
    "Windows animated cursor (ANI)"
  );
});

void test("returns null for insufficient bytes", () => {
  assert.strictEqual(run([0xff]), null);
});
