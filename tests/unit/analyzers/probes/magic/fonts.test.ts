"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { fontProbes } from "../../../../../analyzers/probes/magic-fonts.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);
const run = (bytes: ArrayLike<number>): string | null => fontProbes.map(p => p(dvFrom(bytes))).find(Boolean) || null;

void test("detects TrueType/OpenType sfnt font signatures", () => {
  assert.strictEqual(run([0x00, 0x01, 0x00, 0x00]), "TrueType/OpenType font (sfnt glyph outlines)");
});

void test("detects WOFF2 web font signatures", () => {
  assert.strictEqual(
    run([0x77, 0x4f, 0x46, 0x32]),
    "Web Open Font Format 2 font (WOFF2 compressed web font)"
  );
});

void test("detects WOFF web font signatures", () => {
  assert.strictEqual(
    run([0x77, 0x4f, 0x46, 0x46]),
    "Web Open Font Format font (WOFF compressed web font)"
  );
});

void test("returns null for unknown font bytes", () => {
  assert.strictEqual(run([0x00, 0x01, 0x00]), null);
  assert.strictEqual(run([0x01, 0x00, 0x00, 0x00]), null);
});
