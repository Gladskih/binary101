"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { fontProbes } from "../../../../../analyzers/probes/magic-fonts.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);
const run = (bytes: ArrayLike<number>): string | null => fontProbes.map(p => p(dvFrom(bytes))).find(Boolean) || null;

void test("detects TrueType/OpenType sfnt font signatures", () => {
  assert.strictEqual(run([0x00, 0x01, 0x00, 0x00]), "TrueType/OpenType font (sfnt glyph outlines)");
});

void test("returns null for unknown font bytes", () => {
  assert.strictEqual(run([0x00, 0x01, 0x00]), null);
  assert.strictEqual(run([0x01, 0x00, 0x00, 0x00]), null);
});
