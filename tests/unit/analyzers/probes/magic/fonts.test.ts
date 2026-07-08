"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { fontProbes } from "../../../../../analyzers/probes/magic-fonts.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);
const run = (bytes: ArrayLike<number>): string | null => fontProbes.map(p => p(dvFrom(bytes))).find(Boolean) || null;
const fontCollection = (): Uint8Array => {
  const bytes = new Uint8Array(76);
  const view = new DataView(bytes.buffer);
  bytes.set([0x74, 0x74, 0x63, 0x66]);
  view.setUint32(4, 0x00020000, false);
  view.setUint32(8, 2, false);
  view.setUint32(12, 20, false);
  view.setUint32(16, 48, false);
  for (const offset of [20, 48]) {
    view.setUint32(offset, 0x00010000, false);
    view.setUint16(offset + 4, 1, false);
    bytes.set([0x6e, 0x61, 0x6d, 0x65], offset + 12);
  }
  return bytes;
};

void test("detects TrueType/OpenType sfnt font signatures", () => {
  assert.strictEqual(run([0x00, 0x01, 0x00, 0x00]), "TrueType/OpenType font (sfnt glyph outlines)");
});

void test("detects structurally valid OpenType font collections", () => {
  assert.strictEqual(
    run(fontCollection()),
    "OpenType font collection (TTC/OTC shared font tables)"
  );
  const versionOne = fontCollection();
  new DataView(versionOne.buffer).setUint32(4, 0x00010000, false);
  assert.strictEqual(run(versionOne), "OpenType font collection (TTC/OTC shared font tables)");
});

void test("rejects malformed or truncated OpenType font collections", () => {
  const wrongVersion = fontCollection();
  const noFonts = fontCollection();
  const badOffset = fontCollection();
  const badSfnt = fontCollection();
  const truncatedDirectory = fontCollection();
  new DataView(wrongVersion.buffer).setUint32(4, 0x00030000, false);
  new DataView(noFonts.buffer).setUint32(8, 0, false);
  new DataView(badOffset.buffer).setUint32(12, badOffset.length, false);
  new DataView(badSfnt.buffer).setUint32(20, 0x12345678, false);
  new DataView(truncatedDirectory.buffer).setUint16(24, 4, false);

  assert.strictEqual(run(fontCollection().slice(0, 11)), null);
  assert.strictEqual(run(wrongVersion), null);
  assert.strictEqual(run(noFonts), null);
  assert.strictEqual(run(badOffset), null);
  assert.strictEqual(run(badSfnt), null);
  assert.strictEqual(run(truncatedDirectory), null);
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
