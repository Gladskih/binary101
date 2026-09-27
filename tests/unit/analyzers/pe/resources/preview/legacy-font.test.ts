import assert from "node:assert/strict";
import { test } from "node:test";
import { addLegacyFontPreview } from "../../../../../../analyzers/pe/resources/preview/legacy-font.js";
import { buildLegacyFont } from "../../../../../fixtures/pe-font-resources.js";

void test("reads FNT header metadata and names at validated offsets", () => {
  const result = addLegacyFontPreview(buildLegacyFont());
  assert.equal(result?.preview?.legacyFont?.faceName, "Sample");
  assert.equal(result?.preview?.legacyFont?.pointSize, 12);
  assert.equal(result?.preview?.legacyFont?.weight, 400);
  assert.equal(result?.issues, undefined);
  assert.equal(result?.preview?.previewKind, "legacyFont");
});

void test("uses the shorter FNT v2 header and bounds names by the declared file size", () => {
  const bytes = buildLegacyFont(0x200).slice(0, 128);
  const view = new DataView(bytes.buffer);
  view.setUint32(2, 128, true);
  view.setUint32(105, 118, true);
  view.setUint32(113, 125, true);
  bytes.set(new TextEncoder().encode("Short\0"), 118);
  assert.equal(addLegacyFontPreview(bytes)?.issues, undefined);
  assert.equal(addLegacyFontPreview(bytes)?.preview?.legacyFont?.faceName, "Short");
  view.setUint32(2, 123, true);
  assert.deepEqual(addLegacyFontPreview(bytes)?.issues, [
    "FONT bitmap offset is outside the resource.",
    "Font name is not NUL-terminated within the resource."
  ]);
  view.setUint32(2, 118, true);
  assert.ok(!addLegacyFontPreview(bytes)?.issues?.includes("FONT declared file size is smaller than its header."));
  assert.deepEqual(addLegacyFontPreview(bytes.subarray(0, 113))?.issues, ["FONT FNT header is truncated."]);
});

void test("reports precise size, device offset and character-range warnings", () => {
  const bytes = buildLegacyFont();
  const view = new DataView(bytes.buffer);
  view.setUint32(2, bytes.length + 1, true);
  assert.deepEqual(addLegacyFontPreview(bytes)?.issues, ["FONT declared file size exceeds the resource."]);
  view.setUint32(2, bytes.length, true);
  view.setUint32(101, 6, true);
  assert.deepEqual(addLegacyFontPreview(bytes)?.issues, ["FONT name offset overlaps its header."]);
  view.setUint32(101, 0, true);
  bytes[95] = bytes[96]!;
  view.setUint32(113, bytes.length, true);
  assert.equal(addLegacyFontPreview(bytes)?.issues, undefined);
  bytes[95] = 200;
  assert.deepEqual(addLegacyFontPreview(bytes)?.issues, ["FONT character range is reversed."]);
  view.setUint32(2, 147, true);
  assert.equal(addLegacyFontPreview(bytes)?.issues?.[0], "FONT declared file size is smaller than its header.");
});

void test("warns on truncation and out-of-bounds name offsets", () => {
  const bytes = buildLegacyFont();
  assert.ok(addLegacyFontPreview(bytes.subarray(0, 120))?.issues?.length);
  new DataView(bytes.buffer).setUint32(105, 0xffffffff, true);
  assert.ok(addLegacyFontPreview(bytes)?.issues?.length);
  assert.equal(addLegacyFontPreview(new Uint8Array()), null);
});

void test("reads version 2 fonts, device names and validates declared sizes and character ranges", () => {
  const bytes = buildLegacyFont(0x200);
  const view = new DataView(bytes.buffer);
  view.setUint32(101, 155, true);
  bytes.set(new TextEncoder().encode("Dev\0"), 155);
  assert.equal(addLegacyFontPreview(bytes)?.preview?.legacyFont?.deviceName, "Dev");
  assert.equal(addLegacyFontPreview(bytes)?.issues, undefined);
  view.setUint32(2, 0xffffffff, true);
  assert.match(addLegacyFontPreview(bytes)?.issues?.[0] ?? "", /exceeds/);
  view.setUint32(2, 1, true);
  assert.match(addLegacyFontPreview(bytes)?.issues?.[0] ?? "", /smaller/);
  view.setUint32(2, bytes.length, true);
  view.setUint32(105, 6, true);
  view.setUint32(113, 0xffffffff, true);
  bytes[95] = 200;
  assert.ok(addLegacyFontPreview(bytes)?.issues?.some(issue => issue.includes("overlaps")));
  assert.ok(addLegacyFontPreview(bytes)?.issues?.some(issue => issue.includes("reversed")));
  assert.ok(addLegacyFontPreview(bytes)?.issues?.some(issue => issue.includes("bitmap")));
  view.setUint16(0, 0x100, true);
  assert.equal(addLegacyFontPreview(bytes), null);
  assert.ok(addLegacyFontPreview(buildLegacyFont().subarray(0, 100))?.issues?.length);
});
