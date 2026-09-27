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
});

void test("warns on truncation and out-of-bounds name offsets", () => {
  const bytes = buildLegacyFont();
  assert.ok(addLegacyFontPreview(bytes.subarray(0, 120))?.issues?.length);
  new DataView(bytes.buffer).setUint32(105, 0xffffffff, true);
  assert.ok(addLegacyFontPreview(bytes)?.issues?.length);
  assert.equal(addLegacyFontPreview(new Uint8Array()), null);
});
