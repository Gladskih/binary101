import assert from "node:assert/strict";
import { test } from "node:test";
import { addFontDirectoryPreview } from "../../../../../../analyzers/pe/resources/preview/font-directory.js";
import { buildFontDirectory } from "../../../../../fixtures/pe-font-resources.js";

for (const size of [113, 148]) {
  void test(`reads all FONTDIR entries with a ${size}-byte prefix`, () => {
    const result = addFontDirectoryPreview(buildFontDirectory(size), "FONTDIR");
    assert.equal(result?.preview?.fontDirectory?.entries.length, 2);
    assert.equal(result?.preview?.fontDirectory?.entries[1]?.ordinal, 101);
    assert.equal(result?.preview?.fontDirectory?.entries[0]?.font.faceName, "Sample");
    assert.equal(result?.issues, undefined);
  });
}

void test("warns for every truncated directory prefix and supports empty directories", () => {
  const bytes = buildFontDirectory();
  for (let length = 0; length < bytes.length; length += 1) {
    assert.ok(addFontDirectoryPreview(bytes.subarray(0, length), "FONTDIR")?.issues?.length, `${length}`);
  }
  assert.equal(addFontDirectoryPreview(bytes, "other"), null);
  assert.deepEqual(addFontDirectoryPreview(new Uint8Array(2), "FONTDIR")?.preview?.fontDirectory?.entries, []);
});
