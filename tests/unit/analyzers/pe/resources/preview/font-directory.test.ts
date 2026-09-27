import { assertResourcePrefixWarnings } from "../../../../../helpers/resource-prefix-warnings.js";
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
    assert.equal(result?.preview?.fontDirectory?.entries[0]?.ordinal, 100);
    assert.equal(result?.preview?.fontDirectory?.entries[0]?.font.pointSize, 12);
    assert.equal(result?.preview?.fontDirectory?.headerSize, size);
    assert.equal(result?.preview?.previewKind, "fontDirectory");
    assert.equal(result?.issues, undefined);
  });
}

void test("warns for every truncated directory prefix and supports empty directories", () => {
  const bytes = buildFontDirectory();
  assertResourcePrefixWarnings(bytes, prefix => addFontDirectoryPreview(prefix, "FONTDIR"));
  assert.equal(addFontDirectoryPreview(bytes, "other"), null);
  assert.deepEqual(addFontDirectoryPreview(new Uint8Array(2), "FONTDIR")?.preview?.fontDirectory?.entries, []);
});

void test("retains a complete fixed prefix when names are missing and gives precise diagnostics", () => {
  assert.deepEqual(addFontDirectoryPreview(new Uint8Array(), "FONTDIR")?.issues,
    ["FONTDIR count is truncated."]);
  assert.deepEqual(addFontDirectoryPreview(buildFontDirectory().subarray(0, 100), "FONTDIR")?.issues, [
    "FONTDIR entry header is truncated.", "FONTDIR contains unparsed or truncated entry bytes."
  ]);
  const partial = addFontDirectoryPreview(buildFontDirectory().subarray(0, 117), "FONTDIR");
  assert.equal(partial?.preview?.fontDirectory?.entries.length, 1);
  assert.equal(partial?.preview?.fontDirectory?.entries[0]?.ordinal, 100);
  assert.ok(partial?.issues?.includes("Font name offset is outside the resource."));
});

void test("reports ambiguous layouts instead of guessing silently", () => {
  // One entry can structurally fit both prefixes: the longer header overlaps a
  // long device name in the documented layout and both end with two NUL bytes.
  const bytes = new Uint8Array(154);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 1, true);
  bytes.fill(65, 117, 152);
  assert.match(addFontDirectoryPreview(bytes, "FONTDIR")?.issues?.[0] ?? "", /ambiguous/);
});
