import assert from "node:assert/strict";
import { test } from "node:test";
import { validateFontReferences } from "../../../../../../analyzers/pe/resources/preview/font-reference-validation.js";
import { addFontDirectoryPreview } from "../../../../../../analyzers/pe/resources/preview/font-directory.js";
import { addLegacyFontPreview } from "../../../../../../analyzers/pe/resources/preview/legacy-font.js";
import { buildFontDirectory, buildLegacyFont } from "../../../../../fixtures/pe-font-resources.js";
import { createPreviewLangEntry } from "../../../../../helpers/pe-resource-preview-fixture.js";
import type { ResourceDetailGroup } from "../../../../../../analyzers/pe/resources/preview/types.js";

void test("associates FONTDIR ordinals with FONT entries and reports missing or differing metadata", () => {
  const directory = { ...createPreviewLangEntry(), ...addFontDirectoryPreview(buildFontDirectory(), "FONTDIR")?.preview };
  const font = { ...createPreviewLangEntry(), ...addLegacyFontPreview(buildLegacyFont())?.preview };
  const detail: ResourceDetailGroup[] = [
    { typeName: "FONTDIR", entries: [{ id: 1, name: null, langs: [directory] }] },
    { typeName: "FONT", entries: [{ id: 100, name: null, langs: [font] }] }
  ];
  assert.deepEqual(validateFontReferences(detail)[0]?.entries[0]?.langs[0]?.previewIssues,
    ["FONTDIR references missing FONT #101."]);
  const changed = { ...font, legacyFont: { ...font.legacyFont!, faceName: "changed" } };
  detail[1]!.entries.push({ id: 101, name: null, langs: [changed] });
  assert.match(validateFontReferences(detail)[0]?.entries[0]?.langs[0]?.previewIssues?.[0] ?? "", /differs/);
  assert.equal(directory.previewIssues, undefined);
  assert.deepEqual(validateFontReferences([]), []);
});
