import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../../../../../analyzers/pe/resources/preview/index.js";
import { knownResourceType } from "../../../../../../analyzers/pe/resources/type-names.js";
import { renderPreviewCell, renderPreviewSummary } from "../../../../../../renderers/pe/resource-preview-cell.js";
import { createPreviewDetailGroup, createPreviewFixture, createPreviewLangEntry,
  createPreviewTree } from "../../../../../helpers/pe-resource-preview-fixture.js";
import { buildFontDirectory, buildLegacyFont } from "../../../../../fixtures/pe-font-resources.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

void test("routes FONTDIR, FONT and numeric MFC types through the browser preview contract", async () => {
  const fixture = createPreviewFixture(2048);
  const payloads = [buildFontDirectory(), buildLegacyFont(), new Uint8Array(2),
    new Uint8Array([1, 0, 16, 0, 15, 0, 1, 0, 100, 0])];
  const names = ["FONTDIR", "FONT", knownResourceType(240), knownResourceType(241)];
  const detail = payloads.map((payload, index) => {
    const range = fixture.appendData(payload);
    return createPreviewDetailGroup(names[index]!, index === 1 ? 100 : 1,
      createPreviewLangEntry(range.offset, range.size));
  });

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), createPreviewTree(detail));
  const langs = result.detail.map(group => group.entries[0]!.langs[0]!);

  assert.deepEqual(langs.map(lang => lang.previewKind), ["fontDirectory", "legacyFont", "dialogInit", "toolbar"]);
  assert.match(renderPreviewCell(langs[0]), /FONT #100/);
  assert.match(renderPreviewCell(langs[0]), /missing FONT #101/);
  assert.equal(renderPreviewSummary(langs[0]), "2 fonts");
  assert.equal(renderPreviewSummary(langs[1]), "FNT Sample");
  assert.match(renderPreviewCell(langs[2]), /MFC DLGINIT/);
  assert.equal(renderPreviewSummary(langs[2]), "0 initialization records");
  assert.match(renderPreviewCell(langs[3]), /#100/);
  assert.equal(renderPreviewSummary(langs[3]), "1 toolbar items");
});
