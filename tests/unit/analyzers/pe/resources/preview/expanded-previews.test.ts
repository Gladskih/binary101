import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../../../../../analyzers/pe/resources/preview/index.js";
import { knownResourceType } from "../../../../../../analyzers/pe/resources/type-names.js";
import { renderPreviewCell, renderPreviewSummary } from "../../../../../../renderers/pe/resource-preview-cell.js";
import { createPreviewDetailGroup, createPreviewFixture, createPreviewLangEntry,
  createPreviewTree } from "../../../../../helpers/pe-resource-preview-fixture.js";
import { buildFontDirectory, buildLegacyFont } from "../../../../../fixtures/pe-font-resources.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { parseManifestTestXmlDocument } from "../../../../../helpers/manifest-test-parser.js";

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

void test("routes MFC dialog layout and numeric ribbon XML to structured previews", async () => {
  const fixture = createPreviewFixture(512);
  const layout = fixture.appendData(new Uint8Array([0, 0, 10, 0, 20, 0, 30, 0, 40, 0]));
  const ribbon = fixture.appendData(new TextEncoder().encode("<RIBBON_BAR/>"));
  const detail = [
    createPreviewDetailGroup("AFX_DIALOG_LAYOUT", 1,
      createPreviewLangEntry(layout.offset, layout.size)),
    createPreviewDetailGroup(knownResourceType(28)!, 1,
      createPreviewLangEntry(ribbon.offset, ribbon.size))
  ];
  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes),
    createPreviewTree(detail), parseManifestTestXmlDocument);
  const layoutLang = result.detail[0]?.entries[0]?.langs[0];
  const ribbonLang = result.detail[1]?.entries[0]?.langs[0];
  assert.equal(layoutLang?.previewKind, "dialogLayout");
  assert.equal(renderPreviewSummary(layoutLang), "1 layout controls");
  assert.match(renderPreviewCell(layoutLang), /Move X %/);
  assert.equal(ribbonLang?.previewKind, "ribbonXml");
  assert.equal(renderPreviewSummary(ribbonLang), "XML <RIBBON_BAR>");
});

void test("routes WEVT_TEMPLATE through the resource preview and renderer", async () => {
  const fixture = createPreviewFixture(256);
  const bytes = new Uint8Array(16);
  bytes.set(new TextEncoder().encode("CRIM"));
  const view = new DataView(bytes.buffer);
  view.setUint32(4, bytes.length, true);
  view.setUint16(8, 3, true);
  view.setUint16(10, 1, true);
  const range = fixture.appendData(bytes);
  const detail = [createPreviewDetailGroup("WEVT_TEMPLATE", 1,
    createPreviewLangEntry(range.offset, range.size))];
  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes),
    createPreviewTree(detail));
  const lang = result.detail[0]?.entries[0]?.langs[0];
  assert.equal(lang?.previewKind, "wevtTemplate");
  assert.match(renderPreviewCell(lang), /Windows Event manifest v3.1/);
});
