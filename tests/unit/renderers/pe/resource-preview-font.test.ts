import assert from "node:assert/strict";
import { test } from "node:test";
import { renderFontDirectoryPreview, renderLegacyFontPreview } from "../../../../renderers/pe/resource-preview-font.js";
import { readFontHeader } from "../../../../analyzers/pe/resources/preview/font-header.js";
import { buildLegacyFont } from "../../../fixtures/pe-font-resources.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

void test("renders linked ordinals and font metadata in escaped semantic tables", () => {
  const font = { ...expectDefined(readFontHeader(buildLegacyFont(), 0)), faceName: "<Sample>",
    deviceName: "device", italic: true, underline: true, strikeOut: true };
  const html = renderFontDirectoryPreview({ headerSize: 113, entries: [{ ordinal: 100, font }] });
  assert.match(html, /FONT #100/);
  assert.match(html, /&lt;Sample>/);
  assert.match(html, /italic, underline, strikeout/);
  assert.match(html, /<thead>/);
  assert.match(renderLegacyFontPreview({ ...font, italic: false, underline: false,
    strikeOut: false, deviceName: "" }), /Fixture copyright/);
  assert.match(renderFontDirectoryPreview({ headerSize: 113, entries: [] }), /0 fonts/);
});
