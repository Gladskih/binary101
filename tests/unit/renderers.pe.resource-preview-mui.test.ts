"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPreviewCell, renderPreviewSummary } from "../../renderers/pe/resource-preview-cell.js";
import { parseMuiResourceConfiguration } from "../../analyzers/pe/resources/mui-config.js";
import { buildMuiResourceConfigurationFixture } from "../fixtures/pe-mui-resource-config-fixture.js";
import { expectDefined } from "../helpers/expect-defined.js";
import type { ResourceLangWithPreview } from "../../analyzers/pe/resources/preview/types.js";

void test("renderPreviewCell renders structured MUI resource configuration previews", () => {
  const langEntry: ResourceLangWithPreview = {
    lang: 1033,
    size: 160,
    codePage: 0,
    dataRVA: 0x1000,
    dataFileOffset: 0x1000,
    reserved: 0,
    previewKind: "muiConfig",
    muiConfig: expectDefined(parseMuiResourceConfiguration(buildMuiResourceConfigurationFixture()))
  };
  const html = renderPreviewCell(langEntry);

  assert.equal(renderPreviewSummary(langEntry), "MUI resource config");
  assert.match(html, /MUI resource configuration/);
  assert.match(html, /Language-specific MUI resource/);
  assert.match(html, /en-US\\fixture\.dll\.mui/);
  assert.match(html, /a0a1a2a3 a4a5a6a7 a8a9aaab acadaeaf/);
  assert.match(html, /#24 \(MANIFEST\)/);
  assert.match(html, /#16 \(VERSION\)/);
});
