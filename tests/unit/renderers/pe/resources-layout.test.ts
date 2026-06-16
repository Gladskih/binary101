"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeResources } from "../../../../analyzers/pe/resources/index.js";
import { parseMuiResourceConfiguration } from "../../../../analyzers/pe/resources/mui-config.js";
import { renderResources } from "../../../../renderers/pe/resources.js";
import {
  buildMuiResourceConfigurationFixture
} from "../../../fixtures/pe-mui-resource-config-fixture.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const encoder = new TextEncoder();
// Microsoft documents 0x409 / 1033 as English (United States) LangID.
// Source: https://learn.microsoft.com/en-us/windows/win32/intl/resource-utilities
const WINDOWS_EN_US_LANG_ID = 0x0409;
// Windows code page identifier for UTF-8. Source:
// https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
const WINDOWS_UTF8_CODE_PAGE = 65001;

type ResourceDetail = PeResources["detail"][number];
type ResourceLang = ResourceDetail["entries"][number]["langs"][number];

const createPreviewLang = (
  preview: Partial<ResourceLang>
): ResourceLang => ({
  lang: WINDOWS_EN_US_LANG_ID,
  size: encoder.encode(JSON.stringify(preview)).length,
  // The zeroed PE metadata fields are incidental; this test exercises row layout only.
  codePage: 0,
  dataRVA: 0,
  dataFileOffset: 0,
  reserved: 0,
  ...preview
});

const createPreviewGroup = (
  typeName: string,
  lang: ResourceLang
): ResourceDetail => ({
  typeName,
  entries: [{ id: null, name: `fixture-${typeName}`, langs: [lang] }]
});

const createInfPreview = (): NonNullable<ResourceLang["infPreview"]> => {
  const signatureText = "Signature";
  const lines = ["[Version]", `${signatureText}="$CHICAGO$"`];
  const signatureLine = `${signatureText}="$CHICAGO$"`;
  const entry = {
    line: lines.indexOf(signatureLine) + 1,
    kind: "directive" as const,
    key: signatureText,
    value: "\"$CHICAGO$\""
  };
  const entries = [entry];
  return {
    sections: [
      {
        name: "Version",
        entries
      }
    ],
    commentCount: lines.filter(line => line.startsWith(";")).length,
    entryCount: entries.length
  };
};

void test("renderResources gives large structured resource previews the full table width", () => {
  const infPreview = createInfPreview();
  const resources: PeResources = {
    top: [],
    detail: [
      createPreviewGroup("MUI", createPreviewLang({
        previewKind: "muiConfig",
        muiConfig: expectDefined(parseMuiResourceConfiguration(
          buildMuiResourceConfigurationFixture()
        ))
      })),
      createPreviewGroup("UIFILE", createPreviewLang({
        previewKind: "text",
        textPreview: "<duixml><element id=\"root\" /></duixml>",
        previewFields: [{ label: "Detected", value: "XML/Text (heuristic)" }]
      })),
      createPreviewGroup("REGINST", createPreviewLang({
        codePage: WINDOWS_UTF8_CODE_PAGE,
        previewKind: "inf",
        infPreview
      })),
      createPreviewGroup("TYPELIB", createPreviewLang({
        previewKind: "typeLibrary",
        typeLibrary: {
          format: "placeholder",
          headerFields: [{ label: "Note", value: "MUI placeholder payload" }],
          segments: []
        }
      }))
    ]
  };
  const out: string[] = [];

  renderResources(resources, out);
  const html = out.join("");

  assert.equal(html.match(/peResourcePreviewWideRow/gu)?.length, resources.detail.length);
  assert.match(html, /MUI resource config/);
  assert.match(html, /MUI resource configuration/);
  assert.match(html, /XML\/Text \(heuristic\)/);
  assert.match(html, /&lt;duixml>/);
  assert.match(html, new RegExp(`${infPreview.sections.length} INF sections`));
  assert.match(html, /placeholder type library/);
});
