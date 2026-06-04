"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderPreviewCell,
  renderPreviewSummary
} from "../../renderers/pe/resource-preview-cell.js";
import type { ResourceLangWithPreview } from "../../analyzers/pe/resources/preview/types.js";

const encoder = new TextEncoder();
// Microsoft documents 0x409 / 1033 as English (United States) LangID.
// Source: https://learn.microsoft.com/en-us/windows/win32/intl/resource-utilities
const WINDOWS_EN_US_LANG_ID = 0x0409;

const createBaseLang = (
  preview: Partial<ResourceLangWithPreview> = {}
): ResourceLangWithPreview => ({
  lang: WINDOWS_EN_US_LANG_ID,
  size: encoder.encode(JSON.stringify(preview)).length,
  // The zeroed PE metadata fields are incidental; these tests exercise preview rendering only.
  codePage: 0,
  dataRVA: 0,
  reserved: 0,
  ...preview
});

const createInfPreview = (): NonNullable<ResourceLangWithPreview["infPreview"]> => {
  const addRegText = "AddReg=RegAll";
  const lines = ["[RegDll]", addRegText];
  const entries = [
    {
      line: lines.indexOf(addRegText) + 1,
      kind: "directive" as const,
      key: "AddReg",
      value: "RegAll"
    }
  ];
  return {
    sections: [{ name: "RegDll", entries }],
    commentCount: lines.filter(line => line.startsWith(";")).length,
    entryCount: entries.length
  };
};

void test("renderPreviewCell renders REGINST INF previews", () => {
  const infPreview = createInfPreview();
  const lang = createBaseLang({
    previewKind: "inf",
    infPreview
  });

  const html = renderPreviewCell(lang);

  assert.equal(renderPreviewSummary(lang), `${infPreview.sections.length} INF sections`);
  assert.match(html, /RegDll/);
  assert.match(html, /AddReg/);
});

void test("renderPreviewCell renders generic XML trees", () => {
  const lang = createBaseLang({
    previewKind: "xml",
    textPreview: "<root><child>value</child></root>",
    xmlTree: {
      name: "root",
      attributes: [],
      text: null,
      children: [{ name: "child", attributes: [], text: "value", children: [] }]
    }
  });

  const html = renderPreviewCell(lang);

  assert.equal(renderPreviewSummary(lang), "XML <root>");
  assert.match(html, /Parsed XML tree/);
  assert.match(html, /&lt;child&gt;/);
  assert.match(html, /&lt;root&gt;/);
});

void test("renderPreviewCell renders TYPELIB previews", () => {
  const segmentName = "TypeInfoTab";
  const typeInfoNames = ["fixture-library", "fixture-interface"];
  // ReactOS/Wine MSFT_Header is 0x54 bytes and MSFT_SegDir has 15 0x10-byte entries.
  // Source: https://doxygen.reactos.org/d1/daf/typelib__struct_8h_source.html
  const firstSegmentPayloadOffset = 0x54 + 15 * 0x10;
  const lang = createBaseLang({
    previewKind: "typeLibrary",
    typeLibrary: {
      format: "MSFT",
      headerFields: [{ label: "Type infos", value: String(typeInfoNames.length) }],
      segments: [
        { name: segmentName, offset: firstSegmentPayloadOffset, length: segmentName.length }
      ]
    }
  });

  const html = renderPreviewCell(lang);

  assert.equal(renderPreviewSummary(lang), "MSFT type library");
  assert.match(html, /MSFT type library/);
  assert.match(html, /TypeInfoTab/);
  // 0x144 is the first segment payload offset above, rendered as eight hex digits.
  assert.match(html, /0x00000144/);
});
