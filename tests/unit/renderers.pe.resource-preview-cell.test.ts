"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPreviewCell } from "../../renderers/pe/resource-preview-cell.js";
import type { ResourceLangWithPreview } from "../../analyzers/pe/resources/preview/types.js";
import {
  createManifestInfoFixture,
  createManifestValidationFixture,
  createManifestTextFixture
} from "../fixtures/pe-manifest-preview-fixture.js";

// IMAGE_FILE_HEADER.Machine values are defined by the PE/COFF spec and winnt.h.
const AMD64_MACHINE = 0x8664;

const createBaseLang = (): ResourceLangWithPreview => ({
  lang: 1033,
  size: 64,
  codePage: 0,
  dataRVA: 0,
  reserved: 0
});

void test("renderPreviewCell renders structured dialog, menu, accelerator and summary previews", () => {
  const dialogHtml = renderPreviewCell({
    ...createBaseLang(),
    previewKind: "dialog",
    dialogPreview: {
      templateKind: "extended",
      title: "Settings",
      menu: "&File",
      className: "CustomDialog",
      x: 0,
      y: 0,
      width: 100,
      height: 80,
      style: 0,
      exStyle: 0,
      font: {
        pointSize: 9,
        weight: 400,
        italic: false,
        charset: 1,
        typeface: "MS Shell Dlg"
      },
      controls: [
        { id: 100, kind: "BUTTON", title: "OK", x: 10, y: 10, width: 30, height: 12, style: 0, exStyle: 0 }
      ]
    }
  });
  const menuHtml = renderPreviewCell({
    ...createBaseLang(),
    previewKind: "menu",
    menuPreview: {
      templateKind: "standard",
      helpId: null,
      items: [{ text: "File", id: null, type: 0, state: null, flags: ["popup"], children: [{ text: "Open", id: 100, type: 0, state: null, flags: [], children: [] }] }]
    }
  });
  const acceleratorHtml = renderPreviewCell({
    ...createBaseLang(),
    previewKind: "accelerator",
    acceleratorPreview: {
      entries: [{ id: 100, key: "O", modifiers: ["Ctrl"], flags: ["Ctrl", "VirtualKey"] }]
    }
  });
  const summaryHtml = renderPreviewCell({
    ...createBaseLang(),
    previewKind: "summary",
    previewFields: [{ label: "Detected", value: "PNG (heuristic)" }]
  });

  assert.match(dialogHtml, /Settings/);
  assert.match(dialogHtml, /BUTTON/);
  assert.match(dialogHtml, /DLGTEMPLATEEX/);
  assert.match(dialogHtml, /Menu: &File/);
  assert.match(dialogHtml, /Class: CustomDialog/);
  assert.match(dialogHtml, /Font: 9pt MS Shell Dlg/);
  assert.match(dialogHtml, /background:var\(--card\)/);
  assert.match(dialogHtml, /background:var\(--bg\)/);
  assert.match(dialogHtml, /color:var\(--text\)/);
  assert.doesNotMatch(dialogHtml, /rgba\(255,255,255/i);
  assert.doesNotMatch(dialogHtml, /#f8fafc|#e5e7eb/i);
  assert.match(menuHtml, /File/);
  assert.match(menuHtml, /Open/);
  assert.match(acceleratorHtml, /Ctrl\+O/);
  assert.match(summaryHtml, /PNG \(heuristic\)/);
});

void test("renderPreviewCell renders audio and font inline previews", () => {
  const audioHtml = renderPreviewCell({
    ...createBaseLang(),
    previewKind: "audio",
    previewDataUrl: "data:audio/wav;base64,AAAA",
    previewMime: "audio/wav"
  });
  const fontHtml = renderPreviewCell({
    ...createBaseLang(),
    previewKind: "font",
    previewDataUrl: "data:font/ttf;base64,AAAA",
    previewMime: "font/ttf",
    previewFields: [{ label: "Detected", value: "TrueType font (heuristic)" }]
  });

  assert.match(audioHtml, /<audio controls/);
  assert.match(fontHtml, /@font-face/);
  assert.match(fontHtml, /TrueType font \(heuristic\)/);
});

void test("renderPreviewCell renders grouped VERSION details with human-readable translations", () => {
  const versionHtml = renderPreviewCell({
    ...createBaseLang(),
    previewKind: "version",
    versionInfo: {
      fileVersionString: "1.2.3.4",
      productVersionString: "5.6.7.8",
      translations: [
        { languageId: 1033, codePage: 1200 },
        { languageId: 1031, codePage: 1200 }
      ],
      stringValues: [
        { table: "040904B0", key: "CompanyName", value: "Binary101" },
        { table: "040904B0", key: "FileDescription", value: "PE resource showcase" },
        { table: "040904B0", key: "FileVersion", value: "1.2.3.4" },
        { table: "040904B0", key: "ProductVersion", value: "5.6.7.8" }
      ]
    }
  });

  assert.match(versionHtml, /Fixed version info/);
  assert.strictEqual(versionHtml.match(/FileVersion/g)?.length, 1);
  assert.strictEqual(versionHtml.match(/ProductVersion/g)?.length, 1);
  assert.match(versionHtml, /English \(United States\)/);
  assert.match(versionHtml, /German \(Germany\)/);
  assert.match(versionHtml, /Declared translations/);
  assert.match(versionHtml, /CompanyName/);
  assert.match(versionHtml, /Binary101/);
  assert.doesNotMatch(versionHtml, /040904B0/);
});

void test("renderPreviewCell renders parsed manifest metadata alongside text previews", () => {
  const manifestInfo = createManifestInfoFixture({
    processorArchitecture: "amd64",
    requestedExecutionLevel: "requireAdministrator",
    supportedArchitectures: ["amd64", "arm64"]
  });
  const manifestHtml = renderPreviewCell({
    ...createBaseLang(),
    previewKind: "text",
    textPreview: createManifestTextFixture(),
    manifestInfo,
    manifestValidation: createManifestValidationFixture(
      AMD64_MACHINE,
      { processorArchitecture: "amd64" }
    )
  });

  assert.match(manifestHtml, /Manifest cross-check/);
  assert.match(manifestHtml, /Consistent/);
  assert.match(manifestHtml, /Parsed tree/);
  assert.match(manifestHtml, /Expand all/);
  assert.match(manifestHtml, /Copy manifest XML/);
  assert.match(manifestHtml, new RegExp(String(manifestInfo.assemblyName)));
  assert.match(manifestHtml, /supportedArchitectures/);
  assert.match(manifestHtml, /amd64 arm64/);
  assert.match(manifestHtml, /requireAdministrator/);
  assert.match(manifestHtml, /uiAccess/);
});
