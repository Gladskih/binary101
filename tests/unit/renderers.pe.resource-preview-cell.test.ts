"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPreviewCell } from "../../renderers/pe/resource-preview-cell.js";
import type { ResourceLangWithPreview } from "../../analyzers/pe/resources-preview-types.js";

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
      templateKind: "standard",
      title: "Settings",
      menu: null,
      className: null,
      x: 0,
      y: 0,
      width: 100,
      height: 80,
      style: 0,
      exStyle: 0,
      font: null,
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
