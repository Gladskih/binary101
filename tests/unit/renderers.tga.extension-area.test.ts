"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { renderTgaExtensionArea } from "../../renderers/tga/extension-area.js";
import type { TgaExtensionArea } from "../../analyzers/tga/types.js";

void test("renderTgaExtensionArea renders optional structures when present", () => {
  const ext: TgaExtensionArea = {
    offset: 100,
    size: 495,
    authorName: "Author",
    authorComment: "Comment",
    timestamp: "2025-12-31 23:59:58",
    jobName: "Job",
    jobTime: "1h 2m 3s",
    softwareId: "Binary101",
    softwareVersion: "101a",
    keyColor: 0x11223344,
    pixelAspectRatio: 1,
    gamma: 2.2,
    colorCorrectionTable: { offset: 500, expectedBytes: 1000, truncated: true },
    postageStamp: { offset: 520, width: 2, height: 2, expectedBytes: 14, truncated: false },
    scanLineTable: { offset: 540, expectedBytes: 8, truncated: false },
    attributesType: 1,
    truncated: false
  };
  const html = renderTgaExtensionArea(ext);
  assert.match(html, /Extension area/i);
  assert.match(html, /Author comment/i);
  assert.match(html, /Color correction table/i);
  assert.match(html, /Postage stamp/i);
  assert.match(html, /Scan-line table/i);
  assert.match(html, /Attributes type/i);
});

