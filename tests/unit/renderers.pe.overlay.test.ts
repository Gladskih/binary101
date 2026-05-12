"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import { renderOverlay } from "../../renderers/pe/overlay.js";

// Use a non-zero range so the test checks the button's decimal offsets separately from hex display text.
const OVERLAY_START = 0x400;
const OVERLAY_SIZE = 0x20;
const OVERLAY_END = OVERLAY_START + OVERLAY_SIZE;
const EMBEDDED_OFFSET = OVERLAY_START + 3;
const DETECTED_ARCHIVE_LABEL = "ZIP archive";

const createPeWithOverlay = (embeddedScanComplete = false): PeParseResult => ({
  overlay: {
    ranges: [{
      start: OVERLAY_START,
      end: OVERLAY_END,
      size: OVERLAY_SIZE,
      findings: [{
        start: EMBEDDED_OFFSET,
        end: OVERLAY_END,
        size: OVERLAY_END - EMBEDDED_OFFSET,
        detectedType: DETECTED_ARCHIVE_LABEL,
        endDescription: "End is estimated."
      }],
      embeddedScan: embeddedScanComplete
        ? { status: "complete", scannedBytes: OVERLAY_SIZE }
        : undefined
    }]
  }
}) as PeParseResult;

void test("renderOverlay shows downloadable true overlay ranges and detected type", () => {
  const out: string[] = [];
  renderOverlay(createPeWithOverlay(), out);
  const html = out.join("");
  assert.ok(html.includes(DETECTED_ARCHIVE_LABEL));
  assert.ok(html.includes("Unclassified bytes"));
  assert.ok(html.includes("data-pe-overlay-download"));
  assert.ok(html.includes("data-pe-overlay-scan"));
  assert.ok(html.includes("Not scanned."));
  assert.ok(html.includes(`data-overlay-start="${OVERLAY_START}"`));
  assert.ok(html.includes(`data-overlay-end="${OVERLAY_END}"`));
  assert.ok(html.includes(`data-overlay-start="${EMBEDDED_OFFSET}"`));
});

void test("renderOverlay shows scan completion state after manual scan", () => {
  const out: string[] = [];
  renderOverlay(createPeWithOverlay(true), out);
  const html = out.join("");
  assert.ok(html.includes("Embedded payload signature scan complete."));
  assert.ok(!html.includes("Scan embedded payloads"));
});
