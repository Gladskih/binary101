"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import {
  isOverlayFullyExplainedByNsis,
  renderOverlay,
  renderOverlayPanel
} from "../../../../renderers/pe/overlay.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";

// Use a non-zero range so the test checks the button's decimal offsets separately from hex display text.
const OVERLAY_START = 0x400;
const OVERLAY_SIZE = 0x20;
const OVERLAY_END = OVERLAY_START + OVERLAY_SIZE;
const EMBEDDED_OFFSET = OVERLAY_START + 3;
const DETECTED_ARCHIVE_LABEL = "ZIP archive";

const createPeWithOverlay = (embeddedScanComplete = false): PeWindowsParseResult => {
  const pe = createBasePe();
  pe.overlay = {
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
      ...(embeddedScanComplete
        ? { embeddedScan: { status: "complete" as const, scannedBytes: OVERLAY_SIZE } }
        : {})
    }]
  };
  return pe;
};

const addNsisFinding = (pe: PeWindowsParseResult, followingDataSize = OVERLAY_SIZE): void => {
  pe.packers = {
    reports: [{
      id: "nsis-installer",
      findings: [{
        id: "nsis-installer",
        name: "NSIS installer",
        kind: "installer",
        confidence: "high",
        evidence: ["NSIS verified"],
        compressedHeaderSize: 8,
        firstHeaderOffset: OVERLAY_START,
        flags: 0,
        followingDataSize
      }],
      warnings: []
    }]
  };
};

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

void test("renderOverlay hides an overlay fully explained by verified NSIS data", () => {
  const pe = createPeWithOverlay();
  addNsisFinding(pe);

  assert.equal(isOverlayFullyExplainedByNsis(pe), true);
  assert.equal(renderOverlayPanel(pe), "");
});

void test("renderOverlay keeps overlay UI for partial NSIS coverage", () => {
  const pe = createPeWithOverlay();
  addNsisFinding(pe, OVERLAY_SIZE - 1);

  assert.equal(isOverlayFullyExplainedByNsis(pe), false);
  assert.ok(renderOverlayPanel(pe).includes("Scan embedded payloads"));
});

void test("renderOverlay does not accept an NSIS range with the wrong start", () => {
  const pe = createPeWithOverlay();
  addNsisFinding(pe, OVERLAY_SIZE - 1);
  const finding = pe.packers!.reports[0]!.findings[0]!;
  assert.equal(finding.id, "nsis-installer");
  pe.packers!.reports[0]!.findings[0] = {
    ...finding,
    firstHeaderOffset: OVERLAY_START + 1
  };

  assert.equal(isOverlayFullyExplainedByNsis(pe), false);
});

void test("renderOverlay selects the NSIS report after unrelated reports", () => {
  const pe = createPeWithOverlay();
  addNsisFinding(pe);
  pe.packers!.reports.unshift({ id: "upx", findings: [], warnings: [] });

  assert.equal(isOverlayFullyExplainedByNsis(pe), true);
});

void test("renderOverlay keeps an unmatched second overlay range", () => {
  const pe = createPeWithOverlay();
  pe.overlay!.ranges.push({
    start: OVERLAY_END,
    end: OVERLAY_END + OVERLAY_SIZE,
    size: OVERLAY_SIZE,
    findings: []
  });
  addNsisFinding(pe);

  assert.equal(isOverlayFullyExplainedByNsis(pe), false);
  assert.ok(renderOverlayPanel(pe).includes("True overlay #2"));
});

void test("renderOverlay keeps overlay warnings visible despite full NSIS coverage", () => {
  const pe = createPeWithOverlay();
  pe.overlay!.warnings = ["Overlay warning"];
  addNsisFinding(pe);

  assert.equal(isOverlayFullyExplainedByNsis(pe), false);
  assert.ok(renderOverlayPanel(pe).includes("Overlay warning"));
});
