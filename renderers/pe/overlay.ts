"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { PeOverlayRange } from "../../analyzers/pe/overlay.js";
import { renderDownloadButton } from "../download-button.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

export const PE_OVERLAY_PANEL_ID = "peOverlayPanel";

const getUnexplainedOverlaySize = (pe: PeParseResult): number =>
  pe.overlay?.ranges.reduce((total, range) => total + range.size, 0) ?? 0;

const renderOverlayDownloadButton = (start: number, end: number, label: string): string =>
  renderDownloadButton(label, [
    ["data-pe-overlay-download"],
    ["data-overlay-start", start],
    ["data-overlay-end", end]
  ]);

const overlayScanElementId = (range: PeOverlayRange, suffix: string): string =>
  `peOverlayScan_${range.start}_${range.end}_${suffix}`;

const renderScanControls = (range: PeOverlayRange): string => {
  if (range.embeddedScan?.status === "complete") {
    return `<div class="smallNote">Embedded payload signature scan complete.</div>`;
  }
  return `<div class="peOverlayScanControls">` +
    `<button type="button" class="tableButton" id="${overlayScanElementId(range, "button")}" ` +
    `data-pe-overlay-scan data-overlay-start="${range.start}" data-overlay-end="${range.end}">` +
    `Scan embedded payloads</button>` +
    `<button type="button" class="tableButton" id="${overlayScanElementId(range, "cancel")}" ` +
    `data-pe-overlay-scan-cancel hidden>Cancel</button>` +
    `<progress id="${overlayScanElementId(range, "progress")}" hidden></progress>` +
    `<span class="smallNote" id="${overlayScanElementId(range, "text")}">Not scanned.</span>` +
    `</div>`;
};

const getCoverageSegments = (range: PeOverlayRange): Array<{
  start: number;
  end: number;
  kind: "found" | "unknown";
}> => {
  const findings = range.findings.slice().sort((left, right) => left.start - right.start || left.end - right.end);
  const segments: Array<{ start: number; end: number; kind: "found" | "unknown" }> = [];
  let cursor = range.start;
  for (const finding of findings) {
    if (finding.start > cursor) segments.push({ start: cursor, end: finding.start, kind: "unknown" });
    segments.push({ start: Math.max(range.start, finding.start), end: Math.min(range.end, finding.end), kind: "found" });
    cursor = Math.max(cursor, finding.end);
  }
  if (cursor < range.end) segments.push({ start: cursor, end: range.end, kind: "unknown" });
  return segments.filter(segment => segment.end > segment.start);
};

const renderCoverageBar = (range: PeOverlayRange): string =>
  `<div class="peOverlayBar" role="img" aria-label="Overlay coverage">` +
  getCoverageSegments(range).map(segment => {
    const leftPercent = ((segment.start - range.start) / range.size) * 100;
    const widthPercent = ((segment.end - segment.start) / range.size) * 100;
    const label = segment.kind === "found" ? "Detected payload" : "Unclassified bytes";
    return `<span class="peOverlayBarSegment peOverlayBarSegment--${segment.kind}" ` +
      `style="left:${leftPercent.toFixed(4)}%;width:${widthPercent.toFixed(4)}%" ` +
      `title="${escapeHtml(`${label}: +${hex(segment.start - range.start)}..+${hex(segment.end - range.start)}`)}"></span>`;
  }).join("") +
  `</div>`;

const renderFindingRows = (range: PeOverlayRange): string =>
  range.findings.map((finding, index) =>
    `<tr><td>${index + 1}</td><td>+${hex(finding.start - range.start)}-+${hex(finding.end - range.start)}` +
    `<div class="smallNote">${hex(finding.start, 8)}-${hex(finding.end, 8)}</div></td>` +
    `<td>${humanSize(finding.size)}</td><td>${escapeHtml(finding.detectedType)}` +
    `<div class="smallNote">${escapeHtml(finding.endDescription)}</div></td>` +
    `<td>${renderOverlayDownloadButton(finding.start, finding.end, `Download detected payload ${index + 1}`)}</td></tr>`
  ).join("");

const renderOverlayContent = (pe: PeParseResult, out: string[]): void => {
  if (!pe.overlay?.ranges.length && !pe.overlay?.warnings?.length) return;
  out.push(renderPeSectionStart("Overlay", `${getUnexplainedOverlaySize(pe)} byte(s)`));
  out.push(
    `<div class="smallNote">Only bytes not covered by sections, headers, certificates, debug raw data, COFF data, or trailing alignment padding are listed here.</div>`
  );
  if (pe.overlay.warnings?.length) out.push(renderPeDiagnostics("Overlay warnings", pe.overlay.warnings));
  if (pe.overlay.ranges.length) {
    pe.overlay.ranges.forEach((range, index) => {
      out.push(`<div class="peOverlayRange">`);
      out.push(
        `<div class="peOverlayRangeHeader"><div><b>True overlay #${index + 1}</b>` +
        `<div class="smallNote">${hex(range.start, 8)}-${hex(range.end, 8)}; ${humanSize(range.size)}</div></div>` +
        renderOverlayDownloadButton(range.start, range.end, `Download complete overlay ${index + 1}`) +
        `</div>`
      );
      out.push(renderCoverageBar(range));
      out.push(renderScanControls(range));
      out.push(
        `<div class="smallNote">Detected payload coverage: ${humanSize(
          range.findings.reduce((total, finding) => total + finding.size, 0)
        )}; unclassified bytes are shown on the bar.</div>`
      );
      if (range.findings.length) {
        out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Overlay range</th><th>Size</th><th>Detected payload</th><th>Action</th></tr></thead><tbody>`);
        out.push(renderFindingRows(range));
        out.push(`</tbody></table>`);
      } else {
        out.push(
          range.embeddedScan?.status === "complete"
            ? `<div class="smallNote">No embedded payload signature was recognized inside this overlay range.</div>`
            : `<div class="smallNote">Embedded payload signatures have not been scanned for this range.</div>`
        );
      }
      out.push(`</div>`);
    });
  }
  out.push(renderPeSectionEnd());
};

export const renderOverlayPanel = (pe: PeParseResult): string => {
  const out: string[] = [];
  renderOverlayContent(pe, out);
  return out.length ? `<section id="${PE_OVERLAY_PANEL_ID}">${out.join("")}</section>` : "";
};

export const renderOverlay = (pe: PeParseResult, out: string[]): void => {
  out.push(renderOverlayPanel(pe));
};

export { getUnexplainedOverlaySize };
