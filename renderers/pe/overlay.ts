"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { safe } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { PeOverlayRange } from "../../analyzers/pe/overlay.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

const getUnexplainedOverlaySize = (pe: PeParseResult): number =>
  pe.overlay?.ranges.reduce((total, range) => total + range.size, 0) ?? 0;

const renderDownloadButton = (start: number, end: number, label: string): string =>
  `<button type="button" class="peSecurityTreeDownloadButton" data-pe-overlay-download ` +
  `data-overlay-start="${start}" data-overlay-end="${end}" aria-label="${safe(label)}" title="${safe(label)}">` +
  `<svg aria-hidden="true" viewBox="0 0 16 16" width="14" height="14" fill="none" ` +
  `stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">` +
  `<path d="M8 2.5v7"></path><path d="M5 6.8 8 9.8l3-3"></path><path d="M3 12.5h10"></path>` +
  `</svg></button>`;

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
      `title="${safe(`${label}: +${hex(segment.start - range.start)}..+${hex(segment.end - range.start)}`)}"></span>`;
  }).join("") +
  `</div>`;

const renderFindingRows = (range: PeOverlayRange): string =>
  range.findings.map((finding, index) =>
    `<tr><td>${index + 1}</td><td>+${hex(finding.start - range.start)}-+${hex(finding.end - range.start)}` +
    `<div class="smallNote">${hex(finding.start, 8)}-${hex(finding.end, 8)}</div></td>` +
    `<td>${humanSize(finding.size)}</td><td>${safe(finding.detectedType)}` +
    `<div class="smallNote">${safe(finding.endDescription)}</div></td>` +
    `<td>${renderDownloadButton(finding.start, finding.end, `Download detected payload ${index + 1}`)}</td></tr>`
  ).join("");

export function renderOverlay(pe: PeParseResult, out: string[]): void {
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
        renderDownloadButton(range.start, range.end, `Download complete overlay ${index + 1}`) +
        `</div>`
      );
      out.push(renderCoverageBar(range));
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
        out.push(`<div class="smallNote">No embedded payload signature was recognized inside this overlay range.</div>`);
      }
      out.push(`</div>`);
    });
  }
  out.push(renderPeSectionEnd());
}

export { getUnexplainedOverlaySize };
