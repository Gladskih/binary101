"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { safe } from "../../html-utils.js";
import type {
  PePackerAnalysis,
  PePackerDetail,
  PePackerFinding
} from "../../analyzers/pe/packers/index.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

const kindLabel = (kind: PePackerFinding["kind"]): string =>
  kind === "installer" ? "installer" : "runtime packager";

const formatDetailValue = (detail: PePackerDetail): string => {
  switch (detail.kind) {
    case "bytes":
      return humanSize(detail.value);
    case "number":
      return String(detail.value);
    case "offset":
      return hex(detail.value, 8);
    case "range":
      return `${hex(detail.start, 8)}-${hex(detail.end, 8)} (${humanSize(detail.end - detail.start)})`;
    case "text":
      return detail.value;
  }
};

const renderDetailList = (finding: PePackerFinding): string => {
  const details = finding.details ?? [];
  if (!details.length) return "";
  return `<dl class="smallNote" style="display:grid;grid-template-columns:max-content 1fr;` +
    `gap:.15rem .55rem;margin:.25rem 0 0 0">${details.map(detail =>
      `<dt>${safe(detail.label)}</dt><dd>${safe(formatDetailValue(detail))}</dd>`
    ).join("")}</dl>`;
};

const renderEvidence = (finding: PePackerFinding): string =>
  `<ul class="smallNote" style="margin:.1rem 0 0 0;padding-left:1.1rem">` +
  finding.evidence.map(item => `<li>${safe(item)}</li>`).join("") +
  `</ul>${renderDetailList(finding)}`;

const renderFindingRows = (findings: PePackerFinding[]): string =>
  findings.map(finding =>
    `<tr><td>${safe(finding.name)}</td><td>${safe(kindLabel(finding.kind))}</td>` +
    `<td>${safe(finding.confidence)}</td><td>${renderEvidence(finding)}</td></tr>`
  ).join("");

export const renderPackers = (
  packers: PePackerAnalysis | null | undefined,
  out: string[]
): void => {
  if (!packers?.findings.length && !packers?.warnings?.length) return;
  out.push(renderPeSectionStart("Packaging signatures", `${packers?.findings.length ?? 0} finding(s)`));
  if (packers?.warnings?.length) out.push(renderPeDiagnostics("Packaging signature warnings", packers.warnings));
  if (packers?.findings.length) {
    out.push(
      `<table class="table" style="margin-top:.35rem"><thead><tr><th>Signature</th>` +
      `<th>Kind</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>`
    );
    out.push(renderFindingRows(packers.findings));
    out.push(`</tbody></table>`);
  } else {
    out.push(`<div class="smallNote dim">No high-confidence packaging signature was detected.</div>`);
  }
  out.push(renderPeSectionEnd());
};
