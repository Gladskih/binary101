"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type {
  PeDetailedPackerFinding,
  PePackerDetail,
  PePackerFinding,
  PePackerReport
} from "../../analyzers/pe/packers/index.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { packerDetailMeaning } from "./packer-detail-meanings.js";
import { PE_PACKER_SECTIONS, pePackerReportSummary } from "./packer-sections.js";
import { renderBunFindingDetails } from "./bun-packer.js";
import { renderUpxFindingDetails } from "./upx-packer.js";

const formatDetailValue = (detail: PePackerDetail): string => {
  switch (detail.kind) {
    case "bytes":
      return humanSize(detail.value);
    case "number":
      return String(detail.value);
    case "offset":
      return hex(detail.value, 8);
    case "range":
      return `${hex(detail.start, 8)}-${hex(detail.end, 8)} (` +
        `${humanSize(detail.end - detail.start)})`;
    case "text":
      return detail.value;
  }
};

const renderDetailTable = (finding: PeDetailedPackerFinding): string =>
  `<div class="tableWrap"><table class="table pePackerFinding__details">` +
  `<thead><tr><th>Field</th><th>Value</th><th>Meaning</th></tr></thead><tbody>` +
  finding.details.map(detail =>
    `<tr><th scope="row">${escapeHtml(detail.label)}</th>` +
    `<td${detail.kind === "text" ? "" : ` class="peNumeric"`}>` +
    `${escapeHtml(formatDetailValue(detail))}</td>` +
    `<td class="smallNote pePackerFinding__meaning">` +
    `${escapeHtml(packerDetailMeaning(detail.label))}</td></tr>`
  ).join("") + `</tbody></table></div>`;

const renderEvidence = (finding: PePackerFinding): string =>
  `<div class="smallNote pePackerFinding__evidenceLabel">Validation checks</div>` +
  `<ul class="smallNote manifestCheckList pePackerFinding__evidence">` +
  finding.evidence.map(item =>
    `<li class="manifestCheckItem manifestCheckItem--pass">` +
    `<span class="manifestCheckIcon">&#10003;</span>` +
    `<span>${escapeHtml(item)}</span></li>`
  ).join("") +
  `</ul>`;

const renderFinding = (finding: PePackerFinding, index: number, total: number): string => {
  const heading = total > 1
    ? `<h4 class="pePackerFinding__title">Finding ${index + 1}: ${escapeHtml(finding.name)}</h4>`
    : "";
  const details = finding.id === "upx"
    ? renderUpxFindingDetails(finding)
    : finding.id === "bun-standalone"
      ? renderBunFindingDetails(finding)
      : renderDetailTable(finding);
  return `<div class="pePackerFinding">${heading}${renderEvidence(finding)}${details}</div>`;
};

const renderFindings = (findings: PePackerFinding[]): string =>
  findings.map((finding, index) => renderFinding(finding, index, findings.length)).join("");

export const renderPackerReport = (
  report: PePackerReport | null | undefined,
  out: string[]
): void => {
  if (!report?.findings.length && !report?.warnings.length) return;
  const section = PE_PACKER_SECTIONS[report.id];
  out.push(renderPeSectionStart(section.title, pePackerReportSummary(report)));
  if (report.warnings.length) {
    out.push(renderPeDiagnostics(`${section.title} warnings`, report.warnings));
  }
  if (report.findings.length) out.push(renderFindings(report.findings));
  else out.push(`<div class="smallNote dim">No verified finding was produced.</div>`);
  out.push(renderPeSectionEnd());
};
