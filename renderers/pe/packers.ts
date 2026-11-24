"use strict";

import { escapeHtml } from "../../html-utils.js";
import type {
  PePackerFinding,
  PePackerReport
} from "../../analyzers/pe/packers/index.js";
import type { PePayloadAnalysis } from "../../analyzers/pe/payloads.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { PE_PACKER_SECTIONS, pePackerReportSummary } from "./packer-sections.js";
import { renderBunFindingDetails } from "./bun-packer.js";
import { renderInnoSetupFindingDetails } from "./inno-setup.js";
import { renderNsisFindingDetails } from "./nsis-installer.js";
import { renderUpxFindingDetails } from "./upx-packer.js";
import { renderCrinklerFindingDetails } from "./crinkler.js";

const renderEvidence = (finding: PePackerFinding): string =>
  `<div class="smallNote pePackerFinding__evidenceLabel">Validation checks</div>` +
  `<ul class="smallNote manifestCheckList pePackerFinding__evidence">` +
  finding.evidence.map(item =>
    `<li class="manifestCheckItem manifestCheckItem--pass">` +
    `<span class="manifestCheckIcon">&#10003;</span>` +
    `<span>${escapeHtml(item)}</span></li>`
  ).join("") +
  `</ul>`;

const findNsisPayloads = (
  finding: PePackerFinding,
  payloads: PePayloadAnalysis | null | undefined
) =>
  finding.id === "nsis-installer"
    ? payloads?.entries.filter(payload =>
      payload.provenance.location === "overlay" &&
      payload.provenance.association === "nsis-installer-data" &&
      payload.start >= finding.firstHeaderOffset &&
      payload.end <= finding.firstHeaderOffset + finding.followingDataSize
    ) ?? []
    : [];

const renderFindingDetails = (
  finding: PePackerFinding, payloads: PePayloadAnalysis | null | undefined
): string => {
  switch (finding.id) {
    case "upx": return renderUpxFindingDetails(finding);
    case "bun-standalone": return renderBunFindingDetails(finding);
    case "crinkler": return renderCrinklerFindingDetails(finding);
    case "inno-setup": return renderInnoSetupFindingDetails(finding);
    case "nsis-installer": return renderNsisFindingDetails(finding, findNsisPayloads(finding, payloads));
  }
};

const renderFinding = (
  finding: PePackerFinding,
  index: number,
  total: number,
  payloads: PePayloadAnalysis | null | undefined
): string => {
  const heading = total > 1
    ? `<h4 class="pePackerFinding__title">Finding ${index + 1}: ${escapeHtml(finding.name)}</h4>`
    : "";
  const details = renderFindingDetails(finding, payloads);
  return `<div class="pePackerFinding">${heading}${renderEvidence(finding)}${details}</div>`;
};

const renderFindings = (
  findings: PePackerFinding[],
  payloads: PePayloadAnalysis | null | undefined
): string =>
  findings.map((finding, index) =>
    renderFinding(finding, index, findings.length, payloads)
  ).join("");

export const renderPackerReport = (
  report: PePackerReport | null | undefined,
  out: string[],
  payloads?: PePayloadAnalysis | null
): void => {
  if (!report?.findings.length && !report?.warnings.length) return;
  const section = PE_PACKER_SECTIONS[report.id];
  out.push(renderPeSectionStart(section.title, pePackerReportSummary(report)));
  if (report.warnings.length) {
    out.push(renderPeDiagnostics(`${section.title} warnings`, report.warnings));
  }
  if (report.findings.length) out.push(renderFindings(report.findings, payloads));
  else out.push(`<div class="smallNote dim">No verified finding was produced.</div>`);
  out.push(renderPeSectionEnd());
};
