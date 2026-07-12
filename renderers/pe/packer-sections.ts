"use strict";

import type {
  PePackerAnalysis,
  PePackerId,
  PePackerReport
} from "../../analyzers/pe/packers/index.js";

export type PePackerSectionDefinition = {
  key: "bun-standalone" | "nsis-installer" | "upx";
  title: string;
};

export const PE_PACKER_SECTIONS: Readonly<Record<PePackerId, PePackerSectionDefinition>> = {
  "bun-standalone": { key: "bun-standalone", title: "Bun standalone executable" },
  "nsis-installer": { key: "nsis-installer", title: "NSIS installer" },
  "upx": { key: "upx", title: "UPX executable packer" }
};

export const pePackerReportSummary = (report: PePackerReport): string => {
  const findings = report.findings.length;
  const warnings = report.warnings.length;
  const findingSummary = findings === 1 ? "verified" : `${findings} verified findings`;
  const warningSummary = `${warnings} ${warnings === 1 ? "warning" : "warnings"}`;
  if (findings && warnings) return `${findingSummary}, ${warningSummary}`;
  return findings ? findingSummary : warningSummary;
};

export const pePackerSectionDescriptors = (analysis: PePackerAnalysis | null | undefined) =>
  analysis?.reports.map(report => ({
    key: PE_PACKER_SECTIONS[report.id].key,
    summary: pePackerReportSummary(report),
    title: PE_PACKER_SECTIONS[report.id].title
  })) ?? [];
