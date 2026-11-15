import type { ElfParseResult } from "../analyzers/elf/types.js";
import { isPeWindowsParseResult, type PeParseResult } from "../analyzers/pe/core/parse-result.js";
import { SANITIZER_ABI_SYMBOLS } from "../analyzers/sanitizers/abi-catalog.js";
import { escapeHtml } from "../html-utils.js";
import { markSupplementalAnalysis } from "./supplemental-analysis.js";
import { PE_PACKER_SECTIONS } from "./pe/packer-sections.js";
import { collectPeChecksWithoutFindings } from "./pe/checks-without-findings.js";

const sanitizerChecks = (file: ElfParseResult | PeParseResult): string[] => {
  if (!("sanitizerEvidence" in file) || !file.sanitizerEvidence) return [];
  const found = new Set<string>(file.sanitizerEvidence.map(evidence => evidence.tool));
  return [...new Set([...SANITIZER_ABI_SYMBOLS.values(), "Go race detector"])]
    .filter(tool => !found.has(tool));
};
const embeddedResourceChecks = (file: ElfParseResult | PeParseResult): string[] => {
  const analysis = file.embeddedResources;
  if (analysis === undefined) return [];
  const formats = new Set(analysis?.bundles.map(bundle => bundle.resource.format));
  return (["Qt RCC", "GLib GResource"] as const).filter(format => !formats.has(format));
};
const packerChecks = (file: PeParseResult): string[] => {
  if (!isPeWindowsParseResult(file) || file.packers === undefined) return [];
  const reported = new Set<string>(file.packers?.reports.map(report => report.id));
  return Object.entries(PE_PACKER_SECTIONS).filter(([id]) => !reported.has(id))
    .map(([, section]) => section.title);
};
const elfChecks = (file: ElfParseResult): string[] => ([
  ["NativeAOT", file.nativeAot],
  ["Go build information", file.goBuildInfo]
] as const).filter(([, evidence]) => !evidence).map(([name]) => name);
const collectChecks = (file: ElfParseResult | PeParseResult): string[] => {
  const checks = [...sanitizerChecks(file), ...embeddedResourceChecks(file)];
  if (!("signature" in file)) return checks.concat(elfChecks(file));
  if (!file.dwarf) {
    checks.push("DWARF debug information");
  }
  if (isPeWindowsParseResult(file)) {
    checks.push(...collectPeChecksWithoutFindings(file));
  }
  return checks.concat(packerChecks(file));
};

export const renderChecksWithoutFindings = (file: ElfParseResult | PeParseResult): string => {
  const checks = collectChecks(file).sort((left, right) => left.localeCompare(right));
  if (!checks.length) return "";
  return markSupplementalAnalysis(`<section class="checksWithoutFindings">` +
    `<h4>Checks without findings</h4>` +
    `<p class="smallNote">No findings were returned for these checks. ` +
    `Some checks use heuristics; not detected does not mean absent.</p>` +
    `<ul>` + checks.map(name => `<li>${escapeHtml(name)}</li>`).join("") + `</ul></section>`);
};
