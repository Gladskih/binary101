import type { ElfParseResult } from "../analyzers/elf/types.js";
import { isPeWindowsParseResult, type PeParseResult } from "../analyzers/pe/core/parse-result.js";
import { markSupplementalAnalysis } from "./supplemental-analysis.js";
import { PE_PACKER_SECTIONS } from "./pe/packer-sections.js";

type Check = readonly [name: string, scope: string];
const collectChecks = (file: ElfParseResult | PeParseResult): Check[] => {
  const checks: Check[] = [];
  if ("sanitizerEvidence" in file && file.sanitizerEvidence?.length === 0) {
    checks.push(["Sanitizer evidence", "Available runtime dependencies, symbols and build metadata. " +
      "Stripped, renamed or trap-only instrumentation can escape this check."]);
  }
  if (file.embeddedResources === null) {
    checks.push(["Qt / GLib embedded resources", "Supported containers and resource symbols."]);
  }
  if ("signature" in file && isPeWindowsParseResult(file)) {
    if ((file.clr?.readyToRun ?? file.readyToRun)?.status === "absent") {
      checks.push(["ReadyToRun", "Managed native header and supported composite header export."]);
    }
    if (file.packers !== undefined) {
      const reported = new Set<string>(file.packers?.reports.map(report => report.id));
      const missing = Object.entries(PE_PACKER_SECTIONS).filter(([id]) => !reported.has(id));
      if (missing.length) {
        checks.push(["PE packagers", missing.map(([, section]) => section.title).join(", ")]);
      }
    }
  }
  return checks;
};

export const renderChecksWithoutFindings = (file: ElfParseResult | PeParseResult): string => {
  const checks = collectChecks(file);
  if (!checks.length) return "";
  return markSupplementalAnalysis(`<section class="checksWithoutFindings">` +
    `<h4>Checks without findings</h4>` +
    `<p class="smallNote">These automatic checks returned no matching evidence in the inputs listed. ` +
    `File hashes and disassembly run on demand.</p><dl>` +
    checks.map(([name, scope]) => `<dt>${name}</dt><dd>${scope}</dd>`).join("") +
    `</dl></section>`);
};
