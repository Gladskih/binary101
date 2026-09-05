import { escapeHtml } from "../../html-utils.js";
import type {
  PeSpecialInstructionCategory,
  PeSpecialInstructionFinding
} from "../../analyzers/pe/disassembly/special-instructions.js";

const CATEGORIES: Record<PeSpecialInstructionCategory, [string, string]> = {
  syscall: ["Direct syscall", "Kernel-entry instruction; no syscall number or function inferred."],
  privileged: ["Kernel privilege", "Requires CPU privileges; administrator rights alone do not suffice."],
  "io-privilege": ["I/O privilege", "Access depends on IOPL and, for port I/O, I/O permissions."],
  trap: ["Trap / interrupt", "Software interrupt or explicit exception; not evidence of malicious code."]
};

const renderFinding = (finding: PeSpecialInstructionFinding): string =>
    `<tr><td title="${escapeHtml(CATEGORIES[finding.category][1])}">` +
    `${escapeHtml(CATEGORIES[finding.category][0])}</td>` +
    `<td><code>${escapeHtml(finding.instruction)}</code></td>` +
    `<td style="text-align:right">${finding.count}</td>` +
    `</tr>`;

export const renderSpecialInstructions = (findings: PeSpecialInstructionFinding[]): string => {
  const heading = `<h4>Special instructions</h4>`;
  if (!findings.length) {
    return heading + `<div class="smallNote dim">None detected in the sampled code.</div>`;
  }
  return heading + `<div class="smallNote">Counts are decoded instruction sites, ` +
    `not execution frequency. ` +
    `Unvisited code may contain additional sites.</div>` +
    `<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Category</th><th>Instruction</th><th style="text-align:right">Sites</th>` +
    `</tr></thead><tbody>` +
    findings.map(renderFinding).join("") + `</tbody></table></div>`;
};
