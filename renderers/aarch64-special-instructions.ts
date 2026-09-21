import { escapeHtml } from "../html-utils.js";
import type {
  Aarch64InstructionAccess, Aarch64SpecialInstructionFinding
} from "../analyzers/aarch64/special-instructions.js";

const ACCESS_DESCRIPTIONS: Record<Aarch64InstructionAccess, readonly [string, string]> = {
  "EL1+": ["Kernel privilege (EL1+)",
    "Requires at least Exception Level 1. Ordinary EL0 applications cannot execute this operation " +
    "directly; administrator rights alone do not suffice. System registers may impose further " +
    "restrictions, and the OS may emulate some trapped accesses."],
  "EL2+": ["Hypervisor privilege (EL2+)",
    "Requires at least Exception Level 2, normally used by a hypervisor. EL1 kernel privilege " +
    "alone is insufficient. Virtualization controls may trap or redirect the access."],
  "EL3": ["Monitor privilege (EL3)",
    "Requires Exception Level 3, used by monitor firmware. Lower exception levels cannot " +
    "directly access this facility."],
  configuration: ["Configured EL0 access",
    "DAIF controls interrupt and exception masks. EL0 access depends on SCTLR_EL1.UMA; " +
    "when disabled, the access traps. This is not an unconditional kernel-only instruction."],
  debug: ["Halting debug state",
    "DRPS and DCPS operate in halting debug state. A higher Exception Level alone does not " +
    "make them ordinary executable instructions."]
};

const renderFinding = (finding: Aarch64SpecialInstructionFinding): string =>
  `<tr><td><details><summary>${escapeHtml(ACCESS_DESCRIPTIONS[finding.access][0])}</summary>` +
    `<p class="smallNote">${escapeHtml(ACCESS_DESCRIPTIONS[finding.access][1])}</p></details></td>` +
    `<td><code>${escapeHtml(finding.instruction)}</code></td>` +
    `<td style="text-align:right">${finding.count}</td><td>` +
    (finding.sampleAddresses.map(address => `<code>0x${address.toString(16)}</code>`).join(" ") ||
      "Unavailable") + `</td></tr>`;

export const renderAarch64SpecialInstructions = (
  findings: Aarch64SpecialInstructionFinding[], examplesHeading: string
): string => {
  const heading = `<h4>Special instructions</h4>`;
  if (!findings.length) {
    return heading + `<div class="smallNote dim">None detected in the sampled code.</div>`;
  }
  return heading + `<div class="smallNote">Counts are decoded instruction sites, not execution ` +
    `frequency. Up to three addresses are shown per instruction and access requirement. ` +
    `Expand a category for an explanation.</div>` +
    `<div class="smallNote dim">System access levels are minimum encoding requirements, ` +
    `not proof that an operation exists or is permitted on a particular CPU. EL0-accessible ` +
    `encodings may have additional restrictions. Unvisited code may contain more sites.</div>` +
    `<div class="smallNote">Instruction reference: ` +
    `<a href="https://developer.arm.com/documentation/ddi0487/latest/">Arm Architecture ` +
    `Reference Manual</a>.</div>` +
    `<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Category</th><th>Instruction</th><th style="text-align:right">Sites</th>` +
    `<th>${escapeHtml(examplesHeading)}</th></tr></thead><tbody>` +
    findings.map(renderFinding).join("") + `</tbody></table></div>`;
};
