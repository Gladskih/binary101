import { escapeHtml } from "../../html-utils.js";
import {
  SPECIAL_INSTRUCTION_CATALOG,
  SPECIAL_INSTRUCTION_CATEGORIES,
  type PeSpecialInstructionCategory
} from "../../analyzers/pe/disassembly/special-instruction-catalog.js";
import type { PeSpecialInstructionFinding } from
  "../../analyzers/pe/disassembly/special-instructions.js";
import { hex } from "../../binary-utils.js";

const renderExplanation = (label: string, explanation: string): string =>
  `<details><summary>${escapeHtml(label)}</summary>` +
  `<p class="smallNote">${escapeHtml(explanation)}</p></details>`;

const renderCategory = (category: PeSpecialInstructionCategory): string => {
  const explanation = SPECIAL_INSTRUCTION_CATEGORIES[category];
  return renderExplanation(explanation[0], explanation[1]);
};

const describeInstruction = (finding: PeSpecialInstructionFinding): string =>
  SPECIAL_INSTRUCTION_CATALOG[finding.instruction]?.[1] ??
  (finding.instruction.startsWith("INT ")
    ? SPECIAL_INSTRUCTION_CATALOG["INT"]![1]
    : "A privileged processor operation: it requires access to protected CPU facilities. This glossary does not yet describe its exact operation; consult the vendor instruction reference.");

const renderExamples = (rvas: number[]): string => rvas.map(rva =>
  `<button type="button" class="peEntrypointJump" data-pe-special-rva="${rva}" ` +
  `aria-label="Disassemble at RVA ${hex(rva, 8)}">${hex(rva, 8)}</button>`
).join(" ") || "Unavailable";

const renderFinding = (finding: PeSpecialInstructionFinding): string =>
  `<tr><td>${finding.categories.map(renderCategory).join("")}</td>` +
  `<td>${renderExplanation(finding.instruction, describeInstruction(finding))}</td>` +
  `<td style="text-align:right">${finding.count}</td>` +
  `<td>${renderExamples(finding.sampleRvas)}</td></tr>`;

export const renderSpecialInstructions = (findings: PeSpecialInstructionFinding[]): string => {
  const heading = `<h4>Special instructions</h4>`;
  if (!findings.length) {
    return heading + `<div class="smallNote dim">None detected in the sampled code.</div>`;
  }
  return heading + `<div class="smallNote">Counts are decoded instruction sites, ` +
    `not execution frequency. Unvisited code may contain additional sites. ` +
    `Expand a category or instruction for an explanation. ` +
    `RVA examples show up to three locations per instruction; select one to disassemble there.</div>` +
    `<div class="smallNote">Instruction reference: ` +
    `<a href="https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html">Intel SDM</a>` +
    ` and <a href="https://docs.amd.com/v/u/en-US/24594_3.37">AMD APM</a>.</div>` +
    `<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Category</th><th>Instruction</th><th style="text-align:right">Sites</th>` +
    `<th>Example RVAs</th></tr></thead><tbody>` +
    findings.map(renderFinding).join("") + `</tbody></table></div>`;
};
