import { escapeHtml } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import type { PeInstructionSetReport } from "../../analyzers/pe/disassembly/types.js";
import { renderAarch64RequirementTable } from "../aarch64-instruction-sets.js";

const renderResults = (report: PeInstructionSetReport): string => {
  const issues = report.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<div class="smallNote">Disassembly sample (64-bit): ` +
    `${report.instructionCount} instruction(s) decoded from ` +
    `${formatHumanSize(report.bytesDecoded)} / ${formatHumanSize(report.bytesSampled)}. ` +
    `Invalid decodes: ${report.invalidInstructionCount}.</div>` +
    (report.decoderVersion
      ? `<div class="smallNote dim">${escapeHtml(report.decoderVersion)}</div>` : "") +
    (issues ? `<ul>${issues}</ul>` : "") +
    (report.instructionSets.length ? "" : `<div class="smallNote dim">` +
      `No instruction-set requirements were detected in the sampled bytes.</div>`);
};

export const renderPeAarch64InstructionSets = (report?: PeInstructionSetReport): string =>
  `<details class="analysisPanel"><summary class="analysisPanelSummary">` +
  `<span class="detailsSummaryTitle">Instruction sets</span></summary>` +
  `<div class="analysisPanelBody"><div class="analysisPanelActions">` +
  `<button type="button" class="actionButton" id="peInstructionSetsAnalyzeButton">` +
  `${report ? "Re-analyze" : "Analyze"} instruction sets</button>` +
  `<button type="button" class="actionButton" id="peInstructionSetsCancelButton" hidden>` +
  `Cancel</button></div><div class="smallNote">AArch64 instruction-set requirements</div>` +
  `<div class="smallNote dim">LLVM opcode feature gates preserve “and” / “or” alternatives. ` +
  `Grouped Arm labels are not separate requirements. No recorded gate does not prove ` +
  `base-ISA validity; operand restrictions, execution modes and implied dependencies ` +
  `are not expanded here.</div><div class="smallNote dim">` +
  `Static sampling follows reachable code in executable sections. It may miss code behind ` +
  `indirect jumps/calls, unpacking, or runtime generation. ` +
  `Import and string reference analysis is currently available for x86/x86-64 only.</div>` +
  `<div class="smallNote dim" id="peInstructionSetsProgressText">` +
  `${report ? "Done." : "Not analyzed yet. Start analysis to detect instruction-set requirements."}` +
  `</div><progress id="peInstructionSetsProgress" style="width:100%" hidden></progress>` +
  (report ? renderResults(report) : "") +
  `<div id="peAarch64Requirements">${renderAarch64RequirementTable(report?.instructionSets)}</div>` +
  `</div></details>`;
