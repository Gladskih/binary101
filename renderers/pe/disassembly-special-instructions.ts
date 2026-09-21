import type { PeSpecialInstructionFinding } from
  "../../analyzers/pe/disassembly/special-instructions.js";
import { hex } from "../../binary-utils.js";
import { renderX86SpecialInstructions } from "../x86-special-instructions.js";

const renderExamples = (finding: PeSpecialInstructionFinding): string => finding.sampleRvas.map(rva =>
  `<button type="button" class="peEntrypointJump" data-pe-special-rva="${rva}" ` +
  `aria-label="Disassemble at RVA ${hex(rva, 8)}">${hex(rva, 8)}</button>`
).join(" ") || "Unavailable";

export const renderSpecialInstructions = (findings: PeSpecialInstructionFinding[]): string =>
  renderX86SpecialInstructions(findings, renderExamples, "Example RVAs",
    "RVA examples show up to three locations per instruction; select one to disassemble there.");
