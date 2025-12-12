"use strict";

import { escapeHtml } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

export function renderInstructionSets(pe: PeParseResult, out: string[]): void {
  const disasm = pe.disassembly;
  if (!disasm) return;

  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Instruction sets</h4>`);
  const mode = disasm.bitness === 64 ? "64-bit" : "32-bit";
  out.push(
    `<div class="smallNote">Disassembly sample (${mode}): ${disasm.instructionCount} instruction(s) decoded from ${disasm.bytesAnalyzed} byte(s). Invalid decodes: ${disasm.invalidInstructionCount}.</div>`
  );

  if (disasm.issues?.length) {
    const items = disasm.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
    out.push(`<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Notes</summary><ul>${items}</ul></details>`);
  }

  if (!disasm.instructionSets.length) {
    out.push(`<div class="smallNote dim">No instruction-set requirements were detected in the sampled bytes.</div>`);
    out.push(`</section>`);
    return;
  }

  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>Set</th><th>Instr.</th><th>What it is</th></tr></thead><tbody>`
  );
  for (const set of disasm.instructionSets) {
    const label = escapeHtml(set.label);
    const description = escapeHtml(set.description);
    const count = escapeHtml(String(set.instructionCount));
    const title = escapeHtml(`CpuidFeature.${set.id}`);
    out.push(
      `<tr><td><span class="opt sel" title="${title}">${label}</span></td><td>${count}</td><td>${description}</td></tr>`
    );
  }
  out.push(`</tbody></table></section>`);
}

