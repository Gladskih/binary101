"use strict";
import { escapeHtml } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import {
  KNOWN_CPUID_FEATURES,
  describeCpuidFeature,
  formatCpuidLabel
} from "../../analyzers/pe/cpuid-features.js";

export function renderInstructionSets(pe: PeParseResult, out: string[]): void {
  const disasm = pe.disassembly;

  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Instruction sets</h4>`);
  if (!disasm) {
    out.push(
      `<div class="smallNote dim" id="peInstructionSetsProgressText">Loading disassembler…</div>` +
        `<progress id="peInstructionSetsProgress" style="width:100%"></progress>`
    );
    out.push(`</section>`);
    return;
  }

  const mode = disasm.bitness === 64 ? "64-bit" : "32-bit";
  out.push(
    `<div class="smallNote">Disassembly sample (${mode}): ${disasm.instructionCount} instruction(s) decoded from ${disasm.bytesDecoded} / ${disasm.bytesSampled} byte(s). Invalid decodes: ${disasm.invalidInstructionCount}.</div>`
  );

  if (disasm.issues?.length) {
    const items = disasm.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
    out.push(
      `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Notes</summary><ul>${items}</ul></details>`
    );
  }

  const countsById = new Map<string, number>();
  for (const set of disasm.instructionSets) {
    countsById.set(set.id, (countsById.get(set.id) || 0) + set.instructionCount);
  }

  if (countsById.size === 0) {
    out.push(`<div class="smallNote dim">No instruction-set requirements were detected in the sampled bytes.</div>`);
  }

  const knownIds = new Set(KNOWN_CPUID_FEATURES);
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>Set</th><th>Instr.</th><th>What it is</th></tr></thead><tbody>`
  );
  for (const id of KNOWN_CPUID_FEATURES) {
    const countValue = countsById.get(id) || 0;
    const label = escapeHtml(formatCpuidLabel(id));
    const description = escapeHtml(describeCpuidFeature(id));
    const title = escapeHtml(`CpuidFeature.${id}`);
    const chipClass = countValue > 0 ? "opt sel" : "opt dim";
    const count = countValue > 0 ? escapeHtml(String(countValue)) : `<span class="dim">0</span>`;
    out.push(
      `<tr><td><span class="${chipClass}" title="${title}">${label}</span></td><td>${count}</td><td>${description}</td></tr>`
    );
  }
  out.push(`</tbody></table>`);

  const other = disasm.instructionSets.filter(set => !knownIds.has(set.id));
  if (other.length) {
    out.push(`<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Other detected features (${other.length})</summary>`);
    out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>Set</th><th>Instr.</th><th>What it is</th></tr></thead><tbody>`);
    for (const set of other) {
      const label = escapeHtml(set.label);
      const description = escapeHtml(set.description);
      const count = escapeHtml(String(set.instructionCount));
      const title = escapeHtml(`CpuidFeature.${set.id}`);
      out.push(
        `<tr><td><span class="opt sel" title="${title}">${label}</span></td><td>${count}</td><td>${description}</td></tr>`
      );
    }
    out.push(`</tbody></table></details>`);
  }

  out.push(`</section>`);
}
