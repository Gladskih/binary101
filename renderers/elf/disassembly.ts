"use strict";

import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import {
  KNOWN_CPUID_FEATURES,
  describeCpuidFeature,
  formatCpuidLabel
} from "../../analyzers/x86/cpuid-features.js";

const ANALYZE_BUTTON_ID = "elfInstructionSetsAnalyzeButton";
const CANCEL_BUTTON_ID = "elfInstructionSetsCancelButton";
const PROGRESS_TEXT_ID = "elfInstructionSetsProgressText";
const PROGRESS_BAR_ID = "elfInstructionSetsProgress";
const CHIP_ID_PREFIX = "elfInstructionSetChip_";
const COUNT_ID_PREFIX = "elfInstructionSetCount_";

export function renderInstructionSets(elf: ElfParseResult, out: string[]): void {
  const disasm = elf.disassembly;

  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Instruction sets</h4>`);
  const analyzeLabel = disasm ? "Re-analyze instruction sets" : "Analyze instruction sets";
  out.push(`<div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">`);
  out.push(
    `<button type="button" class="actionButton" id="${ANALYZE_BUTTON_ID}">${escapeHtml(analyzeLabel)}</button>`
  );
  out.push(`<button type="button" class="actionButton" id="${CANCEL_BUTTON_ID}" hidden>Cancel</button>`);
  out.push(`</div>`);

  if (!disasm) {
    out.push(
      `<div class="smallNote dim" id="${PROGRESS_TEXT_ID}">Not analyzed yet. Click the button above to start (may use CPU).</div>` +
        `<progress id="${PROGRESS_BAR_ID}" style="width:100%" hidden></progress>`
    );
    out.push(
      `<table class="table" style="margin-top:.35rem"><thead><tr><th>Set</th><th>Instr.</th><th>What it is</th></tr></thead><tbody>`
    );
    for (const id of KNOWN_CPUID_FEATURES) {
      const label = escapeHtml(formatCpuidLabel(id));
      const description = escapeHtml(describeCpuidFeature(id));
      const title = escapeHtml(`CpuidFeature.${id}`);
      const chipId = escapeHtml(`${CHIP_ID_PREFIX}${id}`);
      const countId = escapeHtml(`${COUNT_ID_PREFIX}${id}`);
      out.push(
        `<tr><td><span class="opt dim" id="${chipId}" title="${title}">${label}</span></td><td class="dim" id="${countId}">0</td><td>${description}</td></tr>`
      );
    }
    out.push(`</tbody></table></section>`);
    return;
  }

  const mode = disasm.bitness === 64 ? "64-bit" : "32-bit";
  out.push(
    `<div class="smallNote">Disassembly sample (${mode}): ${disasm.instructionCount} instruction(s) decoded from ${disasm.bytesDecoded} / ${disasm.bytesSampled} byte(s). Invalid decodes: ${disasm.invalidInstructionCount}.</div>`
  );
  out.push(
    `<div class="smallNote dim">Note: this is a static, control-flow guided sample of reachable code paths; it is not a full disassembly and may miss code behind indirect jumps/calls, self-modifying code, unpacking, or runtime generation.</div>`
  );

  if (disasm.issues?.length) {
    const items = disasm.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
    out.push(
      `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Notes</summary><ul>${items}</ul></details>`
    );
  }

  if (disasm.seedSummary) {
    const seeds = disasm.seedSummary;
    const dimZero = (value: number): string => (value ? escapeHtml(String(value)) : `<span class="dim">0</span>`);
    const entryText = `0x${seeds.entrypointVaddr.toString(16)}`;
    out.push(
      `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Seeds (${seeds.uniqueEntrypoints} unique entrypoint(s))</summary>`
    );
    out.push(
      `<div class="smallNote dim">Seeds are candidate start addresses for control-flow guided sampling (entry point, constructor arrays, function symbols, unwind tables, etc.). Only seeds inside executable segments/sections are used.</div>`
    );
    out.push(
      `<div class="smallNote">Entry point: ${escapeHtml(entryText)}${
        seeds.fallbackSource ? `; fallback: ${escapeHtml(seeds.fallbackSource)}` : ""
      }</div>`
    );
    if (seeds.sources.length) {
      out.push(
        `<table class="table" style="margin-top:.35rem"><thead><tr><th>Source</th><th>Cand.</th><th>Added</th><th>Not exec</th><th>Dup.</th><th>Zero</th></tr></thead><tbody>`
      );
      for (const source of seeds.sources) {
        out.push(
          `<tr><td>${escapeHtml(source.source)}</td><td>${dimZero(source.candidates)}</td><td>${dimZero(
            source.added
          )}</td><td>${dimZero(source.skippedNotExecutable)}</td><td>${dimZero(source.skippedDuplicate)}</td><td>${dimZero(
            source.skippedZero
          )}</td></tr>`
        );
      }
      out.push(`</tbody></table>`);
    } else {
      out.push(`<div class="smallNote dim">No seed sources were collected.</div>`);
    }
    out.push(`</details>`);
  }

  const countsById = new Map<string, number>();
  for (const set of disasm.instructionSets) {
    countsById.set(set.id, (countsById.get(set.id) || 0) + set.instructionCount);
  }

  if (countsById.size === 0) {
    out.push(`<div class="smallNote dim">No instruction-set requirements were detected in the sampled bytes.</div>`);
  }

  const knownIds = new Set<string>(KNOWN_CPUID_FEATURES);
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
    out.push(
      `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Other detected features (${other.length})</summary>`
    );
    out.push(
      `<table class="table" style="margin-top:.35rem"><thead><tr><th>Set</th><th>Instr.</th><th>What it is</th></tr></thead><tbody>`
    );
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
