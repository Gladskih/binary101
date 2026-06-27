"use strict";

import { formatHumanSize } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { peSectionNameValue } from "../../analyzers/pe/sections/name.js";
import {
  KNOWN_CPUID_FEATURES,
  describeCpuidFeature,
  formatCpuidLabel
} from "../../analyzers/x86/cpuid-features.js";
import type {
  PeApiStringReference,
  PeCodeStringReference
} from "../../analyzers/pe/disassembly/index.js";

const ANALYZE_BUTTON_ID = "peInstructionSetsAnalyzeButton";
const CANCEL_BUTTON_ID = "peInstructionSetsCancelButton";
const PROGRESS_TEXT_ID = "peInstructionSetsProgressText";
const PROGRESS_BAR_ID = "peInstructionSetsProgress";
const CHIP_ID_PREFIX = "peInstructionSetChip_";
const COUNT_ID_PREFIX = "peInstructionSetCount_";

export const PE_INSTRUCTION_SETS_PANEL_ID = "peInstructionSetsPanel";

const renderInstructionPanelStart = (): string =>
  `<details class="analysisPanel"><summary class="analysisPanelSummary">` +
  `<span class="detailsSummaryTitle">Instruction-set analysis</span></summary>` +
  `<div class="analysisPanelBody"><div class="analysisPanelActions">`;

const renderInstructionPanelEnd = (): string => "</div></details>";

const renderKnownFeatureRows = (countsById: Map<string, number>): string => {
  const rows = KNOWN_CPUID_FEATURES.map(id => {
    const countValue = countsById.get(id) || 0;
    const label = escapeHtml(formatCpuidLabel(id));
    const description = escapeHtml(describeCpuidFeature(id));
    const title = escapeHtml(`CpuidFeature.${id}`);
    const chipClass = countValue > 0 ? "opt sel" : "opt dim";
    const count = countValue > 0 ? escapeHtml(String(countValue)) : `<span class="dim">0</span>`;
    return (
      `<tr><td><span class="${chipClass}" title="${title}">${label}</span></td>` +
      `<td>${count}</td><td>${description}</td></tr>`
    );
  });
  return rows.join("");
};

const renderPendingFeatureRows = (): string => {
  const rows = KNOWN_CPUID_FEATURES.map(id => {
    const label = escapeHtml(formatCpuidLabel(id));
    const description = escapeHtml(describeCpuidFeature(id));
    const title = escapeHtml(`CpuidFeature.${id}`);
    const chipId = escapeHtml(`${CHIP_ID_PREFIX}${id}`);
    const countId = escapeHtml(`${COUNT_ID_PREFIX}${id}`);
    return (
      `<tr><td><span class="opt dim" id="${chipId}" title="${title}">${label}</span></td>` +
      `<td class="dim" id="${countId}">0</td><td>${description}</td></tr>`
    );
  });
  return rows.join("");
};

const renderFeatureTable = (rows: string): string =>
  `<table class="table" style="margin-top:.35rem"><thead><tr>` +
  `<th>Set</th><th>Instr.</th><th>What it is</th></tr></thead><tbody>${rows}</tbody></table>`;

const formatRva = (rva: number): string => `0x${(rva >>> 0).toString(16).padStart(8, "0")}`;

const sectionForRva = (pe: PeWindowsParseResult, rva: number): string => {
  const section = pe.sections.find(candidate => {
    const start = candidate.virtualAddress >>> 0;
    const span = (candidate.virtualSize >>> 0) || (candidate.sizeOfRawData >>> 0);
    return rva >= start && rva < start + span;
  });
  return section ? peSectionNameValue(section.name) || "(unnamed)" : "-";
};

const clippedText = (text: string): string =>
  text.length > 120 ? `${text.slice(0, 117)}...` : text;

const sourceLabel = (sourceKind: PeApiStringReference["callSites"][number]["sourceKind"]): string =>
  sourceKind === "ucrt" ? "UCRT" : "WinAPI";

const renderCodeStringInstructionRvas = (reference: PeCodeStringReference): string => {
  const rvas = reference.instructionRvas.slice(0, 5).map(formatRva);
  const suffix = reference.instructionRvas.length > rvas.length
    ? ` +${reference.instructionRvas.length - rvas.length} more`
    : "";
  return escapeHtml(`${rvas.join(", ")}${suffix}`);
};

const renderCodeStringRows = (
  pe: PeWindowsParseResult,
  references: PeCodeStringReference[]
): string => references.map(reference => {
  const text = escapeHtml(clippedText(reference.text));
  const title = escapeHtml(reference.text);
  return `<tr><td class="peNumeric">${formatRva(reference.rva)}</td>` +
    `<td>${escapeHtml(sectionForRva(pe, reference.rva))}</td>` +
    `<td>${escapeHtml(reference.encoding)}</td>` +
    `<td class="peNumeric">${reference.instructionRvas.length}</td>` +
    `<td>${renderCodeStringInstructionRvas(reference)}</td>` +
    `<td><code title="${title}">${text}</code></td></tr>`;
}).join("");

const renderCodeStringReferences = (pe: PeWindowsParseResult, out: string[]): void => {
  const references = pe.disassembly?.codeStringReferences ?? [];
  if (!references.length) {
    out.push(`<div class="smallNote dim">No code-referenced strings were detected.</div>`);
    return;
  }
  out.push(
    `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">` +
    `Code-referenced strings (${references.length})</summary>` +
    `<div class="tableWrap"><table class="table" style="margin-top:.35rem">` +
    `<thead><tr><th class="peNumeric">RVA</th><th>Section</th><th>Encoding</th>` +
    `<th class="peNumeric">Refs</th><th>Code refs</th><th>Text</th></tr></thead>` +
    `<tbody>${renderCodeStringRows(pe, references)}</tbody></table></div></details>`
  );
};

const renderApiStringCallSites = (reference: PeApiStringReference): string => {
  const sites = reference.callSites.slice(0, 3).map(site => {
    const parameter = site.parameterName ?? `arg${site.parameterIndex + 1}`;
    return `${sourceLabel(site.sourceKind)} ${site.module}!${site.entrypoint} ` +
      `${parameter} @ ${formatRva(site.instructionRva)}`;
  });
  const suffix = reference.callSites.length > sites.length
    ? ` +${reference.callSites.length - sites.length} more`
    : "";
  return escapeHtml(`${sites.join("; ")}${suffix}`);
};

const renderApiStringRows = (
  pe: PeWindowsParseResult,
  references: PeApiStringReference[]
): string => references.map(reference => {
  const text = escapeHtml(clippedText(reference.text));
  const title = escapeHtml(reference.text);
  return `<tr><td class="peNumeric">${formatRva(reference.rva)}</td>` +
    `<td>${escapeHtml(sectionForRva(pe, reference.rva))}</td>` +
    `<td>${escapeHtml(reference.encoding)}</td>` +
    `<td class="peNumeric">${reference.callSites.length}</td>` +
    `<td>${renderApiStringCallSites(reference)}</td>` +
    `<td><code title="${title}">${text}</code></td></tr>`;
}).join("");

const renderApiStringReferences = (pe: PeWindowsParseResult, out: string[]): void => {
  const references = pe.disassembly?.apiStringReferences ?? [];
  if (!references.length) {
    out.push(
      `<div class="smallNote dim">No WinAPI/UCRT string arguments were detected ` +
      `in direct imported calls.</div>`
    );
    return;
  }
  out.push(
    `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">` +
    `WinAPI/UCRT string arguments (${references.length})</summary>` +
    `<div class="tableWrap"><table class="table" style="margin-top:.35rem">` +
    `<thead><tr><th class="peNumeric">RVA</th><th>Section</th><th>Encoding</th>` +
    `<th class="peNumeric">Refs</th><th>API argument</th><th>Text</th></tr></thead>` +
    `<tbody>${renderApiStringRows(pe, references)}</tbody></table></div></details>`
  );
};

const renderInstructionSetsContent = (pe: PeWindowsParseResult, out: string[]): void => {
  const disasm = pe.disassembly;
  out.push(renderInstructionPanelStart());
  const analyzeLabel = disasm ? "Re-analyze instruction sets" : "Analyze instruction sets";
  out.push(
    `<button type="button" class="actionButton" id="${ANALYZE_BUTTON_ID}">` +
    `${escapeHtml(analyzeLabel)}</button>`
  );
  out.push(
    `<button type="button" class="actionButton" id="${CANCEL_BUTTON_ID}" hidden>` +
    `Cancel</button>`
  );
  out.push(`</div>`);
  out.push(
    `<div class="smallNote">Static code sampling of reachable instructions. ` +
    `This is derived behavior, not a PE file section or header field.</div>`
  );
  if (!disasm) {
    out.push(
      `<div class="smallNote dim" id="${PROGRESS_TEXT_ID}">Not analyzed yet. ` +
      `Start analysis to highlight CPU feature usage as instructions are decoded.</div>` +
      `<progress id="${PROGRESS_BAR_ID}" style="width:100%" hidden></progress>`
    );
    out.push(renderFeatureTable(renderPendingFeatureRows()));
    out.push(renderInstructionPanelEnd());
    return;
  }

  const mode = disasm.bitness === 64 ? "64-bit" : "32-bit";
  out.push(
    `<div class="smallNote">Disassembly sample (${mode}): ` +
    `${disasm.instructionCount} instruction(s) decoded from ` +
    `${formatHumanSize(disasm.bytesDecoded)} / ${formatHumanSize(disasm.bytesSampled)}. ` +
    `Invalid decodes: ${disasm.invalidInstructionCount}.</div>`
  );
  out.push(
    `<div class="smallNote dim">Note: this is a static, control-flow guided sample ` +
    `of reachable code paths; it is not a full disassembly and may miss code behind ` +
    `indirect jumps/calls, unpacking, or runtime generation.</div>`
  );

  if (disasm.issues?.length) {
    const items = disasm.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
    out.push(
      `<details style="margin-top:.35rem"><summary class="dim" ` +
      `style="cursor:pointer">Notes</summary><ul>${items}</ul></details>`
    );
  }

  renderCodeStringReferences(pe, out);
  renderApiStringReferences(pe, out);

  const countsById = new Map<string, number>();
  for (const set of disasm.instructionSets) {
    countsById.set(set.id, (countsById.get(set.id) || 0) + set.instructionCount);
  }

  if (countsById.size === 0) {
    out.push(
      `<div class="smallNote dim">No instruction-set requirements were detected ` +
      `in the sampled bytes.</div>`
    );
  }

  const knownIds = new Set<string>(KNOWN_CPUID_FEATURES);
  out.push(renderFeatureTable(renderKnownFeatureRows(countsById)));

  const other = disasm.instructionSets.filter(set => !knownIds.has(set.id));
  if (other.length) {
    out.push(
      `<details style="margin-top:.35rem"><summary class="dim" ` +
      `style="cursor:pointer">Other detected features (${other.length})</summary>`
    );
    out.push(
      `<table class="table" style="margin-top:.35rem"><thead><tr>` +
      `<th>Set</th><th>Instr.</th><th>What it is</th></tr></thead><tbody>`
    );
    for (const set of other) {
      const label = escapeHtml(set.label);
      const description = escapeHtml(set.description);
      const count = escapeHtml(String(set.instructionCount));
      const title = escapeHtml(`CpuidFeature.${set.id}`);
      out.push(
        `<tr><td><span class="opt sel" title="${title}">${label}</span></td>` +
        `<td>${count}</td><td>${description}</td></tr>`
      );
    }
    out.push(`</tbody></table></details>`);
  }

  out.push(renderInstructionPanelEnd());
};

export const renderInstructionSetsPanel = (pe: PeWindowsParseResult): string => {
  const out: string[] = [];
  renderInstructionSetsContent(pe, out);
  return `<section id="${PE_INSTRUCTION_SETS_PANEL_ID}">${out.join("")}</section>`;
};

export const renderInstructionSets = (pe: PeWindowsParseResult, out: string[]): void => {
  out.push(renderInstructionSetsPanel(pe));
};
