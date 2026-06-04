"use strict";

import { formatHumanSize, hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type {
  PeEntrypointDisassemblyBlock,
  PeEntrypointInstructionTarget
} from "../../analyzers/pe/disassembly/index.js";
import {
  KNOWN_CPUID_FEATURES,
  describeCpuidFeature,
  formatCpuidLabel
} from "../../analyzers/x86/cpuid-features.js";

const ANALYZE_BUTTON_ID = "peInstructionSetsAnalyzeButton";
const CANCEL_BUTTON_ID = "peInstructionSetsCancelButton";
const ENTRYPOINT_BUTTON_ID = "peEntrypointDisassembleButton";
const PROGRESS_TEXT_ID = "peInstructionSetsProgressText";
const PROGRESS_BAR_ID = "peInstructionSetsProgress";
const CHIP_ID_PREFIX = "peInstructionSetChip_";
const COUNT_ID_PREFIX = "peInstructionSetCount_";

const renderInstructionPanelStart = (): string =>
  `<details class="analysisPanel"><summary class="analysisPanelSummary">` +
  `<span class="analysisPanelTitle">Instruction-set analysis</span></summary>` +
  `<div class="analysisPanelBody"><div class="analysisPanelActions">`;

const renderInstructionPanelEnd = (): string => "</div></details>";

const hasEntrypoint = (pe: PeWindowsParseResult): boolean =>
  Number.isSafeInteger(pe.opt.AddressOfEntryPoint) && pe.opt.AddressOfEntryPoint > 0;

const renderEntrypointActions = (pe: PeWindowsParseResult, out: string[]): void => {
  if (!hasEntrypoint(pe)) return;
  const label = pe.entrypointDisassembly
    ? "Re-disassemble entry point"
    : "Disassemble entry point";
  out.push(
    `<button type="button" class="actionButton" id="${ENTRYPOINT_BUTTON_ID}">` +
    `${escapeHtml(label)}</button>`
  );
};

const renderEntrypointTarget = (target: PeEntrypointInstructionTarget | undefined): string => {
  if (!target) return `<span class="dim">-</span>`;
  if (target.kind === "code") {
    const status = target.followed ? "followed" : "not followed";
    return `${escapeHtml(status)} ${hex(target.rva, 8)}`;
  }
  if (target.kind === "branch") {
    const branchStatus = target.branchFollowed ? "followed" : "not followed";
    const fallthroughStatus = target.fallthroughFollowed ? "followed" : "not followed";
    return `branch ${escapeHtml(branchStatus)} ${hex(target.branchRva, 8)}; ` +
      `fallthrough ${escapeHtml(fallthroughStatus)} ${hex(target.fallthroughRva, 8)}`;
  }
  const guard = target.guardIatEntry ? " guarded" : "";
  const returnTarget = target.returnRva != null
    ? `; returns ${target.returnFollowed ? "followed" : "not followed"} to ${hex(target.returnRva, 8)}`
    : "";
  return `${escapeHtml(target.label)} <span class="dim">(${target.importKind}${guard} IAT ` +
    `${hex(target.slotRva, 8)}${returnTarget})</span>`;
};

const renderEntrypointBlockLabel = (block: PeEntrypointDisassemblyBlock): string => {
  if (block.kind === "entrypoint") return "Entry point";
  const source = block.sourceInstructionRva == null ? "" : ` from ${hex(block.sourceInstructionRva, 8)}`;
  if (block.kind === "followed-call") return `Followed call target${source}`;
  if (block.kind === "followed-jump") return `Followed jump target${source}`;
  if (block.kind === "followed-import-return") return `Followed returning import fallthrough${source}`;
  return block.kind === "followed-branch"
    ? `Followed conditional branch target${source}`
    : `Followed conditional fallthrough${source}`;
};

const renderEntrypointBlock = (block: PeEntrypointDisassemblyBlock, out: string[]): void => {
  out.push(
    `<div class="smallNote" style="margin-top:.7rem"><strong>` +
    `${escapeHtml(renderEntrypointBlockLabel(block))}</strong>: RVA ${hex(block.startRva, 8)}, ` +
    `file offset ${hex(block.fileOffsetStart, 8)}.</div>`
  );
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr>` +
    `<th>RVA</th><th>File offset</th><th>Instruction</th><th>Target</th></tr></thead><tbody>` +
    block.instructions.map(instruction => (
      `<tr><td class="mono peNumeric" data-sort-value="${instruction.rva}">` +
      `${hex(instruction.rva, 8)}</td>` +
      `<td class="mono peNumeric" data-sort-value="${instruction.fileOffset}">` +
      `${hex(instruction.fileOffset, 8)}</td>` +
      `<td class="mono">${escapeHtml(instruction.text)}</td>` +
      `<td>${renderEntrypointTarget(instruction.target)}</td></tr>`
    )).join("") +
    `</tbody></table>`
  );
};

const renderEntrypointDisassembly = (pe: PeWindowsParseResult, out: string[]): void => {
  const report = pe.entrypointDisassembly;
  if (!report) return;
  out.push(
    `<div class="smallNote" style="margin-top:.7rem">Entrypoint preview: ` +
    `${report.instructionCount} instruction(s), ${formatHumanSize(report.bytesDecoded)}, ` +
    `RVA ${hex(report.entrypointRva, 8)}.</div>`
  );
  for (const block of report.blocks) {
    renderEntrypointBlock(block, out);
  }
  if (report.issues.length) {
    const items = report.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
    out.push(`<ul class="smallNote">${items}</ul>`);
  }
};

export function renderInstructionSets(pe: PeWindowsParseResult, out: string[]): void {
  const disasm = pe.disassembly;
  out.push(renderInstructionPanelStart());
  const analyzeLabel = disasm ? "Re-analyze instruction sets" : "Analyze instruction sets";
  out.push(
    `<button type="button" class="actionButton" id="${ANALYZE_BUTTON_ID}">` +
    `${escapeHtml(analyzeLabel)}</button>`
  );
  renderEntrypointActions(pe, out);
  out.push(
    `<button type="button" class="actionButton" id="${CANCEL_BUTTON_ID}" hidden>` +
    `Cancel</button>`
  );
  out.push(`</div>`);
  out.push(
    `<div class="smallNote">Static code sampling of reachable instructions. ` +
    `This is derived behavior, not a PE file section or header field.</div>`
  );
  renderEntrypointDisassembly(pe, out);

  if (!disasm) {
    out.push(
      `<div class="smallNote dim" id="${PROGRESS_TEXT_ID}">Not analyzed yet. ` +
      `Start analysis to highlight CPU feature usage as instructions are decoded.</div>` +
      `<progress id="${PROGRESS_BAR_ID}" style="width:100%" hidden></progress>`
    );
    out.push(
      `<table class="table" style="margin-top:.35rem"><thead><tr>` +
      `<th>Set</th><th>Instr.</th><th>What it is</th></tr></thead><tbody>`
    );
    for (const id of KNOWN_CPUID_FEATURES) {
      const label = escapeHtml(formatCpuidLabel(id));
      const description = escapeHtml(describeCpuidFeature(id));
      const title = escapeHtml(`CpuidFeature.${id}`);
      const chipId = escapeHtml(`${CHIP_ID_PREFIX}${id}`);
      const countId = escapeHtml(`${COUNT_ID_PREFIX}${id}`);
      out.push(
        `<tr><td><span class="opt dim" id="${chipId}" title="${title}">${label}</span></td>` +
        `<td class="dim" id="${countId}">0</td><td>${description}</td></tr>`
      );
    }
    out.push(`</tbody></table>`);
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
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr>` +
    `<th>Set</th><th>Instr.</th><th>What it is</th></tr></thead><tbody>`
  );
  for (const id of KNOWN_CPUID_FEATURES) {
    const countValue = countsById.get(id) || 0;
    const label = escapeHtml(formatCpuidLabel(id));
    const description = escapeHtml(describeCpuidFeature(id));
    const title = escapeHtml(`CpuidFeature.${id}`);
    const chipClass = countValue > 0 ? "opt sel" : "opt dim";
    const count = countValue > 0
      ? escapeHtml(String(countValue))
      : `<span class="dim">0</span>`;
    out.push(
      `<tr><td><span class="${chipClass}" title="${title}">${label}</span></td>` +
      `<td>${count}</td><td>${description}</td></tr>`
    );
  }
  out.push(`</tbody></table>`);

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
}
