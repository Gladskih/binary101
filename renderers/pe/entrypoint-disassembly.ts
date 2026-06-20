"use strict";

import { formatHumanSize, hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type {
  PeEntrypointDisassemblyBlock,
  PeEntrypointInstruction,
  PeEntrypointInstructionTarget
} from "../../analyzers/pe/disassembly/index.js";

const ENTRYPOINT_BUTTON_ID = "peEntrypointDisassembleButton";

export const PE_ENTRYPOINT_DISASSEMBLY_PANEL_ID = "peEntrypointDisassemblyPanel";

type RenderBlock = {
  block: PeEntrypointDisassemblyBlock;
  duplicateCount: number;
  sources: number[];
};

type SignatureScalar = string | number | boolean | null;
type TargetSignature = Record<string, SignatureScalar> | null;
type InstructionSignature = {
  rva: number;
  fileOffset: number;
  text: string;
  notes: string[];
  target: TargetSignature;
};

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

const jumpButton = (rva: number): string =>
  `<button type="button" class="peEntrypointJump" data-pe-entrypoint-jump="${rva}">` +
  `${hex(rva, 8)}</button>`;

const renderEntrypointTarget = (target: PeEntrypointInstructionTarget | undefined): string => {
  if (!target) return "";
  if (target.kind === "code") {
    const status = target.followed ? "followed" : "not followed";
    return `${escapeHtml(status)} ${jumpButton(target.rva)}`;
  }
  if (target.kind === "return") {
    if ("rva" in target) {
      const status = target.followed ? "followed" : "not followed";
      return `return ${escapeHtml(status)} ${jumpButton(target.rva)}`;
    }
    return target.reason === "outside-image"
      ? "return target outside image"
      : "return target unknown";
  }
  if (target.kind === "branch") {
    const branchStatus = target.branchFollowed ? "followed" : "not followed";
    const fallthroughStatus = target.fallthroughFollowed ? "followed" : "not followed";
    return `branch ${escapeHtml(branchStatus)} ${jumpButton(target.branchRva)}; ` +
      `fallthrough ${escapeHtml(fallthroughStatus)} ${jumpButton(target.fallthroughRva)}`;
  }
  const guard = target.guardIatEntry ? " guarded" : "";
  const returnTarget = target.returnRva != null
    ? `; returns ${target.returnFollowed ? "followed" : "not followed"} to ` +
      `${jumpButton(target.returnRva)}`
    : "";
  return `${escapeHtml(target.label)} <span class="dim">(${target.importKind}${guard} IAT ` +
    `${hex(target.slotRva, 8)}${returnTarget})</span>`;
};

const renderEntrypointNotes = (instruction: PeEntrypointInstruction): string => {
  const notes = [
    renderEntrypointTarget(instruction.target),
    ...(instruction.notes ?? []).map(note => escapeHtml(note))
  ].filter(Boolean);
  return notes.length ? notes.join("<br>") : `<span class="dim">-</span>`;
};

const sourceLabel = (block: RenderBlock): string => {
  if (!block.sources.length) return "";
  const sources = block.sources.map(rva => hex(rva, 8)).join(", ");
  return ` from ${sources}`;
};

const duplicateLabel = (block: RenderBlock): string =>
  block.duplicateCount > 1 ? `; ${block.duplicateCount - 1} duplicate context(s) merged` : "";

const renderEntrypointBlockLabel = (block: RenderBlock): string => {
  if (block.block.kind === "entrypoint") return "Entry point";
  const source = sourceLabel(block);
  const duplicates = duplicateLabel(block);
  if (block.block.kind === "followed-call") return `Followed call target${source}${duplicates}`;
  if (block.block.kind === "followed-jump") return `Followed jump target${source}${duplicates}`;
  if (block.block.kind === "followed-import-return") {
    return `Followed returning import fallthrough${source}${duplicates}`;
  }
  if (block.block.kind === "followed-return") return `Followed return target${source}${duplicates}`;
  return block.block.kind === "followed-branch"
    ? `Followed conditional branch target${source}${duplicates}`
    : `Followed conditional fallthrough${source}${duplicates}`;
};

const targetSignature = (target: PeEntrypointInstructionTarget | undefined): TargetSignature => {
  if (!target) return null;
  if (target.kind === "code") return { kind: target.kind, rva: target.rva };
  if (target.kind === "return") {
    return "rva" in target
      ? { kind: target.kind, rva: target.rva }
      : { kind: target.kind, reason: target.reason };
  }
  if (target.kind === "branch") {
    return {
      kind: target.kind,
      branchRva: target.branchRva,
      fallthroughRva: target.fallthroughRva
    };
  }
  return {
    kind: target.kind,
    label: target.label,
    slotRva: target.slotRva,
    importKind: target.importKind,
    guardIatEntry: target.guardIatEntry,
    returnRva: target.returnRva ?? null
  };
};

const instructionSignature = (instruction: PeEntrypointInstruction): InstructionSignature => ({
  rva: instruction.rva,
  fileOffset: instruction.fileOffset,
  text: instruction.text,
  notes: instruction.notes ?? [],
  target: targetSignature(instruction.target)
});

const blockSignature = (block: PeEntrypointDisassemblyBlock): string =>
  JSON.stringify({
    kind: block.kind,
    startRva: block.startRva,
    fileOffsetStart: block.fileOffsetStart,
    instructions: block.instructions.map(instructionSignature)
  });

const uniqueSourceRvas = (block: RenderBlock, sourceRva: number | undefined): number[] =>
  sourceRva == null || block.sources.includes(sourceRva)
    ? block.sources
    : [...block.sources, sourceRva];

const visibleBlocks = (blocks: PeEntrypointDisassemblyBlock[]): RenderBlock[] => {
  const out: RenderBlock[] = [];
  const bySignature = new Map<string, RenderBlock>();
  for (const block of blocks) {
    const signature = blockSignature(block);
    const existing = bySignature.get(signature);
    if (existing) {
      existing.duplicateCount += 1;
      existing.sources = uniqueSourceRvas(existing, block.sourceInstructionRva);
    } else {
      const rendered = {
        block,
        duplicateCount: 1,
        sources: block.sourceInstructionRva == null ? [] : [block.sourceInstructionRva]
      };
      bySignature.set(signature, rendered);
      out.push(rendered);
    }
  }
  return out;
};

const renderEntrypointBlock = (rendered: RenderBlock, out: string[]): void => {
  const block = rendered.block;
  out.push(
    `<div class="smallNote peEntrypointBlock" tabindex="-1" ` +
    `data-pe-entrypoint-block-rva="${block.startRva}" data-pe-entrypoint-rva="${block.startRva}">` +
    `<strong>${escapeHtml(renderEntrypointBlockLabel(rendered))}</strong>: ` +
    `RVA ${hex(block.startRva, 8)}, file offset ${hex(block.fileOffsetStart, 8)}.</div>`
  );
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr>` +
    `<th>RVA</th><th>File offset</th><th>Instruction</th><th>Notes</th></tr></thead><tbody>` +
    block.instructions.map(instruction => (
      `<tr class="peEntrypointInstructionRow" tabindex="-1" ` +
      `data-pe-entrypoint-rva="${instruction.rva}"><td class="mono peNumeric" ` +
      `data-sort-value="${instruction.rva}">${hex(instruction.rva, 8)}</td>` +
      `<td class="mono peNumeric" data-sort-value="${instruction.fileOffset}">` +
      `${hex(instruction.fileOffset, 8)}</td>` +
      `<td class="mono">${escapeHtml(instruction.text)}</td>` +
      `<td>${renderEntrypointNotes(instruction)}</td></tr>`
    )).join("") +
    `</tbody></table>`
  );
};

const renderEntrypointReport = (pe: PeWindowsParseResult, out: string[]): void => {
  const report = pe.entrypointDisassembly;
  if (!report) {
    out.push(`<div class="smallNote dim">Not disassembled yet.</div>`);
    return;
  }
  out.push(
    `<div class="smallNote">Entrypoint preview: ` +
    `${report.instructionCount} instruction(s), ${formatHumanSize(report.bytesDecoded)}, ` +
    `RVA ${hex(report.entrypointRva, 8)}.</div>`
  );
  for (const block of visibleBlocks(report.blocks)) {
    renderEntrypointBlock(block, out);
  }
  if (!report.blocks.length && report.issues.length) {
    const items = report.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
    out.push(`<ul class="smallNote">${items}</ul>`);
  }
};

const renderEntrypointDisassemblyContent = (pe: PeWindowsParseResult, out: string[]): void => {
  if (!hasEntrypoint(pe) && !pe.entrypointDisassembly) return;
  out.push(
    `<details class="analysisPanel"><summary class="analysisPanelSummary">` +
    `<span class="detailsSummaryTitle">Entrypoint disassembly</span></summary>` +
    `<div class="analysisPanelBody"><div class="analysisPanelActions">`
  );
  renderEntrypointActions(pe, out);
  out.push(`</div>`);
  renderEntrypointReport(pe, out);
  out.push(`</div></details>`);
};

export const renderEntrypointDisassemblyPanel = (pe: PeWindowsParseResult): string => {
  const out: string[] = [];
  renderEntrypointDisassemblyContent(pe, out);
  return out.length ? `<section id="${PE_ENTRYPOINT_DISASSEMBLY_PANEL_ID}">${out.join("")}</section>` : "";
};

export const renderEntrypointDisassembly = (pe: PeWindowsParseResult, out: string[]): void => {
  out.push(renderEntrypointDisassemblyPanel(pe));
};
