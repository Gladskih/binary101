"use strict";

import { hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type {
  PeEntrypointDisassemblyReport,
  PeEntrypointInstruction,
  PeEntrypointInstructionTarget
} from "../../analyzers/pe/disassembly/index.js";
import {
  DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE,
  PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE,
  PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE,
  entrypointPageCount,
  entrypointPageIndexes,
  normalizeEntrypointExplorerState,
  visibleEntrypointBlocks,
  type PeEntrypointExplorerState,
  type PeEntrypointRenderBlock
} from "./entrypoint-disassembly-model.js";

export type {
  PeEntrypointExplorerState,
  PeEntrypointRenderBlock,
  PeEntrypointRvaSelection
} from "./entrypoint-disassembly-model.js";

export {
  DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE,
  PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE,
  PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE,
  findEntrypointRvaSelection,
  moveEntrypointExplorerPage,
  normalizeEntrypointExplorerState,
  selectEntrypointBlock,
  selectEntrypointRva,
  visibleEntrypointBlocks
} from "./entrypoint-disassembly-model.js";

const jumpButton = (rva: number): string =>
  `<button type="button" class="peEntrypointJump" data-pe-entrypoint-jump="${rva}">` +
  `${hex(rva, 8)}</button>`;

const renderEntrypointTarget = (target: PeEntrypointInstructionTarget | undefined): string => {
  if (!target) return "";
  if (target.kind === "code") return renderCodeTarget(target.followed, target.rva);
  if (target.kind === "return") return renderReturnTarget(target);
  if (target.kind === "branch") return renderBranchTarget(target);
  return renderImportTarget(target);
};

const renderCodeTarget = (followed: boolean, rva: number): string =>
  `${escapeHtml(followed ? "followed" : "not followed")} ${jumpButton(rva)}`;

const renderReturnTarget = (
  target: Extract<PeEntrypointInstructionTarget, { kind: "return" }>
): string => {
  if ("rva" in target) return `return ${renderCodeTarget(target.followed, target.rva)}`;
  return target.reason === "outside-image" ? "return target outside image" : "return target unknown";
};

const renderBranchTarget = (
  target: Extract<PeEntrypointInstructionTarget, { kind: "branch" }>
): string =>
  `branch ${renderCodeTarget(target.branchFollowed, target.branchRva)}; ` +
  `fallthrough ${renderCodeTarget(target.fallthroughFollowed, target.fallthroughRva)}`;

const renderImportTarget = (
  target: Extract<PeEntrypointInstructionTarget, { kind: "import" }>
): string => {
  const guard = target.guardIatEntry ? " guarded" : "";
  const returned = target.returnRva == null
    ? ""
    : `; returns ${target.returnFollowed ? "followed" : "not followed"} to ` +
      `${jumpButton(target.returnRva)}`;
  return `${escapeHtml(target.label)} <span class="dim">(${target.importKind}${guard} IAT ` +
    `${hex(target.slotRva, 8)}${returned})</span>`;
};

const renderEntrypointNotes = (instruction: PeEntrypointInstruction): string => {
  const notes = [
    renderEntrypointTarget(instruction.target),
    ...(instruction.notes ?? []).map(note => escapeHtml(note))
  ].filter(Boolean);
  return notes.length ? notes.join("<br>") : `<span class="dim">-</span>`;
};

const sourceLabel = (block: PeEntrypointRenderBlock): string => {
  if (!block.sources.length) return "";
  return ` from ${block.sources.map(rva => hex(rva, 8)).join(", ")}`;
};

const duplicateLabel = (block: PeEntrypointRenderBlock): string =>
  block.duplicateCount > 1 ? `; ${block.duplicateCount - 1} duplicate context(s) merged` : "";

export const renderEntrypointBlockLabel = (block: PeEntrypointRenderBlock): string => {
  const source = sourceLabel(block);
  const duplicates = duplicateLabel(block);
  if (block.block.kind === "entrypoint") return `Entry point${duplicates}`;
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

export const renderEntrypointExplorer = (
  report: PeEntrypointDisassemblyReport,
  state: PeEntrypointExplorerState = DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE
): string => {
  const blocks = visibleEntrypointBlocks(report.blocks);
  if (!blocks.length) return "";
  const normalized = normalizeEntrypointExplorerState(blocks, state);
  return `<div class="peEntrypointExplorer" data-pe-entrypoint-explorer ` +
    `${entrypointExplorerStateAttributes(normalized)}>` +
    `${renderEntrypointExplorerContent(blocks, normalized)}</div>`;
};

export const renderEntrypointExplorerContent = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState
): string => {
  const normalized = normalizeEntrypointExplorerState(blocks, state);
  return renderBlockIndex(blocks, normalized) + renderSelectedBlock(blocks, normalized);
};

export const entrypointExplorerStateAttributes = (state: PeEntrypointExplorerState): string =>
  `data-pe-entrypoint-selected-block-index="${state.selectedBlockIndex}" ` +
  `data-pe-entrypoint-block-page-index="${state.blockPageIndex}" ` +
  `data-pe-entrypoint-instruction-page-index="${state.instructionPageIndex}"`;

const renderEntrypointBlockKind = (block: PeEntrypointRenderBlock): string => {
  if (block.block.kind === "entrypoint") return "Entry point";
  if (block.block.kind === "followed-call") return "Call target";
  if (block.block.kind === "followed-jump") return "Jump target";
  if (block.block.kind === "followed-import-return") return "Import return";
  if (block.block.kind === "followed-return") return "Return target";
  return block.block.kind === "followed-branch" ? "Branch target" : "Branch fallthrough";
};

const renderBlockIndex = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState
): string => {
  const indexes = entrypointPageIndexes(
    blocks.length,
    PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE,
    state.blockPageIndex
  );
  return `<div class="peEntrypointBlockIndex">` +
    `<div class="smallNote peEntrypointBlockIndexTitle"><strong>Block index ` +
    `(${blocks.length})</strong></div>` +
    renderPager("blocks", "Blocks", blocks.length, PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE, state.blockPageIndex) +
    `<div class="tableWrap"><table class="table peEntrypointBlockIndexTable">` +
    `<thead><tr><th>RVA</th><th>Kind</th><th>Source</th><th>Instructions</th>` +
    `<th>File offset</th></tr></thead><tbody>` +
    `${indexes.map(index => renderBlockIndexRow(blocks[index], index, state)).join("")}` +
    `</tbody></table></div></div>`;
};

const renderBlockIndexRow = (
  block: PeEntrypointRenderBlock | undefined,
  blockIndex: number,
  state: PeEntrypointExplorerState
): string => {
  if (!block) return "";
  const selected = blockIndex === state.selectedBlockIndex ? " data-selected=\"true\"" : "";
  const ariaCurrent = blockIndex === state.selectedBlockIndex ? " aria-current=\"true\"" : "";
  return `<tr class="peEntrypointBlockIndexRow"${selected}>` +
    `<td class="mono peNumeric"><button type="button" class="peEntrypointBlockSelect" ` +
    `data-pe-entrypoint-block-select="${blockIndex}"${ariaCurrent}>` +
    `${hex(block.block.startRva, 8)}</button></td>` +
    `<td>${escapeHtml(renderEntrypointBlockKind(block))}</td>` +
    `<td>${renderSources(block)}</td>` +
    `<td class="mono peNumeric">${escapeHtml(String(block.block.instructions.length))}</td>` +
    `<td class="mono peNumeric">${hex(block.block.fileOffsetStart, 8)}</td></tr>`;
};

const renderSources = (block: PeEntrypointRenderBlock): string =>
  block.sources.length ? block.sources.map(jumpButton).join(", ") : `<span class="dim">-</span>`;

const renderSelectedBlock = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState
): string => {
  const block = blocks[state.selectedBlockIndex];
  if (!block) return "";
  const instructions = block.block.instructions;
  const indexes = entrypointPageIndexes(
    instructions.length,
    PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE,
    state.instructionPageIndex
  );
  return `<div class="peEntrypointSelectedBlock" data-pe-entrypoint-selected-block>` +
    renderSelectedBlockHeader(block, state.selectedBlockIndex) +
    renderPager(
      "instructions",
      "Instructions",
      instructions.length,
      PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE,
      state.instructionPageIndex
    ) +
    `<div class="tableWrap"><table class="table peEntrypointInstructionTable">` +
    `<thead><tr><th>RVA</th><th>File offset</th><th>Instruction</th><th>Notes</th></tr></thead>` +
    `<tbody>${indexes.map(index => renderInstructionRow(instructions[index])).join("")}` +
    `</tbody></table></div></div>`;
};

const renderSelectedBlockHeader = (block: PeEntrypointRenderBlock, blockIndex: number): string =>
  `<div class="smallNote peEntrypointBlock" tabindex="-1" data-pe-entrypoint-block-index="` +
  `${blockIndex}" data-pe-entrypoint-block-rva="${block.block.startRva}" ` +
  `data-pe-entrypoint-rva="${block.block.startRva}"><strong>` +
  `${escapeHtml(renderEntrypointBlockLabel(block))}</strong>: RVA ${hex(block.block.startRva, 8)}, ` +
  `file offset ${hex(block.block.fileOffsetStart, 8)}.</div>`;

const renderInstructionRow = (instruction: PeEntrypointInstruction | undefined): string => {
  if (!instruction) return "";
  return `<tr class="peEntrypointInstructionRow" tabindex="-1" ` +
    `data-pe-entrypoint-rva="${instruction.rva}"><td class="mono peNumeric" ` +
    `data-sort-value="${instruction.rva}">${hex(instruction.rva, 8)}</td>` +
    `<td class="mono peNumeric" data-sort-value="${instruction.fileOffset}">` +
    `${hex(instruction.fileOffset, 8)}</td>` +
    `<td class="mono">${escapeHtml(instruction.text)}</td>` +
    `<td>${renderEntrypointNotes(instruction)}</td></tr>`;
};

const renderPager = (
  target: "blocks" | "instructions",
  label: "Blocks" | "Instructions",
  rowCount: number,
  pageSize: number,
  pageIndex: number
): string => {
  const pages = entrypointPageCount(rowCount, pageSize);
  if (pages <= 1) return "";
  const firstDisabled = pageIndex <= 0 ? " disabled" : "";
  const lastDisabled = pageIndex >= pages - 1 ? " disabled" : "";
  return `<div class="peEntrypointPager pagedSortableTableToolbar">` +
    `<span class="pagedSortableTableRange">${escapeHtml(formatRange(label, rowCount, pageSize, pageIndex))}</span>` +
    `<span class="pagedSortableTableControls">` +
    renderPageButton(target, "first", "First", firstDisabled) +
    renderPageButton(target, "previous", "Prev", firstDisabled) +
    `<input class="pagedSortableTablePageInput" type="number" min="1" max="${pages}" ` +
    `value="${pageIndex + 1}" aria-label="${escapeHtml(label)} page" ` +
    `data-pe-entrypoint-page-input="${target}">` +
    `<span class="pagedSortableTablePageCount">/ ${pages}</span>` +
    renderPageButton(target, "next", "Next", lastDisabled) +
    renderPageButton(target, "last", "Last", lastDisabled) +
    `</span></div>`;
};

const renderPageButton = (
  target: "blocks" | "instructions",
  action: "first" | "previous" | "next" | "last",
  label: string,
  disabled: string
): string =>
  `<button type="button" class="tableButton" data-pe-entrypoint-page-target="${target}" ` +
  `data-pe-entrypoint-page-action="${action}"${disabled}>${label}</button>`;

const formatRange = (
  label: "Blocks" | "Instructions",
  rowCount: number,
  pageSize: number,
  pageIndex: number
): string => {
  if (rowCount <= 0) return `${label} 0 of 0`;
  return `${label} ${pageIndex * pageSize + 1}-${Math.min(rowCount, pageIndex * pageSize + pageSize)} ` +
    `of ${rowCount}`;
};
