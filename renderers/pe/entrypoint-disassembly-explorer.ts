"use strict";

import { hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type {
  PeEntrypointDisassemblyReport,
  PeEntrypointInstruction,
  PeEntrypointInstructionTarget
} from "../../analyzers/pe/disassembly/index.js";
import {
  renderEntrypointBlockKind,
  renderEntrypointBlockLabel,
  renderEntrypointSourceLinks,
  renderEntrypointSourcesPreview
} from "./entrypoint-disassembly-block-labels.js";
import { renderEntrypointJumpButton } from "./entrypoint-disassembly-links.js";
import {
  DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE,
  PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE,
  PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE,
  PE_ENTRYPOINT_SOURCE_PAGE_SIZE,
  entrypointBlockPageIndexes,
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
  PeEntrypointRvaSelection,
  PeEntrypointSortDirection
} from "./entrypoint-disassembly-model.js";

export {
  renderEntrypointBlockLabel
} from "./entrypoint-disassembly-block-labels.js";

export {
  DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE,
  PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE,
  PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE,
  PE_ENTRYPOINT_SOURCE_PAGE_SIZE,
  findEntrypointRvaSelection,
  moveEntrypointExplorerPage,
  normalizeEntrypointExplorerState,
  selectEntrypointBlock,
  selectEntrypointRva,
  toggleEntrypointBlockSort,
  visibleEntrypointBlocks
} from "./entrypoint-disassembly-model.js";

const renderEntrypointTarget = (target: PeEntrypointInstructionTarget | undefined): string => {
  if (!target) return "";
  if (target.kind === "code") return renderCodeTarget(target.followed, target.rva);
  if (target.kind === "return") return renderReturnTarget(target);
  if (target.kind === "branch") return renderBranchTarget(target);
  return renderImportTarget(target);
};

const renderCodeTarget = (followed: boolean, rva: number): string =>
  `${escapeHtml(followed ? "followed" : "not followed")} ${renderEntrypointJumpButton(rva)}`;

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
      `${renderEntrypointJumpButton(target.returnRva)}`;
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
  `data-pe-entrypoint-instruction-page-index="${state.instructionPageIndex}" ` +
  `data-pe-entrypoint-source-page-index="${state.sourcePageIndex}" ` +
  `data-pe-entrypoint-block-sort-column="${state.blockSortColumnIndex ?? ""}" ` +
  `data-pe-entrypoint-block-sort-direction="${state.blockSortDirection ?? ""}"`;

const renderBlockIndex = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState
): string => {
  const indexes = entrypointBlockPageIndexes(blocks, state);
  return `<div class="peEntrypointBlockIndex">` +
    `<div class="smallNote peEntrypointBlockIndexTitle"><strong>Block index ` +
    `(${blocks.length})</strong></div>` +
    renderPager("blocks", "Blocks", blocks.length, PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE, state.blockPageIndex) +
    `<div class="tableWrap"><table class="table peEntrypointBlockIndexTable" ` +
    `data-sortable="false"><thead>${renderBlockIndexHeader(state)}</thead><tbody>` +
    `${indexes.map(index => renderBlockIndexRow(blocks[index], index, state)).join("")}` +
    `</tbody></table></div></div>`;
};

const renderBlockIndexHeader = (state: PeEntrypointExplorerState): string =>
  `<tr>` +
  renderBlockIndexHeaderCell("RVA", 0, "peNumeric", state) +
  renderBlockIndexHeaderCell("Kind", 1, "", state) +
  renderBlockIndexHeaderCell("Source", 2, "", state) +
  renderBlockIndexHeaderCell("Instructions", 3, "peNumeric", state) +
  renderBlockIndexHeaderCell("File offset", 4, "peNumeric", state) +
  `</tr>`;

const renderBlockIndexHeaderCell = (
  label: string,
  columnIndex: number,
  className: string,
  state: PeEntrypointExplorerState
): string => {
  const active = state.blockSortColumnIndex === columnIndex && state.blockSortDirection;
  const sortDirection = active ? ` data-sort-direction="${state.blockSortDirection}"` : "";
  const ariaSort = active ? ` aria-sort="${state.blockSortDirection}"` : "";
  const headerClass = className ? ` ${escapeHtml(className)}` : "";
  return `<th class="sortableTableHeader${headerClass}"${ariaSort}>` +
    `<button type="button" class="sortableTableHeaderButton" ` +
    `data-pe-entrypoint-block-sort="${columnIndex}" aria-label="Sort by ${escapeHtml(label)}"` +
    `${sortDirection}><span class="sortableTableHeaderLabel">${escapeHtml(label)}</span>` +
    `<span class="sortableTableHeaderSortIcon" aria-hidden="true"></span></button></th>`;
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
    `<td>${renderEntrypointSourcesPreview(block)}</td>` +
    `<td class="mono peNumeric">${escapeHtml(String(block.block.instructions.length))}</td>` +
    `<td class="mono peNumeric">${hex(block.block.fileOffsetStart, 8)}</td></tr>`;
};

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
    renderSelectedBlockSources(block, state.sourcePageIndex) +
    renderPager(
      "instructions",
      "Instructions",
      instructions.length,
      PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE,
      state.instructionPageIndex
    ) +
    `<div class="tableWrap"><table class="table peEntrypointInstructionTable" data-sortable="false">` +
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

const renderSelectedBlockSources = (
  block: PeEntrypointRenderBlock,
  sourcePageIndex: number
): string => {
  if (!block.sources.length) return "";
  const indexes = entrypointPageIndexes(
    block.sources.length,
    PE_ENTRYPOINT_SOURCE_PAGE_SIZE,
    sourcePageIndex
  );
  const sources = indexes.map(index => block.sources[index]).filter(isNumber);
  return `<div class="smallNote peEntrypointSources">` +
    renderPager("sources", "Sources", block.sources.length, PE_ENTRYPOINT_SOURCE_PAGE_SIZE, sourcePageIndex) +
    `<span><strong>Sources:</strong> ${renderEntrypointSourceLinks(sources)}</span></div>`;
};

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
  target: "blocks" | "instructions" | "sources",
  label: "Blocks" | "Instructions" | "Sources",
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
  target: "blocks" | "instructions" | "sources",
  action: "first" | "previous" | "next" | "last",
  label: string,
  disabled: string
): string =>
  `<button type="button" class="tableButton" data-pe-entrypoint-page-target="${target}" ` +
  `data-pe-entrypoint-page-action="${action}"${disabled}>${label}</button>`;

const formatRange = (
  label: "Blocks" | "Instructions" | "Sources",
  rowCount: number,
  pageSize: number,
  pageIndex: number
): string => {
  if (rowCount <= 0) return `${label} 0 of 0`;
  return `${label} ${pageIndex * pageSize + 1}-${Math.min(rowCount, pageIndex * pageSize + pageSize)} ` +
    `of ${rowCount}`;
};

const isNumber = (value: number | undefined): value is number => value != null;
