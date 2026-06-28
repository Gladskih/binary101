"use strict";

import {
  visibleEntrypointBlocks,
  type PeEntrypointRenderBlock
} from "./entrypoint-disassembly-visible-blocks.js";

export { visibleEntrypointBlocks, type PeEntrypointRenderBlock };

export const PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE = 20;
export const PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE = 120;
export const PE_ENTRYPOINT_SOURCE_PAGE_SIZE = 8;

export type PeEntrypointSortDirection = "ascending" | "descending";

export type PeEntrypointExplorerState = {
  selectedBlockIndex: number;
  blockPageIndex: number;
  instructionPageIndex: number;
  sourcePageIndex: number;
  blockSortColumnIndex: number | null;
  blockSortDirection: PeEntrypointSortDirection | null;
};

export type PeEntrypointRvaSelection = { blockIndex: number; instructionPageIndex: number };

export const DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE: PeEntrypointExplorerState = {
  selectedBlockIndex: 0,
  blockPageIndex: 0,
  instructionPageIndex: 0,
  sourcePageIndex: 0,
  blockSortColumnIndex: null,
  blockSortDirection: null
};

export const normalizeEntrypointExplorerState = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState
): PeEntrypointExplorerState => {
  const selectedBlockIndex = clampIndex(state.selectedBlockIndex, blocks.length);
  const sortColumnIndex = normalizeSortColumnIndex(state.blockSortColumnIndex);
  const sortDirection = sortColumnIndex == null
    ? null
    : normalizeSortDirection(state.blockSortDirection);
  return {
    selectedBlockIndex,
    blockPageIndex: clampPageIndex(
      state.blockPageIndex,
      entrypointPageCount(blocks.length, PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE)
    ),
    instructionPageIndex: clampPageIndex(
      state.instructionPageIndex,
      instructionPageCount(blocks[selectedBlockIndex])
    ),
    sourcePageIndex: clampPageIndex(
      state.sourcePageIndex,
      sourcePageCount(blocks[selectedBlockIndex])
    ),
    blockSortColumnIndex: sortColumnIndex,
    blockSortDirection: sortDirection
  };
};

export const selectEntrypointBlock = (
  blocks: readonly PeEntrypointRenderBlock[],
  blockIndex: number,
  state: PeEntrypointExplorerState = DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE
): PeEntrypointExplorerState => {
  const selectedBlockIndex = clampIndex(blockIndex, blocks.length);
  const normalized = normalizeEntrypointExplorerState(blocks, state);
  return normalizeEntrypointExplorerState(blocks, {
    ...normalized,
    selectedBlockIndex,
    blockPageIndex: blockPageIndexForBlock(blocks, normalized, selectedBlockIndex),
    instructionPageIndex: 0,
    sourcePageIndex: 0
  });
};

export const moveEntrypointExplorerPage = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState,
  target: "blocks" | "instructions" | "sources",
  next: "first" | "previous" | "next" | "last" | number
): PeEntrypointExplorerState => {
  const normalized = normalizeEntrypointExplorerState(blocks, state);
  if (target === "blocks") return moveBlockPage(blocks, normalized, next);
  if (target === "instructions") return moveInstructionPage(blocks, normalized, next);
  return moveSourcePage(blocks, normalized, next);
};

export const toggleEntrypointBlockSort = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState,
  columnIndex: number
): PeEntrypointExplorerState => {
  const normalized = normalizeEntrypointExplorerState(blocks, state);
  const sortColumnIndex = normalizeSortColumnIndex(columnIndex);
  if (sortColumnIndex == null) return normalized;
  const direction =
    normalized.blockSortColumnIndex === sortColumnIndex &&
    normalized.blockSortDirection === "ascending"
      ? "descending"
      : "ascending";
  return normalizeEntrypointExplorerState(blocks, {
    ...normalized,
    blockPageIndex: 0,
    blockSortColumnIndex: sortColumnIndex,
    blockSortDirection: direction
  });
};

export const entrypointBlockPageIndexes = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState
): number[] => {
  const normalized = normalizeEntrypointExplorerState(blocks, state);
  const indexes = sortedEntrypointBlockIndexes(blocks, normalized);
  const start = normalized.blockPageIndex * PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE;
  const end = Math.min(blocks.length, start + PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE);
  return indexes.slice(start, end);
};

export const findEntrypointRvaSelection = (
  blocks: readonly PeEntrypointRenderBlock[],
  rva: number
): PeEntrypointRvaSelection | null => {
  for (let index = 0; index < blocks.length; index += 1) {
    const instructionIndex = blocks[index]?.block.instructions.findIndex(row => row.rva === rva);
    if (instructionIndex != null && instructionIndex >= 0) {
      return {
        blockIndex: index,
        instructionPageIndex: pageIndexForRow(instructionIndex, PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE)
      };
    }
  }
  const blockIndex = blocks.findIndex(block => block.block.startRva === rva);
  return blockIndex >= 0 ? { blockIndex, instructionPageIndex: 0 } : null;
};

export const selectEntrypointRva = (
  blocks: readonly PeEntrypointRenderBlock[],
  rva: number,
  state: PeEntrypointExplorerState = DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE
): PeEntrypointExplorerState | null => {
  const selection = findEntrypointRvaSelection(blocks, rva);
  if (!selection) return null;
  const normalized = normalizeEntrypointExplorerState(blocks, state);
  return normalizeEntrypointExplorerState(blocks, {
    ...normalized,
    selectedBlockIndex: selection.blockIndex,
    blockPageIndex: blockPageIndexForBlock(blocks, normalized, selection.blockIndex),
    instructionPageIndex: selection.instructionPageIndex,
    sourcePageIndex: 0
  });
};

export const entrypointPageIndexes = (
  rowCount: number,
  pageSize: number,
  pageIndex: number
): number[] => {
  const start = pageIndex * pageSize;
  const end = Math.min(Math.max(0, rowCount), start + pageSize);
  return Array.from({ length: Math.max(0, end - start) }, (_value, index) => start + index);
};

export const entrypointPageCount = (rowCount: number, pageSize: number): number => {
  if (!Number.isSafeInteger(rowCount) || rowCount <= 0) return 1;
  if (!Number.isSafeInteger(pageSize) || pageSize <= 0) return 1;
  return Math.max(1, Math.ceil(rowCount / pageSize));
};

const moveBlockPage = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState,
  next: "first" | "previous" | "next" | "last" | number
): PeEntrypointExplorerState => ({
  ...state,
  blockPageIndex: movedPageIndex(
    state.blockPageIndex,
    entrypointPageCount(blocks.length, PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE),
    next
  )
});

const moveInstructionPage = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState,
  next: "first" | "previous" | "next" | "last" | number
): PeEntrypointExplorerState => ({
  ...state,
  instructionPageIndex: movedPageIndex(
    state.instructionPageIndex,
    instructionPageCount(blocks[state.selectedBlockIndex]),
    next
  )
});

const moveSourcePage = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState,
  next: "first" | "previous" | "next" | "last" | number
): PeEntrypointExplorerState => ({
  ...state,
  sourcePageIndex: movedPageIndex(
    state.sourcePageIndex,
    sourcePageCount(blocks[state.selectedBlockIndex]),
    next
  )
});

const instructionPageCount = (block: PeEntrypointRenderBlock | undefined): number =>
  entrypointPageCount(block?.block.instructions.length ?? 0, PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE);

const sourcePageCount = (block: PeEntrypointRenderBlock | undefined): number =>
  entrypointPageCount(block?.sources.length ?? 0, PE_ENTRYPOINT_SOURCE_PAGE_SIZE);

const sortedEntrypointBlockIndexes = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState
): number[] => {
  const indexes = Array.from({ length: Math.max(0, blocks.length) }, (_value, index) => index);
  if (state.blockSortColumnIndex == null || !state.blockSortDirection) return indexes;
  const sign = state.blockSortDirection === "ascending" ? 1 : -1;
  const columnIndex = state.blockSortColumnIndex;
  return indexes.sort((left, right) => {
    const compared = compareBlockSortValues(
      blockSortValue(blocks[left], columnIndex),
      blockSortValue(blocks[right], columnIndex)
    ) * sign;
    return compared || left - right;
  });
};

const blockPageIndexForBlock = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState,
  blockIndex: number
): number => {
  const sortedIndex = sortedEntrypointBlockIndexes(blocks, state).indexOf(blockIndex);
  return pageIndexForRow(Math.max(0, sortedIndex), PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE);
};

const blockSortValue = (
  block: PeEntrypointRenderBlock | undefined,
  columnIndex: number
): string | number => {
  if (!block) return "";
  if (columnIndex === 0) return block.block.startRva;
  if (columnIndex === 1) return block.block.kind;
  if (columnIndex === 2) return block.sources[0] ?? -1;
  if (columnIndex === 3) return block.block.instructions.length;
  return block.block.fileOffsetStart;
};

const compareBlockSortValues = (left: string | number, right: string | number): number =>
  typeof left === "number" && typeof right === "number"
    ? left - right
    : String(left).localeCompare(
      String(right),
      undefined,
      { numeric: true, sensitivity: "base" }
    );

const normalizeSortColumnIndex = (columnIndex: number | null): number | null =>
  Number.isInteger(columnIndex) && columnIndex != null && columnIndex >= 0 && columnIndex <= 4
    ? columnIndex
    : null;

const normalizeSortDirection = (
  direction: PeEntrypointSortDirection | null
): PeEntrypointSortDirection | null =>
  direction === "ascending" || direction === "descending" ? direction : null;

const movedPageIndex = (
  pageIndex: number,
  pages: number,
  next: "first" | "previous" | "next" | "last" | number
): number => {
  if (next === "first") return 0;
  if (next === "previous") return Math.max(0, pageIndex - 1);
  if (next === "next") return Math.min(pages - 1, pageIndex + 1);
  if (next === "last") return pages - 1;
  return clampPageIndex(next, pages);
};

const pageIndexForRow = (rowIndex: number, pageSize: number): number =>
  Math.max(0, Math.floor(rowIndex / pageSize));

const clampIndex = (index: number, length: number): number => {
  if (length <= 0 || !Number.isInteger(index) || index < 0) return 0;
  return Math.min(index, length - 1);
};

const clampPageIndex = (pageIndex: number, pages: number): number => {
  if (!Number.isInteger(pageIndex) || pageIndex < 0) return 0;
  return Math.min(pageIndex, Math.max(1, pages) - 1);
};
