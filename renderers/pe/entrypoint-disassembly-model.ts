"use strict";

import type {
  PeEntrypointDisassemblyBlock,
  PeEntrypointInstruction,
  PeEntrypointInstructionTarget
} from "../../analyzers/pe/disassembly/index.js";

export const PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE = 50;
export const PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE = 120;

export type PeEntrypointRenderBlock = {
  block: PeEntrypointDisassemblyBlock;
  duplicateCount: number;
  sources: number[];
};

export type PeEntrypointExplorerState = {
  selectedBlockIndex: number;
  blockPageIndex: number;
  instructionPageIndex: number;
};

export type PeEntrypointRvaSelection = {
  blockIndex: number;
  instructionPageIndex: number;
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

export const DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE: PeEntrypointExplorerState = {
  selectedBlockIndex: 0,
  blockPageIndex: 0,
  instructionPageIndex: 0
};

export const visibleEntrypointBlocks = (
  blocks: readonly PeEntrypointDisassemblyBlock[]
): PeEntrypointRenderBlock[] => {
  const out: PeEntrypointRenderBlock[] = [];
  const bySignature = new Map<string, PeEntrypointRenderBlock>();
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

export const normalizeEntrypointExplorerState = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState
): PeEntrypointExplorerState => {
  const selectedBlockIndex = clampIndex(state.selectedBlockIndex, blocks.length);
  return {
    selectedBlockIndex,
    blockPageIndex: clampPageIndex(
      state.blockPageIndex,
      entrypointPageCount(blocks.length, PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE)
    ),
    instructionPageIndex: clampPageIndex(
      state.instructionPageIndex,
      instructionPageCount(blocks[selectedBlockIndex])
    )
  };
};

export const selectEntrypointBlock = (
  blocks: readonly PeEntrypointRenderBlock[],
  blockIndex: number
): PeEntrypointExplorerState => {
  const selectedBlockIndex = clampIndex(blockIndex, blocks.length);
  return normalizeEntrypointExplorerState(blocks, {
    selectedBlockIndex,
    blockPageIndex: pageIndexForRow(selectedBlockIndex, PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE),
    instructionPageIndex: 0
  });
};

export const moveEntrypointExplorerPage = (
  blocks: readonly PeEntrypointRenderBlock[],
  state: PeEntrypointExplorerState,
  target: "blocks" | "instructions",
  next: "first" | "previous" | "next" | "last" | number
): PeEntrypointExplorerState => {
  const normalized = normalizeEntrypointExplorerState(blocks, state);
  if (target === "blocks") return moveBlockPage(blocks, normalized, next);
  return moveInstructionPage(blocks, normalized, next);
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
  rva: number
): PeEntrypointExplorerState | null => {
  const selection = findEntrypointRvaSelection(blocks, rva);
  if (!selection) return null;
  return normalizeEntrypointExplorerState(blocks, {
    selectedBlockIndex: selection.blockIndex,
    blockPageIndex: pageIndexForRow(selection.blockIndex, PE_ENTRYPOINT_BLOCK_INDEX_PAGE_SIZE),
    instructionPageIndex: selection.instructionPageIndex
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

const targetSignature = (target: PeEntrypointInstructionTarget | undefined): TargetSignature => {
  if (!target) return null;
  if (target.kind === "code") return { kind: target.kind, rva: target.rva };
  if (target.kind === "return") {
    return "rva" in target
      ? { kind: target.kind, rva: target.rva }
      : { kind: target.kind, reason: target.reason };
  }
  if (target.kind === "branch") {
    return { kind: target.kind, branchRva: target.branchRva, fallthroughRva: target.fallthroughRva };
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

const uniqueSourceRvas = (
  block: PeEntrypointRenderBlock,
  sourceRva: number | undefined
): number[] =>
  sourceRva == null || block.sources.includes(sourceRva)
    ? block.sources
    : [...block.sources, sourceRva];

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

const instructionPageCount = (block: PeEntrypointRenderBlock | undefined): number =>
  entrypointPageCount(block?.block.instructions.length ?? 0, PE_ENTRYPOINT_INSTRUCTION_PAGE_SIZE);

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
