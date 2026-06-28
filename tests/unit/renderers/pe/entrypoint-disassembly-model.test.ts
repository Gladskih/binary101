"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  PeEntrypointDisassemblyBlock,
  PeEntrypointInstruction
} from "../../../../analyzers/pe/disassembly/index.js";
import {
  DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE,
  entrypointBlockPageIndexes,
  moveEntrypointExplorerPage,
  selectEntrypointRva,
  toggleEntrypointBlockSort,
  visibleEntrypointBlocks
} from "../../../../renderers/pe/entrypoint-disassembly-model.js";

const instruction = (rva: number): PeEntrypointInstruction => ({
  rva,
  fileOffset: rva - 0x1000,
  text: `op_${rva.toString(16)}`
});

const block = (
  startRva: number,
  instructions: readonly PeEntrypointInstruction[],
  sourceInstructionRva?: number
): PeEntrypointDisassemblyBlock => ({
  kind: "followed-call",
  startRva,
  fileOffsetStart: startRva - 0x1000,
  ...(sourceInstructionRva == null ? {} : { sourceInstructionRva }),
  instructions: [...instructions]
});

const createPagedBlocks = (): PeEntrypointDisassemblyBlock[] =>
  Array.from({ length: 51 }, (_value, index) => block(
    0x1000 + index * 0x10,
    index === 50
      ? Array.from({ length: 121 }, (_unused, row) => instruction(0x2000 + row))
      : [instruction(0x1000 + index * 0x10)]
  ));

void test("visibleEntrypointBlocks merges duplicate contexts and keeps source RVAs", () => {
  const blocks = visibleEntrypointBlocks([
    block(0x1010, [instruction(0x1010)], 0x1000),
    block(0x1010, [instruction(0x1010)], 0x1006)
  ]);

  assert.equal(blocks.length, 1);
  assert.equal(blocks[0]?.duplicateCount, 2);
  assert.deepEqual(blocks[0]?.sources, [0x1000, 0x1006]);
});

void test("selectEntrypointRva opens the containing block and instruction page", () => {
  const blocks = visibleEntrypointBlocks(createPagedBlocks());
  // Page-size regression guard: block 51 and instruction 121 should both be on page index 1.
  const state = selectEntrypointRva(blocks, 0x2000 + 120);

  assert.deepEqual(state, {
    selectedBlockIndex: 50,
    blockPageIndex: 2,
    instructionPageIndex: 1,
    sourcePageIndex: 0,
    blockSortColumnIndex: null,
    blockSortDirection: null
  });
});

void test("moveEntrypointExplorerPage clamps oversized page requests", () => {
  const blocks = visibleEntrypointBlocks(createPagedBlocks());
  const state = moveEntrypointExplorerPage(
    blocks,
    { ...DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE, selectedBlockIndex: 50 },
    "instructions",
    99
  );

  assert.deepEqual(state, {
    selectedBlockIndex: 50,
    blockPageIndex: 0,
    instructionPageIndex: 1,
    sourcePageIndex: 0,
    blockSortColumnIndex: null,
    blockSortDirection: null
  });
});

void test("toggleEntrypointBlockSort sorts all block index rows before paging", () => {
  const blocks = visibleEntrypointBlocks([
    block(0x3000, [instruction(0x3000)]),
    block(0x1000, [instruction(0x1000)]),
    block(0x2000, [instruction(0x2000)])
  ]);
  const state = toggleEntrypointBlockSort(blocks, DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE, 0);
  const indexes = entrypointBlockPageIndexes(blocks, state);

  assert.deepEqual(state, {
    selectedBlockIndex: 0,
    blockPageIndex: 0,
    instructionPageIndex: 0,
    sourcePageIndex: 0,
    blockSortColumnIndex: 0,
    blockSortDirection: "ascending"
  });
  assert.deepEqual(indexes, [1, 2, 0]);
});
