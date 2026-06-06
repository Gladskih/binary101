"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyBlock,
  PeEntrypointDisassemblyBlockKind
} from "../types.js";
import { loadCodeBytes, type MappedCodeBlock } from "./code-bytes.js";
import type { ConditionalBranchTargets, FollowedCodeTarget } from "./control-flow.js";
import {
  cloneEmulationState,
  type EmulatedValue,
  type EmulationState
} from "./emulation-state.js";

export type PendingBlock = {
  kind: PeEntrypointDisassemblyBlockKind;
  mapped: MappedCodeBlock;
  emulationState: EmulationState;
  key: string;
  sourceInstructionRva?: number;
};

export type FollowQueueState = {
  blocks: PeEntrypointDisassemblyBlock[];
  visitedBlocks: Set<string>;
  queuedBlocks: Set<string>;
};

export const PREVIEW_BLOCK_LIMIT = 16;

const canQueueBlock = (
  state: FollowQueueState,
  pending: PendingBlock[],
  key: string
): boolean => {
  if (state.visitedBlocks.has(key) || state.queuedBlocks.has(key)) return true;
  return state.blocks.length + pending.length < PREVIEW_BLOCK_LIMIT;
};

const valueKey = (value: EmulatedValue | undefined): string => {
  if (!value) return "unset";
  if (value.kind === "known") return `known:${value.bits}:${value.value.toString(16)}`;
  if (value.kind === "cpuid-output") {
    const subleaf = value.subleaf == null ? "" : `:${value.subleaf}`;
    return `cpuid:${value.leaf}${subleaf}:${value.register}`;
  }
  return "unknown";
};

const registerStateKey = (state: EmulationState): string =>
  Array.from(state.registers, ([name, value]) => `${name}=${valueKey(value)}`)
    .sort()
    .join(",");

const memoryStateKey = (state: EmulationState): string =>
  Array.from(state.memory, ([address, value]) => `${address}=${valueKey(value)}`)
    .sort()
    .join(",");

export const createBlockKey = (rva: number, state: EmulationState): string =>
  `${rva.toString(16)}|r:${registerStateKey(state)}|m:${memoryStateKey(state)}`;

export const queueFollowedBlock = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  pending: PendingBlock[],
  follow: FollowedCodeTarget,
  instructionRva: number,
  issues: string[],
  emulationState: EmulationState
): Promise<boolean> => {
  const key = createBlockKey(follow.rva, emulationState);
  if (state.visitedBlocks.has(key) || state.queuedBlocks.has(key)) return true;
  if (!canQueueBlock(state, pending, key)) {
    issues.push(`Entrypoint preview capped at ${PREVIEW_BLOCK_LIMIT} code blocks.`);
    return false;
  }
  const mapped = await loadCodeBytes(reader, opts, follow.rva, issues, "Control-flow target");
  if (!mapped) return false;
  pending.push({
    kind: follow.kind,
    mapped,
    emulationState,
    key,
    sourceInstructionRva: instructionRva
  });
  state.queuedBlocks.add(key);
  return true;
};

export const queueConditionalBranch = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  pending: PendingBlock[],
  branch: ConditionalBranchTargets,
  instructionRva: number,
  issues: string[],
  emulationState: EmulationState
): Promise<{ branchFollowed: boolean; fallthroughFollowed: boolean }> => ({
  branchFollowed: await queueFollowedBlock(
    reader,
    opts,
    state,
    pending,
    branch.branch,
    instructionRva,
    issues,
    cloneEmulationState(emulationState)
  ),
  fallthroughFollowed: await queueFollowedBlock(
    reader,
    opts,
    state,
    pending,
    branch.fallthrough,
    instructionRva,
    issues,
    cloneEmulationState(emulationState)
  )
});
