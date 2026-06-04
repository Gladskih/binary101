"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyBlock,
  PeEntrypointDisassemblyBlockKind
} from "./types.js";
import { loadCodeBytes, type MappedCodeBlock } from "./entrypoint-code-bytes.js";
import type { ConditionalBranchTargets, FollowedCodeTarget } from "./entrypoint-control-flow.js";

export type PendingEntrypointBlock = {
  kind: PeEntrypointDisassemblyBlockKind;
  mapped: MappedCodeBlock;
  sourceInstructionRva?: number;
  returnRva?: number;
};

export type FollowQueueState = {
  blocks: PeEntrypointDisassemblyBlock[];
  visitedBlocks: Set<number>;
  queuedBlocks: Set<number>;
};

export const ENTRYPOINT_PREVIEW_BLOCK_LIMIT = 16;

const canQueueBlock = (
  state: FollowQueueState,
  pending: PendingEntrypointBlock[],
  rva: number
): boolean => {
  if (state.visitedBlocks.has(rva) || state.queuedBlocks.has(rva)) return true;
  return state.blocks.length + pending.length < ENTRYPOINT_PREVIEW_BLOCK_LIMIT;
};

export const queueFollowedBlock = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  pending: PendingEntrypointBlock[],
  follow: FollowedCodeTarget,
  instructionRva: number,
  issues: string[],
  returnRva?: number | null
): Promise<boolean> => {
  if (state.visitedBlocks.has(follow.rva) || state.queuedBlocks.has(follow.rva)) return true;
  if (!canQueueBlock(state, pending, follow.rva)) {
    issues.push(`Entrypoint preview capped at ${ENTRYPOINT_PREVIEW_BLOCK_LIMIT} code blocks.`);
    return false;
  }
  const mapped = await loadCodeBytes(reader, opts, follow.rva, issues, "Control-flow target");
  if (!mapped) return false;
  pending.push({
    kind: follow.kind,
    mapped,
    sourceInstructionRva: instructionRva,
    ...(returnRva != null ? { returnRva } : {})
  });
  state.queuedBlocks.add(follow.rva);
  return true;
};

export const queueConditionalBranch = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  pending: PendingEntrypointBlock[],
  branch: ConditionalBranchTargets,
  instructionRva: number,
  issues: string[]
): Promise<{ branchFollowed: boolean; fallthroughFollowed: boolean }> => ({
  branchFollowed: await queueFollowedBlock(
    reader,
    opts,
    state,
    pending,
    branch.branch,
    instructionRva,
    issues
  ),
  fallthroughFollowed: await queueFollowedBlock(
    reader,
    opts,
    state,
    pending,
    branch.fallthrough,
    instructionRva,
    issues
  )
});
