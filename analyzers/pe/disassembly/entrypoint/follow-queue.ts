"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyBlock,
  PeEntrypointDisassemblyBlockKind
} from "../types.js";
import { loadCodeBytes, type MappedCodeBlock } from "./code-bytes.js";
import {
  toRva,
  type ConditionalBranchTargets,
  type FollowedCodeTarget
} from "./control-flow.js";
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
  contextKeysByRva: Map<number, Set<string>>;
  contextLimitReportedRvas: Set<number>;
};

// Local browser-safety threshold, not a PE/x86 limit: normal acyclic control-flow
// can visit any number of RVAs, while repeated visits to one RVA with many
// different emulated states usually mean recursion or a mutating loop.
export const MAX_CONTEXTS_PER_RVA = 64;

const formatRva = (rva: number): string =>
  `0x${(rva >>> 0).toString(16).padStart(8, "0")}`;

const contextKeysForRva = (
  state: FollowQueueState,
  rva: number
): Set<string> => {
  const existing = state.contextKeysByRva.get(rva);
  if (existing) return existing;
  const created = new Set<string>();
  state.contextKeysByRva.set(rva, created);
  return created;
};

const canQueueNewContext = (
  state: FollowQueueState,
  rva: number,
  issues: string[]
): boolean => {
  if (contextKeysForRva(state, rva).size < MAX_CONTEXTS_PER_RVA) return true;
  if (!state.contextLimitReportedRvas.has(rva)) {
    state.contextLimitReportedRvas.add(rva);
    issues.push(
      `Entrypoint preview stopped following ${formatRva(rva)} after ` +
      `${MAX_CONTEXTS_PER_RVA} distinct emulation contexts.`
    );
  }
  return false;
};

const valueKey = (value: EmulatedValue | undefined): string => {
  if (!value) return "unset";
  if (value.kind === "known") return `known:${value.bits}:${value.value.toString(16)}`;
  if (value.kind === "import-return") return `import:${value.label}`;
  if (value.kind === "cpuid-output") {
    const subleaf = value.subleaf == null ? "" : `:${value.subleaf}`;
    return `cpuid:${value.leaf}${subleaf}:${value.register}`;
  }
  return "unknown";
};

const pointerBytes = (state: EmulationState): bigint => BigInt(state.bitness / 8);

const stackSlotKey = (
  state: EmulationState,
  address: bigint,
  imageBase: bigint
): string | null => {
  const value = state.memory.get(address.toString());
  if (value?.kind !== "known") return null;
  return toRva(value.value, imageBase) == null
    ? null
    : `${address.toString(16)}=${valueKey(value)}`;
};

const stackSlotKeys = (state: EmulationState, imageBase: bigint): string => {
  const keys = new Set<string>();
  for (const register of ["RSP", "RBP"] as const) {
    const value = state.registers.get(register);
    if (value?.kind !== "known") continue;
    for (const offset of [0n, pointerBytes(state)] as const) {
      const key = stackSlotKey(state, value.value + offset, imageBase);
      if (key) keys.add(key);
    }
  }
  return Array.from(keys)
    .sort()
    .join("|");
};

const stackStateKey = (state: EmulationState, imageBase: bigint): string =>
  `slots=${stackSlotKeys(state, imageBase)}`;

export const createBlockKey = (
  rva: number,
  state: EmulationState,
  imageBase: bigint
): string =>
  `${rva.toString(16)}|stack:${stackStateKey(state, imageBase)}`;

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
  const key = createBlockKey(follow.rva, emulationState, opts.imageBase);
  if (state.visitedBlocks.has(key) || state.queuedBlocks.has(key)) return true;
  if (!canQueueNewContext(state, follow.rva, issues)) return false;
  const mapped = await loadCodeBytes(reader, opts, follow.rva, issues, "Control-flow target");
  if (!mapped) return false;
  contextKeysForRva(state, follow.rva).add(key);
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
