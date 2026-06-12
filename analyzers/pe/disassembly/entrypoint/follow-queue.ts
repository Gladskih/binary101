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
  collectKnownValues,
  cloneEmulationState,
  mergeEmulationStates,
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
  queuedBlocksByKey: Map<string, PendingBlock>;
  emulationStatesByKey: Map<string, EmulationState>;
  contextKeysByRva: Map<number, Set<string>>;
  precisionCostByRva: Map<number, number>;
  precisionLimitReportedRvas: Set<number>;
};

// Local browser-safety threshold, not a PE/x86 limit. It charges both distinct
// contexts and value-set width so merging improves precision without allowing
// recursive or highly mutating flows to grow unbounded in the browser.
export const MAX_PRECISION_BUDGET_PER_RVA = 256;

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
  emulationState: EmulationState,
  issues: string[]
): boolean => {
  const used = state.precisionCostByRva.get(rva) ?? 0;
  const cost = precisionCost(emulationState);
  if (used + cost <= MAX_PRECISION_BUDGET_PER_RVA) return true;
  if (!state.precisionLimitReportedRvas.has(rva)) {
    state.precisionLimitReportedRvas.add(rva);
    issues.push(
      `Entrypoint preview stopped following ${formatRva(rva)} after exhausting ` +
      `${MAX_PRECISION_BUDGET_PER_RVA} emulation precision budget.`
    );
  }
  return false;
};

const recordPrecisionCost = (
  state: FollowQueueState,
  rva: number,
  emulationState: EmulationState
): void => {
  state.precisionCostByRva.set(
    rva,
    (state.precisionCostByRva.get(rva) ?? 0) + precisionCost(emulationState)
  );
};

const precisionCost = (state: EmulationState): number =>
  Math.max(
    1,
    [...state.registers.values(), ...state.memory.values()]
      .reduce((sum, value) => sum + Math.max(1, collectKnownValues(value).length), 0) +
      Object.keys(state.flags).length
  );

const valueKey = (value: EmulatedValue | undefined): string => {
  if (!value) return "unset";
  if (value.kind === "known") return `known:${value.bits}:${value.value.toString(16)}`;
  if (value.kind === "value-set") {
    return `set:${value.values.map(candidate => valueKey(candidate)).join(",")}`;
  }
  if (value.kind === "import-return") return `import:${value.label}`;
  if (value.kind === "cpuid-output") {
    const subleaf = value.subleaf == null ? "" : `:${value.subleaf}`;
    return `cpuid:${value.leaf}${subleaf}:${value.register}`;
  }
  return "unknown";
};

const pointerBytes = (state: EmulationState): bigint => BigInt(state.bitness / 8);

const stackKeyOffsets = (state: EmulationState): bigint[] => {
  const bytes = pointerBytes(state);
  return [0n, bytes, bytes * 2n, bytes * 3n];
};

const stackSlotKey = (
  state: EmulationState,
  address: bigint,
  imageBase: bigint
): string | null => {
  const value = state.memory.get(address.toString());
  const values = collectKnownValues(value);
  if (!values.length) return null;
  return values.every(candidate => toRva(candidate.value, imageBase) != null)
    ? `${address.toString(16)}=${valueKey(value)}`
    : null;
};

const stackSlotKeys = (state: EmulationState, imageBase: bigint): string => {
  const keys = new Set<string>();
  for (const register of ["RSP", "RBP"] as const) {
    const value = state.registers.get(register);
    if (value?.kind !== "known") continue;
    for (const offset of stackKeyOffsets(state)) {
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

const mergeQueuedBlockState = (
  state: FollowQueueState,
  rva: number,
  existing: PendingBlock,
  emulationState: EmulationState
): void => {
  const before = precisionCost(existing.emulationState);
  existing.emulationState = mergeEmulationStates(existing.emulationState, emulationState);
  const after = precisionCost(existing.emulationState);
  if (after > before) {
    state.precisionCostByRva.set(rva, (state.precisionCostByRva.get(rva) ?? 0) + after - before);
  }
};

const stateKey = (state: EmulationState): string => {
  const registerKeys = Array.from(state.registers)
    .map(([key, value]) => `r:${key}=${valueKey(value)}`);
  const memoryKeys = Array.from(state.memory)
    .map(([key, value]) => `m:${key}=${valueKey(value)}`);
  const flagKeys = Object.entries(state.flags)
    .map(([key, value]) => `f:${key}=${value ? "1" : "0"}`);
  return [...registerKeys, ...memoryKeys, ...flagKeys]
    .sort()
    .join("|");
};

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
  const queued = state.queuedBlocksByKey.get(key);
  if (queued) {
    mergeQueuedBlockState(state, follow.rva, queued, emulationState);
    state.emulationStatesByKey.set(key, cloneEmulationState(queued.emulationState));
    return true;
  }
  const knownState = state.emulationStatesByKey.get(key);
  const nextState = knownState ? mergeEmulationStates(knownState, emulationState) : emulationState;
  if (knownState && stateKey(knownState) === stateKey(nextState)) return true;
  if (!canQueueNewContext(state, follow.rva, nextState, issues)) return false;
  const mapped = await loadCodeBytes(reader, opts, follow.rva, issues, "Control-flow target");
  if (!mapped) return false;
  state.emulationStatesByKey.set(key, cloneEmulationState(nextState));
  contextKeysForRva(state, follow.rva).add(key);
  recordPrecisionCost(state, follow.rva, nextState);
  const block = {
    kind: follow.kind,
    mapped,
    emulationState: nextState,
    key,
    sourceInstructionRva: instructionRva
  };
  pending.push(block);
  state.queuedBlocksByKey.set(key, block);
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
): Promise<{ branchFollowed: boolean; fallthroughFollowed: boolean }> => {
  const branchFollowed = branch.taken !== false && await queueFollowedBlock(
    reader,
    opts,
    state,
    pending,
    branch.branch,
    instructionRva,
    issues,
    cloneEmulationState(emulationState)
  );
  const fallthroughFollowed = branch.taken !== true && await queueFollowedBlock(
    reader,
    opts,
    state,
    pending,
    branch.fallthrough,
    instructionRva,
    issues,
    cloneEmulationState(emulationState)
  );
  return { branchFollowed, fallthroughFollowed };
};
