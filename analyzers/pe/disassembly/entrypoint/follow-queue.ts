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
  type EmulationState
} from "./emulation/state.js";
import {
  addCorrelatedState,
  correlatedStatesContain,
  emulatedValueKey,
  MAX_CORRELATED_STATES_PER_CONTEXT,
  mergeCorrelatedStates,
  type CorrelatedEmulationStates
} from "./correlated-states.js";

export type PendingBlock = {
  kind: PeEntrypointDisassemblyBlockKind;
  mapped: MappedCodeBlock;
  emulationState: EmulationState;
  key: string;
  sourceInstructionRva?: number;
};

export type FollowQueueState = {
  blocks: PeEntrypointDisassemblyBlock[];
  pending: PendingBlock[];
  issues: string[];
  visitedBlocks: Set<string>;
  emulationStatesByKey: Map<string, CorrelatedEmulationStates>;
  contextKeysByRva: Map<number, Set<string>>;
  precisionCostByRva: Map<number, number>;
  precisionLimitReportedRvas: Set<number>;
};

// Local browser-safety threshold, not a PE/x86 limit. Preserve the previous
// 256-unit allowance for each complete path retained by the context policy.
export const MAX_PRECISION_BUDGET_PER_RVA =
  256 * MAX_CORRELATED_STATES_PER_CONTEXT;

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

const canSpendPrecision = (
  state: FollowQueueState,
  rva: number,
  addedCost: number
): boolean => {
  const used = state.precisionCostByRva.get(rva) ?? 0;
  if (used + addedCost <= MAX_PRECISION_BUDGET_PER_RVA) return true;
  if (!state.precisionLimitReportedRvas.has(rva)) {
    state.precisionLimitReportedRvas.add(rva);
    state.issues.push(
      `Entrypoint preview stopped following ${formatRva(rva)} after exhausting ` +
      `${MAX_PRECISION_BUDGET_PER_RVA} emulation precision budget.`
    );
  }
  return false;
};

const recordPrecisionCost = (
  state: FollowQueueState,
  rva: number,
  addedCost: number
): void => {
  state.precisionCostByRva.set(
    rva,
    (state.precisionCostByRva.get(rva) ?? 0) + addedCost
  );
};

const precisionCost = (state: EmulationState): number =>
  Math.max(
    1,
    [...state.registers.values(), ...state.memory.values()]
      .reduce((sum, value) => sum + Math.max(1, collectKnownValues(value).length), 0) +
      Object.keys(state.flags).length
  );

const addedPrecisionCost = (
  previous: EmulationState | undefined,
  next: EmulationState
): number => previous
  ? Math.max(0, precisionCost(next) - precisionCost(previous))
  : precisionCost(next);

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
  if (!value) return null;
  const values = collectKnownValues(value);
  if (!values.length) return null;
  return values.every(candidate => toRva(candidate.value, imageBase) != null)
    ? `${address.toString(16)}=${emulatedValueKey(value)}`
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

const stateToProcess = (
  correlated: CorrelatedEmulationStates
): EmulationState => correlated.states.at(-1) ?? correlated.states[0];

const addedCorrelatedPrecisionCost = (
  previous: CorrelatedEmulationStates | undefined,
  next: CorrelatedEmulationStates
): number => {
  if (!previous) return precisionCost(stateToProcess(next));
  if (previous.mode === "complete-paths" && next.mode === "complete-paths") {
    return precisionCost(stateToProcess(next));
  }
  return addedPrecisionCost(
    mergeCorrelatedStates(previous),
    mergeCorrelatedStates(next)
  );
};

export const isPendingBlockCurrent = (
  state: FollowQueueState,
  block: PendingBlock
): boolean => correlatedStatesContain(
  state.emulationStatesByKey.get(block.key),
  block.emulationState
);

export const queueFollowedBlock = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  follow: FollowedCodeTarget,
  instructionRva: number,
  emulationState: EmulationState
): Promise<boolean> => {
  const key = createBlockKey(follow.rva, emulationState, opts.imageBase);
  const knownStates = state.emulationStatesByKey.get(key);
  const nextStates = addCorrelatedState(knownStates, emulationState);
  if (knownStates === nextStates) return true;
  const addedCost = addedCorrelatedPrecisionCost(knownStates, nextStates);
  if (!canSpendPrecision(state, follow.rva, addedCost)) return false;
  const mapped = await loadCodeBytes(reader, opts, follow.rva, state.issues, "Control-flow target");
  if (!mapped) return false;
  const nextState = stateToProcess(nextStates);
  state.emulationStatesByKey.set(key, nextStates);
  contextKeysForRva(state, follow.rva).add(key);
  recordPrecisionCost(state, follow.rva, addedCost);
  const block = {
    kind: follow.kind,
    mapped,
    emulationState: cloneEmulationState(nextState),
    key,
    sourceInstructionRva: instructionRva
  };
  state.pending.push(block);
  return true;
};

export const queueConditionalBranch = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  branch: ConditionalBranchTargets,
  instructionRva: number,
  emulationState: EmulationState
): Promise<{ branchFollowed: boolean; fallthroughFollowed: boolean }> => {
  const branchFollowed = branch.taken !== false && await queueFollowedBlock(
    reader,
    opts,
    state,
    branch.branch,
    instructionRva,
    cloneEmulationState(emulationState)
  );
  const fallthroughFollowed = branch.taken !== true && await queueFollowedBlock(
    reader,
    opts,
    state,
    branch.fallthrough,
    instructionRva,
    cloneEmulationState(emulationState)
  );
  return { branchFollowed, fallthroughFollowed };
};
