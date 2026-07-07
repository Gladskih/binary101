"use strict";

import {
  cloneEmulationState,
  mergeEmulationStates,
  type EmulatedValue,
  type EmulationState
} from "./emulation/state.js";

type CompletePathStates = readonly [EmulationState, ...EmulationState[]];

export type CorrelatedEmulationStates =
  | { mode: "complete-paths"; states: CompletePathStates }
  | { mode: "widened"; states: readonly [EmulationState] };

// Local browser-safety policy: preserve four complete path states per control-flow
// context, then widen them into one bounded abstract state.
export const MAX_CORRELATED_STATES_PER_CONTEXT = 4;

export const emulatedValueKey = (value: EmulatedValue): string => {
  if (value.kind === "known") return `known:${value.bits}:${value.value.toString(16)}`;
  if (value.kind === "value-set") {
    return `set:${value.values.map(candidate => emulatedValueKey(candidate)).join(",")}`;
  }
  if (value.kind === "import-return") return `import:${value.label}`;
  if (value.kind === "cpuid-output") {
    const subleaf = value.subleaf == null ? "" : `:${value.subleaf}`;
    return `cpuid:${value.leaf}${subleaf}:${value.register}`;
  }
  if (value.kind === "partial-known") {
    return `partial:${value.bits}:${value.mask.toString(16)}:${value.value.toString(16)}`;
  }
  return "unknown";
};

const mapKeys = (
  prefix: string,
  values: ReadonlyMap<string, EmulatedValue>
): string[] => Array.from(values)
  .filter(([, value]) => value.kind !== "unknown")
  .map(([key, value]) => `${prefix}:${key}=${emulatedValueKey(value)}`);

export const emulationStateKey = (state: EmulationState): string => [
  ...mapKeys("r", state.registers),
  ...mapKeys("m", state.memory),
  ...Object.entries(state.flags).map(([key, value]) => `f:${key}=${value ? "1" : "0"}`)
]
  .sort()
  .join("|");

const containsState = (
  states: readonly EmulationState[],
  candidate: EmulationState
): boolean => {
  const candidateKey = emulationStateKey(candidate);
  return states.some(state => emulationStateKey(state) === candidateKey);
};

export const mergeCorrelatedStates = (
  correlated: CorrelatedEmulationStates
): EmulationState => correlated.states
  .slice(1)
  .reduce(mergeEmulationStates, correlated.states[0]);

const widenStates = (
  correlated: CorrelatedEmulationStates,
  incoming: EmulationState
): CorrelatedEmulationStates => {
  const merged = mergeEmulationStates(mergeCorrelatedStates(correlated), incoming);
  if (correlated.mode === "widened" && containsState(correlated.states, merged)) {
    return correlated;
  }
  return { mode: "widened", states: [cloneEmulationState(merged)] };
};

export const addCorrelatedState = (
  correlated: CorrelatedEmulationStates | undefined,
  incoming: EmulationState
): CorrelatedEmulationStates => {
  if (!correlated) {
    return { mode: "complete-paths", states: [cloneEmulationState(incoming)] };
  }
  if (containsState(correlated.states, incoming)) return correlated;
  if (correlated.mode === "widened") return widenStates(correlated, incoming);
  if (correlated.states.length < MAX_CORRELATED_STATES_PER_CONTEXT) {
    return {
      mode: "complete-paths",
      states: [...correlated.states, cloneEmulationState(incoming)]
    };
  }
  return widenStates(correlated, incoming);
};

export const correlatedStatesContain = (
  correlated: CorrelatedEmulationStates | undefined,
  candidate: EmulationState
): boolean => correlated != null && containsState(correlated.states, candidate);
