"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  addCorrelatedState,
  correlatedStatesContain,
  emulationStateKey,
  emulatedValueKey,
  type CorrelatedEmulationStates
} from "../../../../../../analyzers/pe/disassembly/entrypoint/correlated-states.js";
import { createEmulationState } from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import {
  collectKnownValues,
  cloneEmulationState,
  importReturn,
  known,
  mergeEmulationStates,
  UNKNOWN,
  type EmulatedValue
} from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/state.js";

// Product safety policy: retain four complete paths before widening a context.
const CORRELATED_PATH_CAPACITY = 4;
const TEST_BITNESS = 64;

const createPathState = (pathIndex: number) => {
  const state = createEmulationState(TEST_BITNESS);
  const pathValue = BigInt(pathIndex + 1);
  state.registers.set("RAX", known(pathValue, TEST_BITNESS));
  state.registers.set("RBX", known(~pathValue, TEST_BITNESS));
  return state;
};

const createReverseInsertionPathState = (pathIndex: number) => {
  const state = createEmulationState(TEST_BITNESS);
  const pathValue = BigInt(pathIndex + 1);
  state.registers.set("RBX", known(~pathValue, TEST_BITNESS));
  state.registers.set("RAX", known(pathValue, TEST_BITNESS));
  return state;
};

const createMemoryPathState = (pathIndex: number) => {
  const state = createEmulationState(TEST_BITNESS);
  const stackPointer = collectKnownValues(state.registers.get("RSP"))[0];
  assert.ok(stackPointer);
  state.memory.set(
    stackPointer.value.toString(),
    known(BigInt(pathIndex + 1), stackPointer.bits)
  );
  return state;
};

const createSpecialValueState = (value: EmulatedValue) => {
  const state = createEmulationState(TEST_BITNESS);
  state.registers.set("RAX", value);
  return state;
};

const createCpuIdValue = (pathIndex: number) => ({
  kind: "cpuid-output" as const,
  leaf: pathIndex,
  ...(pathIndex > 0 ? { subleaf: pathIndex } : {}),
  register: "EAX" as const
});

const createCpuIdPathState = (pathIndex: number) =>
  createSpecialValueState(createCpuIdValue(pathIndex));

const addPaths = (pathCount: number): CorrelatedEmulationStates => {
  let states: CorrelatedEmulationStates | undefined;
  for (let pathIndex = 0; pathIndex < pathCount; pathIndex += 1) {
    states = addCorrelatedState(states, createPathState(pathIndex));
  }
  assert.ok(states);
  return states;
};

const createUnknownDominatedPaths = (): CorrelatedEmulationStates => {
  let states = addCorrelatedState(undefined, createEmulationState(TEST_BITNESS));
  for (let pathIndex = 0; pathIndex < CORRELATED_PATH_CAPACITY - 1; pathIndex += 1) {
    states = addCorrelatedState(states, createPathState(pathIndex));
  }
  return states;
};

const registerPairs = (states: CorrelatedEmulationStates) => states.states.map(state => ({
  left: collectKnownValues(state.registers.get("RAX")),
  right: collectKnownValues(state.registers.get("RBX"))
}));

const expectedRegisterPairs = (pathCount: number) => Array.from(
  { length: pathCount },
  (_, pathIndex) => {
    const pathValue = BigInt(pathIndex + 1);
    return {
      left: [known(pathValue, TEST_BITNESS)],
      right: [known(~pathValue, TEST_BITNESS)]
    };
  }
);

void test("addCorrelatedState retains complete path states up to the context capacity", () => {
  const states = addPaths(CORRELATED_PATH_CAPACITY);

  assert.equal(states.mode, "complete-paths");
  assert.equal(states.states.length, CORRELATED_PATH_CAPACITY);
  assert.deepEqual(registerPairs(states), expectedRegisterPairs(CORRELATED_PATH_CAPACITY));
});

void test("addCorrelatedState widens only after the complete-path capacity is exceeded", () => {
  const states = addPaths(CORRELATED_PATH_CAPACITY + 1);

  assert.equal(states.mode, "widened");
  assert.equal(states.states.length, 1);
});

void test("addCorrelatedState leaves an exact duplicate unchanged", () => {
  const initial = addCorrelatedState(undefined, createPathState(0));
  const withSecondPath = addCorrelatedState(initial, createPathState(1));

  const repeated = addCorrelatedState(withSecondPath, createPathState(1));

  assert.equal(repeated, withSecondPath);
});

void test("addCorrelatedState ignores map insertion order when identifying a path", () => {
  const initial = addCorrelatedState(undefined, createPathState(0));

  const repeated = addCorrelatedState(initial, createReverseInsertionPathState(0));

  assert.equal(repeated, initial);
});

void test("addCorrelatedState treats missing and explicit unknown facts alike", () => {
  const missing = createEmulationState(TEST_BITNESS);
  const explicitUnknown = cloneEmulationState(missing);
  explicitUnknown.registers.set("RAX", UNKNOWN);
  const initial = addCorrelatedState(undefined, missing);

  const repeated = addCorrelatedState(initial, explicitUnknown);

  assert.equal(repeated, initial);
});

void test("addCorrelatedState does not confuse register and memory facts", () => {
  const registerPath = createEmulationState(TEST_BITNESS);
  const memoryPath = cloneEmulationState(registerPath);
  const pathValue = known(BigInt(registerPath.registers.size), TEST_BITNESS);
  registerPath.registers.set("RAX", pathValue);
  memoryPath.memory.set("RAX", pathValue);
  const initial = addCorrelatedState(undefined, registerPath);

  const distinct = addCorrelatedState(initial, memoryPath);

  assert.equal(distinct.states.length, 2);
});

void test("addCorrelatedState distinguishes complete memory and flag facts", () => {
  const memoryPaths = addCorrelatedState(undefined, createMemoryPathState(0));
  const distinctMemoryPaths = addCorrelatedState(memoryPaths, createMemoryPathState(1));
  const clearedZero = createEmulationState(TEST_BITNESS);
  const setZero = createEmulationState(TEST_BITNESS);
  clearedZero.flags.ZF = false;
  setZero.flags.ZF = true;
  const flagPaths = addCorrelatedState(undefined, clearedZero);

  const distinctFlagPaths = addCorrelatedState(flagPaths, setZero);

  assert.equal(distinctMemoryPaths.states.length, 2);
  assert.equal(distinctFlagPaths.states.length, 2);
});

void test("addCorrelatedState identifies all modeled value kinds", () => {
  const unknownPath = addCorrelatedState(undefined, createSpecialValueState(UNKNOWN));
  const importPath = addCorrelatedState(
    unknownPath,
    createSpecialValueState(importReturn(String(unknownPath.states.length)))
  );
  const cpuIdPath = addCorrelatedState(importPath, createCpuIdPathState(0));
  const cpuIdSubleafPath = addCorrelatedState(cpuIdPath, createCpuIdPathState(1));
  const valueSetState = mergeEmulationStates(createPathState(0), createPathState(1));
  const valueSetPath = addCorrelatedState(undefined, valueSetState);

  const repeatedValueSet = addCorrelatedState(valueSetPath, valueSetState);

  assert.equal(cpuIdSubleafPath.states.length, CORRELATED_PATH_CAPACITY);
  assert.equal(repeatedValueSet, valueSetPath);
});

void test("emulatedValueKey gives every modeled value a canonical tagged identity", () => {
  const firstKnown = collectKnownValues(createPathState(0).registers.get("RAX"))[0];
  const secondKnown = collectKnownValues(createPathState(1).registers.get("RAX"))[0];
  assert.ok(firstKnown);
  assert.ok(secondKnown);
  const valueSet = mergeEmulationStates(
    createPathState(0),
    createPathState(1)
  ).registers.get("RAX");
  assert.ok(valueSet);
  const importValue = importReturn(String(TEST_BITNESS));
  const cpuIdValue = createCpuIdValue(0);
  const cpuIdSubleafValue = createCpuIdValue(1);
  const firstKnownKey = `known:${firstKnown.bits}:${firstKnown.value.toString(16)}`;
  const secondKnownKey = `known:${secondKnown.bits}:${secondKnown.value.toString(16)}`;

  const keys = [
    emulatedValueKey(firstKnown),
    emulatedValueKey(valueSet),
    emulatedValueKey(importValue),
    emulatedValueKey(cpuIdValue),
    emulatedValueKey(cpuIdSubleafValue),
    emulatedValueKey(UNKNOWN)
  ];

  assert.deepEqual(keys, [
    firstKnownKey,
    `set:${firstKnownKey},${secondKnownKey}`,
    `import:${importValue.label}`,
    `cpuid:${cpuIdValue.leaf}:${cpuIdValue.register}`,
    `cpuid:${cpuIdSubleafValue.leaf}:${cpuIdSubleafValue.subleaf}:${cpuIdSubleafValue.register}`,
    "unknown"
  ]);
});

void test("emulationStateKey tags and orders registers, memory, and flags", () => {
  const state = createEmulationState(TEST_BITNESS);
  state.registers.clear();
  const pathValue = known(BigInt(state.registers.size + 1), TEST_BITNESS);
  state.registers.set("RAX", pathValue);
  state.memory.set("RAX", pathValue);
  state.flags.ZF = true;
  state.flags.CF = false;
  const valueKey = emulatedValueKey(pathValue);

  const key = emulationStateKey(state);

  assert.equal(key, [
    "f:CF=0",
    "f:ZF=1",
    `m:RAX=${valueKey}`,
    `r:RAX=${valueKey}`
  ].join("|"));
});

void test("addCorrelatedState widens when the summary equals an existing complete path", () => {
  const completePaths = createUnknownDominatedPaths();

  const widened = addCorrelatedState(
    completePaths,
    createPathState(CORRELATED_PATH_CAPACITY)
  );

  assert.equal(widened.mode, "widened");
});

void test("correlatedStatesContain finds only retained complete states", () => {
  const retained = createPathState(0);
  const states = addCorrelatedState(undefined, retained);

  assert.equal(correlatedStatesContain(states, retained), true);
  assert.equal(correlatedStatesContain(states, createPathState(1)), false);
  assert.equal(correlatedStatesContain(undefined, retained), false);
});

void test("addCorrelatedState snapshots an incoming path before execution mutates it", () => {
  const incoming = createPathState(0);
  const states = addCorrelatedState(undefined, incoming);

  incoming.registers.clear();

  assert.notEqual(states.states[0].registers.size, 0);
});

void test("addCorrelatedState keeps a widened context bounded", () => {
  const widened = addPaths(CORRELATED_PATH_CAPACITY + 1);

  const updated = addCorrelatedState(widened, createPathState(0));

  assert.equal(updated, widened);
});
