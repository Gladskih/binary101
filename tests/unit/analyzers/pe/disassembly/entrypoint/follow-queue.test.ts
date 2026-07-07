"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../../../analyzers/file-range-reader.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "../../../../../../analyzers/pe/disassembly/index.js";
import {
  MAX_PRECISION_BUDGET_PER_RVA,
  createBlockKey,
  isPendingBlockCurrent,
  queueFollowedBlock,
  type FollowQueueState,
  type PendingBlock
} from "../../../../../../analyzers/pe/disassembly/entrypoint/follow-queue.js";
import { addCorrelatedState } from "../../../../../../analyzers/pe/disassembly/entrypoint/correlated-states.js";
import { createEmulationState } from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import {
  collectKnownValues,
  importReturn,
  known
} from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/state.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  createExecutableSection
} from "../../../../../helpers/pe-entrypoint-disassembly-fixture.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

const imageBase = 0x140000000n;
const TARGET_FILE_SIZE = Uint8Array.BYTES_PER_ELEMENT;
// The fixture models one stack pointer and one path-dependent call target.
const MODELED_VALUES_PER_PATH = 2;

const createTargetReader = () => createFileRangeReader(
  new MockFile(new Uint8Array(TARGET_FILE_SIZE), "target.exe"),
  0,
  TARGET_FILE_SIZE
);

const createQueueState = (pending: PendingBlock[]): FollowQueueState => ({
  blocks: [],
  pending,
  issues: [],
  visitedBlocks: new Set(),
  emulationStatesByKey: new Map(),
  contextKeysByRva: new Map(),
  precisionCostByRva: new Map(),
  precisionLimitReportedRvas: new Set()
});

const createOptions = (): AnalyzePeEntrypointDisassemblyOptions => ({
  coffMachine: IMAGE_FILE_MACHINE_AMD64,
  is64Bit: true,
  imageBase,
  entrypointRva: 0x1000,
  rvaToOff: rva => rva - 0x1000,
  sections: [createExecutableSection({
    virtualSize: TARGET_FILE_SIZE,
    sizeOfRawData: TARGET_FILE_SIZE
  })]
});

const createPrecisionGrowthStates = (targetRva: number) => {
  const previous = createEmulationState(64);
  const incoming = createEmulationState(64);
  previous.registers.set("R11", known(imageBase + BigInt(targetRva), 64));
  incoming.registers.set(
    "R11",
    known(imageBase + BigInt(targetRva + Uint8Array.BYTES_PER_ELEMENT), 64)
  );
  return { incoming, previous };
};

void test("createBlockKey ignores scratch registers and non-stack memory", () => {
  const left = createEmulationState(64);
  const right = createEmulationState(64);
  left.registers.set("RAX", known(1n, 64));
  left.registers.set("RSP", known(0x100000000000n, 64));
  left.registers.set("RBP", known(0x100000000ff0n, 64));
  right.registers.set("RAX", known(2n, 64));
  right.registers.set("RSP", known(0x100000000fe0n, 64));
  right.registers.set("RBP", known(0x100000000ee0n, 64));
  left.memory.set("4198400", known(3n, 64));
  right.memory.set("4198400", known(4n, 64));

  assert.equal(
    createBlockKey(0x1000, left),
    createBlockKey(0x1000, right)
  );
});

void test("createBlockKey distinguishes stack return targets", () => {
  const left = createEmulationState(64);
  const right = createEmulationState(64);
  left.memory.set("17592186044416", known(0x140001000n, 64));
  right.memory.set("17592186044416", known(0x140002000n, 64));

  assert.notEqual(
    createBlockKey(0x1000, left),
    createBlockKey(0x1000, right)
  );
});

void test("createBlockKey distinguishes stack arguments read by prolog helpers", () => {
  const left = createEmulationState(64);
  const right = createEmulationState(64);
  left.memory.set("17592186044416", known(0x140001000n, 64));
  right.memory.set("17592186044416", known(0x140001000n, 64));
  left.memory.set("17592186044432", known(0x140003000n, 64));
  right.memory.set("17592186044432", known(0x140004000n, 64));

  assert.notEqual(
    createBlockKey(0x1000, left),
    createBlockKey(0x1000, right)
  );
});

void test("createBlockKey distinguishes precise top stack values restored by pops", () => {
  const left = createEmulationState(32);
  const right = createEmulationState(32);
  left.memory.set("268435456", known(0x4080d0n, 32));
  right.memory.set("268435456", importReturn("KERNEL32.dll!GetLastError"));

  assert.notEqual(
    createBlockKey(0x1000, left),
    createBlockKey(0x1000, right)
  );
});

void test("createBlockKey distinguishes frame-pointer return slots", () => {
  const left = createEmulationState(64);
  const right = createEmulationState(64);
  left.registers.set("RBP", known(0x100000000ff0n, 64));
  right.registers.set("RBP", known(0x100000000ff0n, 64));
  left.memory.set("17592186048504", known(0x140001000n, 64));
  right.memory.set("17592186048504", known(0x140002000n, 64));

  assert.notEqual(
    createBlockKey(0x1000, left),
    createBlockKey(0x1000, right)
  );
});

void test("queueFollowedBlock keeps same-context path states separate", async () => {
  const opts = createOptions();
  const pending: PendingBlock[] = [];
  const state = createQueueState(pending);
  const { incoming, previous } = createPrecisionGrowthStates(opts.entrypointRva);

  const firstQueued = await queueFollowedBlock(
    createTargetReader(),
    opts,
    state,
    { kind: "followed-call", rva: 0x1000 },
    0x2000,
    previous
  );
  const secondQueued = await queueFollowedBlock(
    createTargetReader(),
    opts,
    state,
    { kind: "followed-call", rva: 0x1000 },
    0x2001,
    incoming
  );

  assert.equal(firstQueued, true);
  assert.equal(secondQueued, true);
  assert.equal(pending.length, 2);
  assert.deepEqual(
    collectKnownValues(pending[0]?.emulationState.registers.get("R11"))
      .map(value => value.value),
    [imageBase + BigInt(opts.entrypointRva)]
  );
  assert.deepEqual(
    collectKnownValues(pending[1]?.emulationState.registers.get("R11"))
      .map(value => value.value),
    [imageBase + BigInt(opts.entrypointRva + Uint8Array.BYTES_PER_ELEMENT)]
  );
});

void test("isPendingBlockCurrent rejects a superseded state snapshot", async () => {
  const opts = createOptions();
  const state = createQueueState([]);
  const { incoming, previous } = createPrecisionGrowthStates(opts.entrypointRva);
  await queueFollowedBlock(
    createTargetReader(),
    opts,
    state,
    { kind: "followed-call", rva: opts.entrypointRva },
    opts.entrypointRva,
    previous
  );
  const pending = state.pending[0];
  assert.ok(pending);
  const currentBefore = isPendingBlockCurrent(state, pending);
  state.emulationStatesByKey.set(
    pending.key,
    addCorrelatedState(undefined, incoming)
  );

  const currentAfter = isPendingBlockCurrent(state, pending);

  assert.equal(currentBefore, true);
  assert.equal(currentAfter, false);
});

void test("queueFollowedBlock charges a complete new path state", async () => {
  const opts = createOptions();
  const targetRva = opts.entrypointRva;
  const { incoming, previous } = createPrecisionGrowthStates(targetRva);
  const key = createBlockKey(targetRva, previous);
  const state = createQueueState([]);
  state.emulationStatesByKey.set(key, addCorrelatedState(undefined, previous));
  const precisionBefore = MAX_PRECISION_BUDGET_PER_RVA - MODELED_VALUES_PER_PATH;
  state.precisionCostByRva.set(targetRva, precisionBefore);

  const queued = await queueFollowedBlock(
    createTargetReader(),
    opts,
    state,
    { kind: "followed-branch", rva: targetRva },
    targetRva,
    incoming
  );

  assert.equal(queued, true);
  assert.equal(state.pending.length, 1);
  assert.equal(
    state.precisionCostByRva.get(targetRva),
    precisionBefore + MODELED_VALUES_PER_PATH
  );
  assert.deepEqual(state.issues, []);
});

void test("queueFollowedBlock refuses precision growth beyond the pending-context budget", async () => {
  const opts = createOptions();
  const targetRva = opts.entrypointRva;
  const { incoming, previous } = createPrecisionGrowthStates(targetRva);
  const state = createQueueState([]);
  await queueFollowedBlock(
    createTargetReader(),
    opts,
    state,
    { kind: "followed-branch", rva: targetRva },
    targetRva,
    previous
  );
  state.precisionCostByRva.set(targetRva, MAX_PRECISION_BUDGET_PER_RVA);

  const queued = await queueFollowedBlock(
    createTargetReader(),
    opts,
    state,
    { kind: "followed-branch", rva: targetRva },
    targetRva,
    incoming
  );
  const repeated = await queueFollowedBlock(
    createTargetReader(),
    opts,
    state,
    { kind: "followed-branch", rva: targetRva },
    targetRva,
    incoming
  );

  assert.equal(queued, false);
  assert.equal(repeated, false);
  assert.equal(state.pending.length, 1);
  assert.deepEqual(
    collectKnownValues(state.pending[0]?.emulationState.registers.get("R11"))
      .map(value => value.value),
    [imageBase + BigInt(targetRva)]
  );
  assert.equal(state.issues.length, 1);
  assert.match(state.issues[0] ?? "", /precision budget/i);
});
