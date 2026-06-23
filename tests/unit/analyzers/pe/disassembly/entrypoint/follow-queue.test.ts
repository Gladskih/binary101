"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../../../analyzers/file-range-reader.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "../../../../../../analyzers/pe/disassembly/index.js";
import {
  MAX_PRECISION_BUDGET_PER_RVA,
  createBlockKey,
  queueFollowedBlock,
  type FollowQueueState,
  type PendingBlock
} from "../../../../../../analyzers/pe/disassembly/entrypoint/follow-queue.js";
import { createEmulationState } from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import {
  collectKnownValues,
  known
} from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/state.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  createExecutableSection
} from "../../../../../helpers/pe-entrypoint-disassembly-fixture.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

const imageBase = 0x140000000n;
const TARGET_FILE_SIZE = Uint8Array.BYTES_PER_ELEMENT;
const EXPECTED_PRECISION_GROWTH = 1;

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
  queuedBlocksByKey: new Map(),
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
    createBlockKey(0x1000, left, imageBase),
    createBlockKey(0x1000, right, imageBase)
  );
});

void test("createBlockKey distinguishes stack return targets", () => {
  const left = createEmulationState(64);
  const right = createEmulationState(64);
  left.memory.set("17592186044416", known(0x140001000n, 64));
  right.memory.set("17592186044416", known(0x140002000n, 64));

  assert.notEqual(
    createBlockKey(0x1000, left, imageBase),
    createBlockKey(0x1000, right, imageBase)
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
    createBlockKey(0x1000, left, imageBase),
    createBlockKey(0x1000, right, imageBase)
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
    createBlockKey(0x1000, left, imageBase),
    createBlockKey(0x1000, right, imageBase)
  );
});

void test("queueFollowedBlock merges same-key pending emulation states", async () => {
  const pending: PendingBlock[] = [];
  const state = createQueueState(pending);
  const left = createEmulationState(64);
  const right = createEmulationState(64);
  left.registers.set("R11", known(0x140001010n, 64));
  right.registers.set("R11", known(0x140002020n, 64));

  const firstQueued = await queueFollowedBlock(
    createTargetReader(),
    createOptions(),
    state,
    { kind: "followed-call", rva: 0x1000 },
    0x2000,
    left
  );
  const secondQueued = await queueFollowedBlock(
    createTargetReader(),
    createOptions(),
    state,
    { kind: "followed-call", rva: 0x1000 },
    0x2001,
    right
  );

  assert.equal(firstQueued, true);
  assert.equal(secondQueued, true);
  assert.equal(pending.length, 1);
  assert.deepEqual(
    collectKnownValues(pending[0]?.emulationState.registers.get("R11"))
      .map(value => value.value),
    [0x140001010n, 0x140002020n]
  );
});

void test("queueFollowedBlock charges only added precision for a processed context", async () => {
  const opts = createOptions();
  const targetRva = opts.entrypointRva;
  const { incoming, previous } = createPrecisionGrowthStates(targetRva);
  const key = createBlockKey(targetRva, previous, imageBase);
  const state = createQueueState([]);
  state.emulationStatesByKey.set(key, previous);
  const precisionBefore = MAX_PRECISION_BUDGET_PER_RVA - EXPECTED_PRECISION_GROWTH;
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
    precisionBefore + EXPECTED_PRECISION_GROWTH
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
