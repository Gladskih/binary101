"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "../../analyzers/pe/disassembly/index.js";
import {
  createBlockKey,
  queueFollowedBlock,
  type FollowQueueState,
  type PendingBlock
} from "../../analyzers/pe/disassembly/entrypoint/follow-queue.js";
import { createEmulationState } from "../../analyzers/pe/disassembly/entrypoint/emulation.js";
import {
  collectKnownValues,
  known
} from "../../analyzers/pe/disassembly/entrypoint/emulation-state.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  createExecutableSection
} from "../helpers/pe-entrypoint-disassembly-fixture.js";
import { MockFile } from "../helpers/mock-file.js";

const imageBase = 0x140000000n;

const createQueueState = (): FollowQueueState => ({
  blocks: [],
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
  sections: [createExecutableSection({ virtualSize: 1, sizeOfRawData: 1 })]
});

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
  const state = createQueueState();
  const pending: PendingBlock[] = [];
  const left = createEmulationState(64);
  const right = createEmulationState(64);
  left.registers.set("R11", known(0x140001010n, 64));
  right.registers.set("R11", known(0x140002020n, 64));

  await queueFollowedBlock(
    createFileRangeReader(new MockFile(new Uint8Array([0xc3]), "target.exe"), 0, 1),
    createOptions(),
    state,
    pending,
    { kind: "followed-call", rva: 0x1000 },
    0x2000,
    [],
    left
  );
  await queueFollowedBlock(
    createFileRangeReader(new MockFile(new Uint8Array([0xc3]), "target.exe"), 0, 1),
    createOptions(),
    state,
    pending,
    { kind: "followed-call", rva: 0x1000 },
    0x2001,
    [],
    right
  );

  assert.equal(pending.length, 1);
  assert.deepEqual(
    collectKnownValues(pending[0]?.emulationState.registers.get("R11"))
      .map(value => value.value),
    [0x140001010n, 0x140002020n]
  );
});
