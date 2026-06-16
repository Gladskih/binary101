"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { followDirectCodeTarget } from "../../analyzers/pe/disassembly/entrypoint/direct-target.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "../../analyzers/pe/disassembly/index.js";
import type {
  FollowQueueState,
  PendingBlock
} from "../../analyzers/pe/disassembly/entrypoint/follow-queue.js";
import { createEmulationState } from "../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import type { IcedModule } from "../../analyzers/pe/disassembly/entrypoint/iced.js";
import {
  fakeIced,
  IMAGE_FILE_MACHINE_AMD64,
  createExecutableSection
} from "../helpers/pe-entrypoint-disassembly-fixture.js";
import { MockFile } from "../helpers/mock-file.js";

const iced = fakeIced as unknown as IcedModule;

const createOptions = (): AnalyzePeEntrypointDisassemblyOptions => ({
  coffMachine: IMAGE_FILE_MACHINE_AMD64,
  is64Bit: true,
  imageBase: 0x140000000n,
  entrypointRva: 0x1000,
  rvaToOff: rva => rva - 0x1000,
  sections: [createExecutableSection({ virtualSize: 3, sizeOfRawData: 3 })]
});

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

void test("followDirectCodeTarget queues call target with a call-stack state", async () => {
  const pending: PendingBlock[] = [];
  const bytes = new Uint8Array([0xe8, 0x90, 0xc3]);
  const target = await followDirectCodeTarget(
    iced,
    createFileRangeReader(new MockFile(bytes, "entry.exe"), 0, bytes.length),
    createOptions(),
    createQueueState(pending),
    { kind: "followed-call", rva: 0x1002 },
    0x1000,
    0x140001001n,
    createEmulationState(64)
  );

  assert.equal(target.followed, true);
  assert.equal(target.rva, 0x1002);
  assert.deepEqual(pending.map(block => block.kind), ["followed-call"]);
  assert.equal(pending[0]?.emulationState.memory.size, 1);
});

void test("followDirectCodeTarget queues jumps without speculative fallthrough", async () => {
  const pending: PendingBlock[] = [];
  const bytes = new Uint8Array([0xe9, 0x90, 0xc3]);
  const target = await followDirectCodeTarget(
    iced,
    createFileRangeReader(new MockFile(bytes, "entry.exe"), 0, bytes.length),
    createOptions(),
    createQueueState(pending),
    { kind: "followed-jump", rva: 0x1002 },
    0x1000,
    0x140001001n,
    createEmulationState(64)
  );

  assert.equal(target.followed, true);
  assert.deepEqual(pending.map(block => block.kind), ["followed-jump"]);
});
