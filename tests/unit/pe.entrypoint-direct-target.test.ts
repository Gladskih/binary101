"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { followDirectCodeTarget } from "../../analyzers/pe/disassembly/entrypoint-direct-target.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "../../analyzers/pe/disassembly/index.js";
import type {
  FollowQueueState,
  PendingEntrypointBlock
} from "../../analyzers/pe/disassembly/entrypoint-follow-queue.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  createExecutableSection
} from "../helpers/pe-entrypoint-disassembly-fixture.js";
import { MockFile } from "../helpers/mock-file.js";

const createOptions = (): AnalyzePeEntrypointDisassemblyOptions => ({
  coffMachine: IMAGE_FILE_MACHINE_AMD64,
  is64Bit: true,
  imageBase: 0x140000000n,
  entrypointRva: 0x1000,
  rvaToOff: rva => rva - 0x1000,
  sections: [createExecutableSection({ virtualSize: 3, sizeOfRawData: 3 })]
});

const createQueueState = (): FollowQueueState => ({
  blocks: [],
  visitedBlocks: new Set(),
  queuedBlocks: new Set()
});

void test("followDirectCodeTarget queues call target and speculative fallthrough", async () => {
  const pending: PendingEntrypointBlock[] = [];
  const target = await followDirectCodeTarget(
    createFileRangeReader(new MockFile(new Uint8Array([0xe8, 0x90, 0xc3]), "entry.exe"), 0, 3),
    createOptions(),
    createQueueState(),
    pending,
    { kind: "followed-call", rva: 0x1002 },
    0x1000,
    0x140001001n,
    []
  );

  assert.equal(target.followed, true);
  assert.equal(target.fallthroughRva, 0x1001);
  assert.equal(target.fallthroughFollowed, true);
  assert.equal(target.fallthroughKind, "speculative-call-return");
  assert.deepEqual(pending.map(block => block.kind), ["followed-call", "speculative-call-fallthrough"]);
});

void test("followDirectCodeTarget queues jumps without speculative fallthrough", async () => {
  const pending: PendingEntrypointBlock[] = [];
  const target = await followDirectCodeTarget(
    createFileRangeReader(new MockFile(new Uint8Array([0xe9, 0x90, 0xc3]), "entry.exe"), 0, 3),
    createOptions(),
    createQueueState(),
    pending,
    { kind: "followed-jump", rva: 0x1002 },
    0x1000,
    0x140001001n,
    []
  );

  assert.equal(target.followed, true);
  assert.equal(target.fallthroughRva, undefined);
  assert.deepEqual(pending.map(block => block.kind), ["followed-jump"]);
});
