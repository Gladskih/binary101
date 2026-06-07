"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createBlockKey } from "../../analyzers/pe/disassembly/entrypoint/follow-queue.js";
import { createEmulationState } from "../../analyzers/pe/disassembly/entrypoint/emulation.js";
import {
  known
} from "../../analyzers/pe/disassembly/entrypoint/emulation-state.js";

const imageBase = 0x140000000n;

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
