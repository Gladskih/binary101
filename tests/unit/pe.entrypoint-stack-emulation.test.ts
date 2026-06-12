"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createEmulationState } from "../../analyzers/pe/disassembly/entrypoint/emulation.js";
import {
  createCallStackState,
  createReturnStackState
} from "../../analyzers/pe/disassembly/entrypoint/call-stack.js";
import type { IcedInstructionObject } from "../../analyzers/pe/disassembly/entrypoint/iced.js";
import { known } from "../../analyzers/pe/disassembly/entrypoint/emulation-state.js";
import {
  emulateFixtures,
  fixtureIced,
  imm,
  instruction as ins,
  mem,
  reg
} from "../helpers/pe-entrypoint-emulation-fixture.js";

const emulateInstructionsWithState = (
  instructions: readonly IcedInstructionObject[],
  bitness: 32 | 64 = 64
): ReturnType<typeof emulateFixtures>["state"] => emulateFixtures(instructions, bitness).state;

void test("emulateInstruction models basic stack push and pop", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("RBX"), imm(0x1122334455667788n, "Immediate64")]),
    ins("Push", [reg("RBX")]),
    ins("Pop", [reg("RAX")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x1122334455667788n,
    bits: 64
  });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x100000000000n,
    bits: 64
  });
  assert.equal(state.memory.size, 0);
});

void test("emulateInstruction uses operand-size width for 16-bit push", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("RAX"), imm(0x1122)]),
    ins("Push", [reg("AX")])
  ]);

  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0xffffffffffen,
    bits: 64
  });
  assert.deepEqual(state.memory.get(0xffffffffffen.toString()), {
    kind: "known",
    value: 0x1122n,
    bits: 16
  });
});

void test("emulateInstruction models enter nesting zero and leave", () => {
  const state = emulateInstructionsWithState([
    ins("Enter", [imm(0x20, "Immediate16"), imm(0, "Immediate8_2nd")], {
      code: "Enterq"
    }),
    ins("Leave", [], { code: "Leaveq" })
  ]);

  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x100000000000n,
    bits: 64
  });
  assert.deepEqual(state.registers.get("RBP"), { kind: "unknown" });
  assert.equal(state.memory.size, 0);
});

void test("emulateInstruction pushad stores the original ESP slot", () => {
  const state = emulateInstructionsWithState([ins("Pushad")], 32);

  assert.deepEqual(state.memory.get(0x0fffffecn.toString()), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x0fffffe0n,
    bits: 32
  });
});

void test("emulateInstruction popad restores saved general registers", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Mov", [reg("ECX"), imm(2)]),
    ins("Mov", [reg("EDX"), imm(3)]),
    ins("Mov", [reg("EBX"), imm(4)]),
    ins("Mov", [reg("EBP"), imm(5)]),
    ins("Mov", [reg("ESI"), imm(6)]),
    ins("Mov", [reg("EDI"), imm(7)]),
    ins("Pushad"),
    ins("Popad")
  ], 32);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 1n, bits: 32 });
  assert.deepEqual(state.registers.get("RBX"), { kind: "known", value: 4n, bits: 32 });
  assert.deepEqual(state.registers.get("RDI"), { kind: "known", value: 7n, bits: 32 });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.equal(state.memory.size, 0);
});

void test("emulateInstruction marks nested enter frames unknown", () => {
  const state = emulateInstructionsWithState([
    ins("Enter", [imm(0, "Immediate16"), imm(1, "Immediate8_2nd")], {
      code: "Enterq"
    })
  ]);

  assert.deepEqual(state.registers.get("RSP"), { kind: "unknown" });
  assert.deepEqual(state.registers.get("RBP"), { kind: "unknown" });
});

void test("emulateInstruction lets pushed 64-bit flags expose the saved return slot", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("RAX"), imm(0x140001005n, "Immediate64")]),
    ins("Push", [reg("RAX")]),
    ins("Pushfq"),
    ins("Add", [mem("UInt64", "RSP", 8n), imm(0x0c, "Immediate8to64")]),
    ins("Popfq"),
    ins("Pop", [reg("RBX")])
  ]);

  assert.deepEqual(state.registers.get("RBX"), {
    kind: "known",
    value: 0x140001011n,
    bits: 64
  });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x100000000000n,
    bits: 64
  });
  assert.equal(state.memory.size, 0);
});

void test("emulateInstruction lets pushed 32-bit flags expose the saved return slot", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0x401005)]),
    ins("Push", [reg("EAX")]),
    ins("Pushfd"),
    ins("Add", [mem("UInt32", "ESP", 4n), imm(5, "Immediate8to32")]),
    ins("Popfd"),
    ins("Pop", [reg("EBX")])
  ], 32);

  assert.deepEqual(state.registers.get("RBX"), {
    kind: "known",
    value: 0x40100an,
    bits: 32
  });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.equal(state.memory.size, 0);
});

void test("emulateInstruction models operand-size 16-bit flag pushes", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("RAX"), imm(0x140001005n, "Immediate64")]),
    ins("Push", [reg("RAX")]),
    ins("Pushf"),
    ins("Add", [mem("UInt64", "RSP", 2n), imm(0x0c, "Immediate8to64")]),
    ins("Popf"),
    ins("Pop", [reg("RBX")])
  ]);

  assert.deepEqual(state.registers.get("RBX"), {
    kind: "known",
    value: 0x140001011n,
    bits: 64
  });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x100000000000n,
    bits: 64
  });
  assert.equal(state.memory.size, 0);
});

void test("createReturnStackState applies ret immediate stack cleanup", () => {
  const called = createCallStackState(fixtureIced, createEmulationState(32), 0x401000n);
  called.memory.set(0x10000000n.toString(), known(0x1111n, 32));
  called.memory.set(0x10000004n.toString(), known(0x2222n, 32));
  const returned = createReturnStackState(fixtureIced, called, 8n);

  assert.deepEqual(returned.registers.get("RSP"), {
    kind: "known",
    value: 0x10000008n,
    bits: 32
  });
  assert.equal(returned.memory.size, 0);
});
