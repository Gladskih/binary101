"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { IcedInstructionObject } from "../../analyzers/pe/disassembly/entrypoint/iced.js";
import { collectKnownValues } from "../../analyzers/pe/disassembly/entrypoint/emulation/state.js";
import {
  emulateFixtures,
  imm,
  instruction as ins,
  mem,
  reg
} from "../helpers/pe-entrypoint-emulation-fixture.js";

const emulateInstructionsWithState = (
  instructions: readonly IcedInstructionObject[],
  bitness: 32 | 64 = 64
): ReturnType<typeof emulateFixtures>["state"] => emulateFixtures(instructions, bitness).state;

void test("emulateInstruction models sign and zero extension moves", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("RAX"), imm(-1n, "Immediate32to64")]),
    ins("Movzx", [reg("EAX"), reg("AL")]),
    ins("Movsx", [reg("ECX"), reg("AL")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 0xffn, bits: 64 });
  assert.deepEqual(state.registers.get("RCX"), { kind: "known", value: 0xffff_ffffn, bits: 64 });
});

void test("emulateInstruction models unary arithmetic and shifts", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0x80000000)]),
    ins("Sar", [reg("EAX"), imm(1, "Immediate8")]),
    ins("Inc", [reg("EAX")]),
    ins("Neg", [reg("EAX")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x3fff_ffffn,
    bits: 64
  });
});

void test("emulateInstruction masks 64-bit variable shift counts", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("RAX"), imm(1)]),
    ins("Xor", [reg("ECX"), reg("ECX")]),
    ins("Mov", [reg("CL"), imm(0x20, "Immediate8")]),
    ins("Shl", [reg("RAX"), reg("CL")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x1_0000_0000n,
    bits: 64
  });
});

void test("emulateInstruction models logical shifts and rotates", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0x80000000)]),
    ins("Shr", [reg("EAX"), imm(1, "Immediate8")]),
    ins("Mov", [reg("EAX"), imm(0x80000001)]),
    ins("Rol", [reg("EAX"), imm(1, "Immediate8")]),
    ins("Ror", [reg("EAX"), imm(1, "Immediate8")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x8000_0001n,
    bits: 64
  });
});

void test("emulateInstruction models carry rotates with known carry flag", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Cmp", [reg("EAX"), imm(1)]),
    ins("Stc"),
    ins("Rcl", [reg("EAX"), imm(1, "Immediate8")]),
    ins("Mov", [reg("ECX"), imm(2)]),
    ins("Stc"),
    ins("Rcr", [reg("ECX"), imm(1, "Immediate8")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 3n, bits: 64 });
  assert.deepEqual(state.registers.get("RCX"), {
    kind: "known",
    value: 0x8000_0001n,
    bits: 64
  });
  assert.equal(state.flags.CF, false);
  assert.equal(state.flags.OF, true);
  assert.equal(state.flags.ZF, true);
});

void test("emulateInstruction models multi-bit carry rotates and undefined overflow", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Stc"),
    ins("Rcr", [reg("EAX"), imm(2, "Immediate8")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0xc000_0000n,
    bits: 64
  });
  assert.equal(state.flags.CF, false);
  assert.equal(state.flags.OF, undefined);
});

void test("emulateInstruction keeps carry rotates unknown when carry is unknown", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Rcl", [reg("EAX"), imm(1, "Immediate8")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "unknown" });
  assert.equal(state.flags.CF, undefined);
  assert.equal(state.flags.OF, undefined);
});

void test("emulateInstruction handles carry rotate count edge cases", () => {
  const fullCycleState = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0x81)]),
    ins("Stc"),
    ins("Rcl", [reg("AL"), imm(9, "Immediate8")])
  ]);
  const unknownCountState = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Cmp", [reg("EAX"), imm(1)]),
    ins("Stc"),
    ins("Rcr", [reg("EAX"), reg("CL")])
  ]);

  assert.deepEqual(fullCycleState.registers.get("RAX"), {
    kind: "known",
    value: 0x81n,
    bits: 64
  });
  assert.equal(fullCycleState.flags.CF, true);
  assert.deepEqual(unknownCountState.registers.get("RAX"), { kind: "unknown" });
  assert.equal(unknownCountState.flags.CF, undefined);
  assert.equal(unknownCountState.flags.OF, undefined);
  assert.equal(unknownCountState.flags.ZF, true);
});

void test("emulateInstruction models double-precision shifts", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0x12345678)]),
    ins("Mov", [reg("ECX"), imm(0xf0000000)]),
    ins("Shld", [reg("EAX"), reg("ECX"), imm(4, "Immediate8")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x2345_678fn,
    bits: 64
  });
});

void test("emulateInstruction joins conditional move outcomes when flags are unknown", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Mov", [reg("ECX"), imm(2)]),
    ins("Cmovne", [reg("EAX"), reg("ECX")])
  ]);

  assert.deepEqual(
    collectKnownValues(state.registers.get("RAX")).map(value => value.value),
    [1n, 2n]
  );
});

void test("emulateInstruction stores setcc as boolean alternatives", () => {
  const state = emulateInstructionsWithState([
    ins("Setne", [mem("UInt8", "RSP")])
  ]);

  assert.deepEqual(
    collectKnownValues(state.memory.get(0x100000000000n.toString())).map(value => value.value),
    [0n, 1n]
  );
});

void test("emulateInstruction models xchg, xadd, and cmpxchg register effects", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(3)]),
    ins("Mov", [reg("ECX"), imm(4)]),
    ins("Xchg", [reg("EAX"), reg("ECX")]),
    ins("Xadd", [reg("EAX"), reg("ECX")]),
    ins("Mov", [reg("EDX"), imm(9)]),
    ins("Cmpxchg", [reg("EDX"), reg("ECX")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 9n, bits: 64 });
  assert.deepEqual(state.registers.get("RCX"), { kind: "known", value: 4n, bits: 64 });
  assert.deepEqual(state.registers.get("RDX"), { kind: "known", value: 9n, bits: 64 });
});

void test("emulateInstruction models accumulator sign-extension instructions", () => {
  const state = emulateInstructionsWithState([
    ins("Xor", [reg("EAX"), reg("EAX")]),
    ins("Mov", [reg("AL"), imm(0xff, "Immediate8")]),
    ins("Cbw"),
    ins("Cwde"),
    ins("Cdq")
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0xffff_ffffn,
    bits: 64
  });
  assert.deepEqual(state.registers.get("RDX"), {
    kind: "known",
    value: 0xffff_ffffn,
    bits: 64
  });
});

void test("emulateInstruction models multiply and bit count instructions", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(3)]),
    ins("Mov", [reg("ECX"), imm(4)]),
    ins("Mul", [reg("ECX")]),
    ins("Popcnt", [reg("ECX"), reg("EAX")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 12n, bits: 64 });
  assert.deepEqual(state.registers.get("RDX"), { kind: "known", value: 0n, bits: 64 });
  assert.deepEqual(state.registers.get("RCX"), { kind: "known", value: 2n, bits: 64 });
});

void test("emulateInstruction models signed imul low-result forms", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(3)]),
    ins("Imul", [reg("EAX"), reg("EAX"), imm(-2n, "Immediate8to32")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0xffff_fffan,
    bits: 64
  });
});

void test("emulateInstruction computes known accumulator registers for div", () => {
  const state = emulateInstructionsWithState([
    ins("Xor", [reg("EDX"), reg("EDX")]),
    ins("Mov", [reg("EAX"), imm(10)]),
    ins("Mov", [reg("ECX"), imm(2)]),
    ins("Div", [reg("ECX")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 5n, bits: 64 });
  assert.deepEqual(state.registers.get("RDX"), { kind: "known", value: 0n, bits: 64 });
});

void test("emulateInstruction models bit scan and zero-count instructions", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0x10)]),
    ins("Bsf", [reg("ECX"), reg("EAX")]),
    ins("Bsr", [reg("EDX"), reg("EAX")]),
    ins("Lzcnt", [reg("EBX"), reg("EAX")]),
    ins("Tzcnt", [reg("ESI"), reg("EAX")])
  ]);

  assert.deepEqual(state.registers.get("RCX"), { kind: "known", value: 4n, bits: 64 });
  assert.deepEqual(state.registers.get("RDX"), { kind: "known", value: 4n, bits: 64 });
  assert.deepEqual(state.registers.get("RBX"), { kind: "known", value: 27n, bits: 64 });
  assert.deepEqual(state.registers.get("RSI"), { kind: "known", value: 4n, bits: 64 });
});
