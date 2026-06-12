"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { IcedInstructionObject } from "../../analyzers/pe/disassembly/entrypoint/iced.js";
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

void test("emulateInstruction uses flags for conditional moves and sets", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(5)]),
    ins("Mov", [reg("EBX"), imm(0x22)]),
    ins("Mov", [reg("ECX"), imm(0)]),
    ins("Cmp", [reg("EAX"), imm(5)]),
    ins("Sete", [reg("BL")]),
    ins("Setne", [reg("CL")]),
    ins("Mov", [reg("EDX"), imm(9)]),
    ins("Cmove", [reg("EDX"), reg("EAX")])
  ]);

  assert.deepEqual(state.registers.get("RBX"), { kind: "known", value: 1n, bits: 64 });
  assert.deepEqual(state.registers.get("RCX"), { kind: "known", value: 0n, bits: 64 });
  assert.deepEqual(state.registers.get("RDX"), { kind: "known", value: 5n, bits: 64 });
  assert.equal(state.flags.ZF, true);
});

void test("emulateInstruction leaves a false conditional move destination unchanged", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(5)]),
    ins("Mov", [reg("EBX"), imm(0x22)]),
    ins("Cmp", [reg("EAX"), imm(6)]),
    ins("Cmove", [reg("EBX"), reg("EAX")])
  ]);

  assert.deepEqual(state.registers.get("RBX"), { kind: "known", value: 0x22n, bits: 64 });
  assert.equal(state.flags.ZF, false);
});

void test("emulateInstruction uses carry flag controls for adc and sbb", () => {
  const state = emulateInstructionsWithState([
    ins("Stc"),
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Adc", [reg("EAX"), imm(2, "Immediate8to32")]),
    ins("Cmc"),
    ins("Sbb", [reg("EAX"), imm(1, "Immediate8to32")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 2n, bits: 64 });
});

void test("emulateInstruction preserves adc carry-out when source plus carry wraps", () => {
  const state = emulateInstructionsWithState([
    ins("Stc"),
    ins("Mov", [reg("EAX"), imm(0)]),
    ins("Adc", [reg("EAX"), imm(-1n, "Immediate8to32")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0n,
    bits: 64
  });
  assert.equal(state.flags.CF, true);
});

void test("emulateInstruction preserves adc overflow when carry crosses sign bit", () => {
  const state = emulateInstructionsWithState([
    ins("Stc"),
    ins("Mov", [reg("EAX"), imm(0)]),
    ins("Adc", [reg("EAX"), imm(0x7fffffff)])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x80000000n,
    bits: 64
  });
  assert.equal(state.flags.OF, true);
});

void test("emulateInstruction models lahf and sahf flag transfer", () => {
  const lahfState = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Cmp", [reg("EAX"), imm(1)]),
    ins("Lahf")
  ]);
  const sahfState = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0)]),
    ins("Mov", [reg("AH"), imm(0x03, "Immediate8")]),
    ins("Sahf")
  ]);

  assert.deepEqual(lahfState.registers.get("RAX"), {
    kind: "known",
    value: 0x4601n,
    bits: 64
  });
  assert.deepEqual(
    {
      CF: sahfState.flags.CF,
      PF: sahfState.flags.PF,
      AF: sahfState.flags.AF,
      ZF: sahfState.flags.ZF,
      SF: sahfState.flags.SF
    },
    { CF: true, PF: false, AF: false, ZF: false, SF: false }
  );
});

void test("emulateInstruction models scalar bit-test mutations", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(2)]),
    ins("Bts", [reg("EAX"), imm(2, "Immediate8")]),
    ins("Btc", [reg("EAX"), imm(1, "Immediate8")]),
    ins("Btr", [reg("EAX"), imm(2, "Immediate8")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 0n, bits: 64 });
  assert.equal(state.flags.CF, true);
});

void test("emulateInstruction computes known div and idiv results", () => {
  const divState = emulateInstructionsWithState([
    ins("Mov", [reg("EDX"), imm(0)]),
    ins("Mov", [reg("EAX"), imm(10)]),
    ins("Mov", [reg("ECX"), imm(3)]),
    ins("Div", [reg("ECX")])
  ]);
  const idivState = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0xfffffff9n)]),
    ins("Cdq"),
    ins("Mov", [reg("ECX"), imm(3)]),
    ins("Idiv", [reg("ECX")])
  ]);

  assert.deepEqual(divState.registers.get("RAX"), { kind: "known", value: 3n, bits: 64 });
  assert.deepEqual(divState.registers.get("RDX"), { kind: "known", value: 1n, bits: 64 });
  assert.deepEqual(idivState.registers.get("RAX"), {
    kind: "known",
    value: 0xfffffffEn,
    bits: 64
  });
  assert.deepEqual(idivState.registers.get("RDX"), {
    kind: "known",
    value: 0xffffffffn,
    bits: 64
  });
});

void test("emulateInstruction computes movbe loads through memory operands", () => {
  const state = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0x11223344)]),
    ins("Mov", [mem("UInt32", "RSP", 8n), reg("EAX")]),
    ins("Movbe", [reg("EBX"), mem("UInt32", "RSP", 8n)])
  ]);

  assert.deepEqual(state.registers.get("RBX"), {
    kind: "known",
    value: 0x44332211n,
    bits: 64
  });
});
