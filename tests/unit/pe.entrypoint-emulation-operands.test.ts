"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  fixtureIced,
  imm,
  instruction as ins,
  mem,
  reg
} from "../helpers/pe-entrypoint-emulation-fixture.js";
import { resolveRegister } from "../../analyzers/pe/disassembly/entrypoint/emulation/registers.js";
import {
  isSameRegisterOperand,
  operandBits,
  readOperand,
  resolveMemoryAddress,
  resolveStackPointer,
  writeOperand
} from "../../analyzers/pe/disassembly/entrypoint/emulation/operands.js";
import {
  createEmulationState,
  known,
  readRegister,
  writeRegister
} from "../../analyzers/pe/disassembly/entrypoint/emulation/state.js";

const access = (name: string) =>
  resolveRegister(fixtureIced, fixtureIced.Register?.[name] ?? 0);

void test("isSameRegisterOperand compares decoded register operands", () => {
  const same = ins("Xor", [reg("EAX"), reg("EAX")]);
  const different = ins("Xor", [reg("EAX"), reg("ECX")]);
  const immediate = ins("Mov", [reg("EAX"), imm(1)]);

  assert.equal(isSameRegisterOperand(fixtureIced, same), true);
  assert.equal(isSameRegisterOperand(fixtureIced, different), false);
  assert.equal(isSameRegisterOperand(fixtureIced, immediate), false);
});

void test("resolveMemoryAddress rejects unsupported memory base registers", () => {
  const state = createEmulationState(64);
  const instruction = ins("Mov", [reg("RAX"), mem("UInt64", "RIP")]);

  assert.equal(resolveMemoryAddress(fixtureIced, state, instruction), null);
});

void test("readOperand and writeOperand use concrete stack addresses", () => {
  const state = createEmulationState(64);
  const store = ins("Mov", [mem("UInt64", "RSP", 8n), reg("RAX")]);
  const load = ins("Mov", [reg("RBX"), mem("UInt64", "RSP", 8n)]);

  writeRegister(state, access("RAX"), known(9n, 64));
  writeOperand(fixtureIced, state, store, 0, readOperand(fixtureIced, state, store, 1));
  writeOperand(fixtureIced, state, load, 0, readOperand(fixtureIced, state, load, 1));

  assert.deepEqual(readRegister(state, access("RBX")), {
    kind: "known",
    value: 9n,
    bits: 64
  });
});

void test("resolveMemoryAddress uses base, index, scale, and displacement", () => {
  const state = createEmulationState(64);
  const instruction = ins("Mov", [reg("RAX"), mem("UInt64", "RBX", 0x10n, "RCX", 4)]);

  writeRegister(state, access("RBX"), known(0x1000n, 64));
  writeRegister(state, access("RCX"), known(3n, 64));

  assert.equal(resolveMemoryAddress(fixtureIced, state, instruction), 0x101cn);
});

void test("readOperand resolves 32-bit negative frame displacements", () => {
  const state = createEmulationState(32);
  const instruction = ins("Push", [
    mem("UInt32", "EBP", BigInt.asUintN(64, -8n))
  ]);

  writeRegister(state, access("EBP"), known(0x1000n, 32));
  state.memory.set(0x0ff8n.toString(), known(0x40100cn, 32));

  assert.equal(resolveMemoryAddress(fixtureIced, state, instruction), 0x0ff8n);
  assert.deepEqual(readOperand(fixtureIced, state, instruction, 0), {
    kind: "known",
    value: 0x40100cn,
    bits: 32
  });
});

void test("readOperand selects the requested immediate operand", () => {
  const state = createEmulationState(64);
  const instruction = ins("Enter", [imm(0x1234, "Immediate16"), imm(0x56, "Immediate8_2nd")]);

  assert.deepEqual(readOperand(fixtureIced, state, instruction, 1), {
    kind: "known",
    value: 0x56n,
    bits: 64
  });
});

void test("operandBits reports register and memory operand widths", () => {
  const register = ins("Movzx", [reg("EAX"), reg("AL")]);
  const memory = ins("Mov", [reg("EAX"), mem("UInt32", "RSP")]);

  assert.equal(operandBits(fixtureIced, register, 0), 32);
  assert.equal(operandBits(fixtureIced, register, 1), 8);
  assert.equal(operandBits(fixtureIced, memory, 1), 32);
});

void test("readOperand and writeOperand tolerate out-of-range operand indexes", () => {
  const state = createEmulationState(64);
  const instruction = ins("Mov");

  assert.deepEqual(readOperand(fixtureIced, state, instruction, 0), { kind: "unknown" });
  writeOperand(fixtureIced, state, instruction, 0, known(1n, 64));
  assert.equal(state.registers.size, 1);
});

void test("readOperand coerces memory reads to the instruction memory width", () => {
  const state = createEmulationState(64);
  const instruction = ins("Mov", [reg("EAX"), mem("UInt32", "RSP")]);

  state.memory.set(0x100000000000n.toString(), known(0x1122_3344_5566_7788n, 64));

  assert.deepEqual(readOperand(fixtureIced, state, instruction, 1), {
    kind: "known",
    value: 0x5566_7788n,
    bits: 32
  });
});

void test("resolveStackPointer returns the bitness-specific stack alias", () => {
  assert.deepEqual(resolveStackPointer(fixtureIced, createEmulationState(64)), {
    canonical: "RSP",
    accessBits: 64,
    bitOffset: 0
  });
  assert.deepEqual(resolveStackPointer(fixtureIced, createEmulationState(32)), {
    canonical: "RSP",
    accessBits: 32,
    bitOffset: 0
  });
});
