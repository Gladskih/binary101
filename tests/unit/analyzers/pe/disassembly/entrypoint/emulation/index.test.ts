"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeEntrypointInstruction } from "../../../../../../../analyzers/pe/disassembly/index.js";
import type { IcedInstructionObject } from "../../../../../../../analyzers/pe/disassembly/entrypoint/iced.js";
import type { EmulationState } from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import {
  emulateFixtures,
  imm,
  instruction as ins,
  mem,
  reg
} from "../../../../../../helpers/pe-entrypoint-emulation-fixture.js";

const emulateInstructions = (
  instructions: readonly IcedInstructionObject[],
  bitness: 32 | 64 = 64
): PeEntrypointInstruction[] => emulateFixtures(instructions, bitness).rendered;

const emulateInstructionsWithState = (
  instructions: readonly IcedInstructionObject[],
  bitness: 32 | 64 = 64
): { instructions: PeEntrypointInstruction[]; state: EmulationState } => {
  const result = emulateFixtures(instructions, bitness);
  return { instructions: result.rendered, state: result.state };
};

void test("emulateInstruction follows the LLVM two-CPUID startup idiom", () => {
  const instructions = emulateInstructions([
    ins("Xor", [reg("EAX"), reg("EAX")]),
    ins("Xor", [reg("ECX"), reg("ECX")]),
    ins("Cpuid"),
    ins("Xor", [reg("ECX"), imm(0x6c65746e)]),
    ins("Xor", [reg("EDX"), imm(0x49656e69)]),
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Xor", [reg("EBX"), imm(0x756e6547)]),
    ins("Lea", [reg("ECX"), mem("UInt32", "RAX", -1n)]),
    ins("Cpuid")
  ]);

  assert.deepEqual(instructions[2]?.notes, [
    "CPUID leaf 0: highest basic leaf and vendor identification string."
  ]);
  assert.deepEqual(instructions[3]?.notes, [
    "CPUID vendor string chunk 'ntel' (GenuineIntel)."
  ]);
  assert.deepEqual(instructions[4]?.notes, [
    "CPUID vendor string chunk 'ineI' (GenuineIntel)."
  ]);
  assert.deepEqual(instructions[6]?.notes, [
    "CPUID vendor string chunk 'Genu' (GenuineIntel)."
  ]);
  assert.deepEqual(instructions[8]?.notes, [
    "CPUID leaf 1: processor signature and basic feature flags."
  ]);
});

void test("emulateInstruction annotates checks on copied CPUID outputs", () => {
  const instructions = emulateInstructions([
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Cpuid"),
    ins("Mov", [reg("EDI"), reg("ECX")]),
    ins("Test", [reg("EDI"), imm(0x18000000)])
  ]);

  assert.deepEqual(instructions[3]?.notes, [
    "CPUID ECX feature check: OSXSAVE bit 27, AVX bit 28."
  ]);
});

void test("emulateInstruction does not keep stale CPUID leaf setup", () => {
  const instructions = emulateInstructions([
    ins("Mov", [reg("EAX"), imm(7)]),
    ins("Add", [reg("EAX"), imm(1, "Immediate8to32")]),
    ins("Xor", [reg("ECX"), reg("ECX")]),
    ins("Cpuid"),
    ins("Test", [reg("EBX"), imm(0x20)])
  ]);

  assert.deepEqual(instructions[3]?.notes, undefined);
  assert.deepEqual(instructions[4]?.notes, undefined);
});

void test("emulateInstruction handles leaf 7 subleaf 0 feature checks", () => {
  const instructions = emulateInstructions([
    ins("Mov", [reg("EAX"), imm(7)]),
    ins("Xor", [reg("ECX"), reg("ECX")]),
    ins("Cpuid"),
    ins("Test", [reg("EBX"), imm(0x20)])
  ]);

  assert.deepEqual(instructions[3]?.notes, [
    "CPUID EBX feature check: AVX2 bit 5."
  ]);
});

void test("emulateInstruction handles CPUID bit-test feature checks", () => {
  const instructions = emulateInstructions([
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Cpuid"),
    ins("Bt", [reg("ECX"), imm(0x1c, "Immediate8")])
  ]);

  assert.deepEqual(instructions[2]?.notes, [
    "CPUID ECX feature check: AVX bit 28."
  ]);
});

void test("emulateInstruction handles CPUID bit-test boundary bit 31", () => {
  const instructions = emulateInstructions([
    ins("Mov", [reg("EAX"), imm(7)]),
    ins("Xor", [reg("ECX"), reg("ECX")]),
    ins("Cpuid"),
    ins("Bt", [reg("EBX"), imm(0x1f, "Immediate8")])
  ]);

  assert.deepEqual(instructions[3]?.notes, [
    "CPUID EBX feature check: AVX512VL bit 31."
  ]);
});

void test("emulateInstruction does not annotate partial CPUID registers", () => {
  const instructions = emulateInstructions([
    ins("Mov", [reg("EAX"), imm(1)]),
    ins("Cpuid"),
    ins("Test", [reg("CH"), imm(1, "Immediate8")])
  ]);

  assert.deepEqual(instructions[2]?.notes, undefined);
});

void test("emulateInstruction computes basic integer operations", () => {
  const { state } = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(7)]),
    ins("Sub", [reg("EAX"), imm(2, "Immediate8to32")]),
    ins("Add", [reg("EAX"), imm(1, "Immediate8to32")]),
    ins("Or", [reg("EAX"), imm(8, "Immediate8to32")]),
    ins("And", [reg("EAX"), imm(0x0d, "Immediate8to32")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x0cn,
    bits: 64
  });
});

void test("emulateInstruction computes concrete xor operations", () => {
  const { state } = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0xf0)]),
    ins("Xor", [reg("EAX"), imm(0x33, "Immediate8to32")])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0xc3n,
    bits: 64
  });
});

void test("emulateInstruction uses known byte writes for TEST flags", () => {
  const { state } = emulateInstructionsWithState([
    ins("Mov", [reg("BL"), imm(1, "Immediate8")]),
    ins("Test", [reg("BL"), reg("BL")])
  ], 32);

  assert.equal(state.flags.ZF, false);
});

void test("emulateInstruction executes lea through the operand layer", () => {
  const { state } = emulateInstructionsWithState([
    ins("Mov", [reg("RBX"), imm(0x1000)]),
    ins("Mov", [reg("RCX"), imm(3)]),
    ins("Lea", [reg("RAX"), mem("UInt64", "RBX", 0x10n, "RCX", 4)])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x101cn,
    bits: 64
  });
});

void test("emulateInstruction resolves RIP-relative lea addresses", () => {
  const { state } = emulateInstructionsWithState([
    ins("Lea", [reg("RAX"), mem("UInt64", "RIP", 0x14000223bn)])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x14000223bn,
    bits: 64
  });
});

void test("emulateInstruction keeps CPUID leaf 0xffffffff concrete", () => {
  const { state } = emulateInstructionsWithState([
    ins("Mov", [reg("EAX"), imm(0xffffffff)]),
    ins("Cpuid")
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "cpuid-output",
    leaf: 0xffffffff,
    register: "EAX"
  });
});

void test("emulateInstruction clears CPUID outputs when the leaf is unknown", () => {
  const { state } = emulateInstructionsWithState([
    ins("Mov", [reg("AX"), imm(1, "Immediate16")]),
    ins("Cpuid")
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "unknown" });
  assert.deepEqual(state.registers.get("RCX"), { kind: "unknown" });
});

void test("emulateInstruction reads and writes stack memory operands", () => {
  const { state } = emulateInstructionsWithState([
    ins("Mov", [reg("EBX"), imm(5)]),
    ins("Mov", [mem("UInt64", "RSP", 0x10n), reg("RBX")]),
    ins("Mov", [reg("RAX"), mem("UInt64", "RSP", 0x10n)])
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 5n,
    bits: 64
  });
});
