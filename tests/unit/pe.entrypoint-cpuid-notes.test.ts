"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import type { PeEntrypointInstruction } from "../../analyzers/pe/disassembly/index.js";
import {
  createCpuIdNoteState,
  updateCpuIdInstructionNotes
} from "../../analyzers/pe/disassembly/entrypoint-cpuid-notes.js";
import type {
  EntrypointIcedModule,
  IcedInstruction
} from "../../analyzers/pe/disassembly/entrypoint-iced.js";

const icedModule = iced as unknown as EntrypointIcedModule;

const decodeInstructions = (bytes: number[]): iced.Instruction[] => {
  const decoder = new iced.Decoder(32, new Uint8Array(bytes), iced.DecoderOptions.None);
  const instructions: iced.Instruction[] = [];
  while (decoder.canDecode) {
    const instruction = new iced.Instruction();
    decoder.decodeOut(instruction);
    instructions.push(instruction);
  }
  decoder.free();
  return instructions;
};

const collectNotesFromBytes = (
  bytes: number[],
  module: EntrypointIcedModule = icedModule
): PeEntrypointInstruction[] => {
  const state = createCpuIdNoteState();
  const decoded = decodeInstructions(bytes);
  try {
    return decoded.map((instruction, index) => {
      const rendered: PeEntrypointInstruction = { rva: 0x1000 + index, fileOffset: index, text: "" };
      updateCpuIdInstructionNotes(module, instruction, rendered, state);
      return rendered;
    });
  } finally {
    for (const instruction of decoded) instruction.free();
  }
};

const fakeFeatureInstruction = (
  mnemonic: number,
  register: number,
  value: bigint
): IcedInstruction => ({
  mnemonic,
  opCount: 1,
  opKind: () => iced.OpKind.Immediate64,
  opRegister: () => register,
  immediate: () => value
} as unknown as IcedInstruction);

void test("updateCpuIdInstructionNotes marks CPUID vendor signature chunks", () => {
  // Intel SDM CPUID leaf 0 returns GenuineIntel chunks in EBX, EDX, ECX.
  // AMD CPUID publication 25481 documents AuthenticAMD in the same registers.
  const instructions = collectNotesFromBytes([
    0x81, 0xfb, 0x47, 0x65, 0x6e, 0x75,
    0x81, 0xfb, 0x69, 0x6e, 0x65, 0x49,
    0x81, 0xfb, 0x6e, 0x74, 0x65, 0x6c,
    0x81, 0xfb, 0x41, 0x75, 0x74, 0x68,
    0x81, 0xfb, 0x65, 0x6e, 0x74, 0x69,
    0x81, 0xfb, 0x63, 0x41, 0x4d, 0x44
  ]);

  assert.deepEqual(instructions.map(instruction => instruction.notes?.[0]), [
    "CPUID vendor string chunk 'Genu' (GenuineIntel).",
    "CPUID vendor string chunk 'ineI' (GenuineIntel).",
    "CPUID vendor string chunk 'ntel' (GenuineIntel).",
    "CPUID vendor string chunk 'Auth' (AuthenticAMD).",
    "CPUID vendor string chunk 'enti' (AuthenticAMD).",
    "CPUID vendor string chunk 'cAMD' (AuthenticAMD)."
  ]);
});

void test("updateCpuIdInstructionNotes keeps vendor notes when iced enums are absent", () => {
  const moduleWithoutEnums = {
    ...icedModule,
    Mnemonic: undefined,
    Register: undefined
  } as unknown as EntrypointIcedModule;

  assert.deepEqual(
    collectNotesFromBytes([0x81, 0xfb, 0x47, 0x65, 0x6e, 0x75], moduleWithoutEnums)[0]?.notes,
    ["CPUID vendor string chunk 'Genu' (GenuineIntel)."]
  );
  assert.equal(
    collectNotesFromBytes([0xb8, 0x01, 0, 0, 0, 0x0f, 0xa2], moduleWithoutEnums)[0]?.notes,
    undefined
  );
});

void test("updateCpuIdInstructionNotes marks documented CPUID leaf setup values", () => {
  assert.deepEqual(collectNotesFromBytes([0xb8, 0, 0, 0, 0, 0x0f, 0xa2])[0]?.notes, [
    "CPUID leaf 0: highest basic leaf and vendor identification string."
  ]);
  assert.deepEqual(collectNotesFromBytes([0xb8, 0, 0, 0, 0x40, 0x0f, 0xa2])[0]?.notes, [
    "CPUID hypervisor leaf 0x40000000: hypervisor vendor/interface range."
  ]);
  assert.deepEqual(collectNotesFromBytes([0xb8, 0, 0, 0, 0x80, 0x0f, 0xa2])[0]?.notes, [
    "CPUID extended leaf 0x80000000: highest extended leaf."
  ]);
  assert.deepEqual(collectNotesFromBytes([0xb8, 1, 0, 0, 0x80, 0x0f, 0xa2])[0]?.notes, [
    "CPUID extended leaf 0x80000001: extended signature and feature flags."
  ]);
});

void test("updateCpuIdInstructionNotes marks all documented leaf 1 feature labels", () => {
  const instructions = collectNotesFromBytes([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0xa2,
    // Mask 0x7ed81203 covers the leaf 1 ECX features listed in this module.
    0xf7, 0xc1, 0x03, 0x12, 0xd8, 0x7e,
    // Mask 0x07808000 covers the leaf 1 EDX features listed in this module.
    0xf7, 0xc2, 0x00, 0x80, 0x80, 0x07
  ]);

  assert.deepEqual(instructions[0]?.notes, [
    "CPUID leaf 1: processor signature and basic feature flags."
  ]);
  assert.deepEqual(instructions[2]?.notes, [
    "CPUID ECX feature check: SSE3 bit 0, PCLMULQDQ bit 1, SSSE3 bit 9, " +
      "FMA bit 12, SSE4.1 bit 19, SSE4.2 bit 20, MOVBE bit 22, POPCNT bit 23, " +
      "AESNI bit 25, XSAVE bit 26, OSXSAVE bit 27, AVX bit 28, F16C bit 29, " +
      "RDRAND bit 30."
  ]);
  assert.deepEqual(instructions[3]?.notes, [
    "CPUID EDX feature check: CMOV bit 15, MMX bit 23, FXSR bit 24, " +
      "SSE bit 25, SSE2 bit 26."
  ]);
});

void test("updateCpuIdInstructionNotes marks CPUID feature checks in and instructions", () => {
  // Leaf 1 EDX bits 25 and 26 are SSE and SSE2 in Intel SDM CPUID feature flags.
  const instructions = collectNotesFromBytes([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0xa2,
    0x81, 0xe2, 0x00, 0x00, 0x00, 0x06
  ]);

  assert.deepEqual(instructions[2]?.notes, [
    "CPUID EDX feature check: SSE bit 25, SSE2 bit 26."
  ]);
});

void test("updateCpuIdInstructionNotes marks CPUID feature checks in bt instructions", () => {
  // Leaf 1 ECX bit 28 is AVX in Intel SDM CPUID feature flags.
  const instructions = collectNotesFromBytes([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0xa2,
    0x0f, 0xba, 0xe1, 0x1c
  ]);

  assert.deepEqual(instructions[2]?.notes, [
    "CPUID ECX feature check: AVX bit 28."
  ]);
});

void test("updateCpuIdInstructionNotes marks all documented leaf 7 subleaf 0 feature labels", () => {
  const instructions = collectNotesFromBytes([
    0xb8, 0x07, 0x00, 0x00, 0x00,
    0x31, 0xc9,
    0x0f, 0xa2,
    // Mask 0xd00f0328 covers the leaf 7 subleaf 0 EBX features listed here.
    0xf7, 0xc3, 0x28, 0x03, 0x0f, 0xd0
  ]);

  assert.deepEqual(instructions[3]?.notes, [
    "CPUID EBX feature check: BMI1 bit 3, AVX2 bit 5, BMI2 bit 8, ERMS bit 9, " +
      "AVX512F bit 16, AVX512DQ bit 17, RDSEED bit 18, ADX bit 19, " +
      "AVX512CD bit 28, AVX512BW bit 30, AVX512VL bit 31."
  ]);
});

void test("updateCpuIdInstructionNotes marks CPUID leaf 7 subleaf 0 feature masks", () => {
  // Leaf 7 subleaf 0 EBX bit 5 is AVX2 in Intel SDM structured feature flags.
  const instructions = collectNotesFromBytes([
    0xb8, 0x07, 0x00, 0x00, 0x00,
    0x31, 0xc9,
    0x0f, 0xa2,
    0xf7, 0xc3, 0x20, 0x00, 0x00, 0x00
  ]);

  assert.deepEqual(instructions[0]?.notes, [
    "CPUID leaf 7: structured extended feature flags."
  ]);
  assert.deepEqual(instructions[3]?.notes, [
    "CPUID EBX feature check: AVX2 bit 5."
  ]);
});

void test("updateCpuIdInstructionNotes accepts explicit mov ecx subleaf setup", () => {
  const instructions = collectNotesFromBytes([
    0xb8, 0x07, 0x00, 0x00, 0x00,
    0xb9, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0xa2,
    0xf7, 0xc3, 0x20, 0x00, 0x00, 0x00
  ]);

  assert.deepEqual(instructions[3]?.notes, [
    "CPUID EBX feature check: AVX2 bit 5."
  ]);
});

void test("updateCpuIdInstructionNotes treats 0xffffffff as a valid 32-bit feature mask", () => {
  const state = createCpuIdNoteState();
  const rendered: PeEntrypointInstruction = { rva: 0x1000, fileOffset: 0, text: "" };
  state.activeQuery = { leaf: 1 };

  updateCpuIdInstructionNotes(
    icedModule,
    fakeFeatureInstruction(iced.Mnemonic.Test, iced.Register.ECX, 0xffffffffn),
    rendered,
    state
  );

  assert.match(rendered.notes?.[0] ?? "", /SSE3 bit 0/);
  assert.match(rendered.notes?.[0] ?? "", /RDRAND bit 30/);
});

void test("updateCpuIdInstructionNotes ignores feature masks wider than 32 bits", () => {
  const state = createCpuIdNoteState();
  const rendered: PeEntrypointInstruction = { rva: 0x1000, fileOffset: 0, text: "" };
  state.activeQuery = { leaf: 1 };

  updateCpuIdInstructionNotes(
    icedModule,
    fakeFeatureInstruction(iced.Mnemonic.Test, iced.Register.ECX, 0x1_18000000n),
    rendered,
    state
  );

  assert.equal(rendered.notes, undefined);
});

void test("updateCpuIdInstructionNotes marks bit 31 feature checks", () => {
  const state = createCpuIdNoteState();
  const rendered: PeEntrypointInstruction = { rva: 0x1000, fileOffset: 0, text: "" };
  state.activeQuery = { leaf: 7, subleaf: 0 };

  updateCpuIdInstructionNotes(
    icedModule,
    fakeFeatureInstruction(iced.Mnemonic.Bt, iced.Register.EBX, 31n),
    rendered,
    state
  );

  assert.deepEqual(rendered.notes, ["CPUID EBX feature check: AVX512VL bit 31."]);
});

void test("updateCpuIdInstructionNotes does not assume CPUID leaf 7 subleaf", () => {
  const instructions = collectNotesFromBytes([
    0xb8, 0x07, 0x00, 0x00, 0x00,
    0x0f, 0xa2,
    0xf7, 0xc3, 0x20, 0x00, 0x00, 0x00
  ]);

  assert.deepEqual(instructions[0]?.notes, [
    "CPUID leaf 7: structured extended feature flags."
  ]);
  assert.equal(instructions[2]?.notes, undefined);
});

void test("updateCpuIdInstructionNotes does not treat ecx setup as a CPUID leaf", () => {
  const instructions = collectNotesFromBytes([
    0xb9, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0xa2
  ]);

  assert.equal(instructions[0]?.notes, undefined);
});

void test("updateCpuIdInstructionNotes resets active query on untracked CPUID", () => {
  const instructions = collectNotesFromBytes([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0xa2,
    0x0f, 0xa2,
    0xf7, 0xc1, 0x00, 0x00, 0x00, 0x18
  ]);

  assert.equal(instructions[3]?.notes, undefined);
});

void test("updateCpuIdInstructionNotes does not mark feature masks without active CPUID context", () => {
  assert.equal(
    collectNotesFromBytes([0xf7, 0xc1, 0x00, 0x00, 0x00, 0x18])[0]?.notes,
    undefined
  );
});

void test("updateCpuIdInstructionNotes does not mark leaf constants without CPUID", () => {
  assert.equal(collectNotesFromBytes([0xb8, 0x01, 0x00, 0x00, 0x00])[0]?.notes, undefined);
});
