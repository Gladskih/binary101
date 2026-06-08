"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import type { PeEntrypointInstruction } from "../../analyzers/pe/disassembly/index.js";
import {
  createEmulationState,
  emulateInstruction,
  type EmulationState
} from "../../analyzers/pe/disassembly/entrypoint/emulation.js";
import type { IcedModule } from "../../analyzers/pe/disassembly/entrypoint/iced.js";

const icedModule = iced as unknown as IcedModule;

const emulateBytes = (bytes: number[], bitness: 32 | 64 = 64): PeEntrypointInstruction[] => {
  const decoder = new iced.Decoder(bitness, new Uint8Array(bytes), iced.DecoderOptions.None);
  const state = createEmulationState(bitness);
  const instructions: PeEntrypointInstruction[] = [];
  try {
    while (decoder.canDecode) {
      const decoded = new iced.Instruction();
      try {
        decoder.decodeOut(decoded);
        const rendered = { rva: instructions.length, fileOffset: instructions.length, text: "" };
        emulateInstruction(icedModule, decoded, rendered, state);
        instructions.push(rendered);
      } finally {
        decoded.free();
      }
    }
    return instructions;
  } finally {
    decoder.free();
  }
};

const emulateBytesWithState = (
  bytes: number[],
  bitness: 32 | 64 = 64
): { instructions: PeEntrypointInstruction[]; state: EmulationState } => {
  const decoder = new iced.Decoder(bitness, new Uint8Array(bytes), iced.DecoderOptions.None);
  const state = createEmulationState(bitness);
  const instructions: PeEntrypointInstruction[] = [];
  try {
    while (decoder.canDecode) {
      const decoded = new iced.Instruction();
      try {
        decoder.decodeOut(decoded);
        const rendered = { rva: instructions.length, fileOffset: instructions.length, text: "" };
        emulateInstruction(icedModule, decoded, rendered, state);
        instructions.push(rendered);
      } finally {
        decoded.free();
      }
    }
    return { instructions, state };
  } finally {
    decoder.free();
  }
};

void test("emulateInstruction follows the LLVM two-CPUID startup idiom", () => {
  const instructions = emulateBytes([
    0x31, 0xc0,
    0x31, 0xc9,
    0x0f, 0xa2,
    0x81, 0xf1, 0x6e, 0x74, 0x65, 0x6c,
    0x81, 0xf2, 0x69, 0x6e, 0x65, 0x49,
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0x81, 0xf3, 0x47, 0x65, 0x6e, 0x75,
    0x8d, 0x48, 0xff,
    0x0f, 0xa2
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
  const instructions = emulateBytes([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0xa2,
    0x89, 0xcf,
    0xf7, 0xc7, 0x00, 0x00, 0x00, 0x18
  ]);

  assert.deepEqual(instructions[3]?.notes, [
    "CPUID ECX feature check: OSXSAVE bit 27, AVX bit 28."
  ]);
});

void test("emulateInstruction does not keep stale CPUID leaf setup", () => {
  const instructions = emulateBytes([
    0xb8, 0x07, 0x00, 0x00, 0x00,
    0x83, 0xc0, 0x01,
    0x31, 0xc9,
    0x0f, 0xa2,
    0xf7, 0xc3, 0x20, 0x00, 0x00, 0x00
  ]);

  assert.deepEqual(instructions[3]?.notes, undefined);
  assert.deepEqual(instructions[4]?.notes, undefined);
});

void test("emulateInstruction handles leaf 7 subleaf 0 feature checks", () => {
  const instructions = emulateBytes([
    0xb8, 0x07, 0x00, 0x00, 0x00,
    0x31, 0xc9,
    0x0f, 0xa2,
    0xf7, 0xc3, 0x20, 0x00, 0x00, 0x00
  ]);

  assert.deepEqual(instructions[3]?.notes, [
    "CPUID EBX feature check: AVX2 bit 5."
  ]);
});

void test("emulateInstruction handles CPUID bit-test feature checks", () => {
  const instructions = emulateBytes([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0xa2,
    0x0f, 0xba, 0xe1, 0x1c
  ]);

  assert.deepEqual(instructions[2]?.notes, [
    "CPUID ECX feature check: AVX bit 28."
  ]);
});

void test("emulateInstruction handles CPUID bit-test boundary bit 31", () => {
  const instructions = emulateBytes([
    0xb8, 0x07, 0x00, 0x00, 0x00,
    0x31, 0xc9,
    0x0f, 0xa2,
    0x0f, 0xba, 0xe3, 0x1f
  ]);

  assert.deepEqual(instructions[3]?.notes, [
    "CPUID EBX feature check: AVX512VL bit 31."
  ]);
});

void test("emulateInstruction does not annotate partial CPUID registers", () => {
  const instructions = emulateBytes([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0xa2,
    0xf6, 0xc5, 0x01
  ]);

  assert.deepEqual(instructions[2]?.notes, undefined);
});

void test("emulateInstruction computes basic integer operations", () => {
  const { state } = emulateBytesWithState([
    0xb8, 0x07, 0x00, 0x00, 0x00,
    0x83, 0xe8, 0x02,
    0x83, 0xc0, 0x01,
    0x83, 0xc8, 0x08,
    0x83, 0xe0, 0x0d
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x0cn,
    bits: 64
  });
});

void test("emulateInstruction computes concrete xor operations", () => {
  const { state } = emulateBytesWithState([
    0xb8, 0xf0, 0x00, 0x00, 0x00,
    0x83, 0xf0, 0x33
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0xc3n,
    bits: 64
  });
});

void test("emulateInstruction executes lea through the operand layer", () => {
  const { state } = emulateBytesWithState([
    0x48, 0xc7, 0xc3, 0x00, 0x10, 0x00, 0x00,
    0x48, 0xc7, 0xc1, 0x03, 0x00, 0x00, 0x00,
    0x48, 0x8d, 0x44, 0x8b, 0x10
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x101cn,
    bits: 64
  });
});

void test("emulateInstruction keeps CPUID leaf 0xffffffff concrete", () => {
  const { state } = emulateBytesWithState([
    0xb8, 0xff, 0xff, 0xff, 0xff,
    0x0f, 0xa2
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "cpuid-output",
    leaf: 0xffffffff,
    register: "EAX"
  });
});

void test("emulateInstruction clears CPUID outputs when the leaf is unknown", () => {
  const { state } = emulateBytesWithState([
    0x66, 0xb8, 0x01, 0x00,
    0x0f, 0xa2
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "unknown" });
  assert.deepEqual(state.registers.get("RCX"), { kind: "unknown" });
});

void test("emulateInstruction reads and writes stack memory operands", () => {
  const { state } = emulateBytesWithState([
    0xbb, 0x05, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x5c, 0x24, 0x10,
    0x48, 0x8b, 0x44, 0x24, 0x10
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 5n,
    bits: 64
  });
});
