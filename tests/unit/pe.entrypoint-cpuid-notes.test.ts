"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import {
  collectCpuIdVendorChunkNotes,
  describeCpuIdFeatureBits,
  describeCpuIdLeaf
} from "../../analyzers/pe/disassembly/entrypoint/cpuid-notes.js";
import type { IcedModule } from "../../analyzers/pe/disassembly/entrypoint/iced.js";

const icedModule = iced as unknown as IcedModule;

const decodeOne = (bytes: number[]): iced.Instruction => {
  const decoder = new iced.Decoder(32, new Uint8Array(bytes), iced.DecoderOptions.None);
  const instruction = new iced.Instruction();
  decoder.decodeOut(instruction);
  decoder.free();
  return instruction;
};

void test("collectCpuIdVendorChunkNotes marks Intel and AMD vendor chunks", () => {
  // Intel SDM CPUID leaf 0 returns GenuineIntel chunks in EBX, EDX, ECX.
  // AMD CPUID publication 25481 documents AuthenticAMD in the same registers.
  const chunks = [
    [0x81, 0xfb, 0x47, 0x65, 0x6e, 0x75],
    [0x81, 0xfb, 0x69, 0x6e, 0x65, 0x49],
    [0x81, 0xfb, 0x6e, 0x74, 0x65, 0x6c],
    [0x81, 0xfb, 0x41, 0x75, 0x74, 0x68],
    [0x81, 0xfb, 0x65, 0x6e, 0x74, 0x69],
    [0x81, 0xfb, 0x63, 0x41, 0x4d, 0x44]
  ];
  const instructions = chunks.map(decodeOne);
  try {
    assert.deepEqual(instructions.flatMap(instruction =>
      collectCpuIdVendorChunkNotes(icedModule, instruction)
    ), [
      "CPUID vendor string chunk 'Genu' (GenuineIntel).",
      "CPUID vendor string chunk 'ineI' (GenuineIntel).",
      "CPUID vendor string chunk 'ntel' (GenuineIntel).",
      "CPUID vendor string chunk 'Auth' (AuthenticAMD).",
      "CPUID vendor string chunk 'enti' (AuthenticAMD).",
      "CPUID vendor string chunk 'cAMD' (AuthenticAMD)."
    ]);
  } finally {
    for (const instruction of instructions) instruction.free();
  }
});
void test("describeCpuIdLeaf returns documented CPUID leaf notes", () => {
  assert.equal(describeCpuIdLeaf(0), "CPUID leaf 0: highest basic leaf and vendor identification string.");
  assert.equal(describeCpuIdLeaf(1), "CPUID leaf 1: processor signature and basic feature flags.");
  assert.equal(describeCpuIdLeaf(7), "CPUID leaf 7: structured extended feature flags.");
  assert.equal(describeCpuIdLeaf(0x40000000), "CPUID hypervisor leaf 0x40000000: hypervisor vendor/interface range.");
  assert.equal(describeCpuIdLeaf(0x80000000), "CPUID extended leaf 0x80000000: highest extended leaf.");
  assert.equal(describeCpuIdLeaf(0x80000001), "CPUID extended leaf 0x80000001: extended signature and feature flags.");
  assert.equal(describeCpuIdLeaf(3), null);
});

void test("describeCpuIdFeatureBits describes documented feature masks", () => {
  assert.equal(
    describeCpuIdFeatureBits(1, undefined, "ECX", [0, 1, 9, 12, 19, 20, 22, 23, 25, 26, 27, 28, 29, 30]),
    "CPUID ECX feature check: SSE3 bit 0, PCLMULQDQ bit 1, SSSE3 bit 9, FMA bit 12, " +
    "SSE4.1 bit 19, SSE4.2 bit 20, MOVBE bit 22, POPCNT bit 23, AESNI bit 25, " +
    "XSAVE bit 26, OSXSAVE bit 27, AVX bit 28, F16C bit 29, RDRAND bit 30."
  );
  assert.equal(
    describeCpuIdFeatureBits(1, undefined, "EDX", [15, 23, 24, 25, 26]),
    "CPUID EDX feature check: CMOV bit 15, MMX bit 23, FXSR bit 24, SSE bit 25, SSE2 bit 26."
  );
  assert.equal(
    describeCpuIdFeatureBits(1, undefined, "ECX", [27, 28]),
    "CPUID ECX feature check: OSXSAVE bit 27, AVX bit 28."
  );
  assert.equal(
    describeCpuIdFeatureBits(7, 0, "EBX", [3, 5, 8, 9, 16, 17, 18, 19, 28, 30, 31]),
    "CPUID EBX feature check: BMI1 bit 3, AVX2 bit 5, BMI2 bit 8, ERMS bit 9, " +
    "AVX512F bit 16, AVX512DQ bit 17, RDSEED bit 18, ADX bit 19, AVX512CD bit 28, " +
    "AVX512BW bit 30, AVX512VL bit 31."
  );
  assert.equal(describeCpuIdFeatureBits(7, undefined, "EBX", [5]), null);
});
