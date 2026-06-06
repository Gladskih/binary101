"use strict";

import type { IcedModule, IcedInstructionObject } from "./iced.js";
import { collectImmediateOperands } from "./immediate-operands.js";

export type CpuIdOutputRegister = "EAX" | "EBX" | "ECX" | "EDX";

type CpuIdFeature = {
  register: CpuIdOutputRegister;
  bit: number;
  label: string;
};
type CpuIdVendorChunk = {
  value: bigint;
  label: string;
};

// CPUID leaves, vendor strings, and feature bit positions follow Intel SDM
// Vol. 2A "CPUID" and AMD CPUID Specification publication 25481.
// https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
// https://www.amd.com/content/dam/amd/en/documents/archived-tech-docs/design-guides/25481.pdf
const CPUID_VENDOR_CHUNKS: readonly CpuIdVendorChunk[] = [
  { value: 0x756e6547n, label: "CPUID vendor string chunk 'Genu' (GenuineIntel)." },
  { value: 0x49656e69n, label: "CPUID vendor string chunk 'ineI' (GenuineIntel)." },
  { value: 0x6c65746en, label: "CPUID vendor string chunk 'ntel' (GenuineIntel)." },
  { value: 0x68747541n, label: "CPUID vendor string chunk 'Auth' (AuthenticAMD)." },
  { value: 0x69746e65n, label: "CPUID vendor string chunk 'enti' (AuthenticAMD)." },
  { value: 0x444d4163n, label: "CPUID vendor string chunk 'cAMD' (AuthenticAMD)." }
];

const CPUID_LEAF_DESCRIPTIONS = new Map<number, string>([
  [0x00000000, "CPUID leaf 0: highest basic leaf and vendor identification string."],
  [0x00000001, "CPUID leaf 1: processor signature and basic feature flags."],
  [0x00000007, "CPUID leaf 7: structured extended feature flags."],
  [0x40000000, "CPUID hypervisor leaf 0x40000000: hypervisor vendor/interface range."],
  [0x80000000, "CPUID extended leaf 0x80000000: highest extended leaf."],
  [0x80000001, "CPUID extended leaf 0x80000001: extended signature and feature flags."]
]);

const CPUID_LEAF_1_FEATURES: readonly CpuIdFeature[] = [
  { register: "ECX", bit: 0, label: "SSE3" },
  { register: "ECX", bit: 1, label: "PCLMULQDQ" },
  { register: "ECX", bit: 9, label: "SSSE3" },
  { register: "ECX", bit: 12, label: "FMA" },
  { register: "ECX", bit: 19, label: "SSE4.1" },
  { register: "ECX", bit: 20, label: "SSE4.2" },
  { register: "ECX", bit: 22, label: "MOVBE" },
  { register: "ECX", bit: 23, label: "POPCNT" },
  { register: "ECX", bit: 25, label: "AESNI" },
  { register: "ECX", bit: 26, label: "XSAVE" },
  { register: "ECX", bit: 27, label: "OSXSAVE" },
  { register: "ECX", bit: 28, label: "AVX" },
  { register: "ECX", bit: 29, label: "F16C" },
  { register: "ECX", bit: 30, label: "RDRAND" },
  { register: "EDX", bit: 15, label: "CMOV" },
  { register: "EDX", bit: 23, label: "MMX" },
  { register: "EDX", bit: 24, label: "FXSR" },
  { register: "EDX", bit: 25, label: "SSE" },
  { register: "EDX", bit: 26, label: "SSE2" }
];

const CPUID_LEAF_7_SUBLEAF_0_FEATURES: readonly CpuIdFeature[] = [
  { register: "EBX", bit: 3, label: "BMI1" },
  { register: "EBX", bit: 5, label: "AVX2" },
  { register: "EBX", bit: 8, label: "BMI2" },
  { register: "EBX", bit: 9, label: "ERMS" },
  { register: "EBX", bit: 16, label: "AVX512F" },
  { register: "EBX", bit: 17, label: "AVX512DQ" },
  { register: "EBX", bit: 18, label: "RDSEED" },
  { register: "EBX", bit: 19, label: "ADX" },
  { register: "EBX", bit: 28, label: "AVX512CD" },
  { register: "EBX", bit: 30, label: "AVX512BW" },
  { register: "EBX", bit: 31, label: "AVX512VL" }
];

export const collectCpuIdVendorChunkNotes = (
  iced: IcedModule,
  instruction: IcedInstructionObject
): string[] => {
  const notes: string[] = [];
  const seenValues = new Set<bigint>();
  for (const { value } of collectImmediateOperands(iced, instruction)) {
    if (seenValues.has(value)) continue;
    const chunk = CPUID_VENDOR_CHUNKS.find(candidate => candidate.value === value);
    if (chunk) notes.push(chunk.label);
    seenValues.add(value);
  }
  return notes;
};

export const describeCpuIdLeaf = (leaf: number): string | null =>
  CPUID_LEAF_DESCRIPTIONS.get(leaf) ?? null;

const featuresForQuery = (
  leaf: number,
  subleaf: number | undefined
): readonly CpuIdFeature[] => {
  if (leaf === 1) return CPUID_LEAF_1_FEATURES;
  if (leaf === 7 && subleaf === 0) return CPUID_LEAF_7_SUBLEAF_0_FEATURES;
  return [];
};

export const describeCpuIdFeatureBits = (
  leaf: number,
  subleaf: number | undefined,
  register: CpuIdOutputRegister,
  bits: readonly number[]
): string | null => {
  const labels = bits.flatMap(bit =>
    featuresForQuery(leaf, subleaf)
      .filter(feature => feature.register === register && feature.bit === bit)
      .map(feature => `${feature.label} bit ${bit}`)
  );
  return labels.length ? `CPUID ${register} feature check: ${labels.join(", ")}.` : null;
};
