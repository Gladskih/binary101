"use strict";

import type { PeEntrypointInstruction } from "./types.js";
import type { EntrypointIcedModule, IcedInstruction } from "./entrypoint-iced.js";
import { collectImmediateOperands } from "./entrypoint-immediate-operands.js";

type CpuIdQuery = {
  leaf: number;
  subleaf?: number;
  leafInstruction: PeEntrypointInstruction;
};

export type CpuIdNoteState = {
  pendingQuery: CpuIdQuery | null;
  activeQuery: Pick<CpuIdQuery, "leaf" | "subleaf"> | null;
};

type CpuIdFeature = {
  register: "EAX" | "EBX" | "ECX" | "EDX";
  bit: number;
  label: string;
};

type CpuIdVendorChunk = {
  value: bigint;
  label: string;
};

type CpuIdEnumModule = EntrypointIcedModule & {
  Mnemonic: Record<string, number> & Record<number, string | undefined>;
  Register: Record<string, number> & Record<number, string | undefined>;
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

export const createCpuIdNoteState = (): CpuIdNoteState => ({
  pendingQuery: null,
  activeQuery: null
});

const appendNote = (instruction: PeEntrypointInstruction, note: string): void => {
  instruction.notes = [...(instruction.notes ?? []), note];
};

const appendNotes = (instruction: PeEntrypointInstruction, notes: string[]): void => {
  if (notes.length) instruction.notes = [...(instruction.notes ?? []), ...notes];
};

const isRegister = (
  iced: CpuIdEnumModule,
  register: number,
  names: readonly string[]
): boolean => names.some(name => register === iced.Register[name]);

const hasCpuIdEnums = (iced: EntrypointIcedModule): iced is CpuIdEnumModule =>
  iced.Mnemonic != null && iced.Register != null;

const isCpuidInstruction = (iced: CpuIdEnumModule, instruction: IcedInstruction): boolean =>
  instruction.mnemonic === iced.Mnemonic["Cpuid"];

const isWriteAccess = (iced: CpuIdEnumModule, access: number): boolean =>
  access === iced.OpAccess?.["Write"] ||
  access === iced.OpAccess?.["CondWrite"] ||
  access === iced.OpAccess?.["ReadWrite"] ||
  access === iced.OpAccess?.["ReadCondWrite"];

const writesFirstOperandRegister = (
  iced: CpuIdEnumModule,
  instruction: IcedInstruction,
  registerNames: readonly string[]
): boolean => {
  if (!iced.OpAccess || !iced.InstructionInfoFactory) return false;
  const factory = new iced.InstructionInfoFactory();
  const info = factory.info(instruction);
  try {
    return isWriteAccess(iced, info.op0Access) &&
      isRegister(iced, instruction.opRegister(0), registerNames);
  } finally {
    info.free();
    factory.free();
  }
};

const singleImmediate = (
  iced: EntrypointIcedModule,
  instruction: IcedInstruction
): bigint | null => collectImmediateOperands(iced, instruction)[0]?.value ?? null;

const readsLeafRegisterValue = (
  iced: CpuIdEnumModule,
  instruction: IcedInstruction
): number | null => {
  if (readsZeroedRegister(iced, instruction, ["EAX", "RAX"])) return 0;
  if (instruction.mnemonic !== iced.Mnemonic["Mov"]) return null;
  if (!isRegister(iced, instruction.opRegister(0), ["EAX", "RAX"])) return null;
  const value = singleImmediate(iced, instruction);
  return value == null || value > 0xffffffffn ? null : Number(value);
};

const readsZeroedRegister = (
  iced: CpuIdEnumModule,
  instruction: IcedInstruction,
  registerNames: readonly string[]
): boolean =>
  instruction.mnemonic === iced.Mnemonic["Xor"] &&
  isRegister(iced, instruction.opRegister(0), registerNames) &&
  instruction.opRegister(0) === instruction.opRegister(1);

const readsSubleafRegisterImmediate = (
  iced: CpuIdEnumModule,
  instruction: IcedInstruction
): number | null => {
  if (readsZeroedRegister(iced, instruction, ["ECX", "RCX"])) return 0;
  if (instruction.mnemonic !== iced.Mnemonic["Mov"]) return null;
  if (!isRegister(iced, instruction.opRegister(0), ["ECX", "RCX"])) return null;
  const value = singleImmediate(iced, instruction);
  return value == null || value > 0xffffffffn ? null : Number(value);
};

const collectVendorChunkNotes = (
  iced: EntrypointIcedModule,
  instruction: IcedInstruction
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

const outputRegisterName = (
  iced: CpuIdEnumModule,
  instruction: IcedInstruction
): CpuIdFeature["register"] | null => {
  const register = instruction.opRegister(0);
  if (isRegister(iced, register, ["EAX", "RAX"])) return "EAX";
  if (isRegister(iced, register, ["EBX", "RBX"])) return "EBX";
  if (isRegister(iced, register, ["ECX", "RCX"])) return "ECX";
  if (isRegister(iced, register, ["EDX", "RDX"])) return "EDX";
  return null;
};

const featuresForQuery = (
  query: Pick<CpuIdQuery, "leaf" | "subleaf">
): readonly CpuIdFeature[] => {
  if (query.leaf === 1) return CPUID_LEAF_1_FEATURES;
  if (query.leaf === 7 && query.subleaf === 0) return CPUID_LEAF_7_SUBLEAF_0_FEATURES;
  return [];
};

const describeFeatureBits = (
  register: CpuIdFeature["register"],
  features: readonly CpuIdFeature[],
  bits: readonly number[]
): string | null => {
  const labels = bits.flatMap(bit =>
    features
      .filter(feature => feature.register === register && feature.bit === bit)
      .map(feature => `${feature.label} bit ${bit}`)
  );
  return labels.length ? `CPUID ${register} feature check: ${labels.join(", ")}.` : null;
};

const collectFeatureMaskNotes = (
  iced: CpuIdEnumModule,
  instruction: IcedInstruction,
  query: Pick<CpuIdQuery, "leaf" | "subleaf">
): string[] => {
  if (instruction.mnemonic !== iced.Mnemonic["Test"] && instruction.mnemonic !== iced.Mnemonic["And"]) {
    return [];
  }
  const register = outputRegisterName(iced, instruction);
  const value = singleImmediate(iced, instruction);
  if (!register || value == null || value > 0xffffffffn) return [];
  const bits = featuresForQuery(query)
    .filter(feature => feature.register === register && (value & (1n << BigInt(feature.bit))) !== 0n)
    .map(feature => feature.bit);
  const note = describeFeatureBits(register, featuresForQuery(query), bits);
  return note ? [note] : [];
};

const collectFeatureBitIndexNotes = (
  iced: CpuIdEnumModule,
  instruction: IcedInstruction,
  query: Pick<CpuIdQuery, "leaf" | "subleaf">
): string[] => {
  if (instruction.mnemonic !== iced.Mnemonic["Bt"]) return [];
  const register = outputRegisterName(iced, instruction);
  const value = singleImmediate(iced, instruction);
  if (!register || value == null || value > 31n) return [];
  const note = describeFeatureBits(register, featuresForQuery(query), [Number(value)]);
  return note ? [note] : [];
};

export const updateCpuIdInstructionNotes = (
  iced: EntrypointIcedModule,
  decoded: IcedInstruction,
  instruction: PeEntrypointInstruction,
  state: CpuIdNoteState
): void => {
  appendNotes(instruction, collectVendorChunkNotes(iced, decoded));
  if (!hasCpuIdEnums(iced)) return;
  if (isCpuidInstruction(iced, decoded)) {
    if (state.pendingQuery) {
      const description = CPUID_LEAF_DESCRIPTIONS.get(state.pendingQuery.leaf);
      if (description) appendNote(state.pendingQuery.leafInstruction, description);
      state.activeQuery = {
        leaf: state.pendingQuery.leaf,
        ...(state.pendingQuery.subleaf != null ? { subleaf: state.pendingQuery.subleaf } : {})
      };
    } else {
      state.activeQuery = null;
    }
    state.pendingQuery = null;
    return;
  }
  const leaf = readsLeafRegisterValue(iced, decoded);
  if (leaf != null) {
    state.pendingQuery = { leaf, leafInstruction: instruction };
  } else if (state.pendingQuery && writesFirstOperandRegister(iced, decoded, ["EAX", "RAX"])) {
    state.pendingQuery = null;
  }
  const subleaf = state.pendingQuery ? readsSubleafRegisterImmediate(iced, decoded) : null;
  if (state.pendingQuery && subleaf != null) {
    state.pendingQuery = { ...state.pendingQuery, subleaf };
  } else if (
    state.pendingQuery?.subleaf != null &&
    writesFirstOperandRegister(iced, decoded, ["ECX", "RCX"])
  ) {
    state.pendingQuery = {
      leaf: state.pendingQuery.leaf,
      leafInstruction: state.pendingQuery.leafInstruction
    };
  }
  if (!state.activeQuery) return;
  appendNotes(instruction, collectFeatureMaskNotes(iced, decoded, state.activeQuery));
  appendNotes(instruction, collectFeatureBitIndexNotes(iced, decoded, state.activeQuery));
};
