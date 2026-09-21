"use strict";

import type { X86SpecialInstructionFinding } from "../x86/special-instructions.js";
import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import type { NativeAotMetadata } from "../native-aot/format.js";
import type { FeatureRequirements } from "llvm-aarch64-disasm";

export interface ElfInstructionSetUsage {
  aarch64Predicates?: FeatureRequirements["predicates"];
  id: string;
  label: string;
  description: string;
  instructionCount: number;
}

export interface ElfDisassemblySeedSourceStats {
  source: string;
  candidates: number;
  added: number;
  skippedZero: number;
  skippedNotExecutable: number;
  skippedDuplicate: number;
}

export interface ElfDisassemblySeedSummary {
  entrypointVaddr: bigint;
  uniqueEntrypoints: number;
  fallbackSource?: string | null;
  sources: ElfDisassemblySeedSourceStats[];
}

export interface ElfInstructionSetReport {
  specialInstructions?: X86SpecialInstructionFinding[];
  decoderVersion?: string;
  bitness: 32 | 64;
  bytesSampled: number;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  instructionSets: ElfInstructionSetUsage[];
  issues: string[];
  seedSummary?: ElfDisassemblySeedSummary;
}

export interface AnalyzeElfInstructionSetOptions {
  machine: number;
  is64Bit: boolean;
  littleEndian: boolean;
  entrypointVaddr: bigint;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  nativeAot?: NativeAotMetadata | null;
  yieldEveryInstructions?: number;
  signal?: AbortSignal;
  onProgress?: (progress: ElfInstructionSetProgress) => void;
}

export interface ElfInstructionSetProgress {
  aarch64InstructionSets?: ElfInstructionSetUsage[];
  stage: "loading" | "decoding" | "done";
  bytesSampled: number;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  knownFeatureCounts?: Record<string, number>;
}

