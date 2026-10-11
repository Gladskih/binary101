"use strict";

import type { X86SpecialInstructionFinding } from "../x86/special-instructions.js";
import type { ElfProgramHeader, ElfSectionHeader, ElfDynamicSymbolInfo } from "./types.js";
import type { ElfSymbolTable } from "./symbol-tables.js";
import type { ElfRelocationInfo } from "./relocation-types.js";
import type { CodeExclusion } from "../code-exclusions.js";
import type { NativeAotMetadata } from "../native-aot/format.js";
import type { FeatureRequirements } from "llvm-aarch64-disasm";
import type { Aarch64SpecialInstructionFinding } from "../aarch64/special-instructions.js";

export interface ElfInstructionSetUsage {
  aarch64Predicates?: FeatureRequirements["predicates"];
  id: string;
  label: string;
  description: string;
  instructionCount: number;
}

export interface ElfDisassemblySeedSourceStats {
  skippedData?: number;
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
  aarch64SpecialInstructions?: Aarch64SpecialInstructionFinding[];
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
  fileType?: number;
  dynSymbols?: ElfDynamicSymbolInfo;
  symbolTables?: ElfSymbolTable[];
  relocations?: ElfRelocationInfo;
  dataRanges?: readonly CodeExclusion[];
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

