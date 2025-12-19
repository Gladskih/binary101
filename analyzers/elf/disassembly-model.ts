"use strict";

import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";

export interface ElfInstructionSetUsage {
  id: string;
  label: string;
  description: string;
  instructionCount: number;
}

export interface ElfInstructionSetReport {
  bitness: 32 | 64;
  bytesSampled: number;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  instructionSets: ElfInstructionSetUsage[];
  issues: string[];
}

export interface AnalyzeElfInstructionSetOptions {
  machine: number;
  is64Bit: boolean;
  littleEndian: boolean;
  entrypointVaddr: bigint;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  yieldEveryInstructions?: number;
  signal?: AbortSignal;
  onProgress?: (progress: ElfInstructionSetProgress) => void;
}

export interface ElfInstructionSetProgress {
  stage: "loading" | "decoding" | "done";
  bytesSampled: number;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  knownFeatureCounts?: Record<string, number>;
}

