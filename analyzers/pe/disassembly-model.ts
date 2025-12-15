"use strict";

import type { PeSection, RvaToOffset } from "./types.js";

export interface PeInstructionSetUsage {
  id: string;
  label: string;
  description: string;
  instructionCount: number;
}

export interface PeInstructionSetReport {
  bitness: 32 | 64;
  bytesSampled: number;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  instructionSets: PeInstructionSetUsage[];
  issues: string[];
}

export interface AnalyzePeInstructionSetOptions {
  coffMachine: number;
  is64Bit: boolean;
  imageBase: number;
  entrypointRva: number;
  exportRvas?: number[];
  unwindBeginRvas?: number[];
  unwindHandlerRvas?: number[];
  tlsCallbackRvas?: number[];
  rvaToOff: RvaToOffset;
  sections: PeSection[];
  yieldEveryInstructions?: number;
  signal?: AbortSignal;
  onProgress?: (progress: PeInstructionSetProgress) => void;
}

export interface PeInstructionSetProgress {
  stage: "loading" | "decoding" | "done";
  bytesSampled: number;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  knownFeatureCounts?: Record<string, number>;
}
