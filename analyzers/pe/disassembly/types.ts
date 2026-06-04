"use strict";

import type { PeDelayImportEntry } from "../imports/delay.js";
import type { PeImportParseResult } from "../imports/index.js";
import type { PeLoadConfig } from "../load-config/index.js";
import type { PeSection, RvaToOffset } from "../types.js";

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

export interface PeEntrypointInstruction {
  rva: number;
  fileOffset: number;
  text: string;
  notes?: string[];
  target?: PeEntrypointInstructionTarget;
}

export type PeEntrypointInstructionTarget =
  | {
      kind: "code";
      rva: number;
      followed: boolean;
      fallthroughRva?: number;
      fallthroughFollowed?: boolean;
      fallthroughKind?: "speculative-call-return";
    }
  | {
      kind: "branch";
      branchRva: number;
      branchFollowed: boolean;
      fallthroughRva: number;
      fallthroughFollowed: boolean;
    }
  | {
      kind: "import";
      label: string;
      slotRva: number;
      importKind: "eager" | "delay";
      guardIatEntry: boolean;
      returnRva?: number;
      returnFollowed?: boolean;
    };

export type PeEntrypointDisassemblyBlockKind =
  | "entrypoint"
  | "followed-call"
  | "followed-jump"
  | "followed-branch"
  | "followed-fallthrough"
  | "followed-import-return"
  | "speculative-call-fallthrough";

export interface PeEntrypointDisassemblyBlock {
  kind: PeEntrypointDisassemblyBlockKind;
  startRva: number;
  fileOffsetStart: number;
  sourceInstructionRva?: number;
  instructions: PeEntrypointInstruction[];
}

export interface PeEntrypointDisassemblyReport {
  bitness: 32 | 64;
  entrypointRva: number;
  bytesDecoded: number;
  instructionCount: number;
  blocks: PeEntrypointDisassemblyBlock[];
  issues: string[];
}

export interface AnalyzePeInstructionSetOptions {
  coffMachine: number;
  is64Bit: boolean;
  imageBase: bigint;
  headerRvaLimit?: number;
  entrypointRva: number;
  exportRvas?: number[];
  unwindBeginRvas?: number[];
  unwindHandlerRvas?: number[];
  guardCFFunctionRvas?: number[];
  safeSehHandlerRvas?: number[];
  tlsCallbackRvas?: number[];
  extraEntrypoints?: Array<{ source: string; rvas: number[] }>;
  rvaToOff: RvaToOffset;
  sections: PeSection[];
  yieldEveryInstructions?: number;
  signal?: AbortSignal;
  onProgress?: (progress: PeInstructionSetProgress) => void;
}

export interface AnalyzePeEntrypointDisassemblyOptions {
  coffMachine: number;
  is64Bit: boolean;
  imageBase: bigint;
  headerRvaLimit?: number;
  entrypointRva: number;
  imports?: PeImportParseResult;
  delayImports?: { entries: PeDelayImportEntry[] } | null;
  loadcfg?: PeLoadConfig | null;
  rvaToOff: RvaToOffset;
  sections: PeSection[];
}

export interface PeInstructionSetProgress {
  stage: "loading" | "decoding" | "done";
  bytesSampled: number;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  knownFeatureCounts?: Record<string, number>;
}
