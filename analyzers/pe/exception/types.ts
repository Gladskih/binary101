"use strict";

import type { Amd64UnwindV3Statistics } from "./amd64/unwind-v3-types.js";
import type { Amd64UnwindV12Statistics } from "./amd64/unwind-v12-types.js";
import type { ArmntPackedStatistics } from "./armnt-packed-types.js";
import type { ArmntOpcodeStatistics } from "./armnt-opcode-types.js";
import type { Arm64PackedStatistics } from "./arm64-packed-types.js";
import type { Arm64UnwindStatistics } from "./arm64-unwind-types.js";

export interface PeCeExceptionStatistics {
  instruction16Count: number;
  instruction32Count: number;
  extendedEntryCount: number;
  handlerDataCount: number;
  prologs?: { count: number; empty: number; minimumBytes: number; maximumBytes: number };
}

export interface PeIa64UnwindStatistics {
  versions: { version: number; count: number }[];
  descriptorCounts: Record<string, number>;
  exceptionHandlerCount: number;
  unwindHandlerCount: number;
  /** Largest P7 mem_stack_f allocation, not reconstructed peak stack usage. */
  maximumFixedStackBytes?: number;
}

export interface PeExceptionDirectory {
  functionCount: number;
  beginRvas: number[];
  /** Byte lengths of validated ranges; absent when the format has no known end. */
  rangeLengths?: number[];
  handlerRvas: number[];
  uniqueUnwindInfoCount: number;
  unwindInfoVersion1Count?: number;
  unwindInfoVersion2Count?: number;
  unwindInfoV3?: Amd64UnwindV3Statistics;
  unwindInfoV12?: Amd64UnwindV12Statistics;
  epilogUnwindInfoCount?: number;
  epilogScopeCount?: number;
  handlerUnwindInfoCount: number;
  chainedUnwindInfoCount: number;
  armntPacked?: ArmntPackedStatistics;
  armntOpcodes?: ArmntOpcodeStatistics;
  arm64Packed?: Arm64PackedStatistics;
  arm64Unwind?: Arm64UnwindStatistics;
  fragmentEntryCount?: number;
  invalidEntryCount: number;
  issues: string[];
  format?: "amd64" | "arm64" | "armnt" | "ready-to-run-x86" | "native-aot-x86" | "nt-risc32" | "nt-risc64" | "ce" | "ia64";
  riscPrologs?: { count: number; empty: number; minimumBytes: number; maximumBytes: number };
  riscExceptionModes?: number[];
  alphaPrologs?: { resolvedSecondaryRanges: number; unresolvedSecondaryRanges: number };
  ceCompressed?: PeCeExceptionStatistics;
  ia64Unwind?: PeIa64UnwindStatistics;
  exceptionInfoMethodCount?: number;
  exceptionClauseCount?: number;
  catchClauseCount?: number;
  filterClauseCount?: number;
  finallyClauseCount?: number;
  faultClauseCount?: number;
}

export const createEmptyExceptionDirectory = (
  issues: string[],
  format?: PeExceptionDirectory["format"]
): PeExceptionDirectory => ({
  functionCount: 0,
  beginRvas: [],
  handlerRvas: [],
  uniqueUnwindInfoCount: 0,
  handlerUnwindInfoCount: 0,
  chainedUnwindInfoCount: 0,
  invalidEntryCount: 0,
  issues,
  ...(format ? { format } : {})
});
