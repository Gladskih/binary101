"use strict";

import type { Amd64UnwindV3Statistics } from "./amd64/unwind-v3-types.js";
import type { ArmntPackedStatistics } from "./armnt-packed-types.js";

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
  epilogUnwindInfoCount?: number;
  epilogScopeCount?: number;
  handlerUnwindInfoCount: number;
  chainedUnwindInfoCount: number;
  armntPacked?: ArmntPackedStatistics;
  fragmentEntryCount?: number;
  invalidEntryCount: number;
  issues: string[];
  format?: "amd64" | "arm64" | "armnt" | "ready-to-run-x86" | "native-aot-x86";
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
