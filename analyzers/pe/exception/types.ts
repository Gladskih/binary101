"use strict";

export interface PeExceptionDirectory {
  functionCount: number;
  beginRvas: number[];
  handlerRvas: number[];
  uniqueUnwindInfoCount: number;
  handlerUnwindInfoCount: number;
  chainedUnwindInfoCount: number;
  invalidEntryCount: number;
  issues: string[];
  format?: "amd64" | "arm64";
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
