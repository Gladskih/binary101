"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type { RvaToOffset } from "../../types.js";
import { AMD64_RUNTIME_FUNCTION_ENTRY_SIZE } from "./directory.js";
import { collectRuntimeFunctionSpans, readRuntimeFunctionSpan } from "../runtime-spans.js";

const TRUNCATED_RUNTIME_FUNCTION_ISSUE =
  "Exception directory is truncated; some RUNTIME_FUNCTION entries are missing.";

export interface Amd64RuntimeFunctionTable {
  beginRvas: number[];
  functionCount: number;
  invalidEntryCount: number;
  unwindRvas: Set<number>;
}

const hasInvalidMappedRva = (
  rva: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): boolean => {
  const fileOffset = rvaToOff(rva);
  return fileOffset == null || fileOffset < 0 || fileOffset >= fileSize;
};

const isRuntimeFunctionEntryInvalid = (
  beginRva: number,
  endRva: number,
  unwindInfoRva: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): boolean => {
  if (!beginRva || !endRva || beginRva >= endRva) return true;
  if (hasInvalidMappedRva(beginRva, rvaToOff, fileSize)) return true;
  if (hasInvalidMappedRva((endRva - 1) >>> 0, rvaToOff, fileSize)) return true;
  return !!unwindInfoRva && hasInvalidMappedRva(unwindInfoRva, rvaToOff, fileSize);
};

const recordValidBeginRva = (
  beginRvas: number[],
  beginRva: number,
  previousBeginRva: number | null,
  issues: string[]
): { previousBeginRva: number; reportedUnsortedEntries: boolean } => {
  if (previousBeginRva != null && beginRva < previousBeginRva) {
    issues.push("RUNTIME_FUNCTION entries are not sorted by BeginAddress.");
    beginRvas.push(beginRva);
    return { previousBeginRva: beginRva, reportedUnsortedEntries: true };
  }
  beginRvas.push(beginRva);
  return { previousBeginRva: beginRva, reportedUnsortedEntries: false };
};

export const readAmd64RuntimeFunctions = async (
  reader: FileRangeReader,
  directoryRva: number,
  entryCount: number,
  rvaToOff: RvaToOffset,
  issues: string[]
): Promise<Amd64RuntimeFunctionTable> => {
  const beginRvas: number[] = [];
  const unwindRvas = new Set<number>();
  let functionCount = 0;
  let invalidEntryCount = 0;
  let previousBeginRva: number | null = null;
  let reportedUnsortedEntries = false;
  const spans = collectRuntimeFunctionSpans(
    directoryRva,
    entryCount,
    AMD64_RUNTIME_FUNCTION_ENTRY_SIZE,
    rvaToOff,
    reader.size,
    TRUNCATED_RUNTIME_FUNCTION_ISSUE,
    issues
  );
  for (const span of spans) {
    const spanView = await readRuntimeFunctionSpan(
      reader,
      span,
      AMD64_RUNTIME_FUNCTION_ENTRY_SIZE,
      TRUNCATED_RUNTIME_FUNCTION_ISSUE,
      issues
    );
    if (!spanView) break;
    const spanEntries = Math.floor(spanView.byteLength / AMD64_RUNTIME_FUNCTION_ENTRY_SIZE);
    for (let index = 0; index < spanEntries; index += 1) {
      const entryOffset = index * AMD64_RUNTIME_FUNCTION_ENTRY_SIZE;
      const beginRva = spanView.getUint32(entryOffset, true) >>> 0;
      const endRva = spanView.getUint32(entryOffset + 4, true) >>> 0;
      const unwindInfoRva = spanView.getUint32(entryOffset + 8, true) >>> 0;
      const invalid = isRuntimeFunctionEntryInvalid(
        beginRva,
        endRva,
        unwindInfoRva,
        rvaToOff,
        reader.size
      );
      functionCount += 1;
      if (unwindInfoRva) unwindRvas.add(unwindInfoRva);
      if (invalid) {
        invalidEntryCount += 1;
        continue;
      }
      if (reportedUnsortedEntries) {
        beginRvas.push(beginRva);
        previousBeginRva = beginRva;
        continue;
      }
      const recorded = recordValidBeginRva(beginRvas, beginRva, previousBeginRva, issues);
      previousBeginRva = recorded.previousBeginRva;
      reportedUnsortedEntries = recorded.reportedUnsortedEntries;
    }
  }
  return { beginRvas, functionCount, invalidEntryCount, unwindRvas };
};
