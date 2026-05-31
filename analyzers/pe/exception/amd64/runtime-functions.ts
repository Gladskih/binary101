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

const getMappedRvaIssue = (
  rva: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): string | null => {
  // Microsoft x64 exception handling stores RUNTIME_FUNCTION addresses as
  // image-relative offsets. If an RVA cannot map to bytes in this local file,
  // report the bad reference but do not use it as an UNWIND_INFO seed.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
  const fileOffset = rvaToOff(rva);
  if (fileOffset == null) return `RVA ${formatHex(rva)} does not map to file data`;
  if (fileOffset < 0 || fileOffset >= fileSize) {
    return `RVA ${formatHex(rva)} maps outside the file`;
  }
  return null;
};

const getRuntimeFunctionEntryIssue = (
  beginRva: number,
  endRva: number,
  unwindInfoRva: number,
  exceptionDirectoryRva: number,
  exceptionDirectorySize: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): string | null => {
  // Microsoft documents .pdata as sorted RUNTIME_FUNCTION records with
  // image-relative function start, function end, and unwind-info addresses.
  // Chained RUNTIME_FUNCTION records are trailing UNWIND_INFO payload, so the
  // top-level UnwindInfoAddress must not point back into this .pdata table.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-runtime_function
  if (beginRva >= endRva) {
    return "BeginAddress is greater than or equal to EndAddress";
  }
  const beginIssue = getMappedRvaIssue(beginRva, rvaToOff, fileSize);
  if (beginIssue) return `BeginAddress ${beginIssue}`;
  const endIssue = getMappedRvaIssue((endRva - 1) >>> 0, rvaToOff, fileSize);
  if (endIssue) return `EndAddress ${endIssue}`;
  // Leaf functions without unwind state are omitted from .pdata; once a
  // RUNTIME_FUNCTION record exists, the unwind-info address is required.
  if (!unwindInfoRva) return "UnwindInfoAddress is zero";
  if (
    unwindInfoRva >= exceptionDirectoryRva &&
    unwindInfoRva < exceptionDirectoryRva + exceptionDirectorySize
  ) return "UnwindInfoAddress points back into the RUNTIME_FUNCTION table";
  const unwindIssue = getMappedRvaIssue(unwindInfoRva, rvaToOff, fileSize);
  return unwindIssue ? `UnwindInfoAddress ${unwindIssue}` : null;
};

const formatHex = (value: number): string => `0x${(value >>> 0).toString(16)}`;

const addInvalidEntryIssue = (
  invalidEntryIssues: Map<string, number>,
  issue: string
): void => {
  invalidEntryIssues.set(issue, (invalidEntryIssues.get(issue) ?? 0) + 1);
};

const reportInvalidEntryIssues = (
  invalidEntryIssues: Map<string, number>,
  issues: string[]
): void => {
  for (const [issue, count] of invalidEntryIssues) {
    issues.push(
      `${count} RUNTIME_FUNCTION entr${count === 1 ? "y is" : "ies are"} invalid: ${issue}.`
    );
  }
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
  const invalidEntryIssues = new Map<string, number>();
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
      const invalidIssue = getRuntimeFunctionEntryIssue(
        beginRva,
        endRva,
        unwindInfoRva,
        directoryRva,
        entryCount * AMD64_RUNTIME_FUNCTION_ENTRY_SIZE,
        rvaToOff,
        reader.size
      );
      functionCount += 1;
      if (invalidIssue) {
        invalidEntryCount += 1;
        addInvalidEntryIssue(invalidEntryIssues, invalidIssue);
        continue;
      }
      if (unwindInfoRva) unwindRvas.add(unwindInfoRva);
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
  reportInvalidEntryIssues(invalidEntryIssues, issues);
  return { beginRvas, functionCount, invalidEntryCount, unwindRvas };
};
