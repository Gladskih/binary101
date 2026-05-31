"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type { RvaToOffset } from "../../types.js";
import { AMD64_RUNTIME_FUNCTION_ENTRY_SIZE } from "./directory.js";
import { collectRuntimeFunctionSpans, readRuntimeFunctionSpan } from "../runtime-spans.js";

const TRUNCATED_RUNTIME_FUNCTION_ISSUE =
  "Exception directory is truncated; some RUNTIME_FUNCTION entries are missing.";
// Windows SDK winnt.h defines bit 0 of RUNTIME_FUNCTION.UnwindData as
// RUNTIME_FUNCTION_INDIRECT; dumpbin reports these entries as reusing unwind
// metadata from another RUNTIME_FUNCTION row.
// https://mingw.googlesource.com/mingw-w64/+/refs/tags/v11.0.1/mingw-w64-headers/include/winnt.h
const RUNTIME_FUNCTION_INDIRECT = 0x1;

type RuntimeFunctionEntryValidation = {
  issue: string | null;
  unwindInfoRva: number | null;
};

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

const isIndirectRuntimeFunction = (unwindDataRva: number): boolean =>
  (unwindDataRva & RUNTIME_FUNCTION_INDIRECT) !== 0;

const getIndirectRuntimeFunctionRva = (unwindDataRva: number): number =>
  (unwindDataRva & ~RUNTIME_FUNCTION_INDIRECT) >>> 0;

const getExceptionDirectoryIssue = (
  rva: number,
  exceptionDirectoryRva: number,
  exceptionDirectorySize: number
): string | null => {
  const endRva = rva + AMD64_RUNTIME_FUNCTION_ENTRY_SIZE;
  if (rva < exceptionDirectoryRva || endRva > exceptionDirectoryRva + exceptionDirectorySize) {
    return "points outside the RUNTIME_FUNCTION table";
  }
  if ((rva - exceptionDirectoryRva) % AMD64_RUNTIME_FUNCTION_ENTRY_SIZE !== 0) {
    return "does not point to the start of a RUNTIME_FUNCTION entry";
  }
  return null;
};

const readIndirectUnwindInfoRva = async (
  reader: FileRangeReader,
  indirectRuntimeFunctionRva: number,
  rvaToOff: RvaToOffset
): Promise<number | null> => {
  const indirectRuntimeFunctionOff = rvaToOff(indirectRuntimeFunctionRva);
  if (indirectRuntimeFunctionOff == null || indirectRuntimeFunctionOff < 0) return null;
  const unwindDataOff = indirectRuntimeFunctionOff + Uint32Array.BYTES_PER_ELEMENT * 2;
  if (unwindDataOff + Uint32Array.BYTES_PER_ELEMENT > reader.size) return null;
  const view = await reader.read(unwindDataOff, Uint32Array.BYTES_PER_ELEMENT);
  return view.byteLength === Uint32Array.BYTES_PER_ELEMENT
    ? view.getUint32(0, true) >>> 0
    : null;
};

const resolveUnwindInfoRva = async (
  reader: FileRangeReader,
  unwindDataRva: number,
  exceptionDirectoryRva: number,
  exceptionDirectorySize: number,
  rvaToOff: RvaToOffset,
  fileSize: number,
  visitedIndirectRvas = new Set<number>()
): Promise<RuntimeFunctionEntryValidation> => {
  if (!unwindDataRva) return { issue: "UnwindData is zero", unwindInfoRva: null };
  if (!isIndirectRuntimeFunction(unwindDataRva)) {
    if (
      unwindDataRva >= exceptionDirectoryRva &&
      unwindDataRva < exceptionDirectoryRva + exceptionDirectorySize
    ) {
      return {
        issue: "UnwindData points back into the RUNTIME_FUNCTION table",
        unwindInfoRva: null
      };
    }
    const unwindIssue = getMappedRvaIssue(unwindDataRva, rvaToOff, fileSize);
    return {
      issue: unwindIssue ? `UnwindData ${unwindIssue}` : null,
      unwindInfoRva: unwindIssue ? null : unwindDataRva
    };
  }
  const indirectRuntimeFunctionRva = getIndirectRuntimeFunctionRva(unwindDataRva);
  if (visitedIndirectRvas.has(indirectRuntimeFunctionRva)) {
    return { issue: "Indirect UnwindData forms a cycle", unwindInfoRva: null };
  }
  visitedIndirectRvas.add(indirectRuntimeFunctionRva);
  const indirectIssue = getExceptionDirectoryIssue(
    indirectRuntimeFunctionRva,
    exceptionDirectoryRva,
    exceptionDirectorySize
  );
  if (indirectIssue) return { issue: `Indirect UnwindData ${indirectIssue}`, unwindInfoRva: null };
  const unwindInfoRva = await readIndirectUnwindInfoRva(
    reader,
    indirectRuntimeFunctionRva,
    rvaToOff
  );
  if (unwindInfoRva == null) {
    return { issue: "Indirect UnwindData target could not be read", unwindInfoRva: null };
  }
  return resolveUnwindInfoRva(
    reader,
    unwindInfoRva,
    exceptionDirectoryRva,
    exceptionDirectorySize,
    rvaToOff,
    fileSize,
    visitedIndirectRvas
  );
};

const validateRuntimeFunctionEntry = async (
  reader: FileRangeReader,
  beginRva: number,
  endRva: number,
  unwindDataRva: number,
  exceptionDirectoryRva: number,
  exceptionDirectorySize: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): Promise<RuntimeFunctionEntryValidation> => {
  // Microsoft documents .pdata as sorted RUNTIME_FUNCTION records with
  // image-relative function start, function end, and unwind data. Chained
  // RUNTIME_FUNCTION records are trailing UNWIND_INFO payload; indirect
  // RUNTIME_FUNCTION rows use the Windows header low-bit marker instead.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-runtime_function
  if (beginRva >= endRva) {
    return { issue: "BeginAddress is greater than or equal to EndAddress", unwindInfoRva: null };
  }
  const beginIssue = getMappedRvaIssue(beginRva, rvaToOff, fileSize);
  if (beginIssue) return { issue: `BeginAddress ${beginIssue}`, unwindInfoRva: null };
  const endIssue = getMappedRvaIssue((endRva - 1) >>> 0, rvaToOff, fileSize);
  if (endIssue) return { issue: `EndAddress ${endIssue}`, unwindInfoRva: null };
  // Leaf functions without unwind state are omitted from .pdata; once a
  // RUNTIME_FUNCTION record exists, the unwind data is required.
  return resolveUnwindInfoRva(
    reader,
    unwindDataRva,
    exceptionDirectoryRva,
    exceptionDirectorySize,
    rvaToOff,
    fileSize
  );
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
      const unwindDataRva = spanView.getUint32(entryOffset + 8, true) >>> 0;
      const validation = await validateRuntimeFunctionEntry(
        reader,
        beginRva,
        endRva,
        unwindDataRva,
        directoryRva,
        entryCount * AMD64_RUNTIME_FUNCTION_ENTRY_SIZE,
        rvaToOff,
        reader.size
      );
      functionCount += 1;
      if (validation.issue) {
        invalidEntryCount += 1;
        addInvalidEntryIssue(invalidEntryIssues, validation.issue);
        continue;
      }
      if (validation.unwindInfoRva) unwindRvas.add(validation.unwindInfoRva);
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
