"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type { RvaToOffset } from "../../types.js";
import { AMD64_RUNTIME_FUNCTION_ENTRY_SIZE } from "./directory.js";
import { validateAmd64RuntimeFunction } from "./runtime-function-validation.js";

const TRUNCATED_RUNTIME_FUNCTION_ISSUE =
  "Exception directory is truncated; some RUNTIME_FUNCTION entries are missing.";

export interface Amd64RuntimeFunctionTable {
  beginRvas: number[];
  rangeLengths: number[];
  functionCount: number;
  invalidEntryCount: number;
  unwindRvas: Set<number>;
}

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

const readRuntimeFunctionChunks = async function* (
  source: FileRangeReader, entryCount: number, issues: string[]
): AsyncGenerator<DataView> {
  if (!Number.isSafeInteger(entryCount) || entryCount < 0) {
    issues.push("RUNTIME_FUNCTION entry count is invalid.");
    return;
  }
  const size = Math.min(entryCount, Math.floor(source.size / AMD64_RUNTIME_FUNCTION_ENTRY_SIZE)) *
    AMD64_RUNTIME_FUNCTION_ENTRY_SIZE;
  if (size < entryCount * AMD64_RUNTIME_FUNCTION_ENTRY_SIZE) issues.push(TRUNCATED_RUNTIME_FUNCTION_ISSUE);
  // Whole rows within the existing 64 KiB reader window, independent of storage coordinates.
  for (let offset = 0; offset < size; offset += 65532) {
    const requested = Math.min(size - offset, 65532);
    const view = await source.read(offset, requested);
    if (view.byteLength < requested) issues.push(TRUNCATED_RUNTIME_FUNCTION_ISSUE);
    yield new DataView(view.buffer, view.byteOffset, Math.floor(Math.min(view.byteLength, requested) /
      AMD64_RUNTIME_FUNCTION_ENTRY_SIZE) * AMD64_RUNTIME_FUNCTION_ENTRY_SIZE);
    if (view.byteLength < requested) break;
  }
};

export const readAmd64RuntimeFunctionTable = async (
  reader: FileRangeReader,
  source: FileRangeReader,
  entryCount: number,
  rvaToOff: RvaToOffset,
  issues: string[],
  directoryRva?: number
): Promise<Amd64RuntimeFunctionTable> => {
  const beginRvas: number[] = [];
  const rangeLengths: number[] = [];
  const unwindRvas = new Set<number>();
  let functionCount = 0;
  let invalidEntryCount = 0;
  let previousBeginRva: number | null = null;
  let reportedUnsortedEntries = false;
  const invalidEntryIssues = new Map<string, number>();
  for await (const spanView of readRuntimeFunctionChunks(source, entryCount, issues)) {
    const spanEntries = Math.floor(spanView.byteLength / AMD64_RUNTIME_FUNCTION_ENTRY_SIZE);
    for (let index = 0; index < spanEntries; index += 1) {
      const entryOffset = index * AMD64_RUNTIME_FUNCTION_ENTRY_SIZE;
      const beginRva = spanView.getUint32(entryOffset, true) >>> 0;
      const endRva = spanView.getUint32(entryOffset + 4, true) >>> 0;
      const unwindDataRva = spanView.getUint32(entryOffset + 8, true) >>> 0;
      const validation = await validateAmd64RuntimeFunction(reader, beginRva, endRva, unwindDataRva,
        directoryRva, entryCount * AMD64_RUNTIME_FUNCTION_ENTRY_SIZE, rvaToOff, source);
      functionCount += 1;
      if (validation.issue) {
        invalidEntryCount += 1;
        addInvalidEntryIssue(invalidEntryIssues, validation.issue);
        continue;
      }
      if (validation.unwindInfoRva) unwindRvas.add(validation.unwindInfoRva);
      rangeLengths.push(endRva - beginRva);
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
  return { beginRvas, rangeLengths, functionCount, invalidEntryCount, unwindRvas };
};

