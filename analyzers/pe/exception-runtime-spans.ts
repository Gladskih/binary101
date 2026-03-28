"use strict";

import type { PeRangeReader } from "./range-reader.js";
import type { RvaToOffset } from "./types.js";

export interface RuntimeFunctionSpan {
  fileOffset: number;
  entryCount: number;
}

export const collectRuntimeFunctionSpans = (
  directoryRva: number,
  declaredCount: number,
  entrySize: number,
  rvaToOff: RvaToOffset,
  fileSize: number,
  truncatedIssue: string,
  issues: string[]
): RuntimeFunctionSpan[] => {
  const spans: RuntimeFunctionSpan[] = [];
  for (let index = 0; index < declaredCount; index += 1) {
    const entryRva = (directoryRva + index * entrySize) >>> 0;
    const entryOff = rvaToOff(entryRva);
    if (entryOff == null || entryOff < 0 || entryOff + entrySize > fileSize) {
      issues.push(truncatedIssue);
      break;
    }
    const previousSpan = spans[spans.length - 1];
    if (previousSpan && entryOff === previousSpan.fileOffset + previousSpan.entryCount * entrySize) {
      previousSpan.entryCount += 1;
      continue;
    }
    spans.push({ fileOffset: entryOff, entryCount: 1 });
  }
  return spans;
};

export const readRuntimeFunctionSpan = async (
  reader: PeRangeReader,
  span: RuntimeFunctionSpan,
  entrySize: number,
  truncatedIssue: string,
  issues: string[]
): Promise<DataView | null> => {
  const byteLength = span.entryCount * entrySize;
  const view = await reader.read(span.fileOffset, byteLength);
  const availableEntries = Math.floor(view.byteLength / entrySize);
  if (availableEntries < span.entryCount) {
    issues.push(truncatedIssue);
    return availableEntries > 0
      ? new DataView(view.buffer, view.byteOffset, availableEntries * entrySize)
      : null;
  }
  return view;
};
