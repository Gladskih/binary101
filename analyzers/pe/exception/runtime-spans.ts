"use strict";

import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { mappedRvaSize } from "../rva-mapping.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";

export interface RuntimeFunctionSpan {
  rva: number;
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
  const readableBytes = mappedRvaSize(rvaToOff, directoryRva, declaredCount * entrySize, fileSize);
  const count = Math.floor(readableBytes / entrySize);
  if (count < declaredCount) issues.push(truncatedIssue);
  for (let index = 0; index < count;) {
    // Match the shared reader window; no entire-directory allocation for large .pdata tables.
    const entryCount = Math.min(count - index, Math.max(1, Math.floor(65536 / entrySize)));
    spans.push({ rva: directoryRva + index * entrySize, entryCount });
    index += entryCount;
  }
  return spans;
};

export const readRuntimeFunctionSpan = async (
  reader: FileRangeReader,
  span: RuntimeFunctionSpan,
  rvaToOff: RvaToOffset,
  entrySize: number,
  truncatedIssue: string,
  issues: string[]
): Promise<DataView | null> => {
  const byteLength = span.entryCount * entrySize;
  const view = await readMappedRvaPrefix(reader, span.rva, byteLength, rvaToOff);
  const availableEntries = Math.floor(view.byteLength / entrySize);
  if (availableEntries < span.entryCount) {
    issues.push(truncatedIssue);
    return availableEntries > 0
      ? new DataView(view.buffer, view.byteOffset, availableEntries * entrySize)
      : null;
  }
  return view;
};
