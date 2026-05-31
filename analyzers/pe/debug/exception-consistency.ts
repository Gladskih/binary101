"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import type { PeDebugDirectoryEntry } from "./directory.js";
import { IMAGE_DEBUG_TYPE_EXCEPTION } from "./types.js";

type FileRange = { start: number; size: number };
type MainExceptionRange =
  | { kind: "absent" }
  | { kind: "invalid" }
  | { kind: "valid"; range: FileRange };
type DebugExceptionConsistencyFindings = {
  notes: string[];
  warnings: string[];
};

// Match the FileRangeReader cached window so large .pdata copies are compared in bounded chunks.
const BYTE_COMPARE_CHUNK_SIZE = 64 * 1024;

const resolveMainExceptionRange = (
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  fileSize: number
): MainExceptionRange => {
  const exceptionDir = dataDirs.find(directory => directory.name === "EXCEPTION");
  if (!exceptionDir || (exceptionDir.rva === 0 && exceptionDir.size === 0)) return { kind: "absent" };
  const start = exceptionDir.rva ? rvaToOff(exceptionDir.rva) : null;
  if (start == null || start < 0 || start >= fileSize) return { kind: "invalid" };
  if (exceptionDir.size <= 0 || exceptionDir.size > fileSize - start) return { kind: "invalid" };
  return { kind: "valid", range: { start, size: exceptionDir.size } };
};

const resolveDebugExceptionRange = (
  entry: PeDebugDirectoryEntry,
  rvaToOff: RvaToOffset,
  fileSize: number
): FileRange | null => {
  if (entry.sizeOfData <= 0) return null;
  const mappedStart = entry.addressOfRawData ? rvaToOff(entry.addressOfRawData) : null;
  const start = entry.pointerToRawData || mappedStart;
  if (start == null || start < 0 || start >= fileSize) return null;
  if (entry.sizeOfData > fileSize - start) return null;
  return { start, size: entry.sizeOfData };
};

const byteArraysEqual = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);

const formatFileRange = (range: FileRange): string => {
  const end = range.start + range.size;
  return `0x${range.start.toString(16)}-0x${end.toString(16)}`;
};

const fileRangesOverlap = (left: FileRange, right: FileRange): boolean =>
  left.start < right.start + right.size && right.start < left.start + left.size;

const fileRangesEqual = async (
  reader: FileRangeReader,
  left: FileRange,
  right: FileRange
): Promise<boolean> => {
  for (let offset = 0; offset < left.size; offset += BYTE_COMPARE_CHUNK_SIZE) {
    const chunkSize = Math.min(BYTE_COMPARE_CHUNK_SIZE, left.size - offset);
    const leftBytes = await reader.readBytes(left.start + offset, chunkSize);
    const rightBytes = await reader.readBytes(right.start + offset, chunkSize);
    if (!byteArraysEqual(leftBytes, rightBytes)) return false;
  }
  return true;
};

export const collectDebugExceptionConsistencyFindings = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  entries: PeDebugDirectoryEntry[]
): Promise<DebugExceptionConsistencyFindings> => {
  const notes: string[] = [];
  const warnings: string[] = [];
  const mainRange = resolveMainExceptionRange(dataDirs, rvaToOff, reader.size);
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index]!;
    if (entry.type !== IMAGE_DEBUG_TYPE_EXCEPTION) continue;
    const entryLabel = `IMAGE_DEBUG_TYPE_EXCEPTION entry #${index + 1}`;
    if (mainRange.kind === "absent") {
      warnings.push(`${entryLabel} is present, but the PE Exception Table data directory is absent.`);
      continue;
    }
    if (mainRange.kind === "invalid") {
      notes.push(`${entryLabel} physical relationship to the PE Exception Table could not be determined.`);
      continue;
    }
    const debugRange = resolveDebugExceptionRange(entry, rvaToOff, reader.size);
    if (!debugRange) {
      notes.push(`${entryLabel} raw-data byte range could not be resolved.`);
      continue;
    }
    if (debugRange.start === mainRange.range.start && debugRange.size === mainRange.range.size) {
      notes.push(
        `${entryLabel} uses the same physical byte range as the PE Exception Table ` +
          `(${formatFileRange(debugRange)}).`
      );
      continue;
    }
    if (fileRangesOverlap(debugRange, mainRange.range)) {
      warnings.push(
        `${entryLabel} raw-data range partially overlaps the PE Exception Table ` +
          `(debug ${formatFileRange(debugRange)}; exception ${formatFileRange(mainRange.range)}).`
      );
      continue;
    }
    notes.push(
      `${entryLabel} uses a separate physical byte range from the PE Exception Table ` +
        `(debug ${formatFileRange(debugRange)}; exception ${formatFileRange(mainRange.range)}).`
    );
    if (
      debugRange.size !== mainRange.range.size ||
      !(await fileRangesEqual(reader, debugRange, mainRange.range))
    ) {
      warnings.push(`${entryLabel} .pdata copy does not match the PE Exception Table bytes.`);
    }
  }
  return { notes, warnings };
};
