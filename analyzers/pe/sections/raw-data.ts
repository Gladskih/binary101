"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeSection } from "../types.js";

// Keep malformed SizeOfRawData values from turning automatic structural parsing into a deep scan.
const MAX_AUTOMATIC_RAW_TAIL_SCAN_BYTES = 1024 * 1024;

// Microsoft PE format, "Section Table (Section Headers)":
// SizeOfRawData is FileAlignment-rounded file data and can be greater than VirtualSize.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
const getRawTailSize = (section: PeSection): number =>
  Math.max(0, (section.sizeOfRawData >>> 0) - (section.virtualSize >>> 0));

const chunkHasNonZeroByte = (bytes: Uint8Array): boolean => {
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) return true;
  }
  return false;
};

const getReadableRawTailSize = (reader: FileRangeReader, section: PeSection): number => {
  const rawTailSize = getRawTailSize(section);
  const rawTailStart = (section.pointerToRawData >>> 0) + (section.virtualSize >>> 0);
  return Math.max(0, Math.min(rawTailSize, reader.size - rawTailStart));
};

const rawTailHasNonZeroByte = async (
  reader: FileRangeReader,
  section: PeSection,
  scanSize: number
): Promise<boolean> => {
  const rawTailStart = (section.pointerToRawData >>> 0) + (section.virtualSize >>> 0);
  return chunkHasNonZeroByte(await reader.readBytes(rawTailStart, scanSize));
};

const buildRawTail = (
  rawTailSize: number,
  readableRawTailSize: number,
  hasNonZeroByte: boolean
): NonNullable<PeSection["rawTail"]> => {
  const readableSize = Math.max(0, Math.min(rawTailSize, readableRawTailSize));
  const fullyReadable = readableSize === rawTailSize;
  const scanComplete = readableSize <= MAX_AUTOMATIC_RAW_TAIL_SCAN_BYTES;
  const warnings: string[] = [];
  if (!fullyReadable) {
    warnings.push("Section raw tail is truncated by end of file; zero-fill status is incomplete.");
  }
  if (!hasNonZeroByte && !scanComplete) {
    warnings.push("Section raw tail exceeds the automatic 1 MiB zero-fill scan budget.");
  }
  return {
    zeroFilled: hasNonZeroByte ? false : fullyReadable && scanComplete ? true : null,
    readableSize,
    ...(warnings.length ? { warnings } : {})
  };
};

export async function addSectionRawTailAnalysis(
  reader: FileRangeReader,
  sections: PeSection[]
): Promise<void> {
  for (const section of sections) {
    const rawTailSize = getRawTailSize(section);
    if (!rawTailSize) continue;
    const readableSize = getReadableRawTailSize(reader, section);
    const scanSize = Math.min(readableSize, MAX_AUTOMATIC_RAW_TAIL_SCAN_BYTES);
    const hasNonZeroByte = scanSize > 0 &&
      await rawTailHasNonZeroByte(reader, section, scanSize);
    section.rawTail = buildRawTail(rawTailSize, readableSize, hasNonZeroByte);
  }
}
