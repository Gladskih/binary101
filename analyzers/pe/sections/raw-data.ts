"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeSection } from "../types.js";

const ENTROPY_CHUNK_BYTES = 1024 * 1024;

function shannonEntropyFromFrequency(freq: Uint32Array, totalCount: number): number {
  if (totalCount <= 0) return 0;
  let entropy = 0;
  for (let i = 0; i < 256; i += 1) {
    const count = freq[i];
    if (!count) continue;
    const probability = count / totalCount;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

const getReadableRawSize = (reader: FileRangeReader, section: PeSection): number => {
  const pointerToRawData = section.pointerToRawData >>> 0;
  const sizeOfRawData = section.sizeOfRawData >>> 0;
  if (!sizeOfRawData || pointerToRawData >= reader.size) return 0;
  return Math.max(0, Math.min(sizeOfRawData, reader.size - pointerToRawData));
};

// Microsoft PE format, "Section Table (Section Headers)":
// SizeOfRawData is FileAlignment-rounded file data and can be greater than VirtualSize.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
const getRawTailSize = (section: PeSection): number =>
  Math.max(0, (section.sizeOfRawData >>> 0) - (section.virtualSize >>> 0));

const chunkHasNonZeroRawTail = (
  bytes: Uint8Array,
  chunkSectionOffset: number,
  rawTailStart: number
): boolean => {
  const tailIndex = Math.max(0, rawTailStart - chunkSectionOffset);
  for (let index = tailIndex; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) return true;
  }
  return false;
};

const buildRawTail = (
  section: PeSection,
  readableRawSize: number,
  hasNonZeroByte: boolean
): PeSection["rawTail"] => {
  const rawTailSize = getRawTailSize(section);
  if (!rawTailSize) return undefined;
  const readableSize = Math.max(
    0,
    Math.min(rawTailSize, readableRawSize - (section.virtualSize >>> 0))
  );
  const fullyReadable = readableSize === rawTailSize;
  return {
    zeroFilled: hasNonZeroByte ? false : fullyReadable ? true : null,
    readableSize,
    ...(fullyReadable
      ? {}
      : {
          warnings: [
            "Section raw tail is truncated by end of file; zero-fill status is incomplete."
          ]
        })
  };
};

export async function addSectionRawDataAnalysis(
  reader: FileRangeReader,
  sections: PeSection[]
): Promise<void> {
  for (const section of sections) {
    const { pointerToRawData, virtualSize } = section;
    const readableSize = getReadableRawSize(reader, section);
    const rawTailSize = getRawTailSize(section);
    let rawTailHasNonZeroByte = false;
    if (readableSize) {
      const freq = new Uint32Array(256);
      let totalCount = 0;
      for (let offset = 0; offset < readableSize; offset += ENTROPY_CHUNK_BYTES) {
        const chunkStart = pointerToRawData + offset;
        const chunkEnd = Math.min(pointerToRawData + readableSize, chunkStart + ENTROPY_CHUNK_BYTES);
        const bytes = await reader.readBytes(chunkStart, chunkEnd - chunkStart);
        if (rawTailSize) {
          rawTailHasNonZeroByte ||= chunkHasNonZeroRawTail(bytes, offset, virtualSize >>> 0);
        }
        for (const value of bytes) {
          freq[value] = (freq[value] ?? 0) + 1;
        }
        totalCount += bytes.length;
      }
      section.entropy = shannonEntropyFromFrequency(freq, totalCount);
    } else {
      section.entropy = 0;
    }
    const rawTail = buildRawTail(section, readableSize, rawTailHasNonZeroByte);
    if (rawTail) section.rawTail = rawTail;
  }
}
