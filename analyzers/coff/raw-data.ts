"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { CoffSection } from "./types.js";

const ENTROPY_CHUNK_BYTES = 1024 * 1024;
const BYTE_VALUE_COUNT = 256; // One histogram bucket per possible byte value.

const shannonEntropyFromFrequency = (freq: Uint32Array, totalCount: number): number => {
  if (totalCount <= 0) return 0;
  return Array.from(freq).reduce((entropy, count) => {
    if (!count) return entropy;
    const probability = count / totalCount;
    return entropy - probability * Math.log2(probability);
  }, 0);
};

const getReadableRawSize = (reader: FileRangeReader, section: CoffSection): number => {
  const pointerToRawData = section.pointerToRawData >>> 0;
  const sizeOfRawData = section.sizeOfRawData >>> 0;
  if (!sizeOfRawData || pointerToRawData >= reader.size) return 0;
  return Math.max(0, Math.min(sizeOfRawData, reader.size - pointerToRawData));
};

export async function addCoffSectionEntropy(
  reader: FileRangeReader,
  sections: CoffSection[]
): Promise<void> {
  await Promise.all(sections.map(async section => {
    const readableSize = getReadableRawSize(reader, section);
    if (!readableSize) {
      section.entropy = 0;
      return;
    }
    const freq = new Uint32Array(BYTE_VALUE_COUNT);
    const chunkOffsets = Array.from(
      { length: Math.ceil(readableSize / ENTROPY_CHUNK_BYTES) },
      (_, index) => index * ENTROPY_CHUNK_BYTES
    );
    const totalCount = await chunkOffsets.reduce<Promise<number>>(async (pendingTotal, offset) => {
      const currentTotal = await pendingTotal;
      const chunkStart = section.pointerToRawData + offset;
      const chunkEnd = Math.min(section.pointerToRawData + readableSize, chunkStart + ENTROPY_CHUNK_BYTES);
      const bytes = await reader.readBytes(chunkStart, chunkEnd - chunkStart);
      bytes.forEach(value => {
        freq[value] = (freq[value] ?? 0) + 1;
      });
      return currentTotal + bytes.length;
    }, Promise.resolve(0));
    section.entropy = shannonEntropyFromFrequency(freq, totalCount);
  }));
}
