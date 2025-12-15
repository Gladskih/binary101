"use strict";

import type { PeSection } from "./types.js";

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

export async function addSectionEntropies(file: File, sections: PeSection[]): Promise<void> {
  for (const section of sections) {
    const { pointerToRawData, sizeOfRawData } = section;
    if (pointerToRawData && sizeOfRawData) {
      const readableSize = Math.max(0, Math.min(sizeOfRawData, file.size - pointerToRawData));
      const freq = new Uint32Array(256);
      let totalCount = 0;
      for (let offset = 0; offset < readableSize; offset += ENTROPY_CHUNK_BYTES) {
        const chunkStart = pointerToRawData + offset;
        const chunkEnd = Math.min(pointerToRawData + readableSize, chunkStart + ENTROPY_CHUNK_BYTES);
        const bytes = new Uint8Array(await file.slice(chunkStart, chunkEnd).arrayBuffer());
        for (const value of bytes) {
          freq[value] = (freq[value] ?? 0) + 1;
        }
        totalCount += bytes.length;
      }
      section.entropy = shannonEntropyFromFrequency(freq, totalCount);
    } else {
      section.entropy = 0;
    }
  }
}
