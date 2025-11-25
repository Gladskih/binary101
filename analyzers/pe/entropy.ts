"use strict";

import type { PeSection } from "./types.js";

function shannonEntropy(bytes: Uint8Array): number {
  if (!bytes || bytes.length === 0) return 0;
  const freq = new Uint32Array(256);
  for (let index = 0; index < bytes.length; index += 1) {
    const value = bytes[index];
    if (value === undefined) continue;
    const current = freq[value] ?? 0;
    freq[value] = current + 1;
  }
  let entropy = 0;
  const totalCount = bytes.length;
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
      const bytes = new Uint8Array(
        await file.slice(pointerToRawData, pointerToRawData + sizeOfRawData).arrayBuffer()
      );
      section.entropy = shannonEntropy(bytes);
    } else {
      section.entropy = 0;
    }
  }
}
