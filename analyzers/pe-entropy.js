"use strict";

function shannonEntropy(bytes) {
  if (!bytes || bytes.length === 0) return 0;
  const freq = new Uint32Array(256);
  for (let index = 0; index < bytes.length; index++) freq[bytes[index]]++;
  let entropy = 0;
  const totalCount = bytes.length;
  for (let i = 0; i < 256; i++) {
    const count = freq[i];
    if (!count) continue;
    const probability = count / totalCount;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

export async function addSectionEntropies(file, sections) {
  for (const section of sections) {
    const { pointerToRawData, sizeOfRawData } = section;
    if (pointerToRawData && sizeOfRawData) {
      const bytes = new Uint8Array(await file.slice(pointerToRawData, pointerToRawData + sizeOfRawData).arrayBuffer());
      section.entropy = shannonEntropy(bytes);
    } else {
      section.entropy = 0;
    }
  }
}

