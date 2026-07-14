"use strict";

export interface SectionRawDataRange {
  pointerToRawData: number;
  sizeOfRawData: number;
}

type ValidatedSectionRange = {
  start: number;
  end: number;
};

const validatedSectionRange = (
  fileSize: number,
  section: SectionRawDataRange
): ValidatedSectionRange | null => {
  const { pointerToRawData, sizeOfRawData } = section;
  if (!Number.isSafeInteger(pointerToRawData) || pointerToRawData < 0) return null;
  if (!Number.isSafeInteger(sizeOfRawData) || sizeOfRawData <= 0) return null;
  const end = pointerToRawData + sizeOfRawData;
  if (!Number.isSafeInteger(end) || end > fileSize) return null;
  return { start: pointerToRawData, end };
};

const shannonEntropy = (frequencies: Uint32Array, totalBytes: number): number => {
  let entropy = 0;
  for (let value = 0; value < frequencies.length; value += 1) {
    const count = frequencies[value]!;
    if (!count) continue;
    const probability = count / totalBytes;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};

const calculateRangeEntropy = async (
  file: Blob,
  range: ValidatedSectionRange
): Promise<number | null> => {
  const frequencies = new Uint32Array(256); // One bucket per possible byte value.
  const streamReader = file.slice(range.start, range.end).stream().getReader();
  let totalBytes = 0;
  try {
    while (true) {
      const read = await streamReader.read();
      if (read.done) break;
      for (const value of read.value) frequencies[value] = frequencies[value]! + 1;
      totalBytes += read.value.byteLength;
    }
  } finally {
    streamReader.releaseLock();
  }
  return totalBytes === range.end - range.start
    ? shannonEntropy(frequencies, totalBytes)
    : null;
};

export const calculateSectionEntropies = async (
  file: Blob,
  sections: readonly SectionRawDataRange[]
): Promise<Array<number | null>> => {
  const entropies: Array<number | null> = [];
  for (const section of sections) {
    const range = validatedSectionRange(file.size, section);
    entropies.push(range ? await calculateRangeEntropy(file, range) : null);
  }
  return entropies;
};
