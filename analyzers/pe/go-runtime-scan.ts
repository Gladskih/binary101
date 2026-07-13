"use strict";

// Bound adversarial candidate sets while leaving ample room for legitimate duplicate byte patterns.
const MAX_MATCH_COUNT = 64;

interface IndexedPatterns {
  byFirstByte: Array<Uint8Array[] | undefined>;
  longest: number;
}

// Chrome CPU profiling on a 121 MB PE made per-byte Array.some/every callbacks dominant.
// Byte buckets and indexed loops keep the matcher hot path callback- and allocation-free.
const indexPatterns = (
  patterns: readonly Uint8Array[],
  scanSize: number
): IndexedPatterns => {
  const byFirstByte: Array<Uint8Array[] | undefined> = Array.from(
    { length: 256 },
    () => undefined
  );
  let longest = 0;
  for (const pattern of patterns) {
    if (pattern.byteLength === 0 || pattern.byteLength > scanSize) continue;
    const firstByte = pattern[0]!;
    const bucket = byFirstByte[firstByte] ?? [];
    bucket.push(pattern);
    byFirstByte[firstByte] = bucket;
    longest = Math.max(longest, pattern.byteLength);
  }
  return { byFirstByte, longest };
};

const matchesAt = (
  bytes: Uint8Array,
  offset: number,
  patterns: readonly Uint8Array[] | undefined
): boolean => {
  if (!patterns) return false;
  for (const pattern of patterns) {
    if (offset + pattern.byteLength > bytes.byteLength) continue;
    let index = 1;
    while (index < pattern.byteLength && bytes[offset + index] === pattern[index]) index += 1;
    if (index === pattern.byteLength) return true;
  }
  return false;
};

const alignedIndex = (combinedOffset: number, scanOffset: number, alignment: number): number => {
  const remainder = (combinedOffset - scanOffset) % alignment;
  return remainder === 0 ? 0 : alignment - remainder;
};

export const scanFileRangeForPatterns = async (
  file: Blob,
  offset: number,
  size: number,
  patterns: readonly Uint8Array[],
  alignment: number
): Promise<number[]> => {
  if (!Number.isSafeInteger(offset) || offset < 0 ||
    !Number.isSafeInteger(size) || size <= 0 ||
    !Number.isSafeInteger(alignment) || alignment <= 0 || offset >= file.size) return [];
  const scanSize = Math.min(size, file.size - offset);
  const indexed = indexPatterns(patterns, scanSize);
  if (indexed.longest === 0) return [];
  const matches = new Set<number>();
  const end = offset + scanSize;
  let cursor = offset;
  let overlap = new Uint8Array(0);
  const streamReader = file.slice(offset, end).stream().getReader();
  try {
    while (cursor < end && matches.size < MAX_MATCH_COUNT) {
      const read = await streamReader.read();
      if (read.done || !read.value?.byteLength) break;
      const chunk = read.value;
      const combined = overlap.byteLength ? new Uint8Array(overlap.byteLength + chunk.byteLength) : chunk;
      if (overlap.byteLength) {
        combined.set(overlap);
        combined.set(chunk, overlap.byteLength);
      }
      const combinedOffset = cursor - overlap.byteLength;
      const firstIndex = alignedIndex(combinedOffset, offset, alignment);
      for (let index = firstIndex; index < combined.byteLength; index += alignment) {
        const candidates = indexed.byFirstByte[combined[index]!];
        if (matchesAt(combined, index, candidates)) {
          matches.add(combinedOffset + index);
          if (matches.size >= MAX_MATCH_COUNT) break;
        }
      }
      overlap = combined.slice(Math.max(0, combined.byteLength - indexed.longest + 1));
      cursor += chunk.byteLength;
    }
    if (matches.size >= MAX_MATCH_COUNT) await streamReader.cancel();
  } finally {
    streamReader.releaseLock();
  }
  return [...matches];
};
