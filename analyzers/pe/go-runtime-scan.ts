"use strict";

// Bound adversarial candidate sets while leaving ample room for legitimate duplicate byte patterns.
const MAX_MATCH_COUNT = 64;

const matchesAt = (bytes: Uint8Array, offset: number, pattern: Uint8Array): boolean => {
  if (offset + pattern.byteLength > bytes.byteLength) return false;
  return pattern.every((value, index) => bytes[offset + index] === value);
};

export const scanFileRangeForPatterns = async (
  file: Blob,
  offset: number,
  size: number,
  patterns: readonly Uint8Array[]
): Promise<number[]> => {
  const longest = Math.max(0, ...patterns.map(pattern => pattern.byteLength));
  if (!patterns.length || longest === 0 || offset < 0 || size <= 0) return [];
  const matches: number[] = [];
  const end = Math.min(file.size, offset + size);
  let cursor = offset;
  let overlap = new Uint8Array(0);
  const streamReader = file.slice(offset, end).stream().getReader();
  try {
    while (cursor < end && matches.length < MAX_MATCH_COUNT) {
      const read = await streamReader.read();
      if (read.done || !read.value?.byteLength) break;
      const chunk = read.value;
      const combined = new Uint8Array(overlap.byteLength + chunk.byteLength);
      combined.set(overlap);
      combined.set(chunk, overlap.byteLength);
      const combinedOffset = cursor - overlap.byteLength;
      for (let index = 0; index < combined.byteLength; index += 1) {
        if (patterns.some(pattern => matchesAt(combined, index, pattern))) {
          matches.push(combinedOffset + index);
          if (matches.length >= MAX_MATCH_COUNT) break;
        }
      }
      overlap = combined.slice(Math.max(0, combined.byteLength - longest + 1));
      cursor += chunk.byteLength;
    }
    if (matches.length >= MAX_MATCH_COUNT) await streamReader.cancel();
  } finally {
    streamReader.releaseLock();
  }
  return [...new Set(matches)];
};
