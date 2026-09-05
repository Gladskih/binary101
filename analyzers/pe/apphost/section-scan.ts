import { APP_BINARY_PLACEHOLDER, BINDING_PATTERNS, BUNDLE_SIGNATURE } from "./patterns.js";
import type { PeAppHostBinding } from "./types.js";

// Resource budget, not a format limit: at most 64 locators and 64 bindings per section,
// matching the existing go-runtime-scan.ts candidate budget. Limits downstream reads
// while retaining duplicate evidence; independent budgets prevent DLL noise hiding a locator.
const MAX_CANDIDATES = 64;
const PATTERNS = [BUNDLE_SIGNATURE, ...BINDING_PATTERNS];
const INDEXED_PATTERNS = {
  longest: Math.max(...PATTERNS.map(pattern => pattern.length)),
  byFirstByte: Map.groupBy(PATTERNS, pattern => pattern[0]!)
};

type SectionMatches = {
  locators: number[];
  bindings: Array<{ offset: number; kind: PeAppHostBinding["kind"] }>;
  issues: string[];
};

const matchesAt = (bytes: Uint8Array, offset: number, pattern: Uint8Array): boolean => {
  if (offset + pattern.length > bytes.length) return false;
  for (let index = 0; index < pattern.length; index += 1) {
    if (bytes[offset + index] !== pattern[index]) return false;
  }
  return true;
};

const recordMatch = (result: SectionMatches, offset: number, pattern: Uint8Array): void => {
  const target = pattern === BUNDLE_SIGNATURE ? result.locators : result.bindings;
  if (target.length >= MAX_CANDIDATES) {
    if (!result.issues.length) result.issues.push(".NET apphost candidate limit reached; results are incomplete.");
    return;
  }
  if (pattern === BUNDLE_SIGNATURE) result.locators.push(offset);
  else result.bindings.push({
    offset,
    kind: pattern === APP_BINARY_PLACEHOLDER ? "unbound-placeholder" : "managed-assembly"
  });
};

const scanChunk = (
  bytes: Uint8Array,
  offset: number,
  previousEnd: number,
  result: SectionMatches
): void => {
  for (let index = 0; index < bytes.length; index += 1) {
    const patterns = INDEXED_PATTERNS.byFirstByte.get(bytes[index]!);
    if (!patterns) continue;
    for (const pattern of patterns) {
      if (offset + index + pattern.length <= previousEnd) continue;
      if (matchesAt(bytes, index, pattern)) recordMatch(result, offset + index, pattern);
    }
  }
};

export const scanAppHostSection = async (
  file: Blob,
  offset: number,
  size: number
): Promise<SectionMatches> => {
  const result: SectionMatches = { locators: [], bindings: [], issues: [] };
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= file.size ||
    !Number.isSafeInteger(size) || size <= 0) return result;
  const end = offset + Math.min(size, file.size - offset);
  const reader = file.slice(offset, end).stream().getReader();
  let cursor = offset;
  let overlap = new Uint8Array(0);
  try {
    while (cursor < end) {
      const chunk = await reader.read();
      if (chunk.done) {
        result.issues.push(".NET apphost section stream is truncated.");
        break;
      }
      const bytes = new Uint8Array(overlap.length + chunk.value.length);
      bytes.set(overlap);
      bytes.set(chunk.value, overlap.length);
      scanChunk(bytes, cursor - overlap.length, cursor, result);
      // Only longest - 1 bytes can belong to a pattern crossing the next chunk boundary.
      overlap = bytes.slice(-INDEXED_PATTERNS.longest + 1);
      cursor += chunk.value.length;
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  return result;
};
