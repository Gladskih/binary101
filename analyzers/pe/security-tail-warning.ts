"use strict";

import type { ParsedSecurityDirectory } from "./security.js";
import type { PeDataDirectory } from "./types.js";

type FileRange = { start: number; end: number };

const appendUniqueWarnings = (
  existing: string[] | undefined,
  messages: string[]
): string[] | undefined => {
  if (!messages.length) return existing;
  const merged = new Set(existing ?? []);
  messages.forEach(message => merged.add(message));
  return [...merged];
};

const isFullyCoveredByRanges = (start: number, end: number, ranges: FileRange[]): boolean => {
  if (end <= start) return true;
  const relevantRanges = ranges
    .filter(range => range.end > start && range.start < end)
    .map(range => ({ start: Math.max(start, range.start), end: Math.min(end, range.end) }))
    .sort((left, right) => left.start - right.start || left.end - right.end);
  let coveredUntil = start;
  for (const range of relevantRanges) {
    if (range.start > coveredUntil) return false;
    coveredUntil = Math.max(coveredUntil, range.end);
    if (coveredUntil >= end) return true;
  }
  return coveredUntil >= end;
};

export const addSecurityTailWarning = (
  fileSize: number,
  security: ParsedSecurityDirectory | null,
  securityDir: PeDataDirectory | undefined,
  explainedRanges: FileRange[]
): ParsedSecurityDirectory | null => {
  if (!security || !securityDir || securityDir.rva === 0 || securityDir.size === 0) return security;
  if (securityDir.rva >= fileSize) return security;
  const tableEnd = Math.min(fileSize, securityDir.rva + securityDir.size);
  if (tableEnd >= fileSize || isFullyCoveredByRanges(tableEnd, fileSize, explainedRanges)) return security;
  const warnings = appendUniqueWarnings(security.warnings, [
    "Attribute certificate table has bytes after the declared table."
  ]);
  return warnings ? { ...security, warnings } : security;
};
