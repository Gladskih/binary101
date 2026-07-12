"use strict";

import type { PeSection } from "../types.js";

export type FileRange = { start: number; end: number };

const clampEndToFileSize = (end: number, fileSize: number | null): number =>
  fileSize == null ? end : Math.min(end, fileSize);

const isRangeCoveredByAny = (range: FileRange, coveringRanges: FileRange[]): boolean =>
  coveringRanges.some(covering => range.start >= covering.start && range.end <= covering.end);

export const normalizeFileRanges = (ranges: FileRange[]): FileRange[] => {
  const normalized = ranges.filter(range => range.end > range.start).slice()
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const merged: FileRange[] = [];
  for (const range of normalized) {
    const previous = merged[merged.length - 1];
    if (previous && range.start <= previous.end) {
      previous.end = Math.max(previous.end, range.end);
      continue;
    }
    merged.push({ ...range });
  }
  return merged;
};

export const subtractFileRanges = (
  ranges: FileRange[],
  coveredRanges: FileRange[]
): FileRange[] => {
  const covered = normalizeFileRanges(coveredRanges);
  const remaining: FileRange[] = [];
  for (const range of normalizeFileRanges(ranges)) {
    let cursor = range.start;
    for (const coverage of covered) {
      if (coverage.end <= cursor) continue;
      if (coverage.start >= range.end) break;
      if (coverage.start > cursor) {
        remaining.push({ start: cursor, end: Math.min(coverage.start, range.end) });
      }
      cursor = Math.max(cursor, coverage.end);
      if (cursor >= range.end) break;
    }
    if (cursor < range.end) remaining.push({ start: cursor, end: range.end });
  }
  return remaining;
};

export const getMappedImageRanges = (
  headerSpanEnd: number,
  sections: PeSection[],
  fileSize: number | null
): FileRange[] =>
  normalizeFileRanges([
    { start: 0, end: clampEndToFileSize(headerSpanEnd, fileSize) },
    ...sections.map(section => ({
      start: section.pointerToRawData >>> 0,
      end: clampEndToFileSize(
        (section.pointerToRawData >>> 0) + (section.sizeOfRawData >>> 0),
        fileSize
      )
    }))
  ]);

export const getUnmappedFileRanges = (
  ranges: FileRange[],
  mappedRanges: FileRange[]
): FileRange[] => normalizeFileRanges(
  ranges.filter(range => !isRangeCoveredByAny(range, mappedRanges))
);
