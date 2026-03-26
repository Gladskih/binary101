"use strict";

import type { RvaToOffset } from "./types.js";

export interface ResourceLayoutRange {
  start: number;
  end: number;
}

export interface ResourceDataEntryLayout extends ResourceLayoutRange {
  dataRva: number;
  size: number;
}

const formatRelOffset = (rel: number): string => `0x${(rel >>> 0).toString(16)}`;

export const updateDirectoryLayoutEnd = (
  currentEnd: number,
  rel: number,
  entryCount: number
): number => Math.max(currentEnd, rel + 16 + entryCount * 8);

export const validateResourceLayout = (
  maxDirectoryEnd: number,
  resourceStringRanges: ResourceLayoutRange[],
  resourceDataEntries: ResourceDataEntryLayout[],
  resourceSubdirectoryTargets: number[],
  rvaToOff: RvaToOffset,
  fileSize: number,
  addIssue: (message: string) => void
): void => {
  const firstDataEntryStart = resourceDataEntries.length
    ? Math.min(...resourceDataEntries.map(entry => entry.start))
    : Number.POSITIVE_INFINITY;
  for (const resourceStringRange of resourceStringRanges) {
    if (resourceStringRange.start < maxDirectoryEnd) {
      addIssue(
        `Resource string name at ${formatRelOffset(resourceStringRange.start)} does not lie after the last resource directory entry.`
      );
    }
    if (resourceStringRange.end > firstDataEntryStart) {
      addIssue(
        `Resource string name at ${formatRelOffset(resourceStringRange.start)} does not lie before the first resource data entry.`
      );
    }
  }
  const seenSubdirectoryTargets = new Set<number>();
  for (const resourceSubdirectoryTarget of resourceSubdirectoryTargets) {
    if (seenSubdirectoryTargets.has(resourceSubdirectoryTarget)) {
      addIssue(
        `Resource subdirectory at ${formatRelOffset(resourceSubdirectoryTarget)} is referenced by multiple parents.`
      );
      break;
    }
    seenSubdirectoryTargets.add(resourceSubdirectoryTarget);
  }
  const maxStringEnd = resourceStringRanges.reduce(
    (currentEnd, resourceStringRange) => Math.max(currentEnd, resourceStringRange.end),
    0
  );
  for (const resourceDataEntry of resourceDataEntries) {
    if (resourceDataEntry.start < maxDirectoryEnd) {
      addIssue(
        `Resource data entry at ${formatRelOffset(resourceDataEntry.start)} overlaps the resource directory area.`
      );
    }
    if (resourceDataEntry.start < maxStringEnd) {
      addIssue(
        `Resource data entry at ${formatRelOffset(resourceDataEntry.start)} overlaps the resource string area; data entries must follow all resource strings.`
      );
    }
    if (resourceDataEntry.size === 0) continue;
    const mappedPayloadOffset = rvaToOff(resourceDataEntry.dataRva);
    if (mappedPayloadOffset == null) {
      addIssue(
        `Resource data payload at RVA ${formatRelOffset(resourceDataEntry.dataRva)} could not be mapped within the file.`
      );
      continue;
    }
    if (mappedPayloadOffset < 0 || mappedPayloadOffset + resourceDataEntry.size > fileSize) {
      addIssue(
        `Resource data payload at RVA ${formatRelOffset(resourceDataEntry.dataRva)} is truncated by end of file.`
      );
    }
  }
  const sortedPayloadRanges = resourceDataEntries
    .filter(resourceDataEntry => resourceDataEntry.size > 0)
    .map(resourceDataEntry => ({
      start: resourceDataEntry.dataRva,
      end: resourceDataEntry.dataRva + resourceDataEntry.size
    }))
    .sort((leftRange, rightRange) => leftRange.start - rightRange.start);
  for (let index = 1; index < sortedPayloadRanges.length; index += 1) {
    if (sortedPayloadRanges[index - 1]!.end <= sortedPayloadRanges[index]!.start) continue;
    addIssue("Resource data payload ranges overlap in the Resource Data area.");
    break;
  }
};
