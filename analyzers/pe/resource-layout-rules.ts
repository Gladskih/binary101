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
  const firstStringInDirectoryArea = resourceStringRanges.find(
    resourceStringRange => resourceStringRange.start < maxDirectoryEnd
  );
  const firstDataEntryStart = resourceDataEntries.length
    ? Math.min(...resourceDataEntries.map(entry => entry.start))
    : Number.POSITIVE_INFINITY;
  if (firstStringInDirectoryArea) {
    addIssue(
      `Resource string area begins at ${formatRelOffset(firstStringInDirectoryArea.start)}, before the last resource directory entry ends at ${formatRelOffset(maxDirectoryEnd)}.`
    );
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
  const firstStringAfterDataEntry = resourceStringRanges.find(
    resourceStringRange => resourceStringRange.end > firstDataEntryStart
  );
  const firstDataEntryInDirectoryArea = resourceDataEntries.find(
    resourceDataEntry => resourceDataEntry.start < maxDirectoryEnd
  );
  if (firstDataEntryInDirectoryArea) {
    addIssue(
      `Resource data entry area begins at ${formatRelOffset(firstDataEntryInDirectoryArea.start)}, before the resource directory area ends at ${formatRelOffset(maxDirectoryEnd)}.`
    );
  }
  if (firstStringAfterDataEntry) {
    addIssue(
      `Resource string area and Resource Data entry area are interleaved: first resource data entry at ${formatRelOffset(firstDataEntryStart)}, first late resource string at ${formatRelOffset(firstStringAfterDataEntry.start)}, and the string area ends at ${formatRelOffset(maxStringEnd)}.`
    );
  }
  for (const resourceDataEntry of resourceDataEntries) {
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
