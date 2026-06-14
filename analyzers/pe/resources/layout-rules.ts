"use strict";

import {
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE
} from "./directory-format.js";

export interface ResourceLayoutRange {
  start: number;
  end: number;
}

export interface ResourceDataEntryLayout extends ResourceLayoutRange {
  dataRva: number;
  dataFileOffset: number | null;
  size: number;
}

const formatRelOffset = (rel: number): string => `0x${(rel >>> 0).toString(16)}`;

export const updateDirectoryLayoutEnd = (
  currentEnd: number,
  rel: number,
  entryCount: number
): number => Math.max(
  currentEnd,
  rel + IMAGE_RESOURCE_DIRECTORY_SIZE + entryCount * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
);

const minRangeStart = (ranges: ResourceLayoutRange[]): number =>
  ranges.length ? Math.min(...ranges.map(range => range.start)) : Number.POSITIVE_INFINITY;

const getStringDirectoryAreaIssues = (
  maxDirectoryEnd: number,
  resourceStringRanges: ResourceLayoutRange[]
): string[] => {
  const firstStringInDirectoryArea = resourceStringRanges.find(
    resourceStringRange => resourceStringRange.start < maxDirectoryEnd
  );
  return firstStringInDirectoryArea
    ? [
        `Resource string area begins at ${formatRelOffset(firstStringInDirectoryArea.start)}, `
          + `before the last resource directory entry ends at ${formatRelOffset(maxDirectoryEnd)}.`
      ]
    : [];
};

const findFirstDuplicate = (values: number[]): number | null =>
  values.find((value, index) => values.indexOf(value) !== index) ?? null;

const getSubdirectoryTargetIssues = (
  resourceSubdirectoryTargets: number[],
  firstStringStart: number,
  firstDataEntryStart: number
): string[] => {
  const duplicate = findFirstDuplicate(resourceSubdirectoryTargets);
  const firstLateTarget = resourceSubdirectoryTargets.find(
    target => target >= Math.min(firstStringStart, firstDataEntryStart)
  );
  return [
    ...(duplicate == null
      ? []
      : [
          `Resource subdirectory at ${formatRelOffset(duplicate)} is referenced by multiple ` +
            "parents."
        ]),
    ...(firstLateTarget == null
      ? []
      : [
          `Resource subdirectory at ${formatRelOffset(firstLateTarget)} points outside the Resource `
            + "Directory area and into the later string or data-entry region."
        ])
  ];
};

const getDataEntryOrderIssues = (
  maxDirectoryEnd: number,
  resourceStringRanges: ResourceLayoutRange[],
  resourceDataEntries: ResourceDataEntryLayout[],
  firstDataEntryStart: number
): string[] => {
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
  return [
    ...(firstDataEntryInDirectoryArea
      ? [
          `Resource data entry area begins at ${formatRelOffset(firstDataEntryInDirectoryArea.start)}, `
            + `before the resource directory area ends at ${formatRelOffset(maxDirectoryEnd)}.`
        ]
      : []),
    ...(firstStringAfterDataEntry
      ? [
          "Resource string area and Resource Data entry area are interleaved: first resource data "
            + `entry at ${formatRelOffset(firstDataEntryStart)}, first late resource string at `
            + `${formatRelOffset(firstStringAfterDataEntry.start)}, and the string area ends at `
            + `${formatRelOffset(maxStringEnd)}.`
        ]
      : [])
  ];
};

const getDataPayloadSpanIssues = (
  resourceDataEntry: ResourceDataEntryLayout,
  resourceRva: number,
  resourceSize: number,
  resourceBase: number,
  resourceLimitEnd: number,
  fileSize: number
): string[] => {
  if (resourceDataEntry.size === 0) return [];
  const issues: string[] = [];
  if (
    resourceDataEntry.dataRva < resourceRva ||
    resourceDataEntry.dataRva + resourceDataEntry.size > resourceRva + resourceSize
  ) {
    issues.push(
      `Resource data payload at RVA ${formatRelOffset(resourceDataEntry.dataRva)} lies ` +
        "outside the declared .rsrc RVA span."
    );
  }
  if (resourceDataEntry.dataFileOffset == null) {
    return [
      ...issues,
      `Resource data payload at RVA ${formatRelOffset(resourceDataEntry.dataRva)} could ` +
        "not be mapped within the file."
    ];
  }
  if (
    resourceDataEntry.dataFileOffset < 0 ||
    resourceDataEntry.dataFileOffset + resourceDataEntry.size > fileSize
  ) {
    return [
      ...issues,
      `Resource data payload at RVA ${formatRelOffset(resourceDataEntry.dataRva)} is ` +
        "truncated by end of file."
    ];
  }
  if (
    resourceDataEntry.dataFileOffset < resourceBase ||
    resourceDataEntry.dataFileOffset + resourceDataEntry.size > resourceLimitEnd
  ) {
    issues.push(
      `Resource data payload at RVA ${formatRelOffset(resourceDataEntry.dataRva)} maps ` +
        "outside the .rsrc file span."
    );
  }
  return issues;
};

const getDataPayloadOverlapIssues = (
  resourceDataEntries: ResourceDataEntryLayout[]
): string[] => {
  const sortedPayloadRanges = resourceDataEntries
    .filter(resourceDataEntry => resourceDataEntry.size > 0)
    .map(resourceDataEntry => ({
      start: resourceDataEntry.dataRva,
      end: resourceDataEntry.dataRva + resourceDataEntry.size
    }))
    .sort((leftRange, rightRange) => leftRange.start - rightRange.start);
  const firstOverlapIndex = sortedPayloadRanges.findIndex((range, index) =>
    index > 0 && sortedPayloadRanges[index - 1]!.end > range.start
  );
  return firstOverlapIndex === -1
    ? []
    : ["Resource data payload ranges overlap in the Resource Data area."];
};

export const validateResourceLayout = (
  maxDirectoryEnd: number,
  resourceStringRanges: ResourceLayoutRange[],
  resourceDataEntries: ResourceDataEntryLayout[],
  resourceSubdirectoryTargets: number[],
  resourceRva: number,
  resourceSize: number,
  resourceBase: number,
  fileSize: number
): string[] => {
  const resourceLimitEnd = resourceBase + resourceSize;
  const firstDataEntryStart = resourceDataEntries.length
    ? Math.min(...resourceDataEntries.map(entry => entry.start))
    : Number.POSITIVE_INFINITY;
  return [
    ...getStringDirectoryAreaIssues(maxDirectoryEnd, resourceStringRanges),
    ...getSubdirectoryTargetIssues(
      resourceSubdirectoryTargets,
      minRangeStart(resourceStringRanges),
      firstDataEntryStart
    ),
    ...getDataEntryOrderIssues(
      maxDirectoryEnd,
      resourceStringRanges,
      resourceDataEntries,
      firstDataEntryStart
    ),
    ...resourceDataEntries.flatMap(resourceDataEntry => getDataPayloadSpanIssues(
      resourceDataEntry,
      resourceRva,
      resourceSize,
      resourceBase,
      resourceLimitEnd,
      fileSize
    )),
    ...getDataPayloadOverlapIssues(resourceDataEntries)
  ];
};
