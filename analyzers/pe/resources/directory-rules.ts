"use strict";

import type { ResourceLayoutRange } from "./layout-rules.js";

export interface ResourceDirectoryEntry {
  nameIsString: boolean;
  subdir: boolean;
  nameOrId: number | null;
  target: number;
  invalidNameOffset?: boolean;
}

export interface ResourceDirectoryLabelReadResult {
  text: string;
  issues: string[];
  resourceStringRanges: ResourceLayoutRange[];
}

export interface ResourceDirectoryNameValidationResult {
  issues: string[];
  resourceStringRanges: ResourceLayoutRange[];
}

const formatRelOffset = (rel: number): string => `0x${(rel >>> 0).toString(16)}`;

export const validateResourceDirectoryEntryKinds = (
  rel: number,
  namedCount: number,
  entries: ResourceDirectoryEntry[]
): string[] => {
  if (entries.slice(0, namedCount).some(entry => !entry.nameIsString)) {
    return [
      `Resource directory at ${formatRelOffset(rel)} has ID entries inside the name-entry range; `
        + "named entries must appear before ID entries."
    ];
  }
  return entries.slice(namedCount).some(entry => entry.nameIsString)
    ? [
        `Resource directory at ${formatRelOffset(rel)} has named entries after ID entries; `
          + "named entries must appear before ID entries."
      ]
    : [];
};

export const validateResourceDirectoryIdSort = (
  rel: number,
  namedCount: number,
  entries: ResourceDirectoryEntry[]
): string[] => {
  let previousId: number | null = null;
  for (const entry of entries.slice(namedCount)) {
    if (entry.nameIsString || entry.nameOrId == null) continue;
    if (previousId != null && previousId > entry.nameOrId) {
      return [
        `Resource directory at ${formatRelOffset(rel)} has ID entries that are not sorted in ascending order.`
      ];
    }
    previousId = entry.nameOrId;
  }
  return [];
};

export const validateResourceDirectoryNameSort = async (
  rel: number,
  namedCount: number,
  entries: ResourceDirectoryEntry[],
  readLabel: (rel: number) => Promise<ResourceDirectoryLabelReadResult>
): Promise<ResourceDirectoryNameValidationResult> => {
  const issues: string[] = [];
  const resourceStringRanges: ResourceLayoutRange[] = [];
  let previousName: string | null = null;
  for (const entry of entries.slice(0, namedCount)) {
    if (!entry.nameIsString || entry.nameOrId == null) continue;
    if (entry.invalidNameOffset) continue;
    const label = await readLabel(entry.nameOrId);
    issues.push(...label.issues);
    resourceStringRanges.push(...label.resourceStringRanges);
    if (previousName != null && previousName > label.text) {
      issues.push(
        `Resource directory at ${formatRelOffset(rel)} has named entries that are not sorted in ascending order.`
      );
      return { issues, resourceStringRanges };
    }
    previousName = label.text;
  }
  return { issues, resourceStringRanges };
};

export const validateResourceDirectoryDuplicates = async (
  rel: number,
  entries: ResourceDirectoryEntry[],
  readLabel: (rel: number) => Promise<ResourceDirectoryLabelReadResult>
): Promise<ResourceDirectoryNameValidationResult> => {
  const issues: string[] = [];
  const resourceStringRanges: ResourceLayoutRange[] = [];
  const seenIds = new Set<number>();
  const seenNames = new Set<string>();
  for (const entry of entries) {
    if (entry.nameIsString && entry.nameOrId != null) {
      if (entry.invalidNameOffset) continue;
      const label = await readLabel(entry.nameOrId);
      issues.push(...label.issues);
      resourceStringRanges.push(...label.resourceStringRanges);
      if (seenNames.has(label.text)) {
        issues.push(
          `Resource directory at ${formatRelOffset(rel)} has duplicate named entries for "${label.text}".`
        );
        return { issues, resourceStringRanges };
      }
      seenNames.add(label.text);
      continue;
    }
    if (entry.nameOrId == null || !seenIds.has(entry.nameOrId)) {
      if (entry.nameOrId != null) seenIds.add(entry.nameOrId);
      continue;
    }
    issues.push(
      `Resource directory at ${formatRelOffset(rel)} has duplicate ID entries for ${formatRelOffset(entry.nameOrId)}.`
    );
    return { issues, resourceStringRanges };
  }
  return { issues, resourceStringRanges };
};
