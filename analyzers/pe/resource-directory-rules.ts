"use strict";

export interface ResourceDirectoryEntry {
  nameIsString: boolean;
  subdir: boolean;
  nameOrId: number | null;
  target: number;
}

const formatRelOffset = (rel: number): string => `0x${(rel >>> 0).toString(16)}`;

export const validateResourceDirectoryEntryKinds = (
  rel: number,
  namedCount: number,
  entries: ResourceDirectoryEntry[],
  addIssue: (message: string) => void
): void => {
  const availableNamedCount = Math.min(namedCount, entries.length);
  for (let index = 0; index < availableNamedCount; index += 1) {
    if (entries[index]?.nameIsString) continue;
    addIssue(
      `Resource directory at ${formatRelOffset(rel)} has ID entries inside the name-entry range; named entries must appear before ID entries.`
    );
    break;
  }
  for (let index = availableNamedCount; index < entries.length; index += 1) {
    if (!entries[index]?.nameIsString) continue;
    addIssue(
      `Resource directory at ${formatRelOffset(rel)} has named entries after ID entries; named entries must appear before ID entries.`
    );
    break;
  }
};

export const validateResourceDirectoryIdSort = (
  rel: number,
  namedCount: number,
  entries: ResourceDirectoryEntry[],
  addIssue: (message: string) => void
): void => {
  let previousId: number | null = null;
  for (let index = Math.min(namedCount, entries.length); index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry?.nameIsString || entry?.nameOrId == null) continue;
    if (previousId != null && previousId > entry.nameOrId) {
      addIssue(
        `Resource directory at ${formatRelOffset(rel)} has ID entries that are not sorted in ascending order.`
      );
      return;
    }
    previousId = entry.nameOrId;
  }
};

export const validateResourceDirectoryNameSort = async (
  rel: number,
  namedCount: number,
  entries: ResourceDirectoryEntry[],
  readLabel: (rel: number) => Promise<string>,
  addIssue: (message: string) => void
): Promise<void> => {
  let previousName: string | null = null;
  for (let index = 0; index < Math.min(namedCount, entries.length); index += 1) {
    const entry = entries[index];
    if (!entry?.nameIsString || entry.nameOrId == null) continue;
    const currentName = await readLabel(entry.nameOrId);
    if (previousName != null && previousName > currentName) {
      addIssue(
        `Resource directory at ${formatRelOffset(rel)} has named entries that are not sorted in ascending order.`
      );
      return;
    }
    previousName = currentName;
  }
};
