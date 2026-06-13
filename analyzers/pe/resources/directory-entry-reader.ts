"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { ResourceDirectoryEntry } from "./directory-rules.js";
import {
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE,
  RESOURCE_DIRECTORY_HIGH_BIT,
  RESOURCE_DIRECTORY_OFFSET_MASK
} from "./directory-format.js";
import type { ResourceSpanResolver } from "./relative-offsets.js";

export interface ResourceDirectoryEntryTable {
  entries: ResourceDirectoryEntry[];
  issues: string[];
  resourceSubdirectoryTargets: number[];
}

const emptyEntryTable = (): ResourceDirectoryEntryTable => ({
  entries: [],
  issues: [],
  resourceSubdirectoryTargets: []
});

const decodeResourceDirectoryEntry = (
  view: DataView,
  offset: number,
  localDirectoryEnd: number
): ResourceDirectoryEntry => {
  const nameField = view.getUint32(offset, true);
  const targetField = view.getUint32(offset + 4, true);
  const nameIsString = (nameField & RESOURCE_DIRECTORY_HIGH_BIT) !== 0;
  const nameOrId = nameIsString
    ? (nameField & RESOURCE_DIRECTORY_OFFSET_MASK)
    : (nameField >>> 0);
  return {
    nameIsString,
    subdir: (targetField & RESOURCE_DIRECTORY_HIGH_BIT) !== 0,
    nameOrId,
    target: targetField & RESOURCE_DIRECTORY_OFFSET_MASK,
    ...(nameIsString && nameOrId < localDirectoryEnd ? { invalidNameOffset: true } : {})
  };
};

const getResourceDirectoryEntryIssues = (
  resolver: ResourceSpanResolver,
  rel: number,
  entry: ResourceDirectoryEntry
): string[] => [
  ...(entry.invalidNameOffset && entry.nameOrId != null
    ? [
        `Resource string name at ${resolver.formatRelOffset(entry.nameOrId)} `
          + "points into the directory-entry area."
      ]
    : []),
  ...(entry.subdir && entry.target === rel
    ? [
        `Resource directory at ${resolver.formatRelOffset(rel)} has a subdirectory entry that points to itself.`
      ]
    : [])
];

const appendResourceDirectoryEntry = (
  table: ResourceDirectoryEntryTable,
  resolver: ResourceSpanResolver,
  rel: number,
  entry: ResourceDirectoryEntry
): ResourceDirectoryEntryTable => ({
  entries: [...table.entries, entry],
  issues: [...table.issues, ...getResourceDirectoryEntryIssues(resolver, rel, entry)],
  resourceSubdirectoryTargets: entry.subdir
    ? [...table.resourceSubdirectoryTargets, entry.target]
    : table.resourceSubdirectoryTargets
});

const readEntryTable = async (
  reader: FileRangeReader,
  resolver: ResourceSpanResolver,
  rel: number,
  entryCount: number,
  localDirectoryEnd: number,
  offset: number
): Promise<ResourceDirectoryEntryTable> => {
  const view = await reader.read(offset, entryCount * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE);
  const readableEntries = Math.min(
    entryCount,
    Math.floor(view.byteLength / IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE)
  );
  const truncatedIssues = readableEntries < entryCount
    ? [`Resource directory entries for ${resolver.formatRelOffset(rel)} are truncated.`]
    : [];
  let table = { ...emptyEntryTable(), issues: truncatedIssues };
  for (let index = 0; index < readableEntries; index += 1) {
    table = appendResourceDirectoryEntry(
      table,
      resolver,
      rel,
      decodeResourceDirectoryEntry(
        view,
        index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
        localDirectoryEnd
      )
    );
  }
  return table;
};

const readEntriesIndividually = async (
  reader: FileRangeReader,
  resolver: ResourceSpanResolver,
  rel: number,
  entryCount: number,
  localDirectoryEnd: number
): Promise<ResourceDirectoryEntryTable> => {
  let table = emptyEntryTable();
  for (let index = 0; index < entryCount; index += 1) {
    const entryRel = rel + IMAGE_RESOURCE_DIRECTORY_SIZE
      + index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
    const entryOff = resolver.resolveRelOffset(entryRel, IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE);
    if (entryOff == null) {
      return {
        ...table,
        issues: [
          ...table.issues,
          `Resource directory entries for ${resolver.formatRelOffset(rel)} extend past the declared span.`
        ]
      };
    }
    const view = await reader.read(entryOff, IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE);
    if (view.byteLength < IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE) {
      return {
        ...table,
        issues: [
          ...table.issues,
          `Resource directory entry at ${resolver.formatRelOffset(entryRel)} is truncated.`
        ]
      };
    }
    table = appendResourceDirectoryEntry(
      table,
      resolver,
      rel,
      decodeResourceDirectoryEntry(view, 0, localDirectoryEnd)
    );
  }
  return table;
};

export const readResourceDirectoryEntries = async (
  reader: FileRangeReader,
  resolver: ResourceSpanResolver,
  rel: number,
  entryCount: number,
  localDirectoryEnd: number
): Promise<ResourceDirectoryEntryTable> => {
  if (entryCount === 0) return emptyEntryTable();
  const entriesByteLength = entryCount * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const entriesOff = resolver.resolveRelOffset(
    rel + IMAGE_RESOURCE_DIRECTORY_SIZE,
    entriesByteLength
  );
  if (entriesOff == null) {
    return await readEntriesIndividually(reader, resolver, rel, entryCount, localDirectoryEnd);
  }
  return await readEntryTable(reader, resolver, rel, entryCount, localDirectoryEnd, entriesOff);
};
