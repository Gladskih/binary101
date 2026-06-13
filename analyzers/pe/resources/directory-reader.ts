"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory } from "../types.js";
import {
  validateResourceDirectoryDuplicates,
  validateResourceDirectoryEntryKinds,
  validateResourceDirectoryIdSort,
  validateResourceDirectoryNameSort,
  type ResourceDirectoryLabelReadResult
} from "./directory-rules.js";
import type { ResourceDirectoryEntry } from "./directory-rules.js";
import { readResourceDirectoryEntries } from "./directory-entry-reader.js";
import {
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE
} from "./directory-format.js";
import { updateDirectoryLayoutEnd } from "./layout-rules.js";
import type { ResourceLayoutRange } from "./layout-rules.js";
import type { ResourceSpanResolver } from "./relative-offsets.js";
import type { ResourceDirectoryInfo } from "./tree-types.js";

export interface ParsedResourceDirectory {
  namedEntries: number;
  idEntries: number;
  entries: ResourceDirectoryEntry[];
}

export interface ResourceDirectoryReadResult {
  directory: ParsedResourceDirectory | null;
  directoryInfo: ResourceDirectoryInfo | null;
  issues: string[];
  maxDirectoryEnd: number;
  resourceStringRanges: ResourceLayoutRange[];
  resourceSubdirectoryTargets: number[];
}

type ResourceDirectoryHeader = {
  characteristics: number;
  timeDateStamp: number;
  majorVersion: number;
  minorVersion: number;
  namedEntries: number;
  idEntries: number;
};

const emptyDirectoryResult = (issues: string[]): ResourceDirectoryReadResult => ({
  directory: null,
  directoryInfo: null,
  issues,
  maxDirectoryEnd: 0,
  resourceStringRanges: [],
  resourceSubdirectoryTargets: []
});

const readResourceDirectoryHeader = async (
  reader: FileRangeReader,
  resolver: ResourceSpanResolver,
  offset: number,
  rel: number
): Promise<{ header: ResourceDirectoryHeader | null; issues: string[] }> => {
  const view = await reader.read(offset, IMAGE_RESOURCE_DIRECTORY_SIZE);
  if (view.byteLength < IMAGE_RESOURCE_DIRECTORY_SIZE) {
    return {
      header: null,
      issues: [`Resource directory header at ${resolver.formatRelOffset(rel)} is truncated.`]
    };
  }
  const characteristics = view.getUint32(0, true);
  return {
    header: {
      characteristics,
      timeDateStamp: view.getUint32(4, true),
      majorVersion: view.getUint16(8, true),
      minorVersion: view.getUint16(10, true),
      namedEntries: view.getUint16(12, true),
      idEntries: view.getUint16(14, true)
    },
    issues: characteristics !== 0
      ? [
          `IMAGE_RESOURCE_DIRECTORY.Characteristics at ${resolver.formatRelOffset(rel)} `
            + "is non-zero; the field is reserved and should be 0."
        ]
      : []
  };
};

const createResourceDirectoryInfo = (
  rel: number,
  header: ResourceDirectoryHeader
): ResourceDirectoryInfo => ({
  offset: rel,
  characteristics: header.characteristics,
  timeDateStamp: header.timeDateStamp,
  majorVersion: header.majorVersion,
  minorVersion: header.minorVersion,
  namedEntries: header.namedEntries,
  idEntries: header.idEntries
});

const countReadableEntries = (
  dir: PeDataDirectory,
  resolver: ResourceSpanResolver,
  rel: number,
  declaredCount: number
): { entryCount: number; issues: string[] } => {
  const availableEntryCount = Math.max(
    0,
    Math.floor((dir.size - (rel + IMAGE_RESOURCE_DIRECTORY_SIZE)) / IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE)
  );
  const entryCount = Math.min(declaredCount, availableEntryCount);
  return {
    entryCount,
    issues: entryCount < declaredCount
      ? [
          `Resource directory at ${resolver.formatRelOffset(rel)} declares ${declaredCount} entries, `
            + `but only ${entryCount} fit in the declared span.`
        ]
      : []
  };
};

const resolveResourceDirectoryOffset = (
  resolver: ResourceSpanResolver,
  rel: number
): { offset: number } | { offset: null; issue: string } => {
  const offset = resolver.resolveRelOffset(rel, IMAGE_RESOURCE_DIRECTORY_SIZE);
  if (offset != null) return { offset };
  return {
    offset: null,
    issue: resolver.describeRelOffsetFailure(
      rel,
      IMAGE_RESOURCE_DIRECTORY_SIZE,
      `Resource directory at ${resolver.formatRelOffset(rel)}`
    )
  };
};

const readEntriesForDirectoryHeader = async (
  reader: FileRangeReader,
  dir: PeDataDirectory,
  resolver: ResourceSpanResolver,
  rel: number,
  header: ResourceDirectoryHeader
) => {
  const declaredCount = header.namedEntries + header.idEntries;
  const { entryCount, issues } = countReadableEntries(dir, resolver, rel, declaredCount);
  const localDirectoryEnd =
    rel + IMAGE_RESOURCE_DIRECTORY_SIZE + entryCount * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const table = await readResourceDirectoryEntries(reader, resolver, rel, entryCount, localDirectoryEnd);
  return {
    entries: table.entries,
    issues: [...issues, ...table.issues],
    resourceSubdirectoryTargets: table.resourceSubdirectoryTargets
  };
};

const validateParsedResourceDirectory = async (
  rel: number,
  header: ResourceDirectoryHeader,
  entries: ResourceDirectoryEntry[],
  readLabel: (rel: number) => Promise<ResourceDirectoryLabelReadResult>
): Promise<{ issues: string[]; resourceStringRanges: ResourceLayoutRange[] }> => {
  const nameSort = await validateResourceDirectoryNameSort(
    rel,
    header.namedEntries,
    entries,
    readLabel
  );
  const duplicates = await validateResourceDirectoryDuplicates(rel, entries, readLabel);
  return {
    issues: [
      ...validateResourceDirectoryEntryKinds(rel, header.namedEntries, entries),
      ...validateResourceDirectoryIdSort(rel, header.namedEntries, entries),
      ...nameSort.issues,
      ...duplicates.issues
    ],
    resourceStringRanges: [
      ...nameSort.resourceStringRanges,
      ...duplicates.resourceStringRanges
    ]
  };
};

export const readResourceDirectory = async (
  reader: FileRangeReader,
  dir: PeDataDirectory,
  resolver: ResourceSpanResolver,
  readLabel: (rel: number) => Promise<ResourceDirectoryLabelReadResult>,
  rel: number
): Promise<ResourceDirectoryReadResult> => {
  const resolved = resolveResourceDirectoryOffset(resolver, rel);
  if (resolved.offset == null) return emptyDirectoryResult([resolved.issue]);
  const headerResult = await readResourceDirectoryHeader(reader, resolver, resolved.offset, rel);
  if (!headerResult.header) return emptyDirectoryResult(headerResult.issues);
  const entriesResult = await readEntriesForDirectoryHeader(
    reader,
    dir,
    resolver,
    rel,
    headerResult.header
  );
  const validation = await validateParsedResourceDirectory(
    rel,
    headerResult.header,
    entriesResult.entries,
    readLabel
  );
  return {
    directory: {
      namedEntries: headerResult.header.namedEntries,
      idEntries: headerResult.header.idEntries,
      entries: entriesResult.entries
    },
    directoryInfo: createResourceDirectoryInfo(rel, headerResult.header),
    issues: [...headerResult.issues, ...entriesResult.issues, ...validation.issues],
    maxDirectoryEnd: updateDirectoryLayoutEnd(0, rel, entriesResult.entries.length),
    resourceStringRanges: validation.resourceStringRanges,
    resourceSubdirectoryTargets: entriesResult.resourceSubdirectoryTargets
  };
};
