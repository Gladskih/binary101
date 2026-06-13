"use strict";

import type { ResourceDirectoryReadResult } from "./directory-reader.js";
import type { ResourceDataEntryLayout, ResourceLayoutRange } from "./layout-rules.js";
import type {
  ResourceLeafPath,
  ResourceTree
} from "./tree-types.js";
import type {
  ResourceLeafPathReadResult,
  ResourcePathNodeReadResult
} from "./tree-readers.js";

export interface ResourcePathCollections {
  top: ResourceTree["top"];
  detail: ResourceTree["detail"];
  paths: ResourceLeafPath[];
  issues: string[];
  directories: NonNullable<ResourceTree["directories"]>;
  maxDirectoryEnd: number;
  resourceDataEntries: ResourceDataEntryLayout[];
  resourceStringRanges: ResourceLayoutRange[];
  resourceSubdirectoryTargets: number[];
}

export const createEmptyResourcePathCollections = (): ResourcePathCollections => ({
  top: [],
  detail: [],
  paths: [],
  issues: [],
  directories: [],
  maxDirectoryEnd: 0,
  resourceDataEntries: [],
  resourceStringRanges: [],
  resourceSubdirectoryTargets: []
});

export const appendResourcePathIssue = (
  collections: ResourcePathCollections,
  issue: string
): ResourcePathCollections => ({
  ...collections,
  issues: [...collections.issues, issue]
});

export const mergeDirectoryReadResult = (
  collections: ResourcePathCollections,
  directory: ResourceDirectoryReadResult
): ResourcePathCollections => ({
  ...collections,
  directories: directory.directoryInfo
    ? [...collections.directories, directory.directoryInfo]
    : collections.directories,
  issues: [...collections.issues, ...directory.issues],
  maxDirectoryEnd: Math.max(collections.maxDirectoryEnd, directory.maxDirectoryEnd),
  resourceStringRanges: [
    ...collections.resourceStringRanges,
    ...directory.resourceStringRanges
  ],
  resourceSubdirectoryTargets: [
    ...collections.resourceSubdirectoryTargets,
    ...directory.resourceSubdirectoryTargets
  ]
});

export const mergePathNodeReadResult = (
  collections: ResourcePathCollections,
  result: ResourcePathNodeReadResult
): ResourcePathCollections => ({
  ...collections,
  issues: [...collections.issues, ...result.issues],
  resourceStringRanges: [
    ...collections.resourceStringRanges,
    ...result.resourceStringRanges
  ]
});

export const mergeLeafReadResult = (
  collections: ResourcePathCollections,
  result: ResourceLeafPathReadResult
): ResourcePathCollections => ({
  ...collections,
  issues: [...collections.issues, ...result.issues],
  paths: result.leaf ? [...collections.paths, result.leaf] : collections.paths,
  resourceDataEntries: result.resourceDataEntry
    ? [...collections.resourceDataEntries, result.resourceDataEntry]
    : collections.resourceDataEntries
});

export const mergeResourcePathCollections = (
  target: ResourcePathCollections,
  source: ResourcePathCollections
): ResourcePathCollections => ({
  ...target,
  detail: [...target.detail, ...source.detail],
  directories: [...target.directories, ...source.directories],
  issues: [...target.issues, ...source.issues],
  maxDirectoryEnd: Math.max(target.maxDirectoryEnd, source.maxDirectoryEnd),
  paths: [...target.paths, ...source.paths],
  resourceDataEntries: [...target.resourceDataEntries, ...source.resourceDataEntries],
  resourceStringRanges: [...target.resourceStringRanges, ...source.resourceStringRanges],
  resourceSubdirectoryTargets: [
    ...target.resourceSubdirectoryTargets,
    ...source.resourceSubdirectoryTargets
  ]
});
