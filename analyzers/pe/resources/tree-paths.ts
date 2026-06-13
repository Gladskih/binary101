"use strict";

import type { ResourceDirectoryEntry } from "./directory-rules.js";
import { knownResourceType } from "./type-names.js";
import { createResourceDetailEntries } from "./tree-detail.js";
import type { ResourceLeafPath, ResourcePathNode } from "./tree-types.js";
import {
  appendResourcePathIssue,
  createEmptyResourcePathCollections,
  mergeLeafReadResult,
  mergePathNodeReadResult,
  mergeResourcePathCollections,
  type ResourcePathCollections
} from "./tree-path-collections.js";
import {
  collectResourceLeafPaths,
  type ReadResourceDirectory,
  type ReadResourceLeafPath,
  type ReadResourcePathNode
} from "./tree-path-traversal.js";

const addResourceTopEntry = (
  collections: ResourcePathCollections,
  typeName: string,
  kind: "name" | "id",
  leafCount: number
): ResourcePathCollections => ({
  ...collections,
  top: [...collections.top, { typeName, kind, leafCount }]
});

const appendResourceDetail = (
  collections: ResourcePathCollections,
  typeName: string,
  paths: ResourceLeafPath[]
): ResourcePathCollections => {
  const entries = createResourceDetailEntries(paths);
  if (!entries.length) return collections;
  const existingIndex = collections.detail.findIndex(detail => detail.typeName === typeName);
  if (existingIndex === -1) {
    return {
      ...collections,
      detail: [...collections.detail, { typeName, entries }]
    };
  }
  const existing = collections.detail[existingIndex]!;
  return {
    ...collections,
    detail: collections.detail.map((detail, index) => index === existingIndex
      ? { typeName, entries: [...existing.entries, ...entries] }
      : detail)
  };
};

const getResourceTypeName = (
  entry: ResourceDirectoryEntry,
  node: ResourcePathNode
): string => {
  if (node.name != null) return node.name;
  if (!entry.nameIsString && node.id != null) {
    return knownResourceType(node.id) || `TYPE_${node.id}`;
  }
  return "(named)";
};

const appendDirectTypeEntry = async (
  collections: ResourcePathCollections,
  typeEntry: ResourceDirectoryEntry,
  typeNode: ResourcePathNode,
  typeName: string,
  readLeafPath: ReadResourceLeafPath
): Promise<ResourcePathCollections> => {
  const withLeaf = mergeLeafReadResult(
    collections,
    await readLeafPath(typeEntry.target, [typeNode])
  );
  const withIssue = appendResourcePathIssue(
    withLeaf,
    `Top-level resource type entry ${typeName} points directly to data; `
      + "type entries should point to second-level subdirectories."
  );
  return addResourceTopEntry(withIssue, typeName, typeEntry.nameIsString ? "name" : "id", 0);
};

export const buildResourcePathCollections = async (
  rootEntries: ResourceDirectoryEntry[],
  readDirectory: ReadResourceDirectory,
  readLeafPath: ReadResourceLeafPath,
  readPathNode: ReadResourcePathNode
): Promise<ResourcePathCollections> => {
  let collections = createEmptyResourcePathCollections();
  const expandedDirectories = new Set<number>();
  for (const typeEntry of rootEntries) {
    const typeNode = await readPathNode(typeEntry);
    collections = mergePathNodeReadResult(collections, typeNode);
    const typeName = getResourceTypeName(typeEntry, typeNode.node);
    if (!typeEntry.subdir) {
      collections = await appendDirectTypeEntry(
        collections,
        typeEntry,
        typeNode.node,
        typeName,
        readLeafPath
      );
      continue;
    }
    const typePaths = await collectResourceLeafPaths(
      typeName,
      typeEntry.target,
      [typeNode.node],
      readDirectory,
      readLeafPath,
      readPathNode,
      expandedDirectories
    );
    collections = mergeResourcePathCollections(collections, typePaths);
    collections = addResourceTopEntry(
      collections,
      typeName,
      typeEntry.nameIsString ? "name" : "id",
      // Microsoft PE format, ".rsrc Section":
      // `top[].leafCount` intentionally reports only canonical Windows leaves
      // (type -> name/ID -> language), not deeper valid paths.
      typePaths.paths.filter(path => path.nodes.length === 3).length
    );
    collections = appendResourceDetail(collections, typeName, typePaths.paths);
  }
  return collections;
};
