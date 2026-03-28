"use strict";

import type { ResourceDirectoryEntry } from "./directory-rules.js";
import type {
  ResourceDetailEntry,
  ResourceLeafPath,
  ResourcePathNode,
  ResourceTree
} from "./tree-types.js";

type ResourceDetailGroupState = {
  entries: ResourceDetailEntry[];
  entryByKey: Map<string, ResourceDetailEntry>;
};

const ensureDetailEntry = (
  groups: Map<string, ResourceDetailGroupState>,
  typeName: string,
  nameNode: ResourcePathNode
): ResourceDetailEntry => {
  const group = groups.get(typeName) || {
    entries: [],
    entryByKey: new Map<string, ResourceDetailEntry>()
  };
  if (!groups.has(typeName)) {
    groups.set(typeName, group);
  }
  const key = nameNode.name != null ? `name:${nameNode.name}` : `id:${nameNode.id ?? -1}`;
  const existing = group.entryByKey.get(key);
  if (existing) {
    return existing;
  }
  const created: ResourceDetailEntry = {
    id: nameNode.id,
    name: nameNode.name,
    langs: []
  };
  group.entries.push(created);
  group.entryByKey.set(key, created);
  return created;
};

const collectLeafPaths = async (
  typeName: string,
  rel: number,
  nodes: ResourcePathNode[],
  ancestors: Set<number>,
  parseDir: (rel: number) => Promise<{ entries: ResourceDirectoryEntry[] } | null>,
  readPathNode: (entry: ResourceDirectoryEntry) => Promise<ResourcePathNode>,
  readLeafPath: (target: number, nodes: ResourcePathNode[]) => Promise<ResourceLeafPath | null>,
  formatRelOffset: (rel: number) => string,
  detailGroups: Map<string, ResourceDetailGroupState>,
  addIssue: (message: string) => void
): Promise<ResourceLeafPath[]> => {
  if (ancestors.has(rel)) {
    addIssue(`Resource directory graph contains a cycle at ${formatRelOffset(rel)}.`);
    return [];
  }
  const directory = await parseDir(rel);
  if (!directory) {
    return [];
  }
  const nextAncestors = new Set(ancestors);
  nextAncestors.add(rel);
  const leaves: ResourceLeafPath[] = [];
  for (const entry of directory.entries) {
    const node = await readPathNode(entry);
    const nextNodes = [...nodes, node];
    if (entry.subdir) {
      leaves.push(
        ...await collectLeafPaths(
          typeName,
          entry.target,
          nextNodes,
          nextAncestors,
          parseDir,
          readPathNode,
          readLeafPath,
          formatRelOffset,
          detailGroups,
          addIssue
        )
      );
      continue;
    }
    const leaf = await readLeafPath(entry.target, nextNodes);
    if (!leaf) {
      continue;
    }
    leaves.push(leaf);
    if (nodes.length === 1) {
      addIssue(
        `Resource entry under type ${typeName} points directly to data; second-level entries should point to language subdirectories.`
      );
      continue;
    }
    if (nextNodes.length === 3) {
      ensureDetailEntry(detailGroups, typeName, nextNodes[1]!).langs.push({
        lang: nextNodes[2]?.id ?? null,
        size: leaf.size,
        codePage: leaf.codePage,
        dataRVA: leaf.dataRVA,
        reserved: leaf.reserved
      });
    }
  }
  return leaves;
};

export const buildResourcePathCollections = async (
  rootEntries: ResourceDirectoryEntry[],
  parseDir: (rel: number) => Promise<{ entries: ResourceDirectoryEntry[] } | null>,
  readPathNode: (entry: ResourceDirectoryEntry) => Promise<ResourcePathNode>,
  readTypeName: (entry: ResourceDirectoryEntry) => Promise<string>,
  readLeafPath: (target: number, nodes: ResourcePathNode[]) => Promise<ResourceLeafPath | null>,
  formatRelOffset: (rel: number) => string,
  addIssue: (message: string) => void
): Promise<{
  top: ResourceTree["top"];
  detail: ResourceTree["detail"];
  paths: ResourceLeafPath[];
}> => {
  const top: ResourceTree["top"] = [];
  const paths: ResourceLeafPath[] = [];
  const detailGroups = new Map<string, ResourceDetailGroupState>();
  for (const typeEntry of rootEntries) {
    const typeName = await readTypeName(typeEntry);
    const typeNode = await readPathNode(typeEntry);
    if (!typeEntry.subdir) {
      const leaf = await readLeafPath(typeEntry.target, [typeNode]);
      if (leaf) {
        paths.push(leaf);
      }
      addIssue(
        `Top-level resource type entry ${typeName} points directly to data; type entries should point to second-level subdirectories.`
      );
      top.push({ typeName, kind: typeEntry.nameIsString ? "name" : "id", leafCount: 0 });
      continue;
    }
    const typePaths = await collectLeafPaths(
      typeName,
      typeEntry.target,
      [typeNode],
      new Set<number>(),
      parseDir,
      readPathNode,
      readLeafPath,
      formatRelOffset,
      detailGroups,
      addIssue
    );
    paths.push(...typePaths);
    top.push({
      typeName,
      kind: typeEntry.nameIsString ? "name" : "id",
      leafCount: typePaths.filter(path => path.nodes.length === 3).length
    });
  }
  const detail = top
    .map(({ typeName }) => {
      const group = detailGroups.get(typeName);
      return group ? { typeName, entries: group.entries } : null;
    })
    .filter((group): group is { typeName: string; entries: ResourceDetailEntry[] } => group != null);
  return { top, detail, paths };
};
