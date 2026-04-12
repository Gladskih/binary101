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

type ResourceDirectoryTraversalFrame = {
  ancestors: Set<number>;
  entries?: ResourceDirectoryEntry[];
  index: number;
  localDirectoryEnd?: number;
  nextAncestors?: Set<number>;
  nodes: ResourcePathNode[];
  rel: number;
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
  expandedDirectories: Set<number>,
  parseDir: (rel: number) => Promise<{ entries: ResourceDirectoryEntry[] } | null>,
  readPathNode: (entry: ResourceDirectoryEntry) => Promise<ResourcePathNode>,
  readLeafPath: (target: number, nodes: ResourcePathNode[]) => Promise<ResourceLeafPath | null>,
  formatRelOffset: (rel: number) => string,
  detailGroups: Map<string, ResourceDetailGroupState>,
  addIssue: (message: string) => void
): Promise<ResourceLeafPath[]> => {
  const leaves: ResourceLeafPath[] = [];
  const frames: ResourceDirectoryTraversalFrame[] = [{ ancestors, index: 0, nodes, rel }];
  while (frames.length) {
    const frame = frames[frames.length - 1]!;
    if (!frame.entries) {
      if (frame.ancestors.has(frame.rel)) {
        addIssue(`Resource directory graph contains a cycle at ${formatRelOffset(frame.rel)}.`);
        frames.pop();
        continue;
      }
      if (expandedDirectories.has(frame.rel)) {
        addIssue(
          `Resource directory graph re-enters ${formatRelOffset(frame.rel)} from multiple parent paths; `
            + "skipping repeated traversal."
        );
        frames.pop();
        continue;
      }
      expandedDirectories.add(frame.rel);
      const directory = await parseDir(frame.rel);
      if (!directory) {
        frames.pop();
        continue;
      }
      frame.entries = directory.entries;
      frame.localDirectoryEnd =
        frame.rel + 16 + directory.entries.length * 8;
      frame.nextAncestors = new Set(frame.ancestors);
      frame.nextAncestors.add(frame.rel);
    }
    const entry = frame.entries[frame.index];
    if (!entry) {
      frames.pop();
      continue;
    }
    frame.index += 1;
    const node = await readPathNode(entry);
    const nextNodes = [...frame.nodes, node];
    if (entry.subdir) {
      if (entry.target < (frame.localDirectoryEnd ?? frame.rel + 16)) {
        addIssue(
          `Resource subdirectory at ${formatRelOffset(entry.target)} points into the current `
            + `directory-entry area at ${formatRelOffset(frame.rel)}.`
        );
        continue;
      }
      frames.push({
        ancestors: frame.nextAncestors!,
        index: 0,
        nodes: nextNodes,
        rel: entry.target
      });
      continue;
    }
    if (entry.target < (frame.localDirectoryEnd ?? frame.rel + 16)) {
      addIssue(
        `Resource data entry at ${formatRelOffset(entry.target)} points into the current `
          + `directory-entry area at ${formatRelOffset(frame.rel)}.`
      );
      continue;
    }
    const leaf = await readLeafPath(entry.target, nextNodes);
    if (!leaf) {
      continue;
    }
    leaves.push(leaf);
    // Microsoft PE format, ".rsrc Section":
    // Windows convention is type -> name/ID -> language, so a leaf directly below the type
    // directory means the second-level name/ID directory is missing.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
    if (frame.nodes.length === 1) {
      addIssue(
        `Resource entry under type ${typeName} points directly to data; second-level entries should point to language subdirectories.`
      );
      continue;
    }
    // Microsoft PE format, ".rsrc Section":
    // the canonical Windows leaf depth is three nodes: type -> name/ID -> language.
    // Deeper valid paths are preserved in `paths`, but only canonical leaves populate `detail`.
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
  const expandedDirectories = new Set<number>();
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
      expandedDirectories,
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
      // Microsoft PE format, ".rsrc Section":
      // `top[].leafCount` intentionally reports only canonical Windows leaves
      // (type -> name/ID -> language), not deeper valid paths.
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
