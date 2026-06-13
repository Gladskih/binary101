"use strict";

import type {
  ResourceDetailEntry,
  ResourceLangEntry,
  ResourceLeafPath,
  ResourcePathNode
} from "./tree-types.js";

const createDetailKey = (nameNode: ResourcePathNode): string =>
  nameNode.name != null ? `name:${nameNode.name}` : `id:${nameNode.id ?? -1}`;

const createLangEntry = (leaf: ResourceLeafPath): ResourceLangEntry => ({
  lang: leaf.nodes[2]?.id ?? null,
  size: leaf.size,
  codePage: leaf.codePage,
  dataRVA: leaf.dataRVA,
  dataFileOffset: leaf.dataFileOffset,
  reserved: leaf.reserved
});

const appendLeafDetail = (
  entries: ResourceDetailEntry[],
  leaf: ResourceLeafPath
): ResourceDetailEntry[] => {
  const nameNode = leaf.nodes[1]!;
  const key = createDetailKey(nameNode);
  const existing = entries.find(entry => createDetailKey(entry) === key);
  if (!existing) {
    return [
      ...entries,
      { id: nameNode.id, name: nameNode.name, langs: [createLangEntry(leaf)] }
    ];
  }
  return entries.map(entry => entry === existing
    ? { ...entry, langs: [...entry.langs, createLangEntry(leaf)] }
    : entry
  );
};

export const createResourceDetailEntries = (
  paths: ResourceLeafPath[]
): ResourceDetailEntry[] =>
  paths.reduce(
    (entries, leaf) => leaf.nodes.length === 3 ? appendLeafDetail(entries, leaf) : entries,
    [] as ResourceDetailEntry[]
  );
