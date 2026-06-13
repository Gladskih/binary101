"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ResourceDirectoryReadResult } from "../../analyzers/pe/resources/directory-reader.js";
import type { ResourceDirectoryEntry } from "../../analyzers/pe/resources/directory-rules.js";
import type { ResourceLeafPath, ResourcePathNode } from "../../analyzers/pe/resources/tree-types.js";
import { buildResourcePathCollections } from "../../analyzers/pe/resources/tree-paths.js";

const directoryEntry = (
  nameOrId: number,
  target: number,
  subdir: boolean
): ResourceDirectoryEntry => ({
  nameIsString: false,
  nameOrId,
  subdir,
  target
});

const directoryResult = (
  rel: number,
  entries: ResourceDirectoryEntry[] | null
): ResourceDirectoryReadResult => ({
  directory: entries ? { namedEntries: 0, idEntries: entries.length, entries } : null,
  directoryInfo: null,
  issues: [],
  maxDirectoryEnd: entries ? rel + 16 + entries.length * 8 : 0,
  resourceStringRanges: [],
  resourceSubdirectoryTargets: entries?.filter(entry => entry.subdir).map(entry => entry.target) || []
});

const readPathNode = async (entry: ResourceDirectoryEntry) => ({
  node: { id: entry.nameOrId, name: null },
  issues: [],
  resourceStringRanges: []
});

const createLeaf = (
  nodes: ResourcePathNode[],
  target: number
): ResourceLeafPath => ({
  nodes,
  size: target,
  codePage: 1252,
  dataRVA: 0x2000 + target,
  dataFileOffset: 0x40 + target,
  reserved: 0
});

void test("buildResourcePathCollections merges only matching repeated type details", async () => {
  const result = await buildResourcePathCollections(
    [directoryEntry(98, 0x20, true), directoryEntry(99, 0x60, true), directoryEntry(99, 0xa0, true)],
    async rel => {
      if (rel === 0x20) return directoryResult(rel, [directoryEntry(1, 0x40, true)]);
      if (rel === 0x40) return directoryResult(rel, [directoryEntry(1033, 0xe0, false)]);
      if (rel === 0x60) return directoryResult(rel, [directoryEntry(2, 0x80, true)]);
      if (rel === 0x80) return directoryResult(rel, [directoryEntry(1033, 0x100, false)]);
      if (rel === 0xa0) return directoryResult(rel, [directoryEntry(3, 0xc0, true)]);
      if (rel === 0xc0) return directoryResult(rel, [directoryEntry(1031, 0x120, false)]);
      return directoryResult(rel, null);
    },
    async (target, nodes) => ({ leaf: createLeaf(nodes, target), issues: [], resourceDataEntry: null }),
    readPathNode
  );

  assert.deepStrictEqual(result.detail.map(detail => ({
    typeName: detail.typeName,
    ids: detail.entries.map(entry => entry.id)
  })), [
    { typeName: "TYPE_98", ids: [1] },
    { typeName: "TYPE_99", ids: [2, 3] }
  ]);
});

void test("buildResourcePathCollections checks targets against the full directory-entry area", async () => {
  const result = await buildResourcePathCollections(
    [directoryEntry(99, 0x20, true)],
    async rel => directoryResult(rel, [
      directoryEntry(1, 0x38, false),
      directoryEntry(2, 0x80, false)
    ]),
    async (target, nodes) => ({ leaf: createLeaf(nodes, target), issues: [], resourceDataEntry: null }),
    readPathNode
  );

  assert.deepStrictEqual(result.paths.map(path => path.size), [0x80]);
  assert.deepStrictEqual(result.issues, [
    "Resource data entry at 0x38 points into the current directory-entry area at 0x20.",
    "Resource entry under type TYPE_99 points directly to data; "
      + "second-level entries should point to language subdirectories."
  ]);
});
