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

const namedDirectoryEntry = (
  nameOrId: number,
  target: number,
  subdir: boolean
): ResourceDirectoryEntry => ({
  nameIsString: true,
  nameOrId,
  subdir,
  target
});

const directoryResult = (
  rel: number,
  entries: ResourceDirectoryEntry[] | null
): ResourceDirectoryReadResult => ({
  directory: entries ? { namedEntries: 0, idEntries: entries.length, entries } : null,
  directoryInfo: entries
    ? {
        offset: rel,
        characteristics: 0,
        timeDateStamp: 0,
        majorVersion: 0,
        minorVersion: 0,
        namedEntries: 0,
        idEntries: entries.length
      }
    : null,
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

void test("buildResourcePathCollections builds canonical detail entries with file offsets", async () => {
  const result = await buildResourcePathCollections(
    [directoryEntry(3, 0x20, true)],
    async rel => {
      if (rel === 0x20) return directoryResult(rel, [directoryEntry(1, 0x40, true)]);
      if (rel === 0x40) {
        return directoryResult(rel, [
          directoryEntry(1033, 0x60, false),
          directoryEntry(1031, 0x68, false)
        ]);
      }
      return directoryResult(rel, null);
    },
    async (target, nodes) => ({
      leaf: createLeaf(nodes, target),
      issues: [],
      resourceDataEntry: {
        start: target,
        end: target + 16,
        dataRva: 0x2000 + target,
        dataFileOffset: 0x40 + target,
        size: target
      }
    }),
    readPathNode
  );

  assert.deepStrictEqual(result.top, [{ typeName: "ICON", kind: "id", leafCount: 2 }]);
  assert.deepStrictEqual(result.detail, [{
    typeName: "ICON",
    entries: [{
      id: 1,
      name: null,
      langs: [
        { lang: 1033, size: 0x60, codePage: 1252, dataRVA: 0x2060, dataFileOffset: 0xa0, reserved: 0 },
        { lang: 1031, size: 0x68, codePage: 1252, dataRVA: 0x2068, dataFileOffset: 0xa8, reserved: 0 }
      ]
    }]
  }]);
  assert.equal(result.paths.length, 2);
  assert.deepStrictEqual(result.issues, []);
  assert.deepStrictEqual(result.directories.map(directory => directory.offset), [0x20, 0x40]);
  assert.deepStrictEqual(result.resourceDataEntries.map(entry => entry.start), [0x60, 0x68]);
});

void test("buildResourcePathCollections reports top-level data and failed leaf reads", async () => {
  let capturedNodes: ResourcePathNode[] | null = null;
  const result = await buildResourcePathCollections(
    [directoryEntry(3, 0x20, false)],
    async rel => directoryResult(rel, null),
    async (_target, nodes) => {
      capturedNodes = nodes;
      return { leaf: null, issues: ["leaf failed"], resourceDataEntry: null };
    },
    readPathNode
  );

  assert.deepStrictEqual(capturedNodes, [{ id: 3, name: null }]);
  assert.deepStrictEqual(result.top, [{ typeName: "ICON", kind: "id", leafCount: 0 }]);
  assert.deepStrictEqual(result.detail, []);
  assert.deepStrictEqual(result.paths, []);
  assert.deepStrictEqual(result.issues, [
    "leaf failed",
    "Top-level resource type entry ICON points directly to data; "
      + "type entries should point to second-level subdirectories."
  ]);
});

void test("buildResourcePathCollections records failed subdirectory reads without leaf paths", async () => {
  const result = await buildResourcePathCollections(
    [directoryEntry(99, 0x20, true)],
    async rel => ({
      ...directoryResult(rel, null),
      issues: [`directory ${rel} failed`]
    }),
    async (target, nodes) => ({
      leaf: createLeaf(nodes, target),
      issues: [],
      resourceDataEntry: null
    }),
    readPathNode
  );

  assert.deepStrictEqual(result.top, [{ typeName: "TYPE_99", kind: "id", leafCount: 0 }]);
  assert.deepStrictEqual(result.paths, []);
  assert.deepStrictEqual(result.issues, ["directory 32 failed"]);
});

void test("buildResourcePathCollections does not add direct-data warnings when leaf reads fail", async () => {
  const result = await buildResourcePathCollections(
    [directoryEntry(99, 0x20, true)],
    async rel => directoryResult(rel, [directoryEntry(1, 0x40, false)]),
    async () => ({ leaf: null, issues: ["leaf failed"], resourceDataEntry: null }),
    readPathNode
  );

  assert.deepStrictEqual(result.paths, []);
  assert.deepStrictEqual(result.issues, ["leaf failed"]);
});

void test("buildResourcePathCollections reports second-level entries that point directly to data", async () => {
  const result = await buildResourcePathCollections(
    [directoryEntry(99, 0x20, true)],
    async rel => directoryResult(rel, [directoryEntry(1, 0x40, false)]),
    async (target, nodes) => ({ leaf: createLeaf(nodes, target), issues: [], resourceDataEntry: null }),
    readPathNode
  );

  assert.deepStrictEqual(result.issues, [
    "Resource entry under type TYPE_99 points directly to data; "
      + "second-level entries should point to language subdirectories."
  ]);
});

void test("buildResourcePathCollections derives named top-level type names from path nodes", async () => {
  const result = await buildResourcePathCollections(
    [namedDirectoryEntry(0x80, 0x20, false)],
    async rel => directoryResult(rel, null),
    async () => ({ leaf: null, issues: [], resourceDataEntry: null }),
    async entry => ({
      node: { id: null, name: `name-${entry.nameOrId}` },
      issues: ["name issue"],
      resourceStringRanges: [{ start: entry.nameOrId ?? 0, end: (entry.nameOrId ?? 0) + 4 }]
    })
  );

  assert.deepStrictEqual(result.top, [{ typeName: "name-128", kind: "name", leafCount: 0 }]);
  assert.deepStrictEqual(result.issues, [
    "name issue",
    "Top-level resource type entry name-128 points directly to data; "
      + "type entries should point to second-level subdirectories."
  ]);
  assert.deepStrictEqual(result.resourceStringRanges, [{ start: 0x80, end: 0x84 }]);
});

void test("buildResourcePathCollections labels invalid named top-level types generically", async () => {
  const result = await buildResourcePathCollections(
    [namedDirectoryEntry(0x80, 0x20, false)],
    async rel => directoryResult(rel, null),
    async () => ({ leaf: null, issues: [], resourceDataEntry: null }),
    async () => ({ node: { id: null, name: null }, issues: [], resourceStringRanges: [] })
  );

  assert.deepStrictEqual(result.top, [{ typeName: "(named)", kind: "name", leafCount: 0 }]);
});

void test("buildResourcePathCollections merges detail entries for repeated type names", async () => {
  const result = await buildResourcePathCollections(
    [directoryEntry(99, 0x20, true), directoryEntry(99, 0x60, true)],
    async rel => {
      if (rel === 0x20) return directoryResult(rel, [directoryEntry(1, 0x40, true)]);
      if (rel === 0x40) return directoryResult(rel, [directoryEntry(1033, 0x80, false)]);
      if (rel === 0x60) return directoryResult(rel, [directoryEntry(2, 0xa0, true)]);
      if (rel === 0xa0) return directoryResult(rel, [directoryEntry(1031, 0xc0, false)]);
      return directoryResult(rel, null);
    },
    async (target, nodes) => ({
      leaf: createLeaf(nodes, target),
      issues: [],
      resourceDataEntry: null
    }),
    readPathNode
  );

  assert.deepStrictEqual(result.detail, [{
    typeName: "TYPE_99",
    entries: [
      {
        id: 1,
        name: null,
        langs: [{ lang: 1033, size: 0x80, codePage: 1252, dataRVA: 0x2080, dataFileOffset: 0xc0, reserved: 0 }]
      },
      {
        id: 2,
        name: null,
        langs: [{ lang: 1031, size: 0xc0, codePage: 1252, dataRVA: 0x20c0, dataFileOffset: 0x100, reserved: 0 }]
      }
    ]
  }]);
});

void test("buildResourcePathCollections reports repeated directories and bad local targets", async () => {
  const result = await buildResourcePathCollections(
    [directoryEntry(99, 0x20, true), directoryEntry(100, 0x20, true)],
    async rel => directoryResult(rel, [
      directoryEntry(1, 0x24, true),
      directoryEntry(2, 0x28, false)
    ]),
    async (target, nodes) => ({
      leaf: createLeaf(nodes, target),
      issues: [],
      resourceDataEntry: null
    }),
    readPathNode
  );

  assert.deepStrictEqual(result.top, [
    { typeName: "TYPE_99", kind: "id", leafCount: 0 },
    { typeName: "TYPE_100", kind: "id", leafCount: 0 }
  ]);
  assert.deepStrictEqual(result.paths, []);
  assert.deepStrictEqual(result.issues, [
    "Resource subdirectory at 0x24 points into the current directory-entry area at 0x20.",
    "Resource data entry at 0x28 points into the current directory-entry area at 0x20.",
    "Resource directory graph re-enters 0x20 from multiple parent paths; skipping repeated traversal."
  ]);
});
