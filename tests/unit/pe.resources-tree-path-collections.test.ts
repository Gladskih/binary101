"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createEmptyResourcePathCollections,
  mergeDirectoryReadResult,
  mergeLeafReadResult,
  mergePathNodeReadResult,
  mergeResourcePathCollections
} from "../../analyzers/pe/resources/tree-path-collections.js";

void test("resource path collections merge directory, node, leaf, and collection facts", () => {
  const target = createEmptyResourcePathCollections();
  const withDirectory = mergeDirectoryReadResult(target, {
    directory: null,
    directoryInfo: {
      offset: 0x20,
      characteristics: 0,
      timeDateStamp: 0,
      majorVersion: 0,
      minorVersion: 0,
      namedEntries: 0,
      idEntries: 0
    },
    issues: ["directory issue"],
    maxDirectoryEnd: 0x30,
    resourceStringRanges: [{ start: 0x40, end: 0x44 }],
    resourceSubdirectoryTargets: [0x20]
  });
  const withNode = mergePathNodeReadResult(withDirectory, {
    node: { id: null, name: "MAIN" },
    issues: ["node issue"],
    resourceStringRanges: [{ start: 0x44, end: 0x48 }]
  });
  const withLeaf = mergeLeafReadResult(withNode, {
    leaf: {
      nodes: [{ id: 3, name: null }],
      size: 4,
      codePage: 0,
      dataRVA: 0x2000,
      dataFileOffset: 0x80,
      reserved: 0
    },
    issues: ["leaf issue"],
    resourceDataEntry: { start: 0x50, end: 0x60, dataRva: 0x2000, dataFileOffset: 0x80, size: 4 }
  });
  const result = mergeResourcePathCollections(withLeaf, {
    ...createEmptyResourcePathCollections(),
    issues: ["source issue"],
    maxDirectoryEnd: 0x80,
    paths: [{
      nodes: [{ id: 4, name: null }],
      size: 8,
      codePage: 0,
      dataRVA: 0x3000,
      dataFileOffset: 0x90,
      reserved: 0
    }]
  });

  assert.deepStrictEqual(target, createEmptyResourcePathCollections());
  assert.deepStrictEqual(result.issues, [
    "directory issue",
    "node issue",
    "leaf issue",
    "source issue"
  ]);
  assert.deepStrictEqual(result.directories.map(directory => directory.offset), [0x20]);
  assert.deepStrictEqual(result.resourceStringRanges, [
    { start: 0x40, end: 0x44 },
    { start: 0x44, end: 0x48 }
  ]);
  assert.deepStrictEqual(result.resourceSubdirectoryTargets, [0x20]);
  assert.deepStrictEqual(result.resourceDataEntries.map(entry => entry.start), [0x50]);
  assert.deepStrictEqual(result.paths.map(path => path.size), [4, 8]);
  assert.equal(result.maxDirectoryEnd, 0x80);
});
