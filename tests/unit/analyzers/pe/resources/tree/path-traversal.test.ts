"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  collectResourceLeafPaths,
  type ReadResourceDirectory,
  type ReadResourceLeafPath,
  type ReadResourcePathNode
} from "../../../../../../analyzers/pe/resources/tree-path-traversal.js";

const readDirectory: ReadResourceDirectory = async rel => ({
  directory: {
    namedEntries: 0,
    idEntries: 1,
    entries: [{ nameIsString: false, nameOrId: 1033, subdir: false, target: 64 }]
  },
  directoryInfo: null,
  issues: [],
  // IMAGE_RESOURCE_DIRECTORY (16 bytes) followed by one 8-byte entry.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-table
  maxDirectoryEnd: rel + 24,
  resourceStringRanges: [],
  resourceSubdirectoryTargets: []
});

const readLeaf: ReadResourceLeafPath = async (target, nodes) => ({
  leaf: { nodes, dataRVA: target, dataFileOffset: target, size: 1, codePage: 0, reserved: 0 },
  issues: [],
  resourceDataEntry: null
});

const readPathNode: ReadResourcePathNode = async entry => ({
  node: { id: entry.nameOrId, name: null }, issues: [], resourceStringRanges: []
});

void test("collectResourceLeafPaths accepts an empty initial path without a second-level warning", async () => {
  const result = await collectResourceLeafPaths(
    "ICON", 0, [], readDirectory, readLeaf, readPathNode, new Set()
  );

  assert.deepEqual(result.paths.map(path => path.nodes), [[{ id: 1033, name: null }]]);
  assert.deepEqual(result.issues, []);
});
