"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildFolderDetails, buildFileDetails } from "../../dist/analyzers/sevenz/structure.js";

const makeSections = overrides => ({
  mainStreamsInfo: {
    unpackInfo: {
      folders: [],
      unpackSizes: []
    },
    subStreamsInfo: {
      numUnpackStreams: []
    },
    ...overrides?.mainStreamsInfo
  },
  filesInfo: { files: [], fileCount: 0, ...overrides?.filesInfo },
  ...overrides
});

test("buildFolderDetails reports missing folder entry and extra sizes", () => {
  const issues = [];
  const sections = makeSections({
    mainStreamsInfo: {
      unpackInfo: { folders: [undefined], unpackSizes: [] },
      subStreamsInfo: { numUnpackStreams: [], substreamSizes: [1n] },
      packInfo: { packSizes: [] }
    }
  });
  const result = buildFolderDetails(sections, issues);
  assert.equal(result.folders.length, 0);
  assert.ok(issues.some(msg => msg.includes("Folder entry is missing")));
  assert.ok(issues.some(msg => msg.includes("Extra substream size entries")));
});

test("buildFileDetails warns when streams are not matched to folders", () => {
  const issues = [];
  const sections = makeSections({
    filesInfo: {
      files: [
        { index: 1, name: "orphan", hasStream: true }
      ],
      fileCount: 1
    }
  });
  const { files } = buildFileDetails(sections, [], issues);
  assert.equal(files.length, 1);
  assert.ok(issues.some(msg => msg.includes("not matched")));
  assert.equal(files[0].folderIndex, null);
});
