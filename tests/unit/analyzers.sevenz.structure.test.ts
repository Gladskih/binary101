"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildFolderDetails, buildFileDetails } from "../../analyzers/sevenz/structure.js";
import type {
  SevenZipFolderSummary,
  SevenZipHeaderSections,
  SevenZipPackInfo,
  SevenZipSubStreamsInfo,
  SevenZipUnpackInfo,
  SevenZipFolderParseResult
} from "../../analyzers/sevenz/types.js";

type SectionOverrides = Omit<SevenZipHeaderSections, "mainStreamsInfo" | "filesInfo"> & {
  mainStreamsInfo?: {
    unpackInfo?: Partial<SevenZipUnpackInfo>;
    subStreamsInfo?: Partial<SevenZipSubStreamsInfo>;
    packInfo?: Partial<SevenZipPackInfo>;
  };
  filesInfo?: Partial<SevenZipHeaderSections["filesInfo"]>;
};

const makeSections = (overrides: SectionOverrides = {}): SevenZipHeaderSections => {
  const baseMain = overrides.mainStreamsInfo ?? {};
  const unpackInfo: SevenZipUnpackInfo = {
    external: false,
    folders: [],
    unpackSizes: [],
    ...(baseMain.unpackInfo ?? {})
  };
  const subStreamsInfo: SevenZipSubStreamsInfo = {
    numUnpackStreams: [],
    ...(baseMain.subStreamsInfo ?? {})
  };
  const packInfoOverride = baseMain.packInfo;
  const packInfo: SevenZipPackInfo | undefined = packInfoOverride
    ? { packPos: 0n, numPackStreams: 0n, packSizes: [], packCrcs: [], ...packInfoOverride }
    : undefined;
  const filesInfo: SevenZipHeaderSections["filesInfo"] = {
    files: [],
    fileCount: 0,
    ...overrides.filesInfo
  };
  const mainStreamsInfo: SevenZipHeaderSections["mainStreamsInfo"] = {
    ...(packInfo ? { packInfo } : {}),
    unpackInfo,
    subStreamsInfo
  };
  const { mainStreamsInfo: _ignoredMain, filesInfo: _ignoredFiles, ...rest } = overrides;
  return {
    ...rest,
    mainStreamsInfo,
    filesInfo
  };
};

void test("buildFolderDetails reports missing folder entry and extra sizes", () => {
  const issues: string[] = [];
  const sections = makeSections({
    mainStreamsInfo: {
      unpackInfo: { folders: [undefined as unknown as SevenZipFolderParseResult], unpackSizes: [] },
      subStreamsInfo: { numUnpackStreams: [], substreamSizes: [1n] },
      packInfo: { packSizes: [] }
    }
  });
  const result = buildFolderDetails(sections, issues);
  assert.equal(result.folders.length, 0);
  assert.ok(issues.some(msg => msg.includes("Folder entry is missing")));
  assert.ok(issues.some(msg => msg.includes("Extra substream size entries")));
});

void test("buildFileDetails warns when streams are not matched to folders", () => {
  const issues: string[] = [];
  const sections = makeSections({
    filesInfo: {
      files: [
        { index: 1, name: "orphan", hasStream: true }
      ],
      fileCount: 1
    }
  });
  const folders: SevenZipFolderSummary[] = [];
  const { files } = buildFileDetails(sections, folders, issues);
  assert.equal(files.length, 1);
  assert.ok(issues.some(msg => msg.includes("not matched")));
  assert.equal(files[0].folderIndex, null);
});
