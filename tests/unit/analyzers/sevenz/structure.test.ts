"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildFolderDetails, buildFileDetails } from "../../../../analyzers/sevenz/structure.js";
import type {
  SevenZipCoder,
  SevenZipFolderSummary,
  SevenZipHeaderSections,
  SevenZipPackInfo,
  SevenZipSubStreamsInfo,
  SevenZipUnpackInfo,
  SevenZipFolderParseResult
} from "../../../../analyzers/sevenz/types.js";
import { parseSevenZip } from "../../../../analyzers/sevenz/index.js";
import { lzma2SevenZipPlain } from "../../../fixtures/lzma2-sevenzip-file.js";
import { MockFile } from "../../../helpers/mock-file.js";

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
  const file = files[0];
  assert.ok(file);
  assert.equal(file.folderIndex, null);
});

for (const [name, coders, error] of [
  ["valid LZMA2", [{ id: "LZMA2", methodId: "21", numInStreams: 1, numOutStreams: 1,
    propertyBytes: [0], properties: null, isEncryption: false }], undefined],
  ["invalid dictionary", [{ id: "LZMA2", methodId: "21", numInStreams: 1, numOutStreams: 1,
    propertyBytes: [41], properties: null, isEncryption: false }], "LZMA2 coder properties are invalid."],
  ["missing dictionary", [{ id: "LZMA2", methodId: "21", numInStreams: 1, numOutStreams: 1,
    properties: null, isEncryption: false }], "LZMA2 coder properties are invalid."],
  ["multiple inputs", [{ id: "LZMA2", methodId: "21", numInStreams: 2, numOutStreams: 1,
    propertyBytes: [0], properties: null, isEncryption: false }],
  "7z extraction requires a single input/output stream."],
  ["multiple outputs", [{ id: "LZMA2", methodId: "21", numInStreams: 1, numOutStreams: 2,
    propertyBytes: [0], properties: null, isEncryption: false }],
  "7z extraction requires a single input/output stream."],
  ["no coder", [], "7z extraction supports single LZMA or LZMA2 folders."]
] satisfies Array<[string, SevenZipCoder[], string | undefined]>) {
  void test(`7z extraction eligibility validates ${name}`, async () => {
    const parsed = await parseSevenZip(new MockFile(lzma2SevenZipPlain(), "lzma2.7z"));
    assert.equal(parsed.nextHeader!.parsed!.kind, "header");
    const sections = (parsed.nextHeader!.parsed as
      { kind: "header"; sections: SevenZipHeaderSections }).sections;
    parsed.structure!.folders[0]!.coders = coders;

    const result = buildFileDetails(sections, parsed.structure!.folders, []);

    assert.equal(result.files[0]!.extractError, error);
  });
}
