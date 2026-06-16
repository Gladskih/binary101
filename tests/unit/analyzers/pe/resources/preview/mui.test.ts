"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../../../../../analyzers/pe/resources/preview/index.js";
import type { ResourceTree } from "../../../../../../analyzers/pe/resources/core.js";
import { buildMuiResourceConfigurationFixture } from "../../../../../fixtures/pe-mui-resource-config-fixture.js";
import {
  createPreviewDetailGroup,
  createPreviewFixture,
  createPreviewLangEntry,
  createPreviewTree
} from "../../../../../helpers/pe-resource-preview-fixture.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

const encoder = new TextEncoder();

type ResourcePreviewResult = Awaited<ReturnType<typeof enrichResourcePreviews>>;
type PreviewResourceLang =
  ResourceTree["detail"][number]["entries"][number]["langs"][number] & {
    muiConfig?: {
      checksum: string;
      fileType: number;
      mainTypeIds: number[];
      muiPaths: string[];
    };
    previewKind?: string;
    textPreview?: string;
    previewIssues?: string[];
  };

const getManifestLang = (result: ResourcePreviewResult): PreviewResourceLang => {
  const group = expectDefined(result.detail.find(entry => entry.typeName === "MANIFEST"));
  const resourceEntry = expectDefined(group.entries[0]);
  return expectDefined(resourceEntry.langs[0]) as PreviewResourceLang;
};

void test("enrichResourcePreviews accepts manifest placeholders only with MUI resource config", async () => {
  const fixture = createPreviewFixture(512);
  const muiConfig = fixture.appendData(buildMuiResourceConfigurationFixture());
  const manifest = fixture.appendData(encoder.encode("placeholder\0"));
  const tree = createPreviewTree([
    createPreviewDetailGroup("MUI", 1, createPreviewLangEntry(muiConfig.offset, muiConfig.size, 0, 1033)),
    createPreviewDetailGroup("MANIFEST", 123, createPreviewLangEntry(manifest.offset, manifest.size, 0, 1033))
  ]);

  const result = await enrichResourcePreviews(
    new MockFile(fixture.fileBytes),
    tree,
    () => {
      throw new Error("fixture parser should not run for a MUI manifest placeholder");
    }
  );
  const manifestLang = getManifestLang(result);
  const muiLang = result.detail.find(entry => entry.typeName === "MUI")?.entries[0]?.langs[0] as
    | PreviewResourceLang
    | undefined;
  assert.equal(muiLang?.previewKind, "muiConfig");
  assert.equal(muiLang?.muiConfig?.checksum, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  assert.deepEqual(muiLang?.muiConfig?.mainTypeIds, [24]);
  assert.deepEqual(muiLang?.muiConfig?.muiPaths, ["en-US\\fixture.dll.mui"]);
  assert.equal(manifestLang.textPreview, "placeholder");
  assert.equal(manifestLang.previewIssues, undefined);
  assert.ok(result.muiResourceConfiguration);
});

void test("enrichResourcePreviews reports manifest placeholders without valid MUI resource config", async () => {
  const fixture = createPreviewFixture(256);
  const manifest = fixture.appendData(encoder.encode("placeholder\0"));
  const tree = createPreviewTree([
    createPreviewDetailGroup("MANIFEST", 123, createPreviewLangEntry(manifest.offset, manifest.size, 0, 1033))
  ]);

  const result = await enrichResourcePreviews(
    new MockFile(fixture.fileBytes),
    tree,
    () => {
      throw new Error("fixture parser sees standalone placeholder");
    }
  );
  const manifestLang = getManifestLang(result);
  assert.ok(manifestLang.previewIssues?.some(issue => /XML parser threw/.test(issue)));
  assert.equal(result.muiResourceConfiguration, undefined);
});

void test("enrichResourcePreviews reports malformed MUI resource configs", async () => {
  const fixture = createPreviewFixture(256);
  const malformed = fixture.appendData(encoder.encode("not-mu"));
  const tree = createPreviewTree([
    createPreviewDetailGroup("MUI", 1, createPreviewLangEntry(malformed.offset, malformed.size, 0, 1033))
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const muiLang = result.detail[0]?.entries[0]?.langs[0] as PreviewResourceLang | undefined;
  assert.equal(muiLang?.previewKind, undefined);
  assert.ok(muiLang?.previewIssues?.includes("MUI resource config signature is not fecdfecd."));
  assert.equal(result.muiResourceConfiguration, undefined);
});
