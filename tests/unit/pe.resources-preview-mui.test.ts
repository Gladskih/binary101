"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../analyzers/pe/resources/preview/index.js";
import type { ResourceTree } from "../../analyzers/pe/resources/core.js";
import { buildMuiResourceConfigurationFixture } from "../fixtures/pe-mui-resource-config-fixture.js";
import {
  createPreviewDetailGroup,
  createPreviewFixture,
  createPreviewLangEntry,
  createPreviewTree
} from "../helpers/pe-resource-preview-fixture.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();

type ResourcePreviewResult = Awaited<ReturnType<typeof enrichResourcePreviews>>;
type PreviewResourceLang =
  ResourceTree["detail"][number]["entries"][number]["langs"][number] & {
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
