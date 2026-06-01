"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../analyzers/pe/resources/preview/index.js";
import {
  createPreviewDetailGroup,
  createPreviewFixture,
  createPreviewLangEntry,
  createPreviewTree
} from "../helpers/pe-resource-preview-fixture.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { MockFile } from "../helpers/mock-file.js";

type ResourcePreviewResult = Awaited<ReturnType<typeof enrichResourcePreviews>>;

const getPreviewLang = (result: ResourcePreviewResult): { previewKind?: string; previewIssues?: string[] } => {
  const group = expectDefined(result.detail.find(entry => entry.typeName === "HTML"));
  const resourceEntry = expectDefined(group.entries[0]);
  return expectDefined(resourceEntry.langs[0]);
};

void test("enrichResourcePreviews skips binary payloads stored under HTML type", async () => {
  const fixture = createPreviewFixture(256);
  const gifHeader = Uint8Array.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x00, 0x00]);
  const html = fixture.appendData(gifHeader);
  const tree = createPreviewTree([
    createPreviewDetailGroup("HTML", 7, createPreviewLangEntry(html.offset, html.size, 0, 1033))
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const htmlLang = getPreviewLang(result);

  assert.strictEqual(htmlLang.previewKind, "image");
  assert.strictEqual(htmlLang.previewIssues, undefined);
});
