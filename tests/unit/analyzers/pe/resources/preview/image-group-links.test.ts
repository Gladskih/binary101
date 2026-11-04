import assert from "node:assert/strict";
import { test } from "node:test";
import { linkImageGroupPreviews, resolveImageGroupTarget } from
  "../../../../../../analyzers/pe/resources/preview/image-group-links.js";
import { indexResourceLeaves } from "../../../../../../analyzers/pe/resources/resource-index.js";
import { createPreviewDetailGroup, createPreviewLangEntry } from "../../../../../helpers/pe-resource-preview-fixture.js";
import type { ResourceDetailGroup } from "../../../../../../analyzers/pe/resources/preview/types.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

const groupedImages = (): ResourceDetailGroup[] => [
  createPreviewDetailGroup("ICON", 80, { ...createPreviewLangEntry(1, 70),
    previewKind: "image", previewDataUrl: "data:image/png;base64,AQ==" }),
  createPreviewDetailGroup("GROUP_ICON", 7, { ...createPreviewLangEntry(2, 20),
    previewKind: "imageGroup", imageGroup: { type: "ICON", entries: [
      { id: 80, width: 32, height: 32, planes: 1, bitCount: 32, size: 70 }
    ] } })
];

void test("resolves the selected leaf without duplicating its preview into the group", () => {
  const detail = linkImageGroupPreviews(groupedImages());
  const group = expectDefined(detail[1]?.entries[0]?.langs[0]);

  assert.deepEqual(resolveImageGroupTarget(indexResourceLeaves(detail), group), { group: 0, entry: 0, language: 0 });
  assert.equal(group.previewDataUrl, undefined);
  assert.equal(group.previewIssues, undefined);
});

void test("reports every missing image and mismatching size", () => {
  const detail = groupedImages();
  const group = expectDefined(detail[1]?.entries[0]?.langs[0]?.imageGroup);
  group.entries.push({ id: 81, width: 16, height: 16, planes: 1, bitCount: 8, size: 70 });
  group.entries[0]!.size = 69;
  const leaf = expectDefined(linkImageGroupPreviews(detail)[1]?.entries[0]?.langs[0]);

  assert.match(leaf.previewIssues?.join(" ") ?? "", /81/);
  assert.match(leaf.previewIssues?.join(" ") ?? "", /size differs/);
});

void test("keeps deferred media and other-language candidates distinct from malformed images", () => {
  const detail = groupedImages();
  const icon = expectDefined(detail[0]?.entries[0]?.langs[0]);
  delete icon.previewDataUrl; icon.previewKind = "deferred";
  const group = expectDefined(linkImageGroupPreviews(detail)[1]?.entries[0]?.langs[0]);

  assert.equal(group.previewIssues, undefined);
  assert.equal(resolveImageGroupTarget(indexResourceLeaves(detail), group), null);
});
