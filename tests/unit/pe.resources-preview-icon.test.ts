"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  addGroupIconPreview,
  addIconPreview
} from "../../analyzers/pe/resources-preview-icon.js";
import { createPngFile } from "../fixtures/image-sample-files.js";
import {
  buildLargeGroupIconResource,
  buildSingleEntryGroupIconResource
} from "../helpers/pe-resource-preview-fixture.js";
import { expectDefined } from "../helpers/expect-defined.js";

const png1x1 = createPngFile().data;

void test("addIconPreview emits PNG previews for RT_ICON resources", () => {
  const result = addIconPreview(png1x1, "ICON");
  assert.strictEqual(result?.preview?.previewKind, "image");
  assert.strictEqual(result?.preview?.previewMime, "image/png");
  assert.match(expectDefined(result?.preview?.previewDataUrl), /^data:image\/png;base64,/);
});

void test("addGroupIconPreview emits ICO previews when the selected icon is at the directory boundary", async () => {
  const groupIcon = buildSingleEntryGroupIconResource(png1x1.length, 1);
  const result = await addGroupIconPreview(
    groupIcon,
    "GROUP_ICON",
    async id => ({ data: id === 1 ? png1x1 : null }),
    1033
  );

  assert.strictEqual(result?.preview?.previewKind, "image");
  assert.match(expectDefined(result?.preview?.previewMime), /x-icon/);
  assert.match(expectDefined(result?.preview?.previewDataUrl), /^data:image\/x-icon;base64,/);
});

void test("addGroupIconPreview reads group-icon tables beyond the old 4096-byte cap", async () => {
  // 300 entries force 6 + (300 * 14) = 4206 bytes, which crosses the old 4096-byte scan cap.
  const groupIcon = buildLargeGroupIconResource(300, png1x1.length, 1);
  const result = await addGroupIconPreview(
    groupIcon,
    "GROUP_ICON",
    async id => ({ data: id === 1 ? png1x1 : null }),
    1033
  );

  assert.strictEqual(result?.preview?.previewKind, "image");
  assert.match(expectDefined(result?.preview?.previewMime), /x-icon/);
});
