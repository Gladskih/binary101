"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  addCursorPreview,
  addGroupCursorPreview
} from "../../analyzers/pe/resources-preview-cursor.js";
import { createPngFile } from "../fixtures/image-sample-files.js";
import {
  buildCursorResource,
  buildSingleEntryGroupCursorResource
} from "../helpers/pe-resource-preview-fixture.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("addCursorPreview renders cursor frames and exposes hotspot metadata", () => {
  const cursor = buildCursorResource(7, 9, createPngFile().data);
  const result = addCursorPreview(cursor, "CURSOR");

  assert.strictEqual(result?.preview?.previewKind, "image");
  assert.strictEqual(result?.preview?.previewMime, "image/png");
  assert.match(expectDefined(result?.preview?.previewDataUrl), /^data:image\/png;base64,/);
  assert.deepEqual(result?.preview?.previewFields, [{ label: "Hotspot", value: "7, 9" }]);
});

void test("addGroupCursorPreview resolves cursor leaves by id and renders the selected frame", async () => {
  const cursorLeaf = buildCursorResource(7, 9, createPngFile().data);
  const groupCursor = buildSingleEntryGroupCursorResource(cursorLeaf.length, 4, 7, 9);

  const result = await addGroupCursorPreview(
    groupCursor,
    "GROUP_CURSOR",
    async id => ({ data: id === 4 ? cursorLeaf : null }),
    1033
  );

  assert.strictEqual(result?.preview?.previewKind, "image");
  assert.match(expectDefined(result?.preview?.previewDataUrl), /^data:image\/png;base64,/);
  assert.deepEqual(result?.preview?.previewFields, [{ label: "Hotspot", value: "7, 9" }]);
});
