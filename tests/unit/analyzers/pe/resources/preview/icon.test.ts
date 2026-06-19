"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  addGroupIconPreview,
  addIconPreview
} from "../../../../../../analyzers/pe/resources/preview/icon.js";
import { createPngFile } from "../../../../../fixtures/image-sample-files.js";
import {
  buildLargeGroupIconResource,
  buildMultiEntryGroupIconResource,
  buildSingleEntryGroupIconResource
} from "../../../../../helpers/pe-resource-preview-fixture.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

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

void test("addGroupIconPreview selects the highest-resolution group entry", async () => {
  const loadedIds: number[] = [];
  const groupIcon = buildMultiEntryGroupIconResource([
    { width: 32, height: 32, bitCount: 32, iconSize: png1x1.length, iconId: 1 },
    { width: 256, height: 256, bitCount: 32, iconSize: png1x1.length, iconId: 2 },
    { width: 48, height: 48, bitCount: 32, iconSize: png1x1.length, iconId: 3 }
  ]);

  const result = await addGroupIconPreview(
    groupIcon,
    "GROUP_ICON",
    async id => {
      loadedIds.push(id);
      return { data: png1x1 };
    },
    1033
  );

  assert.deepEqual(loadedIds, [2]);
  assert.strictEqual(result?.preview?.previewKind, "image");
});

void test("addGroupIconPreview prefers higher color depth at the same resolution", async () => {
  const loadedIds: number[] = [];
  const groupIcon = buildMultiEntryGroupIconResource([
    { width: 64, height: 64, bitCount: 8, iconSize: png1x1.length, iconId: 4 },
    { width: 64, height: 64, bitCount: 32, iconSize: png1x1.length, iconId: 5 }
  ]);

  await addGroupIconPreview(
    groupIcon,
    "GROUP_ICON",
    async id => {
      loadedIds.push(id);
      return { data: png1x1 };
    },
    1033
  );

  assert.deepEqual(loadedIds, [5]);
});

void test("addGroupIconPreview keeps the first entry when later entries are not better", async () => {
  const loadedIds: number[] = [];
  const groupIcon = buildMultiEntryGroupIconResource([
    { width: 64, height: 64, bitCount: 32, iconSize: png1x1.length, iconId: 6 },
    { width: 64, height: 64, bitCount: 8, iconSize: png1x1.length, iconId: 7 },
    { width: 32, height: 32, bitCount: 64, iconSize: png1x1.length, iconId: 8 },
    { width: 64, height: 64, bitCount: 32, iconSize: png1x1.length, iconId: 9 }
  ]);

  await addGroupIconPreview(
    groupIcon,
    "GROUP_ICON",
    async id => {
      loadedIds.push(id);
      return { data: png1x1 };
    },
    1033
  );

  assert.deepEqual(loadedIds, [6]);
});

void test("addGroupIconPreview uses both dimensions when comparing resolution", async () => {
  const loadedIds: number[] = [];
  const groupIcon = buildMultiEntryGroupIconResource([
    { width: 64, height: 16, bitCount: 32, iconSize: png1x1.length, iconId: 10 },
    { width: 32, height: 64, bitCount: 32, iconSize: png1x1.length, iconId: 11 }
  ]);

  await addGroupIconPreview(
    groupIcon,
    "GROUP_ICON",
    async id => {
      loadedIds.push(id);
      return { data: png1x1 };
    },
    1033
  );

  assert.deepEqual(loadedIds, [11]);
});

void test("addGroupIconPreview reads group bit depth as little-endian", async () => {
  const loadedIds: number[] = [];
  const groupIcon = buildMultiEntryGroupIconResource([
    { width: 48, height: 48, bitCount: 1, iconSize: png1x1.length, iconId: 12 },
    { width: 48, height: 48, bitCount: 256, iconSize: png1x1.length, iconId: 13 }
  ]);

  await addGroupIconPreview(
    groupIcon,
    "GROUP_ICON",
    async id => {
      loadedIds.push(id);
      return { data: png1x1 };
    },
    1033
  );

  assert.deepEqual(loadedIds, [13]);
});

void test("addGroupIconPreview rejects empty and truncated group directories", async () => {
  const emptyGroup = new Uint8Array(6);
  const truncatedGroup = buildSingleEntryGroupIconResource(png1x1.length, 1);
  new DataView(truncatedGroup.buffer).setUint16(4, 10, true);
  let loadCount = 0;
  const loadLeaf = async () => {
    loadCount += 1;
    return { data: png1x1 };
  };

  assert.equal(await addGroupIconPreview(emptyGroup, "GROUP_ICON", loadLeaf, 1033), null);
  assert.equal(await addGroupIconPreview(truncatedGroup, "GROUP_ICON", loadLeaf, 1033), null);
  assert.equal(loadCount, 0);
});
