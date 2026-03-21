"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  addGroupIconPreview,
  addIconPreview
} from "../../analyzers/pe/resources-preview-icon.js";
import type { ResourceLangWithPreview } from "../../analyzers/pe/resources-preview-types.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const PNG_1X1_BYTES = Uint8Array.from(Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/5+hHgAFgwJ/"
    + "l7nnMgAAAABJRU5ErkJggg==",
  "base64"
));

const createPreviewLang = (): ResourceLangWithPreview => ({
  lang: 1033,
  size: 0,
  codePage: 0,
  dataRVA: 0,
  reserved: 0
});

const buildGroupIconResource = (iconSize: number, iconId: number): Uint8Array => {
  const bytes = new Uint8Array(20).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(4, 1, true);
  view.setUint8(6, 32);
  view.setUint8(7, 32);
  view.setUint16(10, 1, true);
  view.setUint16(12, 32, true);
  view.setUint32(14, iconSize, true);
  view.setUint16(18, iconId, true);
  return bytes;
};

const buildLargeGroupIconResource = (
  entryCount: number,
  iconSize: number,
  iconId: number
): Uint8Array => {
  const bytes = new Uint8Array(6 + entryCount * 14).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(4, entryCount, true);
  for (let index = 0; index < entryCount; index += 1) {
    const entryOffset = 6 + index * 14;
    const isSelectedEntry = index === entryCount - 1;
    view.setUint8(entryOffset + 0, isSelectedEntry ? 32 : 1);
    view.setUint8(entryOffset + 1, isSelectedEntry ? 32 : 1);
    view.setUint16(entryOffset + 4, 1, true);
    view.setUint16(entryOffset + 6, 32, true);
    view.setUint32(entryOffset + 8, isSelectedEntry ? iconSize : 0, true);
    view.setUint16(entryOffset + 12, isSelectedEntry ? iconId : 0, true);
  }
  return bytes;
};

void test("addIconPreview emits PNG previews for RT_ICON resources", () => {
  const langEntry = createPreviewLang();
  addIconPreview(langEntry, PNG_1X1_BYTES, "ICON");
  assert.strictEqual(langEntry.previewKind, "image");
  assert.strictEqual(langEntry.previewMime, "image/png");
  assert.match(expectDefined(langEntry.previewDataUrl), /^data:image\/png;base64,/);
});

void test("addGroupIconPreview emits ICO previews when the selected icon is at the directory boundary", async () => {
  const groupIcon = buildGroupIconResource(PNG_1X1_BYTES.length, 1);
  const groupOffset = 0x40;
  const iconOffset = 0x100;
  const bytes = new Uint8Array(iconOffset + PNG_1X1_BYTES.length).fill(0);
  bytes.set(groupIcon, groupOffset);
  bytes.set(PNG_1X1_BYTES, iconOffset);
  const langEntry = createPreviewLang();

  await addGroupIconPreview(
    new MockFile(bytes),
    langEntry,
    "GROUP_ICON",
    groupOffset,
    groupIcon.length,
    new Map([[1, { rva: iconOffset, size: PNG_1X1_BYTES.length }]]),
    value => value
  );

  assert.strictEqual(langEntry.previewKind, "image");
  assert.match(expectDefined(langEntry.previewMime), /x-icon/);
  assert.match(expectDefined(langEntry.previewDataUrl), /^data:image\/x-icon;base64,/);
});

void test("addGroupIconPreview reads group-icon tables beyond the old 4096-byte cap", async () => {
  const groupIcon = buildLargeGroupIconResource(300, PNG_1X1_BYTES.length, 1);
  const groupOffset = 0x100;
  const iconOffset = 5000;
  const bytes = new Uint8Array(iconOffset + PNG_1X1_BYTES.length).fill(0);
  bytes.set(groupIcon, groupOffset);
  bytes.set(PNG_1X1_BYTES, iconOffset);
  const langEntry = createPreviewLang();

  await addGroupIconPreview(
    new MockFile(bytes),
    langEntry,
    "GROUP_ICON",
    groupOffset,
    groupIcon.length,
    new Map([[1, { rva: iconOffset, size: PNG_1X1_BYTES.length }]]),
    value => value
  );

  assert.strictEqual(langEntry.previewKind, "image");
  assert.match(expectDefined(langEntry.previewMime), /x-icon/);
});
