"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../analyzers/pe/resources/preview/index.js";
import type { ResourceTree } from "../../analyzers/pe/resources/core.js";
import { createBmpFile, createPngFile } from "../fixtures/image-sample-files.js";
import {
  alignDword,
  buildCursorResource,
  buildSingleEntryGroupCursorResource,
  buildSingleEntryGroupIconResource,
  createPreviewDetailGroup,
  createPreviewFixture,
  createPreviewLangEntry,
  createPreviewTree,
  writeUtf16Z
} from "../helpers/pe-resource-preview-fixture.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

type ResourceDetail = ResourceTree["detail"][number];
type ResourceLang = ResourceDetail["entries"][number]["langs"][number];
type ResourcePreviewResult = Awaited<ReturnType<typeof enrichResourcePreviews>>;
type PreviewResourceLang = ResourceLang & {
  previewKind?: string;
  previewFields?: Array<{ label: string; value: string }>;
};

const MF_END = 0x0080;

const buildStandardDialogTemplate = (): Uint8Array => {
  const bytes = new Uint8Array(160).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x00000040, true); // DS_SETFONT. Source: https://learn.microsoft.com/en-us/windows/win32/menurc/dialog-resource
  view.setUint16(8, 1, true);
  view.setInt16(14, 120, true);
  view.setInt16(16, 80, true);
  let offset = 18;
  offset += 4;
  offset = writeUtf16Z(bytes, offset, "Preview Dialog");
  view.setUint16(offset, 9, true);
  offset = writeUtf16Z(bytes, offset + 2, "MS Shell Dlg");
  offset = alignDword(offset);
  view.setUint32(offset, 0x50010000, true);
  view.setInt16(offset + 8, 14, true);
  view.setInt16(offset + 10, 50, true);
  view.setInt16(offset + 12, 50, true);
  view.setInt16(offset + 14, 14, true);
  view.setUint16(offset + 16, 100, true);
  // DLGITEMTEMPLATE uses 0xFFFF + an ordinal to reference a predefined control class; BUTTON = 0x0080.
  // Source: https://learn.microsoft.com/en-us/windows/win32/menurc/dialog-resource
  view.setUint16(offset + 18, 0xffff, true);
  view.setUint16(offset + 20, 0x0080, true);
  const next = writeUtf16Z(bytes, offset + 22, "OK");
  view.setUint16(next, 0, true);
  return bytes.subarray(0, next + 2);
};

const buildStandardMenuTemplate = (): Uint8Array => {
  const bytes = new Uint8Array(64).fill(0);
  const view = new DataView(bytes.buffer);
  let offset = 4;
  view.setUint16(offset, 0x0010 | MF_END, true); // MF_POPUP | MF_END. Source: https://learn.microsoft.com/en-us/windows/win32/menurc/menu-resource
  offset = writeUtf16Z(bytes, offset + 2, "File");
  view.setUint16(offset, MF_END, true);
  view.setUint16(offset + 2, 100, true);
  offset = writeUtf16Z(bytes, offset + 4, "Open");
  return bytes.subarray(0, offset);
};

const buildAcceleratorTable = (): Uint8Array => {
  const bytes = new Uint8Array(8).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint8(0, 0x01 | 0x08 | 0x80); // FVIRTKEY | FCONTROL | FLAST. Source: https://learn.microsoft.com/en-us/windows/win32/menurc/accelerators-resource
  view.setUint16(2, "O".charCodeAt(0), true);
  view.setUint16(4, 100, true);
  return bytes;
};

const getPreviewLang = (result: ResourcePreviewResult, typeName: string): PreviewResourceLang => {
  const group = expectDefined(result.detail.find(entry => entry.typeName === typeName));
  const resourceEntry = expectDefined(group.entries[0]);
  return expectDefined(resourceEntry.langs[0]) as PreviewResourceLang;
};

void test("enrichResourcePreviews wires standard and heuristic preview modules together", async () => {
  const fixture = createPreviewFixture(4096);
  const png = createPngFile().data;
  const icon = fixture.appendData(png);
  const groupIcon = fixture.appendData(buildSingleEntryGroupIconResource(png.length, 1));
  const cursor = fixture.appendData(buildCursorResource(7, 9, png));
  const groupCursor = fixture.appendData(buildSingleEntryGroupCursorResource(cursor.size, 4, 7, 9));
  const bitmap = fixture.appendData(createBmpFile().data.subarray(14));
  const dialog = fixture.appendData(buildStandardDialogTemplate());
  const menu = fixture.appendData(buildStandardMenuTemplate());
  const accelerator = fixture.appendData(buildAcceleratorTable());
  const rcdata = fixture.appendData(png);
  const fontDir = fixture.appendData(new Uint8Array([1, 0, 0, 0]));
  const font = fixture.appendData(new Uint8Array([0x00, 0x01, 0x00, 0x00]));
  const dlgInclude = fixture.appendData(new TextEncoder().encode("#include \"preview-dialog.h\"\n"));
  const plugPlay = fixture.appendData(new Uint8Array([0x50, 0x4e, 0x50, 0x00]));
  const vxd = fixture.appendData(new Uint8Array([0x56, 0x58, 0x44, 0x00]));
  const tree = createPreviewTree([
    createPreviewDetailGroup("ICON", 1, createPreviewLangEntry(icon.offset, icon.size, 0, 1033)),
    createPreviewDetailGroup("GROUP_ICON", 2, createPreviewLangEntry(groupIcon.offset, groupIcon.size, 0, 1033)),
    createPreviewDetailGroup("CURSOR", 4, createPreviewLangEntry(cursor.offset, cursor.size, 0, 1033)),
    createPreviewDetailGroup(
      "GROUP_CURSOR",
      5,
      createPreviewLangEntry(groupCursor.offset, groupCursor.size, 0, 1033)
    ),
    createPreviewDetailGroup("BITMAP", 6, createPreviewLangEntry(bitmap.offset, bitmap.size, 0, 1033)),
    createPreviewDetailGroup("DIALOG", 7, createPreviewLangEntry(dialog.offset, dialog.size, 0, 1033)),
    createPreviewDetailGroup("MENU", 8, createPreviewLangEntry(menu.offset, menu.size, 0, 1033)),
    createPreviewDetailGroup("FONTDIR", 8, createPreviewLangEntry(fontDir.offset, fontDir.size, 0, 1033)),
    createPreviewDetailGroup("FONT", 8, createPreviewLangEntry(font.offset, font.size, 0, 1033)),
    createPreviewDetailGroup(
      "ACCELERATOR",
      9,
      createPreviewLangEntry(accelerator.offset, accelerator.size, 0, 1033)
    ),
    createPreviewDetailGroup("RCDATA", 10, createPreviewLangEntry(rcdata.offset, rcdata.size, 0, 1033)),
    createPreviewDetailGroup(
      "DLGINCLUDE",
      17,
      createPreviewLangEntry(dlgInclude.offset, dlgInclude.size, 65001, 1033)
    ),
    createPreviewDetailGroup("PLUGPLAY", 19, createPreviewLangEntry(plugPlay.offset, plugPlay.size, 0, 1033)),
    createPreviewDetailGroup("VXD", 20, createPreviewLangEntry(vxd.offset, vxd.size, 0, 1033))
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);

  assert.strictEqual(getPreviewLang(result, "GROUP_ICON").previewKind, "image");
  assert.strictEqual(getPreviewLang(result, "GROUP_CURSOR").previewKind, "image");
  assert.strictEqual(getPreviewLang(result, "BITMAP").previewKind, "image");
  assert.strictEqual(getPreviewLang(result, "DIALOG").previewKind, "dialog");
  assert.strictEqual(getPreviewLang(result, "MENU").previewKind, "menu");
  assert.strictEqual(getPreviewLang(result, "FONTDIR").previewKind, "summary");
  assert.strictEqual(getPreviewLang(result, "FONT").previewKind, "font");
  assert.strictEqual(getPreviewLang(result, "ACCELERATOR").previewKind, "accelerator");
  assert.strictEqual(getPreviewLang(result, "RCDATA").previewKind, "image");
  assert.strictEqual(getPreviewLang(result, "DLGINCLUDE").previewKind, "text");
  assert.strictEqual(getPreviewLang(result, "PLUGPLAY").previewKind, "summary");
  assert.strictEqual(getPreviewLang(result, "VXD").previewKind, "summary");
  assert.deepEqual(getPreviewLang(result, "GROUP_CURSOR").previewFields, [{ label: "Hotspot", value: "7, 9" }]);
});
