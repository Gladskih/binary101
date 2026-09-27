"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addMenuPreview } from "../../../../../../analyzers/pe/resources/preview/menu.js";
import {
  alignDword,
  writeUtf16Z
} from "../../../../../helpers/pe-resource-preview-fixture.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

// Standard and extended menu-template flags come from MENUITEMTEMPLATEHEADER / MENUEX templates.
// Sources:
// https://learn.microsoft.com/en-us/windows/win32/menurc/menu-resource
// https://learn.microsoft.com/en-us/windows/win32/menurc/menuex-template-header
const MF_END = 0x0080;

const buildStandardMenuTemplate = (): Uint8Array => {
  const bytes = new Uint8Array(64).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0, true);
  view.setUint16(2, 0, true);
  let offset = 4;
  view.setUint16(offset, 0x0010 | MF_END, true); // MF_POPUP | MF_END
  offset = writeUtf16Z(bytes, offset + 2, "File");
  view.setUint16(offset, MF_END, true);
  view.setUint16(offset + 2, 100, true);
  offset = writeUtf16Z(bytes, offset + 4, "Open");
  return bytes.subarray(0, offset);
};

const buildExtendedMenuTemplate = (): Uint8Array => {
  const bytes = new Uint8Array(96).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 1, true);
  view.setUint16(2, 4, true);
  view.setUint32(4, 0, true);
  let offset = 8;
  view.setUint32(offset, 0, true);
  view.setUint32(offset + 4, 0, true);
  view.setUint32(offset + 8, 0, true);
  view.setUint16(offset + 12, 0x0001 | 0x0080, true); // MFR_POPUP | MFR_END in MENUEX.
  offset = writeUtf16Z(bytes, offset + 14, "Tools");
  offset = alignDword(offset);
  view.setUint32(offset, 0, true);
  offset += 4;
  view.setUint32(offset, 0, true);
  view.setUint32(offset + 4, 0, true);
  view.setUint32(offset + 8, 200, true);
  view.setUint16(offset + 12, 0x0080, true); // MFR_END terminates the child item list in MENUEX.
  offset = writeUtf16Z(bytes, offset + 14, "Run");
  return bytes.subarray(0, offset);
};

void test("addMenuPreview parses standard menu templates", () => {
  const result = addMenuPreview(buildStandardMenuTemplate(), "MENU");

  const preview = expectDefined(result?.preview?.menuPreview);
  assert.strictEqual(result?.preview?.previewKind, "menu");
  assert.strictEqual(preview.templateKind, "standard");
  assert.strictEqual(preview.items[0]?.text, "File");
  assert.strictEqual(preview.items[0]?.children[0]?.text, "Open");
  assert.strictEqual(preview.items[0]?.children[0]?.id, 100);
});

void test("addMenuPreview parses MENUEX templates", () => {
  const result = addMenuPreview(buildExtendedMenuTemplate(), "MENU");

  const preview = expectDefined(result?.preview?.menuPreview);
  assert.strictEqual(preview.templateKind, "extended");
  assert.strictEqual(preview.items[0]?.text, "Tools");
  assert.strictEqual(preview.items[0]?.children[0]?.text, "Run");
  assert.strictEqual(preview.items[0]?.children[0]?.id, 200);
});

void test("decodes MENUEX type and state flags", () => {
  const bytes = buildExtendedMenuTemplate();
  const view = new DataView(bytes.buffer);
  // MFT_OWNERDRAW | MFT_RADIOCHECK | MFT_RIGHTORDER | MFT_RIGHTJUSTIFY.
  view.setUint32(8, 0x6300, true);
  // MFS_GRAYED | MFS_CHECKED | MFS_HILITE | MFS_DEFAULT.
  view.setUint32(12, 0x108b, true);
  const flags = addMenuPreview(bytes, "MENU")?.preview?.menuPreview?.items[0]?.flags ?? [];

  assert.ok(flags.includes("MFT_RADIOCHECK"));
  assert.ok(flags.includes("MFS_DEFAULT"));
  assert.ok(flags.includes("MFS_HILITE"));
});

void test("warns for every truncated menu prefix and unknown versions", () => {
  const bytes = buildStandardMenuTemplate();
  for (let length = 0; length < bytes.length; length += 1) {
    assert.ok(addMenuPreview(bytes.subarray(0, length), "MENU")?.issues?.length, `${length}`);
  }
  new DataView(bytes.buffer).setUint16(0, 2, true);
  assert.ok(addMenuPreview(bytes, "MENU")?.issues?.length);
});

void test("bounds popup nesting and rejects bad extended offsets", () => {
  const bytes = new Uint8Array(4 + 65 * 4);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < 65; index += 1) view.setUint16(4 + index * 4, 0x90, true);
  assert.ok(addMenuPreview(bytes, "MENU")?.issues?.some(issue => issue.includes("nesting")));
  view.setUint16(0, 1, true);
  view.setUint16(2, 0, true);
  assert.ok(addMenuPreview(bytes, "MENU")?.issues?.length);
  view.setUint16(2, 0xffff, true);
  assert.ok(addMenuPreview(bytes, "MENU")?.issues?.length);
  assert.equal(addMenuPreview(bytes, "other"), null);
});

void test("warns on incomplete extended text and popup help IDs", () => {
  const bytes = buildExtendedMenuTemplate();
  assert.ok(addMenuPreview(bytes.subarray(0, 20), "MENU")?.issues?.length);
  assert.ok(addMenuPreview(bytes.subarray(0, 34), "MENU")?.issues?.length);
});
