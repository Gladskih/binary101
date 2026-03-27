"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addDialogPreview } from "../../analyzers/pe/resources/preview/dialog.js";
import {
  alignDword,
  writeUtf16Z
} from "../helpers/pe-resource-preview-fixture.js";
import { expectDefined } from "../helpers/expect-defined.js";

// DS_SETFONT requests font metadata after the dialog title. Source:
// https://learn.microsoft.com/en-us/windows/win32/menurc/dialog-resource
const DS_SETFONT = 0x00000040;

const buildStandardDialogTemplate = (): Uint8Array => {
  const bytes = new Uint8Array(160).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, DS_SETFONT, true);
  view.setUint32(4, 0, true);
  view.setUint16(8, 1, true);
  view.setInt16(10, 10, true);
  view.setInt16(12, 10, true);
  view.setInt16(14, 120, true);
  view.setInt16(16, 80, true);
  let offset = 18;
  view.setUint16(offset, 0, true);
  offset += 2;
  view.setUint16(offset, 0, true);
  offset += 2;
  offset = writeUtf16Z(bytes, offset, "Sample Dialog");
  view.setUint16(offset, 9, true);
  offset += 2;
  offset = writeUtf16Z(bytes, offset, "MS Shell Dlg");
  offset = alignDword(offset);
  view.setUint32(offset, 0x50010000, true);
  view.setUint32(offset + 4, 0, true);
  view.setInt16(offset + 8, 14, true);
  view.setInt16(offset + 10, 50, true);
  view.setInt16(offset + 12, 50, true);
  view.setInt16(offset + 14, 14, true);
  view.setUint16(offset + 16, 100, true);
  // DLGITEMTEMPLATE uses 0xFFFF + an ordinal to reference a predefined control class; BUTTON = 0x0080.
  // Source: https://learn.microsoft.com/en-us/windows/win32/menurc/dialog-resource
  view.setUint16(offset + 18, 0xffff, true); // 0xFFFF marks a predefined control class ordinal.
  view.setUint16(offset + 20, 0x0080, true); // 0x0080 is the predefined BUTTON class ordinal.
  const next = writeUtf16Z(bytes, offset + 22, "OK");
  view.setUint16(next, 0, true);
  return bytes.subarray(0, next + 2);
};

const buildExtendedDialogTemplate = (): Uint8Array => {
  const bytes = new Uint8Array(96).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 1, true);
  view.setUint16(2, 0xffff, true);
  view.setUint32(8, 0, true);
  view.setUint32(12, DS_SETFONT, true);
  view.setUint16(16, 0, true);
  view.setInt16(18, 5, true);
  view.setInt16(20, 6, true);
  view.setInt16(22, 80, true);
  view.setInt16(24, 50, true);
  let offset = 26;
  view.setUint16(offset, 0, true);
  offset += 2;
  view.setUint16(offset, 0, true);
  offset += 2;
  offset = writeUtf16Z(bytes, offset, "Extended");
  view.setUint16(offset, 9, true);
  view.setUint16(offset + 2, 400, true);
  view.setUint8(offset + 4, 0);
  view.setUint8(offset + 5, 1);
  offset = writeUtf16Z(bytes, offset + 6, "Segoe UI");
  return bytes.subarray(0, offset);
};

void test("addDialogPreview parses standard dialog templates and controls", () => {
  const result = addDialogPreview(buildStandardDialogTemplate(), "DIALOG");

  const preview = expectDefined(result?.preview?.dialogPreview);
  assert.strictEqual(result?.preview?.previewKind, "dialog");
  assert.strictEqual(preview.templateKind, "standard");
  assert.strictEqual(preview.title, "Sample Dialog");
  assert.strictEqual(preview.font?.typeface, "MS Shell Dlg");
  assert.strictEqual(preview.controls.length, 1);
  assert.strictEqual(preview.controls[0]?.kind, "BUTTON");
  assert.strictEqual(preview.controls[0]?.title, "OK");
});

void test("addDialogPreview parses extended dialog headers and font metadata", () => {
  const result = addDialogPreview(buildExtendedDialogTemplate(), "DIALOG");

  const preview = expectDefined(result?.preview?.dialogPreview);
  assert.strictEqual(preview.templateKind, "extended");
  assert.strictEqual(preview.title, "Extended");
  assert.strictEqual(preview.font?.weight, 400);
  assert.strictEqual(preview.font?.charset, 1);
  assert.strictEqual(preview.font?.typeface, "Segoe UI");
});
