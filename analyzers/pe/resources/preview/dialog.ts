"use strict";

import type { ResourceDialogControlPreview, ResourceDialogPreview, ResourcePreviewResult } from "./types.js";
import { readDialogField, readDialogFont } from "./dialog-fields.js";

const alignDword = (offset: number): number => Math.ceil(offset / 4) * 4;

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgitemtemplate
// https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgitemtemplateex
const readCreationData = (
  view: DataView, offset: number, templateKind: ResourceDialogPreview["templateKind"], issues: string[]
): { data: Uint8Array; nextOffset: number } => {
  if (offset + 2 > view.byteLength) {
    issues.push("DIALOG control creation-data size is truncated.");
    return { data: new Uint8Array(), nextOffset: view.byteLength };
  }
  const count = view.getUint16(offset, true);
  // Standard size includes the size WORD; extended size counts only the payload.
  const length = templateKind === "standard" ? Math.max(0, count - 2) : count;
  if (templateKind === "standard" && count === 1) issues.push("DIALOG creation-data size is invalid.");
  const end = offset + 2 + length;
  if (end > view.byteLength) issues.push("DIALOG control creation data is truncated.");
  return {
    data: new Uint8Array(view.buffer, view.byteOffset + offset + 2,
      Math.min(length, view.byteLength - offset - 2)),
    nextOffset: alignDword(Math.min(end, view.byteLength))
  };
};

const readControl = (
  view: DataView, offset: number, templateKind: ResourceDialogPreview["templateKind"], issues: string[]
): { control: ResourceDialogControlPreview; nextOffset: number } | null => {
  const size = templateKind === "standard" ? 18 : 24;
  if (offset + size > view.byteLength) {
    issues.push("DIALOG control header is truncated.");
    return null;
  }
  const boundsOffset = offset + (templateKind === "standard" ? 8 : 12);
  const klass = readDialogField(view, offset + size, "class", issues);
  const title = readDialogField(view, klass.nextOffset, "title", issues);
  const creation = readCreationData(view, title.nextOffset, templateKind, issues);
  return {
    control: {
      helpId: templateKind === "extended" ? view.getUint32(offset, true) : null,
      id: templateKind === "extended" ? view.getUint32(offset + 20, true)
        : view.getUint16(offset + 16, true),
      kind: klass.value || "(custom)", title: title.value,
      x: view.getInt16(boundsOffset, true), y: view.getInt16(boundsOffset + 2, true),
      width: view.getInt16(boundsOffset + 4, true), height: view.getInt16(boundsOffset + 6, true),
      style: view.getUint32(offset + (templateKind === "standard" ? 0 : 8), true),
      exStyle: view.getUint32(offset + 4, true), creationData: creation.data
    },
    nextOffset: creation.nextOffset
  };
};

const readControls = (
  view: DataView, offset: number, count: number,
  templateKind: ResourceDialogPreview["templateKind"], issues: string[]
): ResourceDialogControlPreview[] => {
  const controls: ResourceDialogControlPreview[] = [];
  let pos = alignDword(offset);
  for (let index = 0; index < count; index += 1) {
    const result = readControl(view, pos, templateKind, issues);
    if (!result) break;
    controls.push(result.control);
    pos = result.nextOffset;
  }
  return controls;
};

const readDialog = (
  view: DataView, templateKind: ResourceDialogPreview["templateKind"], issues: string[]
): ResourceDialogPreview | null => {
  const size = templateKind === "standard" ? 18 : 26;
  if (view.byteLength < size) return null;
  const style = view.getUint32(templateKind === "standard" ? 0 : 12, true);
  const boundsOffset = templateKind === "standard" ? 10 : 18;
  const menu = readDialogField(view, size, "menu", issues);
  const klass = readDialogField(view, menu.nextOffset, "class", issues);
  const title = readDialogField(view, klass.nextOffset, "title", issues);
  const font = readDialogFont(view, title.nextOffset, style, templateKind, issues);
  return {
    templateKind, helpId: templateKind === "extended" ? view.getUint32(4, true) : null,
    title: title.value, menu: menu.value, className: klass.value,
    x: view.getInt16(boundsOffset, true), y: view.getInt16(boundsOffset + 2, true),
    width: view.getInt16(boundsOffset + 4, true), height: view.getInt16(boundsOffset + 6, true),
    style, exStyle: view.getUint32(templateKind === "standard" ? 4 : 8, true), font: font.font,
    controls: readControls(view, font.nextOffset,
      view.getUint16(boundsOffset - 2, true), templateKind, issues)
  };
};

export const addDialogPreview = (data: Uint8Array, typeName: string): ResourcePreviewResult | null => {
  if (typeName !== "DIALOG") return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  // DLGTEMPLATEEX dlgVer=1, signature=0xFFFF:
  // https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgtemplateex
  const kind = view.byteLength >= 4 && view.getUint16(0, true) === 1
    && view.getUint16(2, true) === 0xffff ? "extended" : "standard";
  const issues: string[] = [];
  const preview = readDialog(view, kind, issues);
  if (!preview) return { issues: ["DIALOG resource is truncated or malformed."] };
  return {
    preview: { previewKind: "dialog", dialogPreview: preview },
    ...(issues.length ? { issues } : {})
  };
};
