"use strict";

import type { ResourceDialogFontPreview, ResourceDialogPreview } from "./types.js";

// System-class ordinals are meaningful only in the class field, never in a menu or title.
// https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgitemtemplate
const classes = new Map([
  [0x80, "BUTTON"], [0x81, "EDIT"], [0x82, "STATIC"], [0x83, "LISTBOX"],
  [0x84, "SCROLLBAR"], [0x85, "COMBOBOX"]
]);

const readText = (
  view: DataView, offset: number, issues: string[]
): { value: string; nextOffset: number } => {
  let pos = offset;
  let value = "";
  while (pos + 2 <= view.byteLength) {
    const code = view.getUint16(pos, true);
    pos += 2;
    if (!code) return { value, nextOffset: pos };
    value += String.fromCharCode(code);
  }
  issues.push("DIALOG string is not NUL-terminated within the resource.");
  return { value, nextOffset: view.byteLength };
};

export const readDialogField = (
  view: DataView, offset: number, field: "class" | "title" | "menu", issues: string[]
): { value: string | null; nextOffset: number } => {
  if (offset + 2 > view.byteLength) {
    issues.push(`DIALOG ${field} field is truncated.`);
    return { value: null, nextOffset: view.byteLength };
  }
  const first = view.getUint16(offset, true);
  if (!first) return { value: null, nextOffset: offset + 2 };
  if (first !== 0xffff) return readText(view, offset, issues);
  if (offset + 4 > view.byteLength) {
    issues.push(`DIALOG ${field} ordinal is truncated.`);
    return { value: null, nextOffset: view.byteLength };
  }
  const ordinal = view.getUint16(offset + 2, true);
  return { value: (field === "class" ? classes.get(ordinal) : undefined) ?? `#${ordinal}`,
    nextOffset: offset + 4 };
};

export const readDialogFont = (
  view: DataView, offset: number, style: number,
  templateKind: ResourceDialogPreview["templateKind"], issues: string[]
): { font: ResourceDialogFontPreview | null; nextOffset: number } => {
  // DS_SETFONT (including DS_SHELLFONT) adds font metadata after the title.
  // https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgtemplateex
  if (!(style & 0x40)) return { font: null, nextOffset: offset };
  const size = templateKind === "standard" ? 2 : 6;
  if (offset + size > view.byteLength) {
    issues.push("DIALOG font metadata is truncated.");
    return { font: null, nextOffset: view.byteLength };
  }
  const typeface = readText(view, offset + size, issues);
  return { font: {
    pointSize: view.getUint16(offset, true),
    weight: templateKind === "extended" ? view.getUint16(offset + 2, true) : null,
    italic: templateKind === "extended" && view.getUint8(offset + 4) !== 0,
    charset: templateKind === "extended" ? view.getUint8(offset + 5) : null,
    typeface: typeface.value
  }, nextOffset: typeface.nextOffset };
};
