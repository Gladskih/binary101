"use strict";

import type {
  ResourceDialogControlPreview,
  ResourceDialogFontPreview,
  ResourceDialogPreview,
  ResourcePreviewResult
} from "./resources-preview-types.js";

// DS_SETFONT requests font metadata after the dialog title. Source:
// Microsoft Learn, Dialog Box Styles / https://learn.microsoft.com/en-us/windows/win32/dlgbox/dialog-box-styles
const DS_SETFONT = 0x00000040;

// Predefined system control-class ordinals used after a 0xFFFF marker in DLGITEMTEMPLATE class arrays.
// Source: Microsoft Learn, DLGITEMTEMPLATE / https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgitemtemplate
const standardDialogClasses = new Map<number, string>([
  [0x0080, "BUTTON"],
  [0x0081, "EDIT"],
  [0x0082, "STATIC"],
  [0x0083, "LISTBOX"],
  [0x0084, "SCROLLBAR"],
  [0x0085, "COMBOBOX"]
]);

const alignDword = (offset: number): number => (offset + 3) & ~3;

const readUtf16Z = (view: DataView, offset: number, end: number): { text: string; nextOffset: number } => {
  let pos = offset;
  let text = "";
  while (pos + 1 < end) {
    const codeUnit = view.getUint16(pos, true);
    pos += 2;
    if (codeUnit === 0) break;
    text += String.fromCharCode(codeUnit);
  }
  return { text, nextOffset: pos };
};

const readDialogField = (
  view: DataView,
  offset: number,
  end: number
): { value: string | null; nextOffset: number } => {
  if (offset + 1 >= end) return { value: null, nextOffset: end };
  const first = view.getUint16(offset, true);
  if (first === 0x0000) return { value: null, nextOffset: offset + 2 };
  // A 0xFFFF marker means the next WORD is a predefined system-class ordinal.
  if (first === 0xffff && offset + 3 < end) {
    const ordinal = view.getUint16(offset + 2, true);
    return {
      value: standardDialogClasses.get(ordinal) || `#${ordinal}`,
      nextOffset: offset + 4
    };
  }
  const text = readUtf16Z(view, offset, end);
  return { value: text.text, nextOffset: text.nextOffset };
};

const parseStandardFont = (
  view: DataView,
  style: number,
  offset: number,
  end: number
): { font: ResourceDialogFontPreview | null; nextOffset: number } => {
  if ((style & DS_SETFONT) === 0 || offset + 1 >= end) return { font: null, nextOffset: offset };
  const pointSize = view.getUint16(offset, true);
  const typeface = readUtf16Z(view, offset + 2, end);
  return {
    font: {
      pointSize,
      weight: null,
      italic: false,
      charset: null,
      typeface: typeface.text
    },
    nextOffset: typeface.nextOffset
  };
};

const parseExtendedFont = (
  view: DataView,
  style: number,
  offset: number,
  end: number
): { font: ResourceDialogFontPreview | null; nextOffset: number } => {
  if ((style & DS_SETFONT) === 0 || offset + 5 >= end) return { font: null, nextOffset: offset };
  const pointSize = view.getUint16(offset, true);
  const weight = view.getUint16(offset + 2, true);
  const italic = view.getUint8(offset + 4) !== 0;
  const charset = view.getUint8(offset + 5);
  const typeface = readUtf16Z(view, offset + 6, end);
  return {
    font: {
      pointSize,
      weight,
      italic,
      charset,
      typeface: typeface.text
    },
    nextOffset: typeface.nextOffset
  };
};

const parseStandardControl = (
  view: DataView,
  offset: number,
  end: number
): { control: ResourceDialogControlPreview | null; nextOffset: number } => {
  const aligned = alignDword(offset);
  if (aligned + 17 > end) return { control: null, nextOffset: end };
  let pos = aligned;
  const style = view.getUint32(pos, true);
  const exStyle = view.getUint32(pos + 4, true);
  const x = view.getInt16(pos + 8, true);
  const y = view.getInt16(pos + 10, true);
  const width = view.getInt16(pos + 12, true);
  const height = view.getInt16(pos + 14, true);
  const id = view.getUint16(pos + 16, true);
  pos += 18;
  const klass = readDialogField(view, pos, end);
  const title = readDialogField(view, klass.nextOffset, end);
  if (title.nextOffset + 1 >= end) return { control: null, nextOffset: end };
  const extraCount = view.getUint16(title.nextOffset, true);
  const nextOffset = alignDword(Math.min(end, title.nextOffset + 2 + extraCount));
  return {
    control: {
      id,
      kind: klass.value || "(custom)",
      title: title.value,
      x,
      y,
      width,
      height,
      style,
      exStyle
    },
    nextOffset
  };
};

const parseExtendedControl = (
  view: DataView,
  offset: number,
  end: number
): { control: ResourceDialogControlPreview | null; nextOffset: number } => {
  const aligned = alignDword(offset);
  if (aligned + 23 > end) return { control: null, nextOffset: end };
  let pos = aligned;
  const exStyle = view.getUint32(pos + 4, true);
  const style = view.getUint32(pos + 8, true);
  const x = view.getInt16(pos + 12, true);
  const y = view.getInt16(pos + 14, true);
  const width = view.getInt16(pos + 16, true);
  const height = view.getInt16(pos + 18, true);
  const id = view.getUint32(pos + 20, true);
  pos += 24;
  const klass = readDialogField(view, pos, end);
  const title = readDialogField(view, klass.nextOffset, end);
  if (title.nextOffset + 1 >= end) return { control: null, nextOffset: end };
  const extraCount = view.getUint16(title.nextOffset, true);
  const nextOffset = alignDword(Math.min(end, title.nextOffset + 2 + extraCount));
  return {
    control: {
      id,
      kind: klass.value || "(custom)",
      title: title.value,
      x,
      y,
      width,
      height,
      style,
      exStyle
    },
    nextOffset
  };
};

const parseStandardDialog = (view: DataView): ResourceDialogPreview | null => {
  if (view.byteLength < 18) return null;
  const style = view.getUint32(0, true);
  const exStyle = view.getUint32(4, true);
  const controlCount = view.getUint16(8, true);
  const x = view.getInt16(10, true);
  const y = view.getInt16(12, true);
  const width = view.getInt16(14, true);
  const height = view.getInt16(16, true);
  const menu = readDialogField(view, 18, view.byteLength);
  const klass = readDialogField(view, menu.nextOffset, view.byteLength);
  const title = readDialogField(view, klass.nextOffset, view.byteLength);
  const font = parseStandardFont(view, style, title.nextOffset, view.byteLength);
  const controls: ResourceDialogControlPreview[] = [];
  let pos = alignDword(font.nextOffset);
  for (let index = 0; index < controlCount && pos < view.byteLength; index += 1) {
    const control = parseStandardControl(view, pos, view.byteLength);
    if (!control.control) break;
    controls.push(control.control);
    pos = control.nextOffset;
  }
  return {
    templateKind: "standard",
    title: title.value,
    menu: menu.value,
    className: klass.value,
    x,
    y,
    width,
    height,
    style,
    exStyle,
    font: font.font,
    controls
  };
};

const parseExtendedDialog = (view: DataView): ResourceDialogPreview | null => {
  if (view.byteLength < 26) return null;
  const style = view.getUint32(12, true);
  const exStyle = view.getUint32(8, true);
  const controlCount = view.getUint16(16, true);
  const x = view.getInt16(18, true);
  const y = view.getInt16(20, true);
  const width = view.getInt16(22, true);
  const height = view.getInt16(24, true);
  const menu = readDialogField(view, 26, view.byteLength);
  const klass = readDialogField(view, menu.nextOffset, view.byteLength);
  const title = readDialogField(view, klass.nextOffset, view.byteLength);
  const font = parseExtendedFont(view, style, title.nextOffset, view.byteLength);
  const controls: ResourceDialogControlPreview[] = [];
  let pos = alignDword(font.nextOffset);
  for (let index = 0; index < controlCount && pos < view.byteLength; index += 1) {
    const control = parseExtendedControl(view, pos, view.byteLength);
    if (!control.control) break;
    controls.push(control.control);
    pos = control.nextOffset;
  }
  return {
    templateKind: "extended",
    title: title.value,
    menu: menu.value,
    className: klass.value,
    x,
    y,
    width,
    height,
    style,
    exStyle,
    font: font.font,
    controls
  };
};

export const addDialogPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "DIALOG" || data.byteLength < 18) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  // DLGTEMPLATEEX starts with dlgVer=1 and signature=0xFFFF. Source:
  // Microsoft Learn, DLGTEMPLATEEX / https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgtemplateex
  const isExtended = view.byteLength >= 4 && view.getUint16(0, true) === 1 && view.getUint16(2, true) === 0xffff;
  const preview = isExtended ? parseExtendedDialog(view) : parseStandardDialog(view);
  if (!preview) {
    return { issues: ["DIALOG resource is truncated or malformed."] };
  }
  return {
    preview: {
      previewKind: "dialog",
      dialogPreview: preview
    }
  };
};
