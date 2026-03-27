"use strict";

import type {
  ResourceMenuItemPreview,
  ResourceMenuPreview,
  ResourcePreviewResult
} from "./types.js";

// Standard menu-template option bits. Source:
// Microsoft Learn, MENU resource / https://learn.microsoft.com/en-us/windows/win32/menurc/menu-resource
const MF_GRAYED = 0x0001;
const MF_CHECKED = 0x0008;
const MF_POPUP = 0x0010;
const MF_MENUBREAK = 0x0040;
const MF_MENUBARBREAK = 0x0020;
const MF_END = 0x0080;
const MF_SEPARATOR = 0x0800;

// MENUEX wFlags and state bits. Sources:
// MENUEX resource / https://learn.microsoft.com/en-us/windows/win32/menurc/menuex-resource
// MENUEX_TEMPLATE_ITEM / https://learn.microsoft.com/en-us/windows/win32/menurc/menuex-template-item
const MFR_POPUP = 0x0001;
const MFR_END = 0x0080;
const MFS_GRAYED = 0x0003;
const MFS_CHECKED = 0x0008;

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

const describeStandardFlags = (options: number): string[] => {
  const flags: string[] = [];
  if ((options & MF_POPUP) !== 0) flags.push("popup");
  if ((options & MF_SEPARATOR) !== 0) flags.push("separator");
  if ((options & MF_GRAYED) !== 0) flags.push("grayed");
  if ((options & MF_CHECKED) !== 0) flags.push("checked");
  if ((options & MF_MENUBREAK) !== 0) flags.push("menu-break");
  if ((options & MF_MENUBARBREAK) !== 0) flags.push("menu-bar-break");
  return flags;
};

const describeExtendedFlags = (type: number, state: number, resInfo: number): string[] => {
  const flags: string[] = [];
  if ((resInfo & MFR_POPUP) !== 0) flags.push("popup");
  if ((type & MF_SEPARATOR) !== 0) flags.push("separator");
  if ((state & MFS_GRAYED) !== 0) flags.push("grayed");
  if ((state & MFS_CHECKED) !== 0) flags.push("checked");
  return flags;
};

const parseStandardItems = (
  view: DataView,
  offset: number,
  end: number
): { items: ResourceMenuItemPreview[]; nextOffset: number } => {
  const items: ResourceMenuItemPreview[] = [];
  let pos = offset;
  while (pos + 1 < end) {
    const options = view.getUint16(pos, true);
    pos += 2;
    const isPopup = (options & MF_POPUP) !== 0;
    const isEnd = (options & MF_END) !== 0;
    const id = isPopup || pos + 1 >= end ? null : view.getUint16(pos, true);
    if (!isPopup) pos += 2;
    const text = readUtf16Z(view, pos, end);
    pos = text.nextOffset;
    const item: ResourceMenuItemPreview = {
      text: text.text || null,
      id,
      type: options,
      state: null,
      flags: describeStandardFlags(options),
      children: []
    };
    if (isPopup) {
      const child = parseStandardItems(view, pos, end);
      item.children = child.items;
      pos = child.nextOffset;
    }
    items.push(item);
    if (isEnd) break;
  }
  return { items, nextOffset: pos };
};

const parseExtendedItems = (
  view: DataView,
  offset: number,
  end: number
): { items: ResourceMenuItemPreview[]; nextOffset: number } => {
  const items: ResourceMenuItemPreview[] = [];
  let pos = offset;
  // MENUEX_TEMPLATE_ITEM has a fixed 14-byte prefix before the UTF-16 item text.
  while (pos + 13 < end) {
    const type = view.getUint32(pos, true);
    const state = view.getUint32(pos + 4, true);
    const id = view.getUint32(pos + 8, true);
    const resInfo = view.getUint16(pos + 12, true);
    pos += 14;
    const text = readUtf16Z(view, pos, end);
    pos = alignDword(text.nextOffset);
    const isPopup = (resInfo & MFR_POPUP) !== 0;
    const isEnd = (resInfo & MFR_END) !== 0;
    let helpId: number | null = null;
    if (isPopup && pos + 3 < end) {
      helpId = view.getUint32(pos, true);
      pos += 4;
    }
    const item: ResourceMenuItemPreview = {
      text: text.text || null,
      id: isPopup ? (id || null) : id,
      type,
      state,
      flags: describeExtendedFlags(type, state, resInfo),
      children: []
    };
    if (helpId != null) item.flags.push(`help:${helpId}`);
    if (isPopup) {
      const child = parseExtendedItems(view, pos, end);
      item.children = child.items;
      pos = child.nextOffset;
    }
    items.push(item);
    if (isEnd) break;
  }
  return { items, nextOffset: pos };
};

const parseStandardMenu = (view: DataView): ResourceMenuPreview | null => {
  if (view.byteLength < 4) return null;
  const offset = view.getUint16(2, true);
  const itemOffset = 4 + offset;
  if (itemOffset > view.byteLength) return null;
  return {
    templateKind: "standard",
    helpId: null,
    items: parseStandardItems(view, itemOffset, view.byteLength).items
  };
};

const parseExtendedMenu = (view: DataView): ResourceMenuPreview | null => {
  if (view.byteLength < 8) return null;
  // MENUEX_TEMPLATE_HEADER is WORD dwVersion, WORD cbHeaderSize, DWORD dwHelpId.
  const itemOffset = 4 + view.getUint16(2, true);
  if (itemOffset > view.byteLength) return null;
  return {
    templateKind: "extended",
    helpId: view.getUint32(4, true),
    items: parseExtendedItems(view, itemOffset, view.byteLength).items
  };
};

export const addMenuPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "MENU" || data.byteLength < 4) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  // Standard menu templates use version 0; MENUEX uses version 1.
  const version = view.getUint16(0, true);
  const preview = version === 1 ? parseExtendedMenu(view) : parseStandardMenu(view);
  if (!preview) {
    return { issues: ["MENU resource is truncated or malformed."] };
  }
  return {
    preview: {
      previewKind: "menu",
      menuPreview: preview
    }
  };
};
