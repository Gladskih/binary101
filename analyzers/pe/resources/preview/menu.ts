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

const readUtf16Z = (
  view: DataView, offset: number, end: number, issues: string[]
): { text: string; nextOffset: number } => {
  let pos = offset;
  let text = "";
  while (pos + 1 < end) {
    const codeUnit = view.getUint16(pos, true);
    pos += 2;
    if (codeUnit === 0) return { text, nextOffset: pos };
    text += String.fromCharCode(codeUnit);
  }
  issues.push("MENU item text is not NUL-terminated.");
  return { text, nextOffset: pos };
};

const describeStandardFlags = (options: number): string[] => {
  const flags: string[] = [];
  if ((options & MF_POPUP) !== 0) flags.push("popup");
  if ((options & MF_SEPARATOR) !== 0) flags.push("separator");
  if ((options & MF_GRAYED) !== 0) flags.push("grayed");
  if (options & 0x0002) flags.push("MF_DISABLED");
  if (options & 0x0004) flags.push("MF_BITMAP");
  if (options & 0x0100) flags.push("MF_OWNERDRAW");
  if (options & 0x1000) flags.push("MF_DEFAULT");
  if (options & 0x4000) flags.push("MF_RIGHTJUSTIFY");
  if ((options & MF_CHECKED) !== 0) flags.push("checked");
  if ((options & MF_MENUBREAK) !== 0) flags.push("menu-break");
  if ((options & MF_MENUBARBREAK) !== 0) flags.push("menu-bar-break");
  return flags;
};

const describeExtendedFlags = (type: number, state: number, resInfo: number): string[] => {
  const flags: string[] = [];
  if ((resInfo & MFR_POPUP) !== 0) flags.push("popup");
  // MFT_* and MFS_* values from the Windows SDK WinUser.h.
  // https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/WinUser.h
  for (const [mask, name] of [
    [0x4, "MFT_BITMAP"], [0x20, "MFT_MENUBARBREAK"], [0x40, "MFT_MENUBREAK"],
    [0x100, "MFT_OWNERDRAW"], [0x200, "MFT_RADIOCHECK"], [0x800, "MFT_SEPARATOR"],
    [0x2000, "MFT_RIGHTORDER"], [0x4000, "MFT_RIGHTJUSTIFY"]
  ] as const) {
    if (type & mask) flags.push(name);
  }
  if (state & 0x80) flags.push("MFS_HILITE");
  if (state & 0x1000) flags.push("MFS_DEFAULT");
  if ((state & MFS_GRAYED) !== 0) flags.push("grayed");
  if ((state & MFS_CHECKED) !== 0) flags.push("checked");
  return flags;
};

const parseStandardItems = (
  view: DataView,
  offset: number,
  end: number,
  issues: string[],
  depth = 0
): { items: ResourceMenuItemPreview[]; nextOffset: number } => {
  // Bound recursion for malicious popup nesting; keep partial previews and report the limit.
  if (depth >= 64) {
    issues.push("MENU nesting exceeds the preview limit of 64 levels.");
    return { items: [], nextOffset: end };
  }
  const items: ResourceMenuItemPreview[] = [];
  let pos = offset;
  while (pos + 1 < end) {
    const options = view.getUint16(pos, true);
    pos += 2;
    const isPopup = (options & MF_POPUP) !== 0;
    const isEnd = (options & MF_END) !== 0;
    const id = isPopup || pos + 1 >= end ? null : view.getUint16(pos, true);
    if (!isPopup) pos += 2;
    const text = readUtf16Z(view, pos, end, issues);
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
      const child = parseStandardItems(view, pos, end, issues, depth + 1);
      item.children = child.items;
      pos = child.nextOffset;
    }
    items.push(item);
    if (isEnd) return { items, nextOffset: pos };
  }
  issues.push("MENU item list is truncated or lacks an end marker.");
  return { items, nextOffset: pos };
};

const parseExtendedItems = (
  view: DataView,
  offset: number,
  end: number,
  issues: string[],
  depth = 0
): { items: ResourceMenuItemPreview[]; nextOffset: number } => {
  // Bound recursion for malicious popup nesting; keep partial previews and report the limit.
  if (depth >= 64) {
    issues.push("MENU nesting exceeds the preview limit of 64 levels.");
    return { items: [], nextOffset: end };
  }
  const items: ResourceMenuItemPreview[] = [];
  let pos = offset;
  // MENUEX_TEMPLATE_ITEM has a fixed 14-byte prefix before the UTF-16 item text.
  while (pos + 13 < end) {
    const type = view.getUint32(pos, true);
    const state = view.getUint32(pos + 4, true);
    const id = view.getUint32(pos + 8, true);
    const resInfo = view.getUint16(pos + 12, true);
    pos += 14;
    const text = readUtf16Z(view, pos, end, issues);
    pos = alignDword(text.nextOffset);
    const isPopup = (resInfo & MFR_POPUP) !== 0;
    const isEnd = (resInfo & MFR_END) !== 0;
    if (isPopup && pos + 4 > end) issues.push("MENUEX popup help ID is truncated.");
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
      const child = parseExtendedItems(view, pos, end, issues, depth + 1);
      item.children = child.items;
      pos = child.nextOffset;
    }
    items.push(item);
    if (isEnd) return { items, nextOffset: pos };
  }
  issues.push("MENU item list is truncated or lacks an end marker.");
  return { items, nextOffset: pos };
};

const parseStandardMenu = (view: DataView, issues: string[]): ResourceMenuPreview | null => {
  if (view.byteLength < 4) return null;
  const offset = view.getUint16(2, true);
  const itemOffset = 4 + offset;
  if (itemOffset > view.byteLength || itemOffset % 2) return null;
  return {
    templateKind: "standard",
    helpId: null,
    items: parseStandardItems(view, itemOffset, view.byteLength, issues).items
  };
};

const parseExtendedMenu = (view: DataView, issues: string[]): ResourceMenuPreview | null => {
  if (view.byteLength < 8) return null;
  // MENUEX_TEMPLATE_HEADER is WORD dwVersion, WORD cbHeaderSize, DWORD dwHelpId.
  const itemOffset = 4 + view.getUint16(2, true);
  if (itemOffset < 8 || itemOffset > view.byteLength || itemOffset % 4) return null;
  return {
    templateKind: "extended",
    helpId: view.getUint32(4, true),
    items: parseExtendedItems(view, itemOffset, view.byteLength, issues).items
  };
};

export const addMenuPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "MENU") return null;
  if (data.byteLength < 4) return { issues: ["MENU resource header is truncated."] };
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  // Standard menu templates use version 0; MENUEX uses version 1.
  const version = view.getUint16(0, true);
  if (version !== 0 && version !== 1) return { issues: ["MENU template version is unsupported."] };
  const issues: string[] = [];
  const preview = version === 1 ? parseExtendedMenu(view, issues) : parseStandardMenu(view, issues);
  if (!preview) {
    return { issues: ["MENU resource is truncated or malformed."] };
  }
  return {
    preview: {
      previewKind: "menu",
      menuPreview: preview
    },
    ...(issues.length ? { issues } : {})
  };
};
