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

const alignDword = (offset: number): number => Math.ceil(offset / 4) * 4;

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
  // Standard menu flags from WinUser.h; MF_END is structural in a template.
  // https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/WinUser.h
  const names = [
    [MF_POPUP, "popup"], [MF_SEPARATOR, "separator"], [MF_GRAYED, "grayed"],
    [MF_CHECKED, "checked"], [MF_MENUBREAK, "menu-break"], [MF_MENUBARBREAK, "menu-bar-break"],
    [0x2, "MF_DISABLED"], [0x4, "MF_BITMAP"], [0x100, "MF_OWNERDRAW"],
    [0x1000, "MF_DEFAULT"], [0x4000, "MF_RIGHTJUSTIFY"]
  ] as const;
  return names.filter(([mask]) => options & mask).map(([, name]) => name);
};

const readStandardId = (view: DataView, offset: number, end: number): number | null =>
  offset + 2 <= end ? view.getUint16(offset, true) : null;

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

const readStandardItem = (
  view: DataView, offset: number, end: number, issues: string[]
): { item: ResourceMenuItemPreview; nextOffset: number; popup: boolean; last: boolean } | null => {
  if (offset + 2 > end) return null;
  const options = view.getUint16(offset, true);
  const popup = (options & MF_POPUP) !== 0;
  if (!popup && offset + 4 > end) return null;
  const id = popup ? null : readStandardId(view, offset + 2, end);
  const text = readUtf16Z(view, offset + (popup ? 2 : 4), end, issues);
  return { item: { text: text.text || null, id, type: options, state: null,
    flags: describeStandardFlags(options), children: [] }, nextOffset: text.nextOffset,
  popup, last: (options & MF_END) !== 0 };
};

const readExtendedItem = (
  view: DataView, offset: number, end: number, issues: string[]
): { item: ResourceMenuItemPreview; nextOffset: number; resInfo: number } => {
  const type = view.getUint32(offset, true);
  const state = view.getUint32(offset + 4, true);
  const id = view.getUint32(offset + 8, true);
  const resInfo = view.getUint16(offset + 12, true);
  let pos = offset + 14;
  const text = readUtf16Z(view, pos, end, issues);
  pos = alignDword(text.nextOffset);
  const isPopup = (resInfo & MFR_POPUP) !== 0;
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
  return { item, nextOffset: pos, resInfo };
};

const readMenuItem = (view: DataView, pos: number, end: number,
  kind: ResourceMenuPreview["templateKind"], issues: string[]) => {
  return kind === "standard" ? readStandardItem(view, pos, end, issues) : (() => {
      const result = readExtendedItem(view, pos, end, issues);
      return { item: result.item, nextOffset: result.nextOffset,
        popup: (result.resInfo & MFR_POPUP) !== 0, last: (result.resInfo & MFR_END) !== 0 };
    })();
};

const discardEndedMenus = (stack: Array<{ endAfterChild: boolean }>): void => {
  while (stack[stack.length - 1]?.endAfterChild) stack.pop();
};

const parseMenuItems = (
  view: DataView, offset: number, end: number,
  kind: ResourceMenuPreview["templateKind"], issues: string[]
): ResourceMenuItemPreview[] => {
  const items: ResourceMenuItemPreview[] = [];
  const stack = [{ items, endAfterChild: false }];
  let pos = offset;
  while (stack.length) {
    if (pos + (kind === "standard" ? 2 : 14) > end) break;
    const record = readMenuItem(view, pos, end, kind, issues);
    if (!record) break;
    const frame = stack[stack.length - 1]!;
    frame.items.push(record.item);
    pos = record.nextOffset;
    if (record.popup) {
      frame.endAfterChild = record.last;
      stack.push({ items: record.item.children, endAfterChild: false });
    } else if (record.last) {
      stack.pop();
      discardEndedMenus(stack);
    }
  }
  if (stack.length) issues.push("MENU item list is truncated or lacks an end marker.");
  return items;
};

const parseStandardMenu = (view: DataView, issues: string[]): ResourceMenuPreview | null => {
  if (view.byteLength < 4) return null;
  const offset = view.getUint16(2, true);
  const itemOffset = 4 + offset;
  if (itemOffset > view.byteLength || itemOffset % 2) return null;
  return {
    templateKind: "standard",
    helpId: null,
    items: parseMenuItems(view, itemOffset, view.byteLength, "standard", issues)
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
    items: parseMenuItems(view, itemOffset, view.byteLength, "extended", issues)
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
