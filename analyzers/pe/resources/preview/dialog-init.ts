"use strict";

import type { ResourcePreviewData, ResourcePreviewResult } from "./types.js";

// MFC CWnd::ExecuteDlgInit: WORD control ID, WORD message, DWORD byte length,
// followed immediately by the bytes; a zero control ID terminates the list.
// The payload can leave the next record unaligned. Source (Microsoft MFC source mirror):
// https://gist.github.com/thinkhy/794742#file-mfc_wincore-L3973
const readEntries = (
  data: Uint8Array, issues: string[]
): NonNullable<ResourcePreviewData["dialogInit"]>["entries"] => {
  const view = new DataView(data.buffer, data.byteOffset, data.length);
  const entries: NonNullable<ResourcePreviewData["dialogInit"]>["entries"] = [];
  let pos = 0;
  while (pos + 2 <= data.length) {
    const controlId = view.getUint16(pos, true);
    if (!controlId) return entries;
    if (pos + 8 > data.length) {
      issues.push("DLGINIT record header is truncated.");
      return entries;
    }
    const message = view.getUint16(pos + 2, true);
    const length = view.getUint32(pos + 4, true);
    pos += 8;
    const payload = data.subarray(pos, Math.min(data.length, pos + length));
    entries.push({ controlId, message, data: payload });
    if (length > data.length - pos) {
      issues.push("DLGINIT record payload is truncated.");
      return entries;
    }
    // Win16 LB_ADDSTRING/CB_ADDSTRING records require a counted NUL-terminated ANSI string.
    if ((message === 0x401 || message === 0x403) && (!length || payload[length - 1] !== 0)) {
      issues.push("DLGINIT ADDSTRING payload lacks a terminating NUL.");
    }
    pos += length;
  }
  issues.push("DLGINIT list lacks its terminating zero control ID.");
  return entries;
};

export const addDialogInitPreview = (
  data: Uint8Array, typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "DLGINIT") return null;
  const issues: string[] = [];
  const entries = readEntries(data, issues);
  return { preview: { previewKind: "dialogInit", dialogInit: { entries } },
    ...(issues.length ? { issues } : {}) };
};
