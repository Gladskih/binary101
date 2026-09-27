"use strict";

import type { ResourceFontDirectory } from "./font-types.js";
import type { ResourcePreviewResult } from "./types.js";
import { readFontHeader, readFontName } from "./font-header.js";

const matchesLayout = (data: Uint8Array, headerSize: number): boolean => {
  const count = new DataView(data.buffer, data.byteOffset, data.length).getUint16(0, true);
  let pos = 2;
  for (let index = 0; index < count; index += 1) {
    if (pos + 2 + headerSize > data.length) return false;
    const deviceEnd = data.indexOf(0, pos + 2 + headerSize);
    if (deviceEnd < 0) return false;
    const faceEnd = data.indexOf(0, deviceEnd + 1);
    if (faceEnd < 0) return false;
    pos = faceEnd + 1;
  }
  return pos === data.length;
};

const readDirectory = (
  data: Uint8Array, headerSize: number
): { directory: ResourceFontDirectory; issues: string[]; end: number } => {
  const view = new DataView(data.buffer, data.byteOffset, data.length);
  const issues: string[] = [];
  const entries: ResourceFontDirectory["entries"] = [];
  let pos = 2;
  for (let index = 0; index < view.getUint16(0, true); index += 1) {
    if (pos + 2 + headerSize > data.length) {
      issues.push("FONTDIR entry header is truncated.");
      break;
    }
    const font = readFontHeader(data, pos + 2);
    if (!font) break;
    const device = readFontName(data, pos + 2 + headerSize, issues);
    const face = readFontName(data, device.nextOffset, issues);
    entries.push({ ordinal: view.getUint16(pos, true),
      font: { ...font, deviceName: device.text, faceName: face.text } });
    pos = face.nextOffset;
  }
  return { directory: { headerSize, entries }, issues, end: pos };
};

export const addFontDirectoryPreview = (
  data: Uint8Array, typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "FONTDIR") return null;
  if (data.length < 2) return { issues: ["FONTDIR count is truncated."] };
  // Documented packed prefix vs Win32 rc.exe's full FNT v3 prefix. Select by
  // complete structural consumption, not dfSize (which describes the original FONT).
  // https://squeek502.github.io/resinator/windows/resources/font.html
  const documented = matchesLayout(data, 113);
  const win32 = matchesLayout(data, 148);
  const chosen = readDirectory(data, !documented && win32 ? 148 : 113);
  if (documented && win32 && chosen.directory.entries.length) {
    chosen.issues.push("FONTDIR layout is ambiguous; displaying the documented 113-byte prefix.");
  }
  if (chosen.end < data.length) chosen.issues.push("FONTDIR contains unparsed or truncated entry bytes.");
  return { preview: { previewKind: "fontDirectory", fontDirectory: chosen.directory },
    ...(chosen.issues.length ? { issues: chosen.issues } : {}) };
};
