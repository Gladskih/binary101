"use strict";

import { readFontHeader, readFontName } from "./font-header.js";
import type { ResourcePreviewResult } from "./types.js";
import type { ResourceFontPreview } from "./font-types.js";

const validateFontLayout = (
  font: ResourceFontPreview, headerSize: number, dataSize: number, bitmapOffset: number
): string[] => {
  const issues: string[] = [];
  if (font.fileSize > dataSize) issues.push("FONT declared file size exceeds the resource.");
  if (font.fileSize < headerSize) issues.push("FONT declared file size is smaller than its header.");
  if (font.firstChar > font.lastChar) issues.push("FONT character range is reversed.");
  if (bitmapOffset > Math.min(dataSize, font.fileSize)) issues.push("FONT bitmap offset is outside the resource.");
  return issues;
};

const readNames = (
  data: Uint8Array, view: DataView, font: ResourceFontPreview, headerSize: number, issues: string[]
): ResourceFontPreview => {
  const bounded = data.subarray(0, Math.min(data.length, font.fileSize));
  const deviceOffset = view.getUint32(101, true);
  const faceOffset = view.getUint32(105, true);
  const deviceName = deviceOffset ? readFontName(bounded, deviceOffset, issues).text : "";
  const faceName = readFontName(bounded, faceOffset, issues).text;
  if (faceOffset < headerSize || (deviceOffset && deviceOffset < headerSize)) {
    issues.push("FONT name offset overlaps its header.");
  }
  return { ...font, deviceName, faceName };
};

export const addLegacyFontPreview = (data: Uint8Array): ResourcePreviewResult | null => {
  if (data.length < 2) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.length);
  const version = view.getUint16(0, true);
  // Windows FNT v2 and v3 have packed headers of 118 and 148 bytes.
  // https://github.com/wine-mirror/wine/blob/master/tools/sfnt2fon/sfnt2fon.c
  if (version !== 0x200 && version !== 0x300) return null;
  const headerSize = version === 0x200 ? 118 : 148;
  const font = readFontHeader(data, 0);
  if (!font || data.length < headerSize) return { issues: ["FONT FNT header is truncated."] };
  const issues = validateFontLayout(font, headerSize, data.length, view.getUint32(113, true));
  const namedFont = readNames(data, view, font, headerSize, issues);
  return { preview: { previewKind: "legacyFont", legacyFont: namedFont },
    ...(issues.length ? { issues } : {}) };
};
