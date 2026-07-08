"use strict";
import type { ProbeResult } from "./probe-types.js";
import { hasTrueTypeSfntSignature, hasWoffSignature, hasWoff2Signature } from "./file-signatures.js";

const hasValidSfntDirectory = (dv: DataView, offset: number): boolean => {
  if (offset > dv.byteLength - 12) return false;
  const sfntVersion = dv.getUint32(offset, false);
  if (sfntVersion !== 0x00010000 && sfntVersion !== 0x4f54544f) return false;
  const tableCount = dv.getUint16(offset + 4, false);
  return tableCount > 0 && tableCount <= Math.floor((dv.byteLength - offset - 12) / 16);
};

const detectFontCollection = (dv: DataView): ProbeResult => {
  // OpenType 1.9.1, "Font Collections": TTCHeader starts with "ttcf", a
  // 1.0/2.0 version, a font count, and offsets to complete sfnt directories.
  // https://learn.microsoft.com/en-us/typography/opentype/spec/otff#font-collections
  if (dv.byteLength < 12 || dv.getUint32(0, false) !== 0x74746366) return null;
  const version = dv.getUint32(4, false);
  if (version !== 0x00010000 && version !== 0x00020000) return null;
  const fontCount = dv.getUint32(8, false);
  if (fontCount === 0 || fontCount > Math.floor((dv.byteLength - 12) / 4)) return null;
  for (let index = 0; index < fontCount; index += 1) {
    if (!hasValidSfntDirectory(dv, dv.getUint32(12 + index * 4, false))) return null;
  }
  return "OpenType font collection (TTC/OTC shared font tables)";
};

const detectTrueTypeFont = (dv: DataView): ProbeResult => {
  return hasTrueTypeSfntSignature(dv) ? "TrueType/OpenType font (sfnt glyph outlines)" : null;
};

const detectWoff2Font = (dv: DataView): ProbeResult => {
  return hasWoff2Signature(dv) ? "Web Open Font Format 2 font (WOFF2 compressed web font)" : null;
};

const detectWoffFont = (dv: DataView): ProbeResult => {
  return hasWoffSignature(dv) ? "Web Open Font Format font (WOFF compressed web font)" : null;
};

const fontProbes: Array<(dv: DataView) => ProbeResult> = [
  detectFontCollection,
  detectTrueTypeFont,
  detectWoff2Font,
  detectWoffFont
];

export { fontProbes };
