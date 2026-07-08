"use strict";
import type { ProbeResult } from "./probe-types.js";
import { hasTrueTypeSfntSignature, hasWoff2Signature } from "./file-signatures.js";

const detectTrueTypeFont = (dv: DataView): ProbeResult => {
  return hasTrueTypeSfntSignature(dv) ? "TrueType/OpenType font (sfnt glyph outlines)" : null;
};

const detectWoff2Font = (dv: DataView): ProbeResult => {
  return hasWoff2Signature(dv) ? "Web Open Font Format 2 font (WOFF2 compressed web font)" : null;
};

const fontProbes: Array<(dv: DataView) => ProbeResult> = [
  detectTrueTypeFont,
  detectWoff2Font
];

export { fontProbes };
