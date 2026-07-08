"use strict";
import type { ProbeResult } from "./probe-types.js";
import { hasTrueTypeSfntSignature } from "./file-signatures.js";

const detectTrueTypeFont = (dv: DataView): ProbeResult => {
  return hasTrueTypeSfntSignature(dv) ? "TrueType/OpenType font (sfnt glyph outlines)" : null;
};

const fontProbes: Array<(dv: DataView) => ProbeResult> = [
  detectTrueTypeFont
];

export { fontProbes };
