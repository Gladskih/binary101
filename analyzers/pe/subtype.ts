"use strict";

import type { PeClrHeader } from "./clr/types.js";
import type { MuiResourceConfiguration } from "./resources/mui-config.js";
import {
  detectPeClrNativeImageSubtypeFromClr,
  isPeClrNativeImage,
  type PeClrNativeImageSubtype
} from "./clr-native-image.js";
import {
  detectPeWinmdSubtypeFromClr,
  isPeWinmd,
  type PeWinmdSubtype
} from "./winmd.js";

export type PeMuiResourceSubtype = "mui-resource-image";
export type PeSubtype = PeWinmdSubtype | PeClrNativeImageSubtype | PeMuiResourceSubtype;

export const detectPeSubtypeFromClr = (clr: PeClrHeader | null): PeSubtype | null => {
  if (!clr) return null;
  return detectPeWinmdSubtypeFromClr(clr) ?? detectPeClrNativeImageSubtypeFromClr(clr);
};

export const detectPeMuiResourceSubtype = (
  muiResourceConfiguration: MuiResourceConfiguration | null | undefined,
  addressOfEntryPoint: number,
  sections: Array<{ characteristics: number }>
): PeMuiResourceSubtype | null => {
  if (!muiResourceConfiguration || addressOfEntryPoint !== 0) return null;
  for (const section of sections) {
    // Microsoft PE format, "Section Flags": IMAGE_SCN_MEM_EXECUTE is 0x20000000.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
    if ((section.characteristics & 0x20000000) !== 0) return null;
  }
  return "mui-resource-image";
};

export const detectPeSubtype = (
  clr: PeClrHeader | null,
  muiResourceConfiguration: MuiResourceConfiguration | null | undefined,
  addressOfEntryPoint: number,
  sections: Array<{ characteristics: number }>
): PeSubtype | null =>
  detectPeSubtypeFromClr(clr) ??
  detectPeMuiResourceSubtype(muiResourceConfiguration, addressOfEntryPoint, sections);

export { isPeClrNativeImage, isPeWinmd };
