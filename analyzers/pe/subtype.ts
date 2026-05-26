"use strict";

import type { PeClrHeader } from "./clr/types.js";
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

export type PeSubtype = PeWinmdSubtype | PeClrNativeImageSubtype;

export const detectPeSubtypeFromClr = (clr: PeClrHeader | null): PeSubtype | null => {
  if (!clr) return null;
  return detectPeWinmdSubtypeFromClr(clr) ?? detectPeClrNativeImageSubtypeFromClr(clr);
};

export { isPeClrNativeImage, isPeWinmd };
