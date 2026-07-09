"use strict";

import type { PeClrHeader } from "./clr/types.js";
import { BOOT_FLAG_MAGIC } from "./linux-boot-header.js";
import type { PeLinuxBootProtocol } from "./linux-boot.js";
import type { MuiResourceConfiguration } from "./resources/mui-config.js";
import type { PeDosHeader } from "./types.js";
import {
  detectPeClrNativeImageSubtypeFromClr,
  isPeClrNativeImage,
  type PeClrNativeImageSubtype
} from "./clr-native-image.js";
import {
  detectPeReferenceAssemblySubtypeFromClr,
  isPeReferenceAssembly,
  type PeReferenceAssemblySubtype
} from "./reference-assembly.js";
import {
  detectPeWinmdSubtypeFromClr,
  isPeWinmd,
  type PeWinmdSubtype
} from "./winmd.js";

export type PeMuiResourceSubtype = "mui-resource-image";
export type PeLinuxBootSubtype = "linux-boot-kernel";
export type PeDosStubNestedPeSubtype = "intel-txt-mle-nested-pe" | "dos-stub-nested-pe";
export type PeSubtype =
  PeWinmdSubtype |
  PeReferenceAssemblySubtype |
  PeClrNativeImageSubtype |
  PeLinuxBootSubtype |
  PeDosStubNestedPeSubtype |
  PeMuiResourceSubtype;

export const detectPeSubtypeFromClr = (clr: PeClrHeader | null): PeSubtype | null => {
  if (!clr) return null;
  return (
    detectPeWinmdSubtypeFromClr(clr) ??
    detectPeReferenceAssemblySubtypeFromClr(clr) ??
    detectPeClrNativeImageSubtypeFromClr(clr)
  );
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

export const detectPeLinuxBootSubtype = (
  linuxBoot: PeLinuxBootProtocol | null | undefined
): PeLinuxBootSubtype | null =>
  linuxBoot?.bootFlag === BOOT_FLAG_MAGIC ? "linux-boot-kernel" : null;

export const detectPeDosStubNestedPeSubtype = (
  dos: Pick<PeDosHeader, "stub"> | null | undefined
): PeDosStubNestedPeSubtype | null => {
  const nestedPe = dos?.stub.code?.nestedPe;
  if (!nestedPe) return null;
  return nestedPe.mle ? "intel-txt-mle-nested-pe" : "dos-stub-nested-pe";
};

export const detectPeSubtype = (
  clr: PeClrHeader | null,
  muiResourceConfiguration: MuiResourceConfiguration | null | undefined,
  addressOfEntryPoint: number,
  sections: Array<{ characteristics: number }>,
  linuxBoot: PeLinuxBootProtocol | null | undefined,
  dos: Pick<PeDosHeader, "stub"> | null | undefined
): PeSubtype | null =>
  detectPeSubtypeFromClr(clr) ??
  detectPeLinuxBootSubtype(linuxBoot) ??
  detectPeDosStubNestedPeSubtype(dos) ??
  detectPeMuiResourceSubtype(muiResourceConfiguration, addressOfEntryPoint, sections);

export { isPeClrNativeImage, isPeReferenceAssembly, isPeWinmd };
