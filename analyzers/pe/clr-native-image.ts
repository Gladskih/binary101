"use strict";

import type { PeClrHeader } from "./clr/types.js";

export type PeClrNativeImageSubtype = "clr-native-image";

const MANAGED_NATIVE_HEADER_SUBTYPES = new Set([
  "ready-to-run",
  "ngen",
  "unknown-managed-native-header"
]);

export const detectPeClrNativeImageSubtypeFromClr = (
  clr: PeClrHeader
): PeClrNativeImageSubtype | null =>
  // Microsoft Learn documents that Ngen.exe creates native images in the native
  // image cache. CoreCLR corhdr.h says precompiled NGen images use
  // IMAGE_COR20_HEADER.ManagedNativeHeader and ReadyToRun points it at
  // READYTORUN_HEADER; unknown non-RTR values still identify managed-native
  // headers but are not treated as malformed without a matching format source.
  // https://learn.microsoft.com/en-us/dotnet/framework/tools/ngen-exe-native-image-generator
  // https://github.com/dotnet/runtime/blob/9071409ca4566506f218263e40c3b672a8508b35/src/coreclr/inc/corhdr.h#L206-L243
  clr.readyToRun && MANAGED_NATIVE_HEADER_SUBTYPES.has(clr.readyToRun.status)
    ? "clr-native-image"
    : null;

export const isPeClrNativeImage = (pe: { subtype?: string | null }): boolean =>
  pe.subtype === "clr-native-image";
