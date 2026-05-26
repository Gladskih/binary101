"use strict";

import type { PeClrHeader } from "./clr/types.js";

export type PeSubtype = "winmd" | "clr-native-image";

// Microsoft Learn, "Windows Metadata (WinMD) files", specifies that a WinMD CLR
// metadata version string must contain "Windows Runtime 1.2".
// https://learn.microsoft.com/en-us/uwp/winrt-cref/winmd-files#winmd-file-format
//
// Microsoft tooling also emits and consumes the compact "WindowsRuntime" token
// with later minor versions. The xlang generator builds metadata with
// /mdv="WindowsRuntime 1.4", and NuGet BuildTasks classifies WinMDs by the
// "WindowsRuntime" token while covering 1.3 and "1.4;CLR v4.0.30319" in tests.
// https://github.com/microsoft/xlang/blob/28faea764da2c1cbf61fd12c7c784d39d4373987/src/foundation/CMakeLists.txt#L3
// https://github.com/dotnet/NuGet.BuildTasks/blob/607dadc8f84580c77548eaadade8e67122fd6239/src/Microsoft.NuGet.Build.Tasks/ResolveNuGetPackageAssets.cs#L1026-L1037
// https://github.com/dotnet/NuGet.BuildTasks/blob/607dadc8f84580c77548eaadade8e67122fd6239/src/Microsoft.NuGet.Build.Tasks.Tests/ReferenceResolutionTests.cs#L401-L432
const WINMD_METADATA_VERSION_COMPONENTS = new Set([
  "WindowsRuntime 1.2",
  "WindowsRuntime 1.3",
  "WindowsRuntime 1.4",
  "Windows Runtime 1.2",
  "Windows Runtime 1.3",
  "Windows Runtime 1.4"
]);

const MANAGED_NATIVE_HEADER_SUBTYPES = new Set([
  "ready-to-run",
  "unknown-managed-native-header"
]);

const detectWinmdFromClr = (clr: PeClrHeader): PeSubtype | null => {
  const version = clr.meta?.version;
  if (!version) return null;
  return version.split(";").some(component => WINMD_METADATA_VERSION_COMPONENTS.has(component.trim()))
    ? "winmd"
    : null;
};

const detectClrNativeImageFromClr = (clr: PeClrHeader): PeSubtype | null =>
  // Microsoft Learn documents that Ngen.exe creates native images in the native
  // image cache. CoreCLR corhdr.h says precompiled NGen images use
  // IMAGE_COR20_HEADER.ManagedNativeHeader and ReadyToRun points it at
  // READYTORUN_HEADER; non-RTR NGen images are reported as unknown managed-native
  // headers by our CLR parser.
  // https://learn.microsoft.com/en-us/dotnet/framework/tools/ngen-exe-native-image-generator
  // https://github.com/dotnet/runtime/blob/9071409ca4566506f218263e40c3b672a8508b35/src/coreclr/inc/corhdr.h#L206-L243
  clr.readyToRun && MANAGED_NATIVE_HEADER_SUBTYPES.has(clr.readyToRun.status)
    ? "clr-native-image"
    : null;

export const detectPeSubtypeFromClr = (clr: PeClrHeader | null): PeSubtype | null => {
  if (!clr) return null;
  return detectWinmdFromClr(clr) ?? detectClrNativeImageFromClr(clr);
};

export const isPeWinmd = (pe: { subtype?: PeSubtype | null }): boolean =>
  pe.subtype === "winmd";

export const isPeClrNativeImage = (pe: { subtype?: PeSubtype | null }): boolean =>
  pe.subtype === "clr-native-image";
