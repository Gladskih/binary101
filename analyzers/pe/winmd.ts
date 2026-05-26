"use strict";

import type { PeClrHeader } from "./clr/types.js";

export type PeWinmdSubtype = "winmd";

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

export const detectPeWinmdSubtypeFromClr = (clr: PeClrHeader): PeWinmdSubtype | null => {
  const version = clr.meta?.version;
  if (!version) return null;
  return version.split(";").some(component => WINMD_METADATA_VERSION_COMPONENTS.has(component.trim()))
    ? "winmd"
    : null;
};

export const isPeWinmd = (pe: { subtype?: string | null }): boolean =>
  pe.subtype === "winmd";
