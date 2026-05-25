"use strict";

import type { PeClrHeader } from "./clr/types.js";

export type PeSubtype = "winmd";

// Microsoft Learn, "Windows Metadata (WinMD) files", identifies WinMD by a CLR
// metadata version-string component in the Windows Runtime family. Windows SDK
// 10.0.26100.0 WinMD files use "WindowsRuntime 1.4" and older SDK files use 1.2.
// https://learn.microsoft.com/en-us/uwp/winrt-cref/winmd-files#winmd-file-format
const WINMD_METADATA_VERSION_COMPONENTS = new Set([
  "WindowsRuntime 1.2",
  "WindowsRuntime 1.3",
  "WindowsRuntime 1.4",
  "Windows Runtime 1.2",
  "Windows Runtime 1.3",
  "Windows Runtime 1.4"
]);

export const detectPeSubtypeFromClr = (clr: PeClrHeader | null): PeSubtype | null => {
  const version = clr?.meta?.version;
  if (!version) return null;
  return version.split(";").some(component => WINMD_METADATA_VERSION_COMPONENTS.has(component.trim()))
    ? "winmd"
    : null;
};

export const isPeWinmd = (pe: { subtype?: PeSubtype | null }): boolean =>
  pe.subtype === "winmd";
