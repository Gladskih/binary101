"use strict";

import type { PeClrHeader } from "./clr/types.js";

export type PeSubtype = "winmd";

// Microsoft Learn, "Windows Metadata (WinMD) files", requires the WinMD metadata
// version string to contain "Windows Runtime 1.2". Microsoft SDK WinMD files encode
// that marker as the compact metadata token below.
// https://learn.microsoft.com/en-us/uwp/winrt-cref/winmd-files#winmd-file-format
const WINMD_METADATA_VERSION_TOKEN = "WindowsRuntime 1.2";
const WINMD_METADATA_VERSION_TOKEN_WITH_SPACE = "Windows Runtime 1.2";

export const detectPeSubtypeFromClr = (clr: PeClrHeader | null): PeSubtype | null => {
  const version = clr?.meta?.version;
  if (!version) return null;
  if (version.includes(WINMD_METADATA_VERSION_TOKEN)) return "winmd";
  return version.includes(WINMD_METADATA_VERSION_TOKEN_WITH_SPACE) ? "winmd" : null;
};

export const isPeWinmd = (pe: { subtype?: PeSubtype | null }): boolean =>
  pe.subtype === "winmd";
