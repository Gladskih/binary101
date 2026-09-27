"use strict";

import type { ResourceVersionFixedFileInfo } from "../../analyzers/pe/resources/preview/types.js";

// Win32 VS_FIXEDFILEINFO constants and subtype semantics (verrsrc.h):
// https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
const fileTypes = new Map([
  [0, "VFT_UNKNOWN"], [1, "VFT_APP"], [2, "VFT_DLL"], [3, "VFT_DRV"],
  [4, "VFT_FONT"], [5, "VFT_VXD"], [7, "VFT_STATIC_LIB"]
]);
const driverTypes = new Map([
  [0, "UNKNOWN"], [1, "PRINTER"], [2, "KEYBOARD"], [3, "LANGUAGE"], [4, "DISPLAY"],
  [5, "MOUSE"], [6, "NETWORK"], [7, "SYSTEM"], [8, "INSTALLABLE"], [9, "SOUND"],
  [10, "COMM"], [12, "VERSIONED_PRINTER"]
]);
const fontTypes = new Map([[0, "UNKNOWN"], [1, "RASTER"], [2, "VECTOR"], [3, "TRUETYPE"]]);
const fileFlags = ["DEBUG", "PRERELEASE", "PATCHED", "PRIVATEBUILD", "INFOINFERRED", "SPECIALBUILD"];
const operatingSystems = new Map([
  [0, "VOS_UNKNOWN"], [0x10000, "VOS_DOS"], [0x20000, "VOS_OS216"],
  [0x30000, "VOS_OS232"], [0x40000, "VOS_NT"]
]);
const environments = new Map([
  [1, "VOS__WINDOWS16"], [2, "VOS__PM16"], [3, "VOS__PM32"], [4, "VOS__WINDOWS32"]
]);

const hex = (value: number): string => `0x${(value >>> 0).toString(16).padStart(8, "0")}`;

const describeFlags = (value: number): string => {
  const names = fileFlags.filter((_name, index) => value & (1 << index))
    .map(name => `VS_FF_${name}`);
  if (value & ~0x3f) names.push(`unknown ${hex(value & ~0x3f)}`);
  return names.length ? `${hex(value)} (${names.join(" | ")})` : hex(value);
};

const describeOS = (value: number): string => {
  const names = [operatingSystems.get((value & 0xffff0000) >>> 0), environments.get(value & 0xffff)]
    .filter(Boolean);
  return `${hex(value)}${names.length ? ` (${names.join(" | ")})` : ""}`;
};

const describeSubtype = (info: ResourceVersionFixedFileInfo): string => {
  const value = info.fileSubtype ?? 0;
  const name = info.fileType === 3 ? driverTypes.get(value) : info.fileType === 4
    ? fontTypes.get(value) : undefined;
  return `${hex(value)}${name ? ` (VFT2_${name === "UNKNOWN" ? name
    : `${info.fileType === 3 ? "DRV" : "FONT"}_${name}`})` : ""}`;
};

export const versionFixedRows = (
  info: ResourceVersionFixedFileInfo
): Array<{ label: string; value: string }> => {
  if (info.fileFlagsMask == null) return [];
  return [
    { label: "FileFlagsMask", value: hex(info.fileFlagsMask) },
    { label: "FileFlags", value: describeFlags(info.fileFlags ?? 0) },
    { label: "Effective flags", value: describeFlags((info.fileFlags ?? 0) & info.fileFlagsMask) },
    { label: "FileOS", value: describeOS(info.fileOS ?? 0) },
    { label: "FileType", value: `${hex(info.fileType ?? 0)} (${fileTypes.get(info.fileType ?? 0) ?? "reserved"})` },
    { label: "FileSubtype", value: describeSubtype(info) },
    // The specification gives a binary date without defining an epoch; preserve all 64 bits.
    { label: "FileDateMS / LS", value: `${hex(info.fileDateMS ?? 0)} / ${hex(info.fileDateLS ?? 0)}` }
  ];
};
