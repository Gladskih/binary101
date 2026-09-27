"use strict";

import type { ResourceVersionPreview } from "./types.js";

// Numeric StringFileInfo versions are not required to have the fixed-info syntax.
// Compare only unambiguous four-component numbers, accepting common comma separators.
// https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource
const numericVersion = (value: string): string | null => {
  if (!/^\s*\d+\s*[.,]\s*\d+\s*[.,]\s*\d+\s*[.,]\s*\d+\s*$/.test(value)) return null;
  return value.trim().split(/\s*[.,]\s*/).map(part => String(Number(part))).join(".");
};

export const validateVersionInfo = (info: ResourceVersionPreview): string[] => {
  const issues: string[] = [];
  for (const entry of info.stringValues || []) {
    const fixed = entry.key === "FileVersion" ? info.fileVersionString
      : entry.key === "ProductVersion" ? info.productVersionString : undefined;
    const numeric = numericVersion(entry.value);
    if (fixed && numeric && numeric !== fixed) {
      issues.push(`${entry.table} ${entry.key} (${entry.value}) differs from fixed version ${fixed}.`);
    }
  }
  const flags = (info.fixedFileInfo?.fileFlags || 0) & (info.fixedFileInfo?.fileFlagsMask || 0);
  // VS_FF_PRIVATEBUILD and VS_FF_SPECIALBUILD require corresponding string entries.
  // https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
  for (const [flag, key] of [[0x08, "PrivateBuild"], [0x20, "SpecialBuild"]] as const) {
    if ((flags & flag) && !info.stringValues?.some(entry => entry.key === key && entry.value.trim())) {
      issues.push(`VS_FF_${key.toUpperCase()} is set without a ${key} string.`);
    }
  }
  if (flags & 0x10) issues.push("VS_FF_INFOINFERRED must not be set in a VERSION resource.");
  return issues;
};
