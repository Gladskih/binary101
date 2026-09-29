"use strict";

import type { PeResources } from "./index.js";
import type { ResourceCrossCheck } from "./resource-consistency.js";

// VFT_APP=1 and VFT_DLL=2: VS_FIXEDFILEINFO.dwFileType.
// https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
const versionTypes = new Map([[1, "VFT_APP"], [2, "VFT_DLL"]]);
// IMAGE_FILE_DLL in IMAGE_FILE_HEADER.Characteristics.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
const IMAGE_FILE_DLL = 0x2000;

const versionChecks = (resources: PeResources, characteristics: number): ResourceCrossCheck[] => {
  const checks: ResourceCrossCheck[] = [];
  for (const group of resources.detail) {
    if (group.typeName !== "VERSION") continue;
    for (const entry of group.entries) for (const lang of entry.langs) {
      const fileType = lang.versionInfo?.fixedFileInfo?.fileType;
      const declared = versionTypes.get(fileType ?? -1);
      if (!declared) continue;
      const isDll = (characteristics & IMAGE_FILE_DLL) !== 0;
      const consistent = (fileType === 2) === isDll;
      checks.push({ status: consistent ? "confirmed" : "warning",
        subject: `${entry.name ?? `#${entry.id ?? "?"}`} / LANG ${lang.lang ?? "neutral"}`,
        detail: `VERSION ${declared} ${consistent ? "agrees" : "disagrees"} with ` +
          `COFF IMAGE_FILE_DLL (${isDll ? "set" : "clear"}).` });
    }
  }
  return checks;
};

export const attachVersionFileTypeChecks = (
  resources: PeResources | null, characteristics: number
): PeResources | null => {
  if (!resources) return null;
  const checks = versionChecks(resources, characteristics);
  return checks.length
    ? { ...resources, crossChecks: [...(resources.crossChecks ?? []), ...checks] }
    : resources;
};
