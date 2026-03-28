"use strict";

import type { PeDataDirectory } from "./types.js";

// Microsoft PE format, "Optional Header Data Directories":
// ARCHITECTURE is reserved and must be zero.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
export interface PeArchitectureDirectory {
  rva: number;
  size: number;
  warnings?: string[];
}

export const parseArchitectureDirectory = (
  dataDirs: PeDataDirectory[]
): PeArchitectureDirectory | null => {
  const dir = dataDirs.find(directory => directory.name === "ARCHITECTURE");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  return {
    rva: dir.rva,
    size: dir.size,
    warnings: [
      "ARCHITECTURE directory is reserved by the PE specification and should have RVA=0 and Size=0."
    ]
  };
};
