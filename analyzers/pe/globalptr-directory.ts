"use strict";

import type { PeDataDirectory, RvaToOffset } from "./types.js";

// Microsoft PE format, "Optional Header Data Directories":
// GLOBALPTR stores the RVA of the value for the global pointer register and its
// Size must be zero.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
export interface PeGlobalPtrDirectory {
  rva: number;
  size: number;
  warnings?: string[];
}

export const parseGlobalPtrDirectory = (
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): PeGlobalPtrDirectory | null => {
  const dir = dataDirs.find(directory => directory.name === "GLOBALPTR");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  const warnings: string[] = [];
  if (dir.size !== 0) {
    warnings.push("GLOBALPTR directory Size must be 0 according to the PE specification.");
  }
  if (dir.rva === 0) {
    warnings.push("GLOBALPTR directory has a non-zero size but RVA is 0.");
  } else {
    const offset = rvaToOff(dir.rva);
    if (offset == null || offset < 0) {
      warnings.push("GLOBALPTR directory RVA could not be mapped to a file offset.");
    }
  }
  return {
    rva: dir.rva,
    size: dir.size,
    ...(warnings.length ? { warnings } : {})
  };
};
