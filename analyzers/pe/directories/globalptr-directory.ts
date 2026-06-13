"use strict";

import type { PeDataDirectory } from "../types.js";
import { isRvaRangeInsideSizeOfImage } from "../layout/rva-limits.js";

// Microsoft PE format, "Optional Header Data Directories":
// GLOBALPTR stores the RVA of the value for the global pointer register and its
// Size must be zero.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
const GLOBALPTR_RVA_ADDRESSABLE_BYTE_SIZE = 1;

export interface PeGlobalPtrDirectory {
  rva: number;
  size: number;
  warnings?: string[];
}

export const parseGlobalPtrDirectory = (
  dataDirs: PeDataDirectory[],
  sizeOfImage?: number
): PeGlobalPtrDirectory | null => {
  const dir = dataDirs.find(directory => directory.name === "GLOBALPTR");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  const warnings: string[] = [];
  if (dir.size !== 0) {
    warnings.push("GLOBALPTR directory Size must be 0 according to the PE specification.");
  }
  if (dir.rva === 0) {
    warnings.push("GLOBALPTR directory has a non-zero size but RVA is 0.");
  } else if (
    sizeOfImage != null &&
    !isRvaRangeInsideSizeOfImage(dir.rva, GLOBALPTR_RVA_ADDRESSABLE_BYTE_SIZE, sizeOfImage)
  ) {
    warnings.push("GLOBALPTR directory RVA is outside SizeOfImage.");
  }
  return {
    rva: dir.rva,
    size: dir.size,
    ...(warnings.length ? { warnings } : {})
  };
};
