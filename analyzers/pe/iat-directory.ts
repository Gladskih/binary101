"use strict";

import type { PeDataDirectory, RvaToOffset } from "./types.js";

export interface PeIatDirectory {
  rva: number;
  size: number;
  warnings?: string[];
}

export const parseIatDirectory = (
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): PeIatDirectory | null => {
  const dir = dataDirs.find(directory => directory.name === "IAT");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  if (!dir.size) return null;
  if (!dir.rva) {
    return {
      rva: 0,
      size: dir.size,
      warnings: ["IAT directory has a non-zero size but RVA is 0."]
    };
  }
  const offset = rvaToOff(dir.rva);
  if (offset == null || offset < 0) {
    return {
      rva: dir.rva,
      size: dir.size,
      warnings: ["IAT directory RVA could not be mapped to a file offset."]
    };
  }
  return { rva: dir.rva, size: dir.size };
};
