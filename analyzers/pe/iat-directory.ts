"use strict";

import type { PeDataDirectory, RvaToOffset } from "./types.js";

export interface PeIatDirectory {
  rva: number;
  size: number;
}

export const parseIatDirectory = (
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: (label: string, offset: number, size: number) => void
): PeIatDirectory | null => {
  const dir = dataDirs.find(directory => directory.name === "IAT");
  if (!dir?.rva || !dir.size) return null;
  const offset = rvaToOff(dir.rva);
  if (offset == null) return null;
  addCoverageRegion("IAT", offset, dir.size);
  return { rva: dir.rva, size: dir.size };
};
