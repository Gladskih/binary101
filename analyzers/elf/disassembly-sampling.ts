"use strict";

import type { ElfExecutableRegion } from "./executable-regions.js";

export type ElfSampledSection = {
  vaddrStart: bigint;
  data: Uint8Array<ArrayBuffer>;
  label: string;
};

export const toSafeElfFileIndex = (
  value: bigint,
  label: string,
  issues: string[]
): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

export const sampleElfExecutableRegions = async (
  file: File,
  regions: ElfExecutableRegion[],
  issues: string[]
): Promise<ElfSampledSection[]> =>
  (
    await Promise.all(
      regions.map(region => sampleElfExecutableRegion(file, region, issues))
    )
  ).filter((entry): entry is ElfSampledSection => entry != null && entry.data.length > 0);

const sampleElfExecutableRegion = async (
  file: File,
  region: ElfExecutableRegion,
  issues: string[]
): Promise<ElfSampledSection | null> => {
  const start = toSafeElfFileIndex(region.fileOffset, `${region.label} file offset`, issues);
  const size = toSafeElfFileIndex(region.fileSize, `${region.label} file size`, issues);
  if (start == null || size == null || size <= 0) return null;
  const end = Math.min(file.size, start + size);
  if (start >= file.size || end <= start) return null;
  if (end !== start + size) {
    issues.push(`${region.label} extends past end of file; truncating to available bytes.`);
  }
  return {
    vaddrStart: region.vaddr,
    data: new Uint8Array(await file.slice(start, end).arrayBuffer()),
    label: region.label
  };
};
