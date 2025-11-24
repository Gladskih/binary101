"use strict";

import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";

export async function parseExceptionDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<{
  count: number;
  sample: Array<{ BeginAddress: number; EndAddress: number; UnwindInfoAddress: number }>;
} | null> {
  const dir = dataDirs.find(d => d.name === "EXCEPTION");
  if (!dir?.rva || dir.size < 12) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("EXCEPTION directory", base, dir.size);
  const count = Math.min(1024, Math.floor(dir.size / 12));
  const dv = new DataView(await file.slice(base, base + count * 12).arrayBuffer());
  const entries: Array<{ BeginAddress: number; EndAddress: number; UnwindInfoAddress: number }> = [];
  for (let index = 0; index < count; index += 1) {
    entries.push({
      BeginAddress: dv.getUint32(index * 12 + 0, true),
      EndAddress: dv.getUint32(index * 12 + 4, true),
      UnwindInfoAddress: dv.getUint32(index * 12 + 8, true)
    });
  }
  return { count, sample: entries };
}
