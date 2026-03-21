"use strict";

import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";

export async function parseBaseRelocations(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<{
  blocks: Array<{ pageRva: number; size: number; count: number; entries: Array<{ type: number; offset: number }> }>;
  totalEntries: number;
} | null> {
  const dir = dataDirs.find(d => d.name === "BASERELOC");
  if (!dir?.rva || dir.size < 8) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("BASERELOC directory", base, Math.min(dir.size, Math.max(0, file.size - base)));
  const blocks: Array<{
    pageRva: number;
    size: number;
    count: number;
    entries: Array<{ type: number; offset: number }>;
  }> = [];
  let rel = 0;
  let totalEntries = 0;
  while (rel + 8 <= dir.size) {
    const blockRva = (dir.rva + rel) >>> 0;
    const blockOff = rvaToOff(blockRva >>> 0);
    if (blockOff == null) break;
    const dv = new DataView(await file.slice(blockOff, blockOff + 8).arrayBuffer());
    if (dv.byteLength < 8) break;
    const pageRva = dv.getUint32(0, true);
    const blockSize = dv.getUint32(4, true);
    if (!blockSize) break;
    if (blockSize < 8) break;
    const availableBlockBytes = Math.min(blockSize, dir.size - rel);
    const availableEntries = Math.floor(Math.max(0, availableBlockBytes - 8) / 2);
    const entries: Array<{ type: number; offset: number }> = [];
    for (let i = 0; i < availableEntries; i += 1) {
      const entryRva = (blockRva + 8 + i * 2) >>> 0;
      const entryOff = rvaToOff(entryRva);
      if (entryOff == null || entryOff < 0 || entryOff + 2 > file.size) break;
      const entryView = new DataView(await file.slice(entryOff, entryOff + 2).arrayBuffer());
      if (entryView.byteLength < 2) break;
      const raw = entryView.getUint16(0, true);
      entries.push({ type: (raw >> 12) & 0xf, offset: raw & 0xfff });
    }
    blocks.push({ pageRva, size: blockSize, count: entries.length, entries });
    totalEntries += entries.length;
    rel += blockSize;
  }
  return { blocks, totalEntries };
}
