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
  addCoverageRegion("BASERELOC directory", base, dir.size);
  const end = base + dir.size;
  const blocks: Array<{
    pageRva: number;
    size: number;
    count: number;
    entries: Array<{ type: number; offset: number }>;
  }> = [];
  let off = base;
  let totalEntries = 0;
  while (off + 8 <= end && blocks.length < 256) {
    const dv = new DataView(await file.slice(off, off + 8).arrayBuffer());
    if (dv.byteLength < 8) break;
    const pageRva = dv.getUint32(0, true);
    const blockSize = dv.getUint32(4, true);
    if (!pageRva || !blockSize) break;
    if (blockSize < 8) break;
    const blockEnd = Math.min(end, off + blockSize);
    const entryCount = Math.floor((blockEnd - off - 8) / 2);
    const blockView = new DataView(await file.slice(off + 8, off + 8 + entryCount * 2).arrayBuffer());
    const availableEntries = Math.floor(blockView.byteLength / 2);
    const entries: Array<{ type: number; offset: number }> = [];
    for (let i = 0; i < availableEntries; i += 1) {
      const raw = blockView.getUint16(i * 2, true);
      entries.push({ type: (raw >> 12) & 0xf, offset: raw & 0xfff });
    }
    blocks.push({ pageRva, size: blockSize, count: availableEntries, entries });
    totalEntries += availableEntries;
    off = blockEnd;
  }
  return { blocks, totalEntries };
}
