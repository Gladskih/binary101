"use strict";

import { clampReadLength, readElementHeader, readVint } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues } from "./types.js";

export const countBlocksInCluster = async (
  file: File,
  clusterHeader: EbmlElementHeader,
  issues: Issues
): Promise<{ blocks: number; keyframes: number }> => {
  if (clusterHeader.size == null || clusterHeader.size <= 0) return { blocks: 0, keyframes: 0 };
  const { length } = clampReadLength(file.size, clusterHeader.dataOffset, clusterHeader.size, clusterHeader.size);
  const dv = new DataView(await file.slice(clusterHeader.dataOffset, clusterHeader.dataOffset + length).arrayBuffer());
  const limit = Math.min(length, clusterHeader.size);
  let cursor = 0;
  let blocks = 0;
  let keyframes = 0;
  while (cursor < limit) {
    const header = readElementHeader(dv, cursor, clusterHeader.dataOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - dataStart);
    if (header.id === 0xa3 && available > 3) {
      const trackVint = readVint(dv, dataStart);
      const flagsOffset = trackVint ? dataStart + trackVint.length + 2 : dataStart + 3;
      const flags = flagsOffset < dataStart + available ? dv.getUint8(flagsOffset) : 0;
      blocks += 1;
      if ((flags & 0x80) !== 0) keyframes += 1;
    } else if (header.id === 0xa0 && available > 0) {
      let innerCursor = dataStart;
      const innerLimit = Math.min(dataStart + available, dv.byteLength);
      let hasReference = false;
      let hasBlock = false;
      while (innerCursor < innerLimit) {
        const innerHeader = readElementHeader(dv, innerCursor, clusterHeader.dataOffset + innerCursor, issues);
        if (!innerHeader || innerHeader.headerSize === 0 || innerHeader.size == null) break;
        if (innerHeader.id === 0xa1) {
          hasBlock = true;
          blocks += 1;
        } else if (innerHeader.id === 0xfb) {
          hasReference = true;
        }
        innerCursor += innerHeader.headerSize + innerHeader.size;
      }
      if (hasBlock && !hasReference) keyframes += 1;
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  return { blocks, keyframes };
};
