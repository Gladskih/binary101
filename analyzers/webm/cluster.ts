"use strict";

import { clampReadLength, readElementHeader, readUnsigned, readVint } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues } from "./types.js";

type OnClusterBlock = (timing: {
  trackNumber: number | null;
  timecode: number | null;
  durationTimecode: number | null;
  frames: number;
}) => void;

export const countBlocksInCluster = async (
  file: File,
  clusterHeader: EbmlElementHeader,
  issues: Issues,
  onBlock?: OnClusterBlock
): Promise<{ blocks: number; keyframes: number }> => {
  if (clusterHeader.size == null || clusterHeader.size <= 0) return { blocks: 0, keyframes: 0 };
  const { length } = clampReadLength(file.size, clusterHeader.dataOffset, clusterHeader.size, clusterHeader.size);
  const dv = new DataView(await file.slice(clusterHeader.dataOffset, clusterHeader.dataOffset + length).arrayBuffer());
  const limit = Math.min(length, clusterHeader.size);
  let cursor = 0;
  let blocks = 0;
  let keyframes = 0;
  let clusterTimecode: number | null = null;

  const parseBlockHeader = (
    offset: number,
    available: number
  ): { trackNumber: number | null; relativeTimecode: number | null; flags: number | null; frames: number } => {
    if (available < 4) return { trackNumber: null, relativeTimecode: null, flags: null, frames: 1 };
    const trackVint = readVint(dv, offset);
    if (!trackVint) return { trackNumber: null, relativeTimecode: null, flags: null, frames: 1 };
    const trackData = trackVint.data;
    const trackNumber =
      trackData <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(trackData) : null;
    if (trackNumber == null) issues.push("Block track number exceeds safe integer range.");
    const timecodeOffset = offset + trackVint.length;
    if (timecodeOffset + 2 > offset + available) {
      issues.push("Block timecode is truncated.");
      return { trackNumber, relativeTimecode: null, flags: null, frames: 1 };
    }
    const relativeTimecode = dv.getInt16(timecodeOffset, false);
    const flagsOffset = timecodeOffset + 2;
    if (flagsOffset >= offset + available) {
      issues.push("Block flags are truncated.");
      return { trackNumber, relativeTimecode, flags: null, frames: 1 };
    }
    const flags = dv.getUint8(flagsOffset);
    const lacingMode = (flags & 0x06) >> 1;
    let frames = 1;
    if (lacingMode !== 0) {
      const laceCountOffset = flagsOffset + 1;
      if (laceCountOffset < offset + available) {
        frames = dv.getUint8(laceCountOffset) + 1;
      } else {
        issues.push("Block lacing header is truncated.");
      }
    }
    return { trackNumber, relativeTimecode, flags, frames };
  };

  while (cursor < limit) {
    const header = readElementHeader(dv, cursor, clusterHeader.dataOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - dataStart);
    if (header.id === 0xe7 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "ClusterTimecode");
      if (value != null) {
        const numeric = Number(value);
        if (Number.isSafeInteger(numeric)) {
          clusterTimecode = numeric;
        } else {
          issues.push("Cluster timecode exceeds safe integer range.");
        }
      }
    } else if (header.id === 0xa3 && available > 3) {
      const block = parseBlockHeader(dataStart, available);
      blocks += 1;
      if (block.flags != null && (block.flags & 0x80) !== 0) keyframes += 1;
      if (onBlock && block.trackNumber != null && block.relativeTimecode != null) {
        const base = clusterTimecode ?? 0;
        onBlock({
          trackNumber: block.trackNumber,
          timecode: base + block.relativeTimecode,
          durationTimecode: null,
          frames: block.frames
        });
      }
    } else if (header.id === 0xa0 && available > 0) {
      let innerCursor = dataStart;
      const innerLimit = Math.min(dataStart + available, dv.byteLength);
      let hasReference = false;
      let hasBlock = false;
      let durationTimecode: number | null = null;
      let blockTiming: { trackNumber: number | null; relativeTimecode: number | null; frames: number } | null =
        null;
      while (innerCursor < innerLimit) {
        const innerHeader = readElementHeader(dv, innerCursor, clusterHeader.dataOffset + innerCursor, issues);
        if (!innerHeader || innerHeader.headerSize === 0 || innerHeader.size == null) break;
        if (innerHeader.id === 0xa1) {
          hasBlock = true;
          blocks += 1;
          const dataOffset = innerCursor + innerHeader.headerSize;
          const dataAvailable = Math.min(innerHeader.size, innerLimit - dataOffset);
          if (dataAvailable > 3) {
            const parsed = parseBlockHeader(dataOffset, dataAvailable);
            blockTiming = {
              trackNumber: parsed.trackNumber,
              relativeTimecode: parsed.relativeTimecode,
              frames: parsed.frames
            };
          }
        } else if (innerHeader.id === 0xfb) {
          hasReference = true;
        } else if (innerHeader.id === 0x9b) {
          const dataOffset = innerCursor + innerHeader.headerSize;
          const dataAvailable = Math.min(innerHeader.size, innerLimit - dataOffset);
          if (dataAvailable > 0) {
            const value = readUnsigned(dv, dataOffset, dataAvailable, issues, "BlockDuration");
            if (value != null) {
              const numeric = Number(value);
              if (Number.isSafeInteger(numeric)) {
                durationTimecode = numeric;
              } else {
                issues.push("BlockDuration exceeds safe integer range.");
              }
            }
          }
        }
        innerCursor += innerHeader.headerSize + innerHeader.size;
      }
      if (hasBlock && !hasReference) keyframes += 1;
      if (onBlock && blockTiming?.trackNumber != null && blockTiming.relativeTimecode != null) {
        const base = clusterTimecode ?? 0;
        onBlock({
          trackNumber: blockTiming.trackNumber,
          timecode: base + blockTiming.relativeTimecode,
          durationTimecode,
          frames: blockTiming.frames
        });
      }
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  return { blocks, keyframes };
};
