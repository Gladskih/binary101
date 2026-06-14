"use strict";

import { clampReadLength, readElementHeader, readUnsigned, readVint } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues } from "./types.js";

type OnClusterBlock = (timing: {
  trackNumber: number | null;
  timecode: number | null;
  durationTimecode: number | null;
  frames: number;
  isKeyframe: boolean;
  lacingMode: number | null;
  payload: Uint8Array | null;
}) => void;

type WebmBlockHeader = {
  trackNumber: number | null;
  relativeTimecode: number | null;
  flags: number | null;
  frames: number;
  lacingMode: number | null;
  payloadOffset: number | null;
  payloadSize: number | null;
};

const emptyBlockHeader = (): WebmBlockHeader => ({
  trackNumber: null,
  relativeTimecode: null,
  flags: null,
  frames: 1,
  lacingMode: null,
  payloadOffset: null,
  payloadSize: null
});

const parseBlockHeader = (
  dv: DataView,
  offset: number,
  available: number,
  issues: Issues
): WebmBlockHeader => {
  if (available < 4) return emptyBlockHeader();
  const trackVint = readVint(dv, offset);
  if (!trackVint) return emptyBlockHeader();
  const trackNumber =
    trackVint.data <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(trackVint.data) : null;
  if (trackNumber == null) issues.push("Block track number exceeds safe integer range.");
  const timecodeOffset = offset + trackVint.length;
  if (timecodeOffset + 2 > offset + available) {
    issues.push("Block timecode is truncated.");
    return { ...emptyBlockHeader(), trackNumber };
  }
  const relativeTimecode = dv.getInt16(timecodeOffset, false);
  const flagsOffset = timecodeOffset + 2;
  if (flagsOffset >= offset + available) {
    issues.push("Block flags are truncated.");
    return { ...emptyBlockHeader(), trackNumber, relativeTimecode };
  }
  const flags = dv.getUint8(flagsOffset);
  const lacingMode = (flags & 0x06) >> 1;
  if (lacingMode === 0) {
    return {
      trackNumber,
      relativeTimecode,
      flags,
      frames: 1,
      lacingMode,
      payloadOffset: flagsOffset + 1,
      payloadSize: Math.max(0, offset + available - (flagsOffset + 1))
    };
  }
  const laceCountOffset = flagsOffset + 1;
  if (laceCountOffset >= offset + available) issues.push("Block lacing header is truncated.");
  return {
    trackNumber,
    relativeTimecode,
    flags,
    frames: laceCountOffset < offset + available ? dv.getUint8(laceCountOffset) + 1 : 1,
    lacingMode,
    payloadOffset: null,
    payloadSize: null
  };
};

const emitBlockTiming = (
  dv: DataView,
  block: WebmBlockHeader,
  clusterTimecode: number | null,
  durationTimecode: number | null,
  isKeyframe: boolean,
  onBlock?: OnClusterBlock
): void => {
  if (!onBlock || block.trackNumber == null || block.relativeTimecode == null) return;
  const payload =
    block.payloadOffset != null && block.payloadSize != null && block.payloadSize > 0
      ? new Uint8Array(dv.buffer, dv.byteOffset + block.payloadOffset, block.payloadSize)
      : null;
  onBlock({
    trackNumber: block.trackNumber,
    timecode: (clusterTimecode ?? 0) + block.relativeTimecode,
    durationTimecode,
    frames: block.frames,
    isKeyframe,
    lacingMode: block.lacingMode,
    payload
  });
};

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
      const block = parseBlockHeader(dv, dataStart, available, issues);
      blocks += 1;
      const isKeyframe = block.flags != null && (block.flags & 0x80) !== 0;
      if (isKeyframe) keyframes += 1;
      emitBlockTiming(dv, block, clusterTimecode, null, isKeyframe, onBlock);
    } else if (header.id === 0xa0 && available > 0) {
      let innerCursor = dataStart;
      const innerLimit = Math.min(dataStart + available, dv.byteLength);
      let hasReference = false;
      let hasBlock = false;
      let durationTimecode: number | null = null;
      let blockTiming: WebmBlockHeader | null = null;
      while (innerCursor < innerLimit) {
        const innerHeader = readElementHeader(dv, innerCursor, clusterHeader.dataOffset + innerCursor, issues);
        if (!innerHeader || innerHeader.headerSize === 0 || innerHeader.size == null) break;
        if (innerHeader.id === 0xa1) {
          hasBlock = true;
          blocks += 1;
          const dataOffset = innerCursor + innerHeader.headerSize;
          const dataAvailable = Math.min(innerHeader.size, innerLimit - dataOffset);
          if (dataAvailable > 3) {
            blockTiming = parseBlockHeader(dv, dataOffset, dataAvailable, issues);
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
      const isKeyframe = hasBlock && !hasReference;
      if (isKeyframe) keyframes += 1;
      if (blockTiming) emitBlockTiming(dv, blockTiming, clusterTimecode, durationTimecode, isKeyframe, onBlock);
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  return { blocks, keyframes };
};
