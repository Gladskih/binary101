"use strict";

import type { RiffChunk, RiffParserOptions, RiffParseResult, RiffStats } from "./types.js";

const DEFAULT_MAX_CHUNKS = 4096;
const DEFAULT_MAX_DEPTH = 8;

export const readFourCc = (dv: DataView, offset: number): string | null => {
  if (offset + 4 > dv.byteLength) return null;
  return (
    String.fromCharCode(dv.getUint8(offset)) +
    String.fromCharCode(dv.getUint8(offset + 1)) +
    String.fromCharCode(dv.getUint8(offset + 2)) +
    String.fromCharCode(dv.getUint8(offset + 3))
  );
};

type ParseState = {
  littleEndian: boolean;
  maxDepth: number;
  chunkLimit: number;
  stats: RiffStats;
  issues: string[];
};

const createStats = (): RiffStats => ({
  chunkCount: 0,
  listCount: 0,
  maxDepth: 0,
  parsedBytes: 0,
  overlayBytes: 0,
  paddingBytes: 0,
  truncatedChunks: 0,
  stoppedEarly: false
});

const parseChunkList = (
  dv: DataView,
  start: number,
  endLimit: number,
  depth: number,
  state: ParseState
): { chunks: RiffChunk[]; offset: number } => {
  const chunks: RiffChunk[] = [];
  let cursor = start;
  while (cursor + 8 <= dv.byteLength && cursor + 8 <= endLimit) {
    if (state.stats.chunkCount >= state.chunkLimit) {
      state.stats.stoppedEarly = true;
      state.issues.push("Chunk scan stopped after reaching maximum chunk count.");
      break;
    }
    const id = readFourCc(dv, cursor);
    const size = dv.getUint32(cursor + 4, state.littleEndian);
    const dataOffset = cursor + 8;
    const dataEnd = dataOffset + size;
    const paddedEnd = size % 2 === 0 ? dataEnd : dataEnd + 1;
    const paddingBytes = paddedEnd - dataEnd;
    const truncated = dataEnd > dv.byteLength || dataOffset > dv.byteLength;
    const inParentLimit = paddedEnd <= endLimit;
    const chunk: RiffChunk = {
      id,
      offset: cursor,
      size,
      dataOffset,
      dataEnd: Math.min(dataEnd, dv.byteLength),
      paddedSize: paddedEnd - cursor,
      paddingBytes,
      truncated,
      listType: null,
      children: null,
      depth,
      inParentLimit
    };
    state.stats.chunkCount += 1;
    state.stats.maxDepth = Math.max(state.stats.maxDepth, depth);
    if (paddingBytes > 0) state.stats.paddingBytes += paddingBytes;
    if (truncated) {
      state.stats.truncatedChunks += 1;
      const label = id || "unknown chunk";
      state.issues.push(`Chunk ${label} at ${cursor} extends beyond file size.`);
    }

    const isContainer = id === "LIST" || id === "RIFF";
    if (isContainer && !truncated) {
      if (size < 4 || dataOffset + 4 > dv.byteLength) {
        state.issues.push(`${id} chunk at ${cursor} is too small to contain a type.`);
      } else {
        chunk.listType = readFourCc(dv, dataOffset);
        const childStart = dataOffset + 4;
        const childEnd = Math.min(endLimit, dataOffset + size);
        if (childStart < childEnd) {
          if (depth + 1 >= state.maxDepth) {
            state.stats.stoppedEarly = true;
            state.issues.push(`Nested ${id} chunk depth limit reached at offset ${cursor}.`);
          } else {
            const child = parseChunkList(
              dv,
              childStart,
              childEnd,
              depth + 1,
              state
            );
            chunk.children = child.chunks;
          }
        } else {
          chunk.children = [];
        }
        state.stats.listCount += 1;
      }
    }

    chunks.push(chunk);
    if (truncated) {
      cursor = Math.min(paddedEnd, dv.byteLength);
      break;
    }
    cursor = paddedEnd;
  }
  return { chunks, offset: cursor };
};

export const parseRiffFromView = (
  dv: DataView,
  options: RiffParserOptions = {}
): RiffParseResult | null => {
  if (dv.byteLength < 12) return null;
  const signature = readFourCc(dv, 0);
  if (signature !== "RIFF" && signature !== "RIFX") return null;
  const littleEndian = signature === "RIFF";
  const riffSize = dv.getUint32(4, littleEndian);
  const expectedSize = dv.byteLength >= 8 ? Math.max(0, dv.byteLength - 8) : 0;
  const formType = readFourCc(dv, 8);
  const issues: string[] = [];
  if (!formType) issues.push("RIFF form type is missing or truncated.");
  if (riffSize !== expectedSize) {
    issues.push(
      `RIFF size field (${riffSize}) does not match file size (${expectedSize}).`
    );
  }

  const state: ParseState = {
    littleEndian,
    maxDepth: options.maxDepth ?? DEFAULT_MAX_DEPTH,
    chunkLimit: options.maxChunks ?? DEFAULT_MAX_CHUNKS,
    stats: createStats(),
    issues
  };
  const dataLimit = Math.min(dv.byteLength, riffSize + 8);
  const { chunks, offset } = parseChunkList(dv, 12, dataLimit, 0, state);
  state.stats.parsedBytes = offset;
  state.stats.overlayBytes = offset < dv.byteLength ? dv.byteLength - offset : 0;
  return {
    signature,
    littleEndian,
    riffSize,
    expectedSize,
    formType,
    fileSize: dv.byteLength,
    chunks,
    stats: state.stats,
    issues: state.issues
  };
};

export const parseRiff = async (
  file: File,
  options: RiffParserOptions = {}
): Promise<RiffParseResult | null> => {
  const dv = new DataView(await file.arrayBuffer());
  return parseRiffFromView(dv, options);
};
