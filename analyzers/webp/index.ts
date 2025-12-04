"use strict";

import {
  flattenChunks,
  findFirstChunk,
  parseRiffFromView
} from "../riff/index.js";
import type { RiffChunk } from "../riff/types.js";
import type {
  WebpAnimationInfo,
  WebpDimensions,
  WebpParseResult
} from "./types.js";

const VP8_MIN_HEADER = 10;
const VP8L_MIN_HEADER = 5;
const VP8X_MIN_HEADER = 10;
const ANIM_HEADER_SIZE = 6;

const chunkDataLength = (chunk: RiffChunk, dv: DataView): number =>
  Math.max(0, Math.min(chunk.size, dv.byteLength - chunk.dataOffset));

function parseVp8Dimensions(
  dv: DataView,
  chunk: RiffChunk,
  issues: string[]
): WebpDimensions | null {
  const available = chunkDataLength(chunk, dv);
  if (available < VP8_MIN_HEADER) {
    issues.push(`VP8 chunk at ${chunk.offset} too small to read frame header.`);
    return null;
  }
  const startCode0 = dv.getUint8(chunk.dataOffset + 3);
  const startCode1 = dv.getUint8(chunk.dataOffset + 4);
  const startCode2 = dv.getUint8(chunk.dataOffset + 5);
  if (startCode0 !== 0x9d || startCode1 !== 0x01 || startCode2 !== 0x2a) {
    issues.push("VP8 chunk missing expected start code (0x9d 0x01 0x2a).");
    return null;
  }
  const width = dv.getUint16(chunk.dataOffset + 6, true) & 0x3fff;
  const height = dv.getUint16(chunk.dataOffset + 8, true) & 0x3fff;
  return width && height ? { width, height, source: "VP8 key frame" } : null;
}

function parseVp8lDimensions(
  dv: DataView,
  chunk: RiffChunk,
  issues: string[]
): WebpDimensions | null {
  const available = chunkDataLength(chunk, dv);
  if (available < VP8L_MIN_HEADER) {
    issues.push("VP8L chunk too small to read lossless header.");
    return null;
  }
  const signature = dv.getUint8(chunk.dataOffset);
  if (signature !== 0x2f) {
    issues.push("VP8L chunk missing 0x2f signature byte.");
    return null;
  }
  const bits = dv.getUint32(chunk.dataOffset + 1, true);
  const width = (bits & 0x3fff) + 1;
  const height = ((bits >> 14) & 0x3fff) + 1;
  return { width, height, source: "VP8L lossless header" };
}

function parseVp8xChunk(
  dv: DataView,
  chunk: RiffChunk,
  issues: string[]
): WebpDimensions | null {
  const available = chunkDataLength(chunk, dv);
  if (available < VP8X_MIN_HEADER) {
    issues.push("VP8X chunk too small to read canvas info.");
    return null;
  }
  const flags = dv.getUint8(chunk.dataOffset);
  const reservedHigh = dv.getUint8(chunk.dataOffset + 1);
  const reservedMid = dv.getUint8(chunk.dataOffset + 2);
  const reservedLow = dv.getUint8(chunk.dataOffset + 3);
  if (reservedHigh !== 0 || reservedMid !== 0 || reservedLow !== 0) {
    issues.push("VP8X reserved bytes are non-zero.");
  }
  const widthMinusOne =
    dv.getUint8(chunk.dataOffset + 4) |
    (dv.getUint8(chunk.dataOffset + 5) << 8) |
    (dv.getUint8(chunk.dataOffset + 6) << 16);
  const heightMinusOne =
    dv.getUint8(chunk.dataOffset + 7) |
    (dv.getUint8(chunk.dataOffset + 8) << 8) |
    (dv.getUint8(chunk.dataOffset + 9) << 16);
  const width = widthMinusOne + 1;
  const height = heightMinusOne + 1;
  const features = {
    hasIccProfile: (flags & 0x20) !== 0,
    hasAlpha: (flags & 0x10) !== 0,
    hasExif: (flags & 0x08) !== 0,
    hasXmp: (flags & 0x04) !== 0,
    hasAnimation: (flags & 0x02) !== 0
  };
  return {
    width,
    height,
    features,
    source: "VP8X canvas"
  };
}

function parseAnimChunk(
  dv: DataView,
  chunk: RiffChunk,
  issues: string[]
): WebpAnimationInfo | null {
  const available = chunkDataLength(chunk, dv);
  if (available < ANIM_HEADER_SIZE) {
    issues.push("ANIM chunk too small to read header.");
    return null;
  }
  const backgroundColor = dv.getUint32(chunk.dataOffset, true);
  const loopCount = dv.getUint16(chunk.dataOffset + 4, true);
  return { backgroundColor, loopCount };
}

export async function parseWebp(file: File): Promise<WebpParseResult | null> {
  const dv = new DataView(await file.arrayBuffer());
  const riff = parseRiffFromView(dv, { maxChunks: 4096, maxDepth: 2 });
  if (!riff || riff.formType !== "WEBP") return null;

  const issues = [...riff.issues];
  const flatChunks = flattenChunks(riff.chunks);
  let dimensions: WebpDimensions | null = null;
  let format: string | null = null;
  let hasAlpha = false;
  let hasAnimation = false;
  let hasIccProfile = false;
  let hasExif = false;
  let hasXmp = false;
  let frameCount = 0;
  let animationInfo: WebpAnimationInfo | null = null;

  const vp8xChunk = findFirstChunk(riff.chunks, "VP8X");
  if (vp8xChunk && !vp8xChunk.truncated) {
    const info = parseVp8xChunk(dv, vp8xChunk, issues);
    if (info) {
      dimensions = info;
      format = "VP8X";
      hasAlpha = info.features?.hasAlpha === true;
      hasAnimation = info.features?.hasAnimation === true;
      hasIccProfile = info.features?.hasIccProfile === true;
      hasExif = info.features?.hasExif === true;
      hasXmp = info.features?.hasXmp === true;
    }
  } else if (vp8xChunk?.truncated) {
    issues.push("VP8X chunk is truncated.");
  }

  const vp8Chunk = !dimensions ? findFirstChunk(riff.chunks, "VP8 ") : null;
  if (vp8Chunk && !vp8Chunk.truncated) {
    const lossyDimensions = parseVp8Dimensions(dv, vp8Chunk, issues);
    if (lossyDimensions) {
      dimensions = lossyDimensions;
      format = "VP8";
    }
  } else if (vp8Chunk?.truncated) {
    issues.push("VP8 chunk is truncated.");
  }

  const vp8lChunk = !dimensions ? findFirstChunk(riff.chunks, "VP8L") : null;
  if (vp8lChunk && !vp8lChunk.truncated) {
    const losslessDimensions = parseVp8lDimensions(dv, vp8lChunk, issues);
    if (losslessDimensions) {
      dimensions = losslessDimensions;
      format = "VP8L";
    }
  } else if (vp8lChunk?.truncated) {
    issues.push("VP8L chunk is truncated.");
  }

  const animChunk = findFirstChunk(riff.chunks, "ANIM");
  if (animChunk && !animChunk.truncated) {
    animationInfo = parseAnimChunk(dv, animChunk, issues);
    hasAnimation = true;
  } else if (animChunk?.truncated) {
    issues.push("ANIM chunk is truncated.");
  }

  frameCount = flatChunks.filter(chunk => chunk.id === "ANMF").length;
  if (frameCount > 0) hasAnimation = true;
  hasAlpha = hasAlpha || flatChunks.some(chunk => chunk.id === "ALPH");
  hasIccProfile = hasIccProfile || flatChunks.some(chunk => chunk.id === "ICCP");
  hasExif = hasExif || flatChunks.some(chunk => chunk.id === "EXIF");
  hasXmp = hasXmp || flatChunks.some(chunk => chunk.id === "XMP ");

  const chunkStats = {
    chunkCount: riff.stats.chunkCount,
    parsedBytes: riff.stats.parsedBytes,
    overlayBytes: riff.stats.overlayBytes
  };

  return {
    size: riff.fileSize,
    riffSizeField: riff.riffSize,
    expectedRiffSize: riff.expectedSize,
    format,
    dimensions,
    hasAlpha,
    hasAnimation,
    hasIccProfile,
    hasExif,
    hasXmp,
    animationInfo,
    frameCount,
    chunks: riff.chunks,
    chunkStats,
    issues
  };
}
