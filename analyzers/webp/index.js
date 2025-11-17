"use strict";

import { alignUpTo } from "../../binary-utils.js";

const RIFF_SIG = 0x52494646;
const WEBP_SIG = 0x57454250;
const MAX_CHUNKS = 4096;

const VP8_MIN_HEADER = 10;
const VP8L_MIN_HEADER = 5;
const VP8X_MIN_HEADER = 10;
const ANIM_HEADER_SIZE = 6;

function readFourCc(dv, offset) {
  if (offset + 4 > dv.byteLength) return null;
  return (
    String.fromCharCode(dv.getUint8(offset)) +
    String.fromCharCode(dv.getUint8(offset + 1)) +
    String.fromCharCode(dv.getUint8(offset + 2)) +
    String.fromCharCode(dv.getUint8(offset + 3))
  );
}

function parseVp8Dimensions(dv, offset, length, issues) {
  if (length < VP8_MIN_HEADER || offset + VP8_MIN_HEADER > dv.byteLength) {
    issues.push("VP8 chunk too small to read frame header.");
    return null;
  }
  const startCode0 = dv.getUint8(offset + 3);
  const startCode1 = dv.getUint8(offset + 4);
  const startCode2 = dv.getUint8(offset + 5);
  if (startCode0 !== 0x9d || startCode1 !== 0x01 || startCode2 !== 0x2a) {
    issues.push("VP8 chunk missing expected start code (0x9d 0x01 0x2a).");
    return null;
  }
  const width = dv.getUint16(offset + 6, true) & 0x3fff;
  const height = dv.getUint16(offset + 8, true) & 0x3fff;
  return width && height ? { width, height, source: "VP8 key frame" } : null;
}

function parseVp8lDimensions(dv, offset, length, issues) {
  if (length < VP8L_MIN_HEADER || offset + VP8L_MIN_HEADER > dv.byteLength) {
    issues.push("VP8L chunk too small to read lossless header.");
    return null;
  }
  const signature = dv.getUint8(offset);
  if (signature !== 0x2f) {
    issues.push("VP8L chunk missing 0x2f signature byte.");
    return null;
  }
  const bits = dv.getUint32(offset + 1, true);
  const width = (bits & 0x3fff) + 1;
  const height = ((bits >> 14) & 0x3fff) + 1;
  return { width, height, source: "VP8L lossless header" };
}

function parseVp8xChunk(dv, offset, length, issues) {
  if (length < VP8X_MIN_HEADER || offset + VP8X_MIN_HEADER > dv.byteLength) {
    issues.push("VP8X chunk too small to read canvas info.");
    return null;
  }
  const flags = dv.getUint8(offset);
  const reservedHigh = dv.getUint8(offset + 1);
  const reservedMid = dv.getUint8(offset + 2);
  const reservedLow = dv.getUint8(offset + 3);
  if (reservedHigh !== 0 || reservedMid !== 0 || reservedLow !== 0) {
    issues.push("VP8X reserved bytes are non-zero.");
  }
  const widthMinusOne =
    dv.getUint8(offset + 4) |
    (dv.getUint8(offset + 5) << 8) |
    (dv.getUint8(offset + 6) << 16);
  const heightMinusOne =
    dv.getUint8(offset + 7) |
    (dv.getUint8(offset + 8) << 8) |
    (dv.getUint8(offset + 9) << 16);
  const width = widthMinusOne + 1;
  const height = heightMinusOne + 1;
  const features = {
    hasIccProfile: (flags & 0x20) !== 0,
    hasAlpha: (flags & 0x10) !== 0,
    hasExif: (flags & 0x08) !== 0,
    hasXmp: (flags & 0x04) !== 0,
    hasAnimation: (flags & 0x02) !== 0
  };
  return { flags, width, height, features, source: "VP8X canvas" };
}

function parseAnimChunk(dv, offset, length, issues) {
  if (length < ANIM_HEADER_SIZE || offset + ANIM_HEADER_SIZE > dv.byteLength) {
    issues.push("ANIM chunk too small to read header.");
    return null;
  }
  const backgroundColor = dv.getUint32(offset, true);
  const loopCount = dv.getUint16(offset + 4, true);
  return { backgroundColor, loopCount };
}

export async function parseWebp(file) {
  const dv = new DataView(await file.arrayBuffer());
  if (dv.byteLength < 12) return null;
  if (dv.getUint32(0, false) !== RIFF_SIG || dv.getUint32(8, false) !== WEBP_SIG) {
    return null;
  }

  const size = dv.byteLength;
  const riffSizeField = dv.getUint32(4, true);
  const expectedRiffSize = size >= 8 ? size - 8 : size;
  const issues = [];
  if (riffSizeField !== expectedRiffSize) {
    issues.push(
      `RIFF size field (${riffSizeField}) does not match file size (${expectedRiffSize}).`
    );
  }

  const chunks = [];
  let offset = 12;
  let chunkCount = 0;
  let dimensions = null;
  let format = null;
  let hasAlpha = false;
  let hasAnimation = false;
  let hasIccProfile = false;
  let hasExif = false;
  let hasXmp = false;
  let frameCount = 0;
  let animationInfo = null;

  while (offset + 8 <= dv.byteLength && chunkCount < MAX_CHUNKS) {
    const type = readFourCc(dv, offset);
    const chunkSize = dv.getUint32(offset + 4, true);
    const dataOffset = offset + 8;
    const dataEnd = dataOffset + chunkSize;
    const paddedEnd = alignUpTo(dataEnd, 2);
    const truncated = dataEnd > dv.byteLength;
    chunks.push({
      type,
      offset,
      size: chunkSize,
      paddedSize: paddedEnd - offset,
      truncated
    });
    if (truncated) {
      issues.push(`Chunk ${type} at ${offset} extends beyond file size.`);
      break;
    }

    if (type === "VP8X") {
      const info = parseVp8xChunk(dv, dataOffset, chunkSize, issues);
      if (info) {
        dimensions = info;
        format = "VP8X";
        hasAlpha = hasAlpha || info.features.hasAlpha;
        hasAnimation = hasAnimation || info.features.hasAnimation;
        hasIccProfile = hasIccProfile || info.features.hasIccProfile;
        hasExif = hasExif || info.features.hasExif;
        hasXmp = hasXmp || info.features.hasXmp;
      }
    } else if (type === "VP8 " && !dimensions) {
      const lossyDimensions = parseVp8Dimensions(
        dv,
        dataOffset,
        chunkSize,
        issues
      );
      if (lossyDimensions) {
        dimensions = lossyDimensions;
        format = "VP8";
      }
    } else if (type === "VP8L" && !dimensions) {
      const losslessDimensions = parseVp8lDimensions(
        dv,
        dataOffset,
        chunkSize,
        issues
      );
      if (losslessDimensions) {
        dimensions = losslessDimensions;
        format = "VP8L";
      }
    } else if (type === "ALPH") {
      hasAlpha = true;
    } else if (type === "ANIM") {
      const info = parseAnimChunk(dv, dataOffset, chunkSize, issues);
      if (info) {
        animationInfo = info;
        hasAnimation = true;
      }
    } else if (type === "ANMF") {
      frameCount += 1;
      hasAnimation = true;
    } else if (type === "ICCP") {
      hasIccProfile = true;
    } else if (type === "EXIF") {
      hasExif = true;
    } else if (type === "XMP ") {
      hasXmp = true;
    }

    chunkCount += 1;
    offset = paddedEnd;
  }

  if (chunkCount >= MAX_CHUNKS && offset < dv.byteLength) {
    issues.push("Chunk scan stopped after reaching maximum chunk count.");
  }

  const chunkStats = {
    chunkCount: chunks.length,
    parsedBytes: offset,
    overlayBytes: offset < dv.byteLength ? dv.byteLength - offset : 0
  };

  return {
    size,
    riffSizeField,
    expectedRiffSize,
    format,
    dimensions,
    hasAlpha,
    hasAnimation,
    hasIccProfile,
    hasExif,
    hasXmp,
    animationInfo,
    frameCount,
    chunks,
    chunkStats,
    issues
  };
}
