// @ts-nocheck
"use strict";

import {
  readAsciiRange,
  readSubBlocks,
  parseGraphicControl,
  parseApplicationExtension,
  parseCommentExtension,
  parsePlainTextExtension
} from "./helpers.js";

function parseImageDescriptor(dv, offset, nextGraphicControl) {
  if (offset + 10 > dv.byteLength) {
    return {
      frame: null,
      nextOffset: dv.byteLength,
      warning: "Truncated image descriptor."
    };
  }
  const left = dv.getUint16(offset + 1, true);
  const top = dv.getUint16(offset + 3, true);
  const width = dv.getUint16(offset + 5, true);
  const height = dv.getUint16(offset + 7, true);
  const packed = dv.getUint8(offset + 9);
  const hasLocalColorTable = (packed & 0x80) !== 0;
  const interlaced = (packed & 0x40) !== 0;
  const sortFlag = (packed & 0x20) !== 0;
  const sizeCode = packed & 0x07;
  const localColorCount = hasLocalColorTable ? 2 ** (sizeCode + 1) : 0;
  let cursor = offset + 10;
  const colorTableSize = localColorCount * 3;
  if (hasLocalColorTable) {
    if (cursor + colorTableSize > dv.byteLength) {
      return {
        frame: null,
        nextOffset: dv.byteLength,
        warning: "Local color table truncated before image data."
      };
    }
    cursor += colorTableSize;
  }
  if (cursor >= dv.byteLength) {
    return {
      frame: null,
      nextOffset: dv.byteLength,
      warning: "Missing LZW minimum code size."
    };
  }
  const lzwMinCodeSize = dv.getUint8(cursor);
  cursor += 1;
  const subBlocks = readSubBlocks(dv, cursor, 0);
  return {
    frame: {
      left,
      top,
      width,
      height,
      interlaced,
      localColorCount,
      hasLocalColorTable,
      localColorTableSorted: sortFlag,
      lzwMinCodeSize,
      dataSize: subBlocks.totalSize,
      dataTruncated: subBlocks.truncated,
      gce: nextGraphicControl || null
    },
    nextOffset: subBlocks.endOffset,
    warning: null
  };
}

export async function parseGif(file) {
  const dv = new DataView(await file.arrayBuffer());
  if (dv.byteLength < 13) return null;
  const sig = readAsciiRange(dv, 0, 6);
  if (sig !== "GIF87a" && sig !== "GIF89a") return null;

  const width = dv.getUint16(6, true);
  const height = dv.getUint16(8, true);
  const packed = dv.getUint8(10);
  const hasGct = (packed & 0x80) !== 0;
  const colorResolutionBits = ((packed >> 4) & 0x07) + 1;
  const globalSorted = (packed & 0x08) !== 0;
  const gctSizeCode = packed & 0x07;
  const globalColorCount = hasGct ? 2 ** (gctSizeCode + 1) : 0;
  const backgroundColorIndex = dv.getUint8(11);
  const pixelAspectByte = dv.getUint8(12);
  const pixelAspectRatio =
    pixelAspectByte === 0 ? null : (pixelAspectByte + 15) / 64;

  let offset = 13;
  const warnings = [];
  if (hasGct) {
    const gctBytes = globalColorCount * 3;
    if (offset + gctBytes > dv.byteLength) {
      warnings.push("Global color table truncated before data blocks.");
      offset = dv.byteLength;
    } else {
      offset += gctBytes;
    }
  }

  const frames = [];
  const comments = [];
  const applicationExtensions = [];
  let plainTextCount = 0;
  let loopCount = null;
  let lastGce = null;
  let hasTrailer = false;

  while (offset < dv.byteLength) {
    const marker = dv.getUint8(offset);
    if (marker === 0x3b) { hasTrailer = true; offset += 1; break; }
    if (marker === 0x21) {
      if (offset + 1 >= dv.byteLength) { warnings.push("Extension introducer truncated."); break; }
      const label = dv.getUint8(offset + 1);
      if (label === 0xf9) {
        const { gce, nextOffset, warning } = parseGraphicControl(dv, offset);
        if (warning) warnings.push(warning);
        lastGce = gce;
        offset = nextOffset;
        continue;
      }
      if (label === 0xff) {
        const { info, nextOffset, warning } = parseApplicationExtension(dv, offset);
        if (warning) warnings.push(warning);
        if (info) {
          applicationExtensions.push(info);
          if (info.loopCount != null) loopCount = info.loopCount;
        }
        offset = nextOffset;
        continue;
      }
      if (label === 0xfe) {
        const { comment, nextOffset } = parseCommentExtension(dv, offset);
        comments.push(comment);
        offset = nextOffset;
        continue;
      }
      if (label === 0x01) {
        const { nextOffset, warning } = parsePlainTextExtension(dv, offset);
        if (warning) warnings.push(warning);
        plainTextCount += 1;
        offset = nextOffset;
        continue;
      }
      const subBlocks = readSubBlocks(dv, offset + 2, 0);
      if (subBlocks.truncated) warnings.push("Extension sub-blocks truncated.");
      offset = subBlocks.endOffset;
      continue;
    }
    if (marker === 0x2c) {
      const { frame, nextOffset, warning } = parseImageDescriptor(
        dv,
        offset,
        lastGce
      );
      if (warning) warnings.push(warning);
      if (frame) frames.push(frame);
      lastGce = null;
      offset = nextOffset;
      continue;
    }
    warnings.push(`Unknown block marker 0x${marker.toString(16)} encountered.`);
    offset += 1;
    break;
  }

  const overlayBytes = offset < dv.byteLength ? dv.byteLength - offset : 0;
  return {
    size: dv.byteLength,
    version: sig,
    width,
    height,
    hasGlobalColorTable: hasGct,
    globalColorCount,
    globalColorTableSorted: globalSorted,
    colorResolutionBits,
    backgroundColorIndex,
    pixelAspectRatio,
    frames,
    frameCount: frames.length,
    loopCount,
    comments,
    applicationExtensions,
    plainTextCount,
    hasTrailer,
    overlayBytes,
    warnings
  };
}

export const isGifSignature = dv => {
  if (dv.byteLength < 6) return false;
  const sig = readAsciiRange(dv, 0, 6);
  return sig === "GIF87a" || sig === "GIF89a";
};
