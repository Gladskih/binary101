"use strict";

import {
  readAsciiRange,
  readSubBlocks,
  parseGraphicControl,
  parseApplicationExtension,
  parseCommentExtension,
  parsePlainTextExtension
} from "./helpers.js";
import type {
  GifApplicationExtension,
  GifComment,
  GifFrame,
  GifGraphicControlExtension,
  GifParseResult
} from "./types.js";

interface GifImageDescriptorResult {
  frame: GifFrame | null;
  nextOffset: number;
  warning: string | null;
}

interface GifBlockState {
  offset: number;
  frames: GifFrame[];
  comments: GifComment[];
  applicationExtensions: GifApplicationExtension[];
  plainTextCount: number;
  loopCount: number | null;
  lastGce: GifGraphicControlExtension | null;
  hasTrailer: boolean;
  warnings: string[];
}

function parseImageDescriptor(
  dv: DataView,
  offset: number,
  nextGraphicControl: GifGraphicControlExtension | null
): GifImageDescriptorResult {
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

function skipGlobalColorTable(
  dv: DataView,
  offset: number,
  hasGlobalColorTable: boolean,
  globalColorCount: number,
  warnings: string[]
): number {
  if (!hasGlobalColorTable) return offset;
  const gctBytes = globalColorCount * 3;
  if (offset + gctBytes > dv.byteLength) {
    warnings.push("Global color table truncated before data blocks.");
    return dv.byteLength;
  }
  return offset + gctBytes;
}

function parseExtensionBlock(dv: DataView, state: GifBlockState): void {
  if (state.offset + 1 >= dv.byteLength) {
    state.warnings.push("Extension introducer truncated.");
    state.offset = dv.byteLength;
    return;
  }
  const label = dv.getUint8(state.offset + 1);
  if (label === 0xf9) parseGraphicControlBlock(dv, state);
  else if (label === 0xff) parseApplicationBlock(dv, state);
  else if (label === 0xfe) parseCommentBlock(dv, state);
  else if (label === 0x01) parsePlainTextBlock(dv, state);
  else skipUnknownExtensionBlock(dv, state);
}

function parseGraphicControlBlock(dv: DataView, state: GifBlockState): void {
  const { gce, nextOffset, warning } = parseGraphicControl(dv, state.offset);
  if (warning) state.warnings.push(warning);
  state.lastGce = gce;
  state.offset = nextOffset;
}

function parseApplicationBlock(dv: DataView, state: GifBlockState): void {
  const { info, nextOffset, warning } = parseApplicationExtension(dv, state.offset);
  if (warning) state.warnings.push(warning);
  if (info) {
    state.applicationExtensions.push(info);
    if (info.loopCount != null) state.loopCount = info.loopCount;
  }
  state.offset = nextOffset;
}

function parseCommentBlock(dv: DataView, state: GifBlockState): void {
  const { comment, nextOffset } = parseCommentExtension(dv, state.offset);
  state.comments.push(comment);
  state.offset = nextOffset;
}

function parsePlainTextBlock(dv: DataView, state: GifBlockState): void {
  const { nextOffset, warning } = parsePlainTextExtension(dv, state.offset);
  if (warning) state.warnings.push(warning);
  state.plainTextCount += 1;
  state.offset = nextOffset;
}

function skipUnknownExtensionBlock(dv: DataView, state: GifBlockState): void {
  const subBlocks = readSubBlocks(dv, state.offset + 2, 0);
  if (subBlocks.truncated) state.warnings.push("Extension sub-blocks truncated.");
  state.offset = subBlocks.endOffset;
}

function parseImageBlock(dv: DataView, state: GifBlockState): void {
  const { frame, nextOffset, warning } = parseImageDescriptor(dv, state.offset, state.lastGce);
  if (warning) state.warnings.push(warning);
  if (frame) state.frames.push(frame);
  state.lastGce = null;
  state.offset = nextOffset;
}

function parseDataBlocks(dv: DataView, offset: number, warnings: string[]): GifBlockState {
  const state: GifBlockState = {
    offset,
    frames: [],
    comments: [],
    applicationExtensions: [],
    plainTextCount: 0,
    loopCount: null,
    lastGce: null,
    hasTrailer: false,
    warnings
  };
  while (state.offset < dv.byteLength) {
    const marker = dv.getUint8(state.offset);
    if (marker === 0x3b) {
      state.hasTrailer = true;
      state.offset += 1;
      break;
    }
    if (marker === 0x21) {
      parseExtensionBlock(dv, state);
      continue;
    }
    if (marker === 0x2c) {
      parseImageBlock(dv, state);
      continue;
    }
    state.warnings.push(`Unknown block marker 0x${marker.toString(16)} encountered.`);
    state.offset += 1;
    break;
  }
  return state;
}

export async function parseGif(file: File): Promise<GifParseResult | null> {
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
  const globalColorCount = hasGct ? 2 ** ((packed & 0x07) + 1) : 0;
  const backgroundColorIndex = dv.getUint8(11);
  const pixelAspectByte = dv.getUint8(12);
  const pixelAspectRatio = pixelAspectByte === 0 ? null : (pixelAspectByte + 15) / 64;
  const warnings: string[] = [];
  const state = parseDataBlocks(dv, skipGlobalColorTable(dv, 13, hasGct, globalColorCount, warnings), warnings);
  const overlayBytes = state.offset < dv.byteLength ? dv.byteLength - state.offset : 0;
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
    frames: state.frames,
    frameCount: state.frames.length,
    loopCount: state.loopCount,
    comments: state.comments,
    applicationExtensions: state.applicationExtensions,
    plainTextCount: state.plainTextCount,
    hasTrailer: state.hasTrailer,
    overlayBytes,
    warnings
  };
}

export const isGifSignature = (dv: DataView): boolean => {
  if (dv.byteLength < 6) return false;
  const sig = readAsciiRange(dv, 0, 6);
  return sig === "GIF87a" || sig === "GIF89a";
};
